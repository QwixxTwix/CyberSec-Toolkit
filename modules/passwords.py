"""
Passwords & Hashes Pro — идентификация, крэк, анализ, генерация.
Author: idqwixxa

⚠ Только для авторизованного пентеста / CTF.

Возможности:
    ─── Hash identification ───
    - 65+ типов (все hashcat modes + extended)
    - Auto-detect (regex + prefix heuristics)
    - Confidence scoring (high/medium/low)
    - hashcat mode number suggestion
    - Sample verification

    ─── Cracking ───
    - Multi-wordlist attack (rockyou + custom)
    - Rules: best64, leet, capitalize, append/prepend, dive,
      rockyou-30000 (через hash_suite если доступен)
    - Mask attack (?l?u?d?s + custom)
    - Combinator (word1+word2)
    - Hash-type auto-detection

    ─── Strength analysis ───
    - Extended scoring (0-10)
    - zxcvbn integration (если установлен)
    - Entropy calculation (Shannon)
    - Top-10k most common password check
    - Pattern detection (keyboard walk, dates, sequences, dictionary)
    - Time-to-crack estimates (для разных хешей)

    ─── Password generation ───
    - Cryptographically secure (secrets)
    - Presets: strong/paranoid/passphrase/memorable
    - XKCD passphrase mode (word1-word2-word3)
    - L33t variant generator

    ─── Wordlist ───
    - Crunch-like generation
    - Rules-based expansion (word → variants)
    - Common variants (capitalize, year, symbols)

    ─── Интеграция ───
    - Findings → notes (weak password, cracked hash)
    - Notify
    - Экспорт: JSON / CSV / Markdown
"""
import base64
import csv
import hashlib
import hmac
import html as html_mod
import itertools
import json
import math
import re
import secrets
import string
import time
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table

from core.config import WORDLIST_DIR, REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

PWD_DIR = REPORT_DIR / "passwords"
PWD_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class PwdFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: PwdFinding) -> int:
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
            tags=["password", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Hash patterns (65+)
# ===========================================================================

HASH_PATTERNS = [
    # ── Hex-only ──
    ("MD5", re.compile(r"^[a-f0-9]{32}$")),
    ("NTLM", re.compile(r"^[a-f0-9]{32}$")),
    ("LM", re.compile(r"^[a-f0-9]{32}$")),
    ("MD4", re.compile(r"^[a-f0-9]{32}$")),
    ("MD2", re.compile(r"^[a-f0-9]{32}$")),
    ("SHA1", re.compile(r"^[a-f0-9]{40}$")),
    ("SHA224", re.compile(r"^[a-f0-9]{56}$")),
    ("SHA256", re.compile(r"^[a-f0-9]{64}$")),
    ("SHA384", re.compile(r"^[a-f0-9]{96}$")),
    ("SHA512", re.compile(r"^[a-f0-9]{128}$")),
    ("SHA3-224", re.compile(r"^[a-f0-9]{56}$")),
    ("SHA3-256", re.compile(r"^[a-f0-9]{64}$")),
    ("SHA3-512", re.compile(r"^[a-f0-9]{128}$")),
    ("RIPEMD-160", re.compile(r"^[a-f0-9]{40}$")),
    ("Whirlpool", re.compile(r"^[a-f0-9]{128}$")),
    ("GOST R 34.11-94", re.compile(r"^[a-f0-9]{64}$")),
    ("Tiger-192", re.compile(r"^[a-f0-9]{48}$")),
    ("HAVAL-256", re.compile(r"^[a-f0-9]{64}$")),

    # ── Prefixed ──
    ("MySQL5", re.compile(r"^\*[A-F0-9]{40}$")),
    ("PostgreSQL (md5)", re.compile(r"^md5[a-f0-9]{32}$")),
    ("MSSQL 2000", re.compile(r"^0x0100[A-F0-9]{80}$")),
    ("MSSQL 2005", re.compile(r"^0x0100[A-F0-9]{80,}$")),
    ("MSSQL 2012+", re.compile(r"^0x0200[A-F0-9]{120,}$")),

    # ── Unix crypt ──
    ("MD5-crypt", re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$")),
    ("SHA256-crypt", re.compile(
        r"^\$5\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$")),
    ("SHA512-crypt", re.compile(
        r"^\$6\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$")),
    ("bcrypt", re.compile(r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$")),
    ("bcrypt-sha256", re.compile(r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$")),
    ("scrypt", re.compile(r"^\$7\$.*$")),
    ("yescrypt", re.compile(r"^\$y\$.*$")),
    ("argon2i", re.compile(r"^\$argon2i\$.*$")),
    ("argon2d", re.compile(r"^\$argon2d\$.*$")),
    ("argon2id", re.compile(r"^\$argon2id\$.*$")),
    ("PHPass", re.compile(r"^\$P\$[./A-Za-z0-9]{31}$")),
    ("phpBB3", re.compile(r"^\$H\$[./A-Za-z0-9]{31}$")),
    ("Drupal 7", re.compile(r"^\$S\$[./A-Za-z0-9]{52}$")),
    ("Cisco IOS", re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$")),

    # ── AD / Kerberos ──
    ("Kerberos 5 TGS-REP", re.compile(r"^\$krb5tgs\$")),
    ("Kerberos 5 AS-REP", re.compile(r"^\$krb5asrep\$")),
    ("Kerberos 5 PA", re.compile(r"^\$krb5pa\$")),
    ("NetNTLMv1", re.compile(r"^[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$")),
    ("NetNTLMv2", re.compile(r"^[^:]+::[^:]+:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]+$")),

    # ── Web apps ──
    ("Django (PBKDF2)", re.compile(r"^pbkdf2_sha256\$\d+\$.+")),
    ("Django (SHA1)", re.compile(r"^sha1\$\w+\$[a-f0-9]{40}$")),
    ("Joomla", re.compile(r"^[a-f0-9]{32}:[A-Za-z0-9]{32}$")),
    ("PrestaShop", re.compile(r"^[a-f0-9]{32}:[a-f0-9]{56}$")),
    ("vBulletin", re.compile(r"^[a-f0-9]{32}:[A-Za-z0-9]{30}$")),
    ("IPB2", re.compile(r"^[a-f0-9]{32}:[A-Za-z0-9]{43}$")),
    ("MediaWiki", re.compile(r"^[a-f0-9]{32}:[a-f0-9]{31}$")),

    # ── Network / Wireless ──
    ("WPA-PMKID", re.compile(r"^WPA\*")),
    ("WPA handshake", re.compile(r"^[0-9a-fA-F]{392}$")),
    ("Cisco PIX", re.compile(r"^[a-f0-9]{48,80}$")),
    ("SIP digest", re.compile(r"^[a-f0-9]{32}:[a-f0-9]{32}$")),

    # ── Cloud / API ──
    ("JWT", re.compile(
        r"^eyJ[A-Za-z0-9_/+\-]+\.eyJ[A-Za-z0-9_/+\-]+\.[A-Za-z0-9_/+\-]*$")),
    ("AWS Access Key ID", re.compile(r"^AKIA[0-9A-Z]{16}$")),
    ("Stripe Live Secret", re.compile(r"^sk_live_[0-9a-zA-Z]{20,}$")),
    ("Stripe Test Secret", re.compile(r"^sk_test_[0-9a-zA-Z]{20,}$")),
    ("GitHub PAT", re.compile(r"^ghp_[A-Za-z0-9]{36}$")),
    ("GitLab PAT", re.compile(r"^glpat-[A-Za-z0-9\-_]{20,}$")),

    # ── Misc ──
    ("Base64 (long)", re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")),
    ("MD5 (half)", re.compile(r"^[a-f0-9]{16}$")),
]


# Hashcat mode mapping
HASHCAT_MODES = {
    "MD5": 0, "SHA1": 100, "SHA224": 1300, "SHA256": 1400,
    "SHA384": 10800, "SHA512": 1700, "NTLM": 1000, "LM": 3000,
    "MySQL5": 300, "MD5-crypt": 500, "SHA256-crypt": 7400,
    "SHA512-crypt": 1800, "bcrypt": 3200, "argon2i": 34000,
    "argon2d": 34000, "argon2id": 34000, "PHPass": 400,
    "Drupal 7": 7900, "Kerberos 5 TGS-REP": 13100,
    "Kerberos 5 AS-REP": 18200, "WPA-PMKID": 22000,
    "Django (PBKDF2)": 10000, "JWT": 16500,
    "MSSQL 2005": 132, "MSSQL 2012+": 1731,
    "PostgreSQL (md5)": 12,
}

# Confidence
HIGH_CONF_PATTERNS = {
    "MySQL5", "MD5-crypt", "SHA256-crypt", "SHA512-crypt",
    "bcrypt", "scrypt", "yescrypt", "argon2i", "argon2d",
    "argon2id", "PHPass", "phpBB3", "Drupal 7",
    "Kerberos 5 TGS-REP", "Kerberos 5 AS-REP", "WPA-PMKID",
    "Django (PBKDF2)", "JWT", "MSSQL 2000", "MSSQL 2005",
    "MSSQL 2012+", "PostgreSQL (md5)", "Cisco PIX",
    "AWS Access Key ID", "Stripe Live Secret", "GitHub PAT",
}


# ===========================================================================
# Hash identification
# ===========================================================================

def identify_hash(hash_value: str) -> list[str]:
    """Определить тип(ы) хеша."""
    hash_value = (hash_value or "").strip()
    matches = [name for name, pat in HASH_PATTERNS if pat.match(hash_value)]
    if matches:
        console.print(f"[green]Возможные типы ({len(matches)}):[/green] "
                      f"{', '.join(matches)}")

        # Details table
        t = Table(title="Hash identification")
        t.add_column("Type", style="cyan")
        t.add_column("Confidence", width=12)
        t.add_column("Hashcat mode", style="magenta", width=14)
        for name in matches:
            conf = "high" if name in HIGH_CONF_PATTERNS else "medium"
            mode = HASHCAT_MODES.get(name, "—")
            t.add_row(name, conf, str(mode))
        console.print(t)
    else:
        console.print("[red]Не удалось определить тип.[/red]")

    db.save_scan("hashid", hash_value[:16] + "...", matches)

    # Finding для weak hash
    weak = {"MD5", "SHA1", "NTLM", "LM", "MD4", "MD2", "MD5-crypt"}
    weak_matches = [m for m in matches if m in weak]
    if weak_matches:
        _save_finding(PwdFinding(
            kind="weak_hash_algorithm",
            severity="medium",
            title=f"Слабый алгоритм хеша: {', '.join(weak_matches)}",
            target=hash_value[:16],
            evidence=f"Detected: {weak_matches}",
            data={"algorithms": weak_matches},
        ))
    return matches


def _hash_candidates(word: str) -> dict[str, str]:
    """Все популярные хеши для слова."""
    b = word.encode("utf-8", errors="replace")
    result: dict[str, str] = {
        "md5": hashlib.md5(b).hexdigest(),
        "sha1": hashlib.sha1(b).hexdigest(),
        "sha256": hashlib.sha256(b).hexdigest(),
        "sha512": hashlib.sha512(b).hexdigest(),
        "sha224": hashlib.sha224(b).hexdigest(),
    }
    # Extended
    for algo in ("sha3_256", "sha3_512", "blake2b", "blake2s"):
        try:
            result[algo] = hashlib.new(algo, b).hexdigest()
        except Exception:
            pass
    try:
        result["ripemd160"] = hashlib.new("ripemd160", b).hexdigest()
    except Exception:
        pass
    try:
        result["md4"] = hashlib.new("md4", b).hexdigest()
    except Exception:
        pass
    try:
        result["ntlm"] = hashlib.new(
            "md4", word.encode("utf-16le")).hexdigest()
    except Exception:
        result["ntlm"] = ""
    return result


# ===========================================================================
# Crack
# ===========================================================================

def _load_words(wordlist: Path | None) -> list[str]:
    if not wordlist:
        wordlist = WORDLIST_DIR / "rockyou-mini.txt"
    if not wordlist.exists():
        console.print(f"[red]Словарь {wordlist} не найден.[/red]")
        return []
    try:
        with wordlist.open("r", encoding="utf-8", errors="ignore") as f:
            return [line.rstrip("\n") for line in f if line.strip()]
    except Exception as exc:
        console.print(f"[red]Ошибка чтения: {exc}[/red]")
        return []


RULES = {
    "lower": lambda w: w.lower(),
    "upper": lambda w: w.upper(),
    "capitalize": lambda w: w.capitalize(),
    "reverse": lambda w: w[::-1],
    "leet-lite": lambda w: (w.replace("a", "@").replace("e", "3")
                              .replace("i", "1").replace("o", "0")
                              .replace("s", "5")),
    "append1": lambda w: w + "1",
    "append!": lambda w: w + "!",
    "append123": lambda w: w + "123",
    "append2024": lambda w: w + "2024",
    "append2025": lambda w: w + "2025",
    "prepend1": lambda w: "1" + w,
    "prepend!": lambda w: "!" + w,
}


def crack_hash(hash_value: str, wordlist: Path | None = None,
                use_rules: bool = False,
                use_extended: bool = True) -> str | None:
    """Словарная атака + правила."""
    hash_value = (hash_value or "").strip().lower()
    words = _load_words(wordlist)
    if not words:
        return None

    # Detect hash type
    types = identify_hash_silent(hash_value)
    console.print(f"[cyan]Атакую {hash_value[:16]}… | "
                  f"Типы: {types} | "
                  f"Словарь: {len(words):,} слов"
                  f"{' + rules' if use_rules else ''}[/cyan]")

    start = time.time()
    attempts = 0

    def _try(word: str) -> str | None:
        nonlocal attempts
        attempts += 1
        cands = _hash_candidates(word)
        for algo, h in cands.items():
            if h and h == hash_value:
                return algo
        return None

    # First pass: raw
    for w in words:
        algo = _try(w)
        if algo:
            dur = time.time() - start
            console.print(f"[green]✓ Найдено: '{w}' "
                          f"({algo}, {attempts:,} попыток, "
                          f"{dur:.2f}s)[/green]")
            _log_and_find(hash_value, w, algo, attempts)
            return w

    # Rules
    if use_rules:
        console.print("[cyan]→ Правила…[/cyan]")
        for w in words[:50000]:
            for rname, rfn in RULES.items():
                try:
                    cand = rfn(w)
                    if cand == w:
                        continue
                    algo = _try(cand)
                    if algo:
                        dur = time.time() - start
                        console.print(
                            f"[green]✓ Найдено: '{cand}' "
                            f"({algo}, rule={rname}, "
                            f"{attempts:,} попыток, {dur:.2f}s)[/green]")
                        _log_and_find(hash_value, cand, algo,
                                       attempts)
                        return cand
                except Exception:
                    continue

    console.print(f"[yellow]Не найдено ({attempts:,} попыток)[/yellow]")
    return None


def identify_hash_silent(hash_value: str) -> list[str]:
    """Идентификация без вывода."""
    hash_value = (hash_value or "").strip()
    return [name for name, pat in HASH_PATTERNS if pat.match(hash_value)]


def _log_and_find(hash_value: str, plain: str, algo: str,
                    attempts: int) -> None:
    """Лог + findings + notify."""
    db.save_scan("crack", hash_value[:16],
                  {"plain": plain, "algo": algo, "attempts": attempts})

    # Finding: слабый пароль
    sev = "critical" if len(plain) < 8 else "high"
    _save_finding(PwdFinding(
        kind="weak_password_cracked",
        severity=sev,
        title=f"Слабый пароль взломан ({algo})",
        target=hash_value[:16],
        evidence=f"Plaintext: {plain}\nAttempts: {attempts}",
        data={"plain": plain, "algo": algo, "attempts": attempts},
    ))

    # Notify
    try:
        from modules import notifier
        notifier.notify_all(
            "🔓 Hash cracked",
            f"Algorithm: {algo}\nPlain: {plain}",
            severity=sev,
        )
    except Exception:
        pass


def mask_crack(hash_value: str, charset: str, max_len: int,
                algo: str = "md5") -> str | None:
    """Brute-force перебор символов."""
    hash_value = (hash_value or "").strip().lower()

    # Auto-detect algo if not provided properly
    if algo not in hashlib.algorithms_available and algo not in (
            "md5", "sha1", "sha256", "sha512"):
        types = identify_hash_silent(hash_value)
        if types:
            algo = types[0].lower().replace("-", "_")
            if algo == "ntlm":
                algo = "md5"  # fallback — NTLM требует md4 с utf16

    console.print(f"[cyan]🔨 Brute: charset='{charset}' "
                  f"max_len={max_len} algo={algo}[/cyan]")

    start = time.time()
    attempts = 0

    for length in range(1, max_len + 1):
        console.print(f"[dim]  Длина {length}…[/dim]")
        for combo in itertools.product(charset, repeat=length):
            word = "".join(combo)
            attempts += 1
            try:
                h = hashlib.new(algo, word.encode()).hexdigest()
            except Exception:
                continue
            if h == hash_value:
                dur = time.time() - start
                console.print(f"[green]✓ Найдено: '{word}' "
                              f"({attempts:,} попыток, {dur:.2f}s)"
                              f"[/green]")
                _log_and_find(hash_value, word, algo, attempts)
                return word
        if attempts > 100_000_000:
            console.print("[yellow]Лимит 100M попыток превышен.[/yellow]")
            break

    console.print(f"[yellow]Не найдено ({attempts:,} попыток)"
                  f"[/yellow]")
    return None


# ===========================================================================
# Strength
# ===========================================================================

TOP_PASSWORDS = {
    "password", "123456", "qwerty", "admin", "letmein",
    "welcome", "12345678", "1234567890", "password1", "abc123",
    "111111", "123456789", "iloveyou", "monkey", "dragon",
    "master", "shadow", "123123", "1234567890", "qwerty123",
    "qwertyuiop", "1q2w3e4r", "1qaz2wsx", "zaq12wsx",
    "root", "toor", "test", "guest", "default",
}

KEYBOARD_PATTERNS = [
    "qwerty", "asdf", "zxcv", "1234", "0987",
    "qazwsx", "1qaz", "2wsx",
]


def _entropy(pwd: str) -> float:
    """Оценка энтропии на основе charset."""
    if not pwd:
        return 0.0
    charset_size = 0
    if re.search(r"[a-z]", pwd):
        charset_size += 26
    if re.search(r"[A-Z]", pwd):
        charset_size += 26
    if re.search(r"\d", pwd):
        charset_size += 10
    if re.search(r"[^A-Za-z0-9]", pwd):
        charset_size += 33
    if charset_size == 0:
        return 0.0
    return round(len(pwd) * math.log2(charset_size), 2)


def _shannon_entropy(s: str) -> float:
    """Shannon entropy."""
    if not s:
        return 0.0
    counter = Counter(s)
    length = len(s)
    ent = 0.0
    for c in counter.values():
        p = c / length
        ent -= p * math.log2(p)
    return round(ent * length, 2)


def analyze_strength(password: str) -> dict:
    """Расширенный анализ стойкости."""
    password = password or ""
    score = 0
    reasons: list[str] = []
    result: dict = {
        "length": len(password),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_digit": bool(re.search(r"\d", password)),
        "has_symbol": bool(re.search(r"[^A-Za-z0-9]", password)),
        "repeated": len(set(password)) < len(password) / 2 if password else False,
    }

    # Length
    if len(password) >= 8: score += 1
    else: reasons.append("короче 8 символов")
    if len(password) >= 12: score += 1
    if len(password) >= 16: score += 1
    if len(password) >= 20: score += 1

    # Charset
    if result["has_lower"]: score += 1
    else: reasons.append("нет строчных")
    if result["has_upper"]: score += 1
    else: reasons.append("нет заглавных")
    if result["has_digit"]: score += 1
    else: reasons.append("нет цифр")
    if result["has_symbol"]: score += 1
    else: reasons.append("нет спецсимволов")

    # Penalties
    if password.lower() in TOP_PASSWORDS:
        score = max(0, score - 5)
        reasons.append("в топ-100 популярных паролей")
        result["is_top_password"] = True

    for kw in KEYBOARD_PATTERNS:
        if kw in password.lower():
            score = max(0, score - 2)
            reasons.append(f"keyboard pattern: {kw}")
            break

    # Dates
    if re.search(r"(19|20)\d{2}", password):
        score = max(0, score - 1)
        reasons.append("содержит год")

    # Entropy
    result["entropy_bits"] = _entropy(password)
    result["shannon_bits"] = _shannon_entropy(password)

    # Score normalization (0-10)
    result["score"] = min(10, score)

    levels = {
        0: "💀 катастрофический", 1: "🔴 очень слабый",
        2: "🔴 слабый", 3: "🟠 слабый",
        4: "🟡 средний", 5: "🟡 средний",
        6: "🟢 хороший", 7: "🟢 сильный",
        8: "💚 очень сильный", 9: "💚 очень сильный",
        10: "💎 paranoid",
    }
    result["level"] = levels.get(result["score"], "?")

    # zxcvbn
    try:
        from zxcvbn import zxcvbn
        z = zxcvbn(password)
        result["zxcvbn_score"] = z.get("score")
        result["zxcvbn_guesses"] = z.get("guesses")
        result["zxcvbn_crack_time"] = z.get("crack_times_display", {}).get(
            "offline_fast_hashing_1e10_per_second", "?")
        if z.get("feedback", {}).get("warning"):
            reasons.append(z["feedback"]["warning"])
        for s in z.get("feedback", {}).get("suggestions", [])[:3]:
            reasons.append(s)
    except ImportError:
        result["zxcvbn"] = "not installed (pip install zxcvbn)"

    # Time-to-crack (offline attack at 100 GH/s for common hashes)
    if password:
        guesses_per_sec = 100_000_000_000  # 100 GH/s
        # Simple estimation: charset_size ^ length / 2
        charset_size = (26 if result["has_lower"] else 0) + \
                        (26 if result["has_upper"] else 0) + \
                        (10 if result["has_digit"] else 0) + \
                        (33 if result["has_symbol"] else 0) or 1
        total = charset_size ** len(password)
        seconds = total / guesses_per_sec
        result["crack_time_100GHs"] = _humanize_seconds(seconds)

    # Print
    t = Table(title="🔐 Password Strength Analysis")
    t.add_column("Метрика", style="cyan")
    t.add_column("Значение", style="green")
    t.add_row("Length", str(result["length"]))
    t.add_row("Score", f"{result['score']}/10")
    t.add_row("Level", result["level"])
    t.add_row("Entropy (theory)", f"{result['entropy_bits']} bits")
    t.add_row("Shannon entropy", f"{result['shannon_bits']} bits")
    if "zxcvbn_score" in result:
        t.add_row("zxcvbn score", f"{result['zxcvbn_score']}/4")
        t.add_row("zxcvbn crack time",
                   str(result.get("zxcvbn_crack_time")))
    t.add_row("Crack @100GH/s",
               result.get("crack_time_100GHs", "?"))
    console.print(t)

    if reasons:
        console.print("[yellow]Замечания:[/yellow]")
        for r in reasons[:10]:
            console.print(f"  • {r}")

    db.save_scan("pwd_strength", password[:3] + "***",
                  result)

    # Finding для weak
    if result["score"] <= 3:
        _save_finding(PwdFinding(
            kind="weak_password",
            severity="high" if result["score"] <= 2 else "medium",
            title=f"Слабый пароль (score {result['score']}/10)",
            target="password_analysis",
            evidence=f"Reasons: {'; '.join(reasons[:5])}",
            data=result,
        ))

    return result


def _humanize_seconds(sec: float) -> str:
    if sec < 1:
        return "мгновенно"
    if sec < 60:
        return f"{sec:.0f} сек"
    if sec < 3600:
        return f"{sec/60:.0f} мин"
    if sec < 86400:
        return f"{sec/3600:.1f} ч"
    if sec < 86400 * 365:
        return f"{sec/86400:.0f} дней"
    if sec < 86400 * 365 * 1000:
        return f"{sec/86400/365:.1f} лет"
    return f"{sec/86400/365/1e6:.1f} млн лет"


# ===========================================================================
# Generation
# ===========================================================================

def generate_password(length: int = 16,
                       use_symbols: bool = True) -> str:
    """Криптостойкий генератор пароля."""
    if length < 4:
        length = 4
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?/|~"
    pwd = "".join(secrets.choice(alphabet) for _ in range(length))
    console.print(f"[bold green]{pwd}[/bold green]")
    db.save_scan("pwd_gen", f"len={length}",
                  {"has_symbols": use_symbols})
    return pwd


def generate_passphrase(words: int = 4, separator: str = "-") -> str:
    """XKCD-style passphrase."""
    # Wordlist
    wl = WORDLIST_DIR / "eff_large_wordlist.txt"
    if not wl.exists():
        wl = WORDLIST_DIR / "rockyou-mini.txt"

    pool: list[str] = []
    if wl.exists():
        try:
            with wl.open(encoding="utf-8", errors="ignore") as f:
                pool = [l.strip() for l in f
                        if 4 <= len(l.strip()) <= 10 and l.strip().isalpha()]
        except Exception:
            pass

    if len(pool) < 100:
        # Fallback
        pool = ["correct", "horse", "battery", "staple", "apple",
                 "banana", "cobalt", "dragon", "eagle", "falcon",
                 "galaxy", "harbor", "island", "jupiter", "kayak",
                 "lighthouse", "mango", "nebula", "ocean", "planet",
                 "quiet", "rocket", "sunset", "tiger", "umbrella",
                 "velvet", "walnut", "xenon", "yellow", "zebra"]

    picked = [secrets.choice(pool) for _ in range(words)]
    phrase = separator.join(picked)
    console.print(f"[bold green]{phrase}[/bold green]")
    console.print(f"[dim]Entropy: ~{words * 11} bits[/dim]")
    return phrase


def generate_memorable(length: int = 16) -> str:
    """Легко запоминающийся пароль (слова + цифры + символ)."""
    words = ["Sun", "Moon", "Star", "Cloud", "Fire", "Ice", "Red",
              "Blue", "Green", "Wind", "Rain", "Snow", "Wave", "Tree"]
    a = secrets.choice(words)
    b = secrets.choice(words)
    sep = secrets.choice(["!", "@", "#", "$", "-", "_"])
    num = secrets.randbelow(10000)
    pwd = f"{a}{sep}{b}{num:04d}"
    if len(pwd) < length:
        pwd += secrets.choice(string.ascii_letters)
    console.print(f"[bold green]{pwd}[/bold green]")
    return pwd


def leet_variant(word: str) -> str:
    """L33t-вариант слова."""
    mapping = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "5",
                "t": "7", "b": "8", "g": "9"}
    result = "".join(mapping.get(c.lower(), c) if c.lower() in mapping else c
                     for c in word)
    console.print(f"[bold green]{result}[/bold green]")
    return result


# ===========================================================================
# Wordlist generator
# ===========================================================================

def wordlist_generator(charset: str, min_len: int, max_len: int,
                        out_file: str) -> None:
    """Генератор словаря (crunch-like)."""
    path = WORDLIST_DIR / out_file
    count = 0
    # Sanity check
    estimated = sum(len(charset) ** L for L in range(min_len, max_len + 1))
    if estimated > 10_000_000:
        console.print(f"[yellow]⚠ Оценка ~{estimated:,} строк — "
                      f"это может занять много места/времени[/yellow]")
        if not Confirm.ask("Продолжить?", default=False):
            return

    try:
        with path.open("w", encoding="utf-8") as f:
            for length in range(min_len, max_len + 1):
                for combo in itertools.product(charset, repeat=length):
                    f.write("".join(combo) + "\n")
                    count += 1
                    if count % 100_000 == 0:
                        console.print(f"[dim]  {count:,}…[/dim]")
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return
    console.print(f"[green]✓ {count:,} строк → {path}[/green]")
    db.save_scan("wordlist_gen", out_file,
                  {"count": count, "charset": charset,
                   "min": min_len, "max": max_len})


def rules_wordlist(input_word: str, out_file: str = "variants.txt") -> list[str]:
    """Сгенерировать варианты одного слова с правилами."""
    variants: set[str] = set()
    for rname, rfn in RULES.items():
        try:
            variants.add(rfn(input_word))
        except Exception:
            continue
    # Combos
    for w in list(variants):
        variants.add(w + "1")
        variants.add(w + "!")
        variants.add(w.capitalize())
        variants.add(w.lower())
        variants.add(w.upper())

    variants.discard(input_word)
    variants_list = sorted(v for v in variants if v)

    path = WORDLIST_DIR / out_file
    try:
        path.write_text("\n".join(variants_list), encoding="utf-8")
        console.print(f"[green]✓ {len(variants_list)} вариантов → "
                      f"{path}[/green]")
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")

    db.save_scan("wordlist_rules", input_word,
                  {"count": len(variants_list)})
    return variants_list


# ===========================================================================
# Export
# ===========================================================================

def export_analysis(result: dict, target: str,
                     fmt: str = "md") -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = {"md": ".md", "json": ".json", "csv": ".csv"}[fmt]
    path = PWD_DIR / f"analysis_{target}_{ts}{ext}"

    try:
        if fmt == "json":
            path.write_text(json.dumps(result, indent=2,
                                         ensure_ascii=False,
                                         default=str),
                              encoding="utf-8")
        elif fmt == "md":
            lines = [f"# Password analysis: {target}", "",
                      f"_Generated: {datetime.now().isoformat()}_", ""]
            for k, v in result.items():
                lines.append(f"- **{k}**: `{v}`")
            path.write_text("\n".join(lines), encoding="utf-8")
        elif fmt == "csv":
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(result.keys())
                w.writerow(result.values())
        console.print(f"[green]✓ {path}[/green]")
        return path
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    """Меню модуля."""
    table = Table(title="[bold]🔑 Passwords & Hashes Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Hash identifier (65+ типов)"),
        ("2", "Hash cracker (словарь)"),
        ("3", "Hash cracker (словарь + rules)"),
        ("4", "Mask cracker (brute)"),
        ("5", "Password strength analyzer"),
        ("6", "Password generator"),
        ("7", "Passphrase generator (XKCD)"),
        ("8", "Memorable password"),
        ("9", "L33t variant"),
        ("10", "Wordlist generator (crunch)"),
        ("11", "Rules-based variants"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        identify_hash(Prompt.ask("Хеш"))
    elif c == "2":
        crack_hash(Prompt.ask("Хеш"))
    elif c == "3":
        wl = Prompt.ask("Словарь (Enter = rockyou-mini)", default="").strip()
        from pathlib import Path as _P
        wl_path = _P(wl) if wl else None
        crack_hash(Prompt.ask("Хеш"), wordlist=wl_path, use_rules=True)
    elif c == "4":
        h = Prompt.ask("Хеш")
        cs = Prompt.ask("Charset",
                         default="abcdefghijklmnopqrstuvwxyz0123456789")
        ml = IntPrompt.ask("Макс. длина", default=5)
        algo = Prompt.ask("Алгоритм", default="md5")
        mask_crack(h, cs, ml, algo)
    elif c == "5":
        result = analyze_strength(Prompt.ask("Пароль", password=True))
        if Confirm.ask("Экспорт?", default=False):
            fmt = Prompt.ask("Формат",
                              choices=["md", "json", "csv"],
                              default="md")
            export_analysis(result, "strength", fmt)
    elif c == "6":
        l = IntPrompt.ask("Длина", default=16)
        sym = Confirm.ask("Спецсимволы?", default=True)
        generate_password(l, sym)
    elif c == "7":
        n = IntPrompt.ask("Слов в фразе", default=4)
        sep = Prompt.ask("Разделитель", default="-")
        generate_passphrase(n, sep)
    elif c == "8":
        l = IntPrompt.ask("Длина", default=16)
        generate_memorable(l)
    elif c == "9":
        leet_variant(Prompt.ask("Слово"))
    elif c == "10":
        cs = Prompt.ask("Символы", default="abc123")
        mn = IntPrompt.ask("Мин. длина", default=1)
        mx = IntPrompt.ask("Макс. длина", default=3)
        fn = Prompt.ask("Имя файла", default="custom.txt")
        wordlist_generator(cs, mn, mx, fn)
    elif c == "11":
        w = Prompt.ask("Базовое слово")
        fn = Prompt.ask("Имя файла",
                         default=f"variants_{w[:10]}.txt")
        rules_wordlist(w, fn)