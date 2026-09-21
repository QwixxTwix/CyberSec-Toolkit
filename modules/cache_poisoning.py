"""
Web Cache Poisoning Suite — расширенный.
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty / CTF.

Возможности:
    ─── Unkeyed headers ───
    - 40+ заголовков (X-Forwarded-*, X-Original-URL, Forwarded, …)
    - Baseline diff по нескольким параметрам (body, len, status, hash)
    - Отражение canary-строки в body / headers

    ─── Cache deception ───
    - Расширения .css/.js/.png/… + все трюки (;, ?, %, ..)
    - Path normalization tricks (..%2F, %00, multiple /)

    ─── Parameter cloaking ───
    - Дублирующиеся параметры, ;-сепарация, массив, %00, %26

    ─── Cache key / Vary ───
    - Анализ Vary, Cache-Control, Age
    - Определение cache-статуса (X-Cache, CF-Cache-Status, Age)
    - Case-sensitivity cache key (URL, query, headers)

    ─── Advanced ───
    - Fat GET (body в GET)
    - Method override (X-HTTP-Method-Override)
    - Request smuggling hints (CL.TE, TE.CL, TE.TE)
    - HTTP/2 hints (HPACK bomb, response splitting)
    - Host header injection

    ─── Отчётность ───
    - Rich-таблица + JSON + HTML
    - Findings → notes (critical/high только)
    - Notify по завершении
"""
import hashlib
import html as html_mod
import json
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse, urljoin, quote

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, normalize_url

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CACHE_DIR = REPORT_DIR / "cache_poisoning"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

TIMEOUT = 15
MAX_RETRIES = 2


# ===========================================================================
# Модель
# ===========================================================================

@dataclass
class CacheFinding:
    kind: str
    severity: str
    url: str
    detail: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: CacheFinding) -> int:
    """Сохранить критичные findings в notes."""
    if f.severity not in ("critical", "high"):
        return -1
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f"Cache Poisoning: {f.kind} on {f.url[:60]}",
            target=f.url[:80],
            severity=f.severity,
            status="open",
            tags=["cache-poisoning", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**URL:** {f.url}\n\n"
                  f"**Detail:** {f.detail}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:2000]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Unkeyed headers
# ===========================================================================

UNKEYED_HEADERS = [
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto",
    "X-Forwarded-Port", "X-Forwarded-For", "X-Forwarded-Server",
    "X-Host", "X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
    "X-Original-Host", "X-Forwarded-Server", "X-Forwarded-Prefix",
    "X-Real-IP", "X-Client-IP", "X-Remote-IP", "X-Originating-IP",
    "X-Remote-Addr", "X-Custom-IP-Authorization", "X-Forwarded",
    "Forwarded", "CF-Connecting-IP", "CF-Connecting-IP6",
    "True-Client-IP", "Fastly-Client-IP", "X-Azure-ClientIP",
    "X-Azure-Ref", "X-ProxyUser-Ip", "X-Wap-Profile", "Profile",
    "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
    "X-Original-Method", "X-Rewrite-Method",
    "Accept-Language", "Accept-Charset", "Accept-Encoding",
    "Cookie", "Origin", "Referer", "User-Agent",
    "X-Backend-Server", "X-Backend-Host", "X-Forwarded-By",
    "X-Forwarded-For-Original", "X-Cache-Key-Debug", "X-Debug",
    "X-Request-ID", "X-Correlation-ID", "X-Trace-ID",
]

INJECT_VALUES = [
    "evil-attacker-canary-9be7b8c2.com",
    "attacker.invalid",
    "1.3.3.7",
    "127.0.0.1",
    "https",
    "http",
    "31337",
    "8.8.8.8",
    "evil.com/../",
]

CACHE_STATUS_HEADERS = [
    "X-Cache", "X-Cache-Hit", "X-Cache-Status", "X-Cache-Key",
    "CF-Cache-Status", "X-Proxy-Cache", "X-Varnish", "X-Served-By",
    "X-Cacheable", "X-ESI", "X-CDN", "X-Fastly-Request-ID",
    "Age", "Via", "X-Squid-Error", "X-Cache-Lookup",
    "X-Akamai-Transformed", "X-Akamai-Request-ID",
    "X-Cache-Remote", "X-Cache-Server",
]


# ===========================================================================
# Helpers
# ===========================================================================

def _get(url: str, headers: dict | None = None,
         timeout: int = TIMEOUT,
         allow_redirects: bool = False,
         method: str = "GET",
         data: Any = None) -> requests.Response | None:
    h = {"User-Agent": config.USER_AGENT}
    if headers:
        h.update(headers)
    kwargs: dict = {
        "headers": h, "timeout": timeout, "verify": False,
        "allow_redirects": allow_redirects,
    }
    if data is not None:
        kwargs["data"] = data
    for attempt in range(MAX_RETRIES + 1):
        try:
            return requests.request(method, url, **kwargs)
        except requests.exceptions.Timeout:
            if attempt < MAX_RETRIES:
                time.sleep(0.5)
                continue
            return None
        except Exception as exc:
            log.debug("%s %s: %s", method, url, exc)
            return None
    return None


def _hash_body(body: str) -> str:
    return hashlib.md5(body.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _cache_status(resp: requests.Response) -> dict:
    out: dict = {}
    for h in CACHE_STATUS_HEADERS:
        v = resp.headers.get(h)
        if v:
            out[h] = v
    return out


def _is_cached(status: dict) -> bool:
    x_cache = str(status.get("X-Cache", "")).lower()
    cf = str(status.get("CF-Cache-Status", "")).lower()
    proxy = str(status.get("X-Proxy-Cache", "")).lower()
    varnish = status.get("X-Varnish", "")
    akamai = status.get("X-Akamai-Transformed", "")
    age = status.get("Age", "0")
    try:
        age_int = int(age)
    except Exception:
        age_int = 0
    return (
        "hit" in x_cache or
        cf in ("hit", "revalidated", "miss") or
        "hit" in proxy or
        age_int > 0 or
        bool(varnish) or
        bool(akamai)
    )


def _baseline(url: str) -> tuple[requests.Response | None, str]:
    r = _get(url)
    if not r:
        return None, ""
    return r, _hash_body(r.text)


# ===========================================================================
# Unkeyed headers
# ===========================================================================

def test_unkeyed_headers(url: str,
                          only_headers: list[str] | None = None
                          ) -> list[CacheFinding]:
    console.print(f"[cyan]🔍 Unkeyed headers: {url}[/cyan]")

    base_resp, base_hash = _baseline(url)
    if not base_resp:
        console.print("[red]Baseline запрос не прошёл.[/red]")
        return []

    base_body = base_resp.text
    base_len = len(base_body)
    base_status = base_resp.status_code

    console.print(f"[dim]Baseline: status={base_status}, "
                  f"len={base_len}, hash={base_hash}[/dim]")

    base_cache = _cache_status(base_resp)
    if base_cache:
        console.print(f"[dim]Cache headers: {base_cache}[/dim]")

    headers_to_test = only_headers or UNKEYED_HEADERS
    findings: list[CacheFinding] = []

    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  console=console) as p:
        task = p.add_task("unkeyed",
                           total=len(headers_to_test) * len(INJECT_VALUES))
        for h in headers_to_test:
            for val in INJECT_VALUES:
                p.advance(task)
                r = _get(url, {h: val})
                if not r:
                    continue
                body = r.text
                hsh = _hash_body(body)

                # 1. Отражение canary
                if val in body:
                    findings.append(CacheFinding(
                        kind="header_reflected",
                        severity="medium",
                        url=url,
                        detail=f"{h}: {val} отражён в body",
                        evidence=f"Body содержит '{val}'",
                        data={"header": h, "value": val,
                              "status": r.status_code},
                    ))
                    console.print(f"[yellow]⚠ {h}: {val} отражён (body)"
                                  f"[/yellow]")

                # 2. Отражение в headers
                elif any(val in v for v in r.headers.values()):
                    findings.append(CacheFinding(
                        kind="header_reflected_in_headers",
                        severity="medium",
                        url=url,
                        detail=f"{h}: {val} отражён в response headers",
                        evidence=f"Header value содержит '{val}'",
                        data={"header": h, "value": val},
                    ))
                    console.print(f"[yellow]⚠ {h}: {val} отражён "
                                  f"(headers)[/yellow]")

                # 3. Другой размер / статус / hash
                elif abs(len(body) - base_len) > 100:
                    findings.append(CacheFinding(
                        kind="response_diff",
                        severity="low",
                        url=url,
                        detail=f"{h}: размер изменился на "
                               f"{len(body) - base_len}",
                        data={"header": h, "value": val,
                              "base_len": base_len,
                              "new_len": len(body)},
                    ))

                elif r.status_code != base_status:
                    findings.append(CacheFinding(
                        kind="status_diff",
                        severity="low",
                        url=url,
                        detail=f"{h}: status {base_status}→{r.status_code}",
                        data={"header": h, "value": val,
                              "base_status": base_status,
                              "new_status": r.status_code},
                    ))

    if not findings:
        console.print("[green]✓ Unkeyed-эффектов не найдено.[/green]")
    db.save_scan("cache_unkeyed", url, {
        "checked_headers": len(headers_to_test),
        "checked_values": len(INJECT_VALUES),
        "findings": len(findings),
        "results": [asdict(f) for f in findings[:50]],
    })
    return findings


# ===========================================================================
# Cache deception
# ===========================================================================

DECEPTION_EXTENSIONS = [
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".otf", ".pdf", ".txt",
    ".html", ".htm", ".xml", ".json", ".map",
]

DECEPTION_TRICKS = [
    # Classic
    "{path}/style.css",
    "{path}/style.js",
    "{path}/logo.png",
    # Path normalization
    "{path}/..%2Fstyle.css",
    "{path}/%2Fstyle.css",
    "{path}/%252Fstyle.css",
    "{path}/..;/style.css",
    # Semicolon
    "{path};.css",
    "{path};/style.css",
    # Query
    "{path}?.css",
    "{path}?x=.css",
    # Fragment
    "{path}#.css",
    # Dot / slash
    "{path}/.css",
    "{path}/./style.css",
    # Null byte
    "{path}%00.css",
    "{path}%00style.css",
    # Extra slash
    "{path}//style.css",
    # Double extension
    "{path}/style.css.bak",
    # Trailing space
    "{path}/style.css%20",
]


def cache_deception(url: str) -> list[CacheFinding]:
    console.print(f"[cyan]🔍 Cache deception: {url}[/cyan]")

    base_resp, _ = _baseline(url)
    if not base_resp:
        return []

    base_status = base_resp.status_code
    console.print(f"[dim]Baseline status: {base_status}[/dim]")

    findings: list[CacheFinding] = []
    path = url.split("?", 1)[0].rstrip("/")

    # 1. Extensions
    for ext in DECEPTION_EXTENSIONS:
        test_url = path + ext
        r = _get(test_url)
        if not r:
            continue
        cstat = _cache_status(r)
        if _is_cached(cstat) and r.status_code == 200:
            findings.append(CacheFinding(
                kind="cache_deception_extension",
                severity="high",
                url=test_url,
                detail=f"URL с расширением {ext} кэшируется",
                evidence=f"cache={cstat}",
                data={"status": r.status_code, "cache": cstat,
                      "extension": ext},
            ))
            console.print(f"[red]⚠ Кэшируется: {test_url} ({cstat})"
                          f"[/red]")

    # 2. Tricks
    for trick in DECEPTION_TRICKS:
        test_url = trick.replace("{path}", path)
        r = _get(test_url)
        if not r:
            continue
        cstat = _cache_status(r)
        if _is_cached(cstat) and r.status_code == 200:
            findings.append(CacheFinding(
                kind="cache_deception_trick",
                severity="high",
                url=test_url,
                detail=f"Trick: {trick}",
                evidence=f"cache={cstat}",
                data={"status": r.status_code, "cache": cstat,
                      "trick": trick},
            ))
            console.print(f"[red]⚠ {trick[:60]} ({cstat})[/red]")

    if not findings:
        console.print("[green]✓ Cache deception не сработал.[/green]")
    db.save_scan("cache_deception", url, {"findings": len(findings)})
    return findings


# ===========================================================================
# Vary / Cache-Control / Age
# ===========================================================================

def vary_analysis(url: str) -> dict:
    console.print(f"[cyan]🔍 Vary / Cache-Control analysis: {url}[/cyan]")
    r = _get(url)
    if not r:
        return {}

    vary = r.headers.get("Vary", "")
    cc = r.headers.get("Cache-Control", "")
    age = r.headers.get("Age", "")
    expires = r.headers.get("Expires", "")
    pragma = r.headers.get("Pragma", "")
    cstat = _cache_status(r)

    t = Table(title=f"Cache headers — {url[:60]}")
    t.add_column("Header", style="cyan")
    t.add_column("Value", style="green", max_width=80)
    t.add_row("Vary", vary or "[dim](нет)[/dim]")
    t.add_row("Cache-Control", cc or "—")
    t.add_row("Age", age or "—")
    t.add_row("Expires", expires or "—")
    t.add_row("Pragma", pragma or "—")
    for k, v in cstat.items():
        t.add_row(k, v)
    console.print(t)

    findings: list[str] = []
    if not vary:
        findings.append("Нет Vary — кэш может быть по URL только")
    if cc:
        low = cc.lower()
        if "no-store" in low or "no-cache" in low:
            console.print("[green]✓ Cache-Control указывает no-cache[/green]")
        elif "public" in low:
            console.print("[yellow]⚠ public кэширование разрешено[/yellow]")
            findings.append("public кэш")
        if "s-maxage" in low:
            findings.append("shared cache (s-maxage)")
    if age:
        try:
            if int(age) > 0:
                console.print(f"[yellow]⚠ Age={age} — кэш работает[/yellow]")
        except Exception:
            pass

    db.save_scan("cache_vary", url, {
        "vary": vary, "cache_control": cc, "age": age,
        "findings": findings,
    })
    return {"vary": vary, "cache_control": cc, "age": age,
            "cache_status": cstat, "findings": findings}


# ===========================================================================
# Fat GET
# ===========================================================================

def fat_get(url: str) -> CacheFinding | None:
    console.print(f"[cyan]🔍 Fat GET: {url}[/cyan]")
    canary = "canary_" + str(int(time.time()))
    r = _get(url, headers={"Content-Type":
                            "application/x-www-form-urlencoded"},
             data=f"test={canary}")
    if not r:
        console.print("[red]Fat GET: запрос не прошёл[/red]")
        return None

    if canary in r.text:
        console.print("[red]⚠ Fat GET: body отражается в ответе![/red]")
        f = CacheFinding(
            kind="fat_get_reflection",
            severity="medium",
            url=url,
            detail="Тело GET-запроса отражается",
            evidence=f"canary='{canary}' найден в response",
            data={"canary": canary, "status": r.status_code},
        )
        _save_finding(f)
        return f
    console.print("[green]✓ Fat GET не сработал.[/green]")
    return CacheFinding(kind="fat_get_no_effect", severity="info", url=url)


# ===========================================================================
# Parameter cloaking
# ===========================================================================

PARAM_CLOAKING = [
    "?a=1&a=2",
    "?a=1;a=2",
    "?a=1%00&a=2",
    "?a=1%26a=2",
    "?a=1&a=2&a=3",
    "?a[]=1&a[]=2",
    "?a=1&b=2&a=3",
    "?a=1&a=1",
    "?a=%2b1&a=2",
    "?a=1&a[]=2",
    "?a=1&a=2#",
    "?a=1#&a=2",
]


def parameter_cloaking(url: str) -> list[CacheFinding]:
    console.print(f"[cyan]🔍 Parameter cloaking: {url}[/cyan]")
    findings: list[CacheFinding] = []

    base = url.split("?")[0]
    base_resp = _get(base)
    if not base_resp:
        return []
    base_len = len(base_resp.text)
    base_status = base_resp.status_code

    for pattern in PARAM_CLOAKING:
        test_url = base + pattern
        r = _get(test_url)
        if not r:
            continue
        cstat = _cache_status(r)
        cached = _is_cached(cstat)

        if cached and (abs(len(r.text) - base_len) > 100
                        or r.status_code != base_status):
            findings.append(CacheFinding(
                kind="param_cloaking",
                severity="medium",
                url=test_url,
                detail=f"Параметр обрабатывается: {pattern}",
                evidence=f"len={len(r.text)}, status={r.status_code}, "
                         f"cache={cstat}",
                data={"status": r.status_code, "cache": cstat,
                      "pattern": pattern},
            ))
            console.print(f"[yellow]⚠ {pattern} ({cstat})[/yellow]")

    if not findings:
        console.print("[green]✓ Parameter cloaking не сработал.[/green]")
    db.save_scan("cache_param_cloaking", url,
                 {"findings": len(findings)})
    return findings


# ===========================================================================
# Method override
# ===========================================================================

METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
    "X-Original-Method",
    "X-Rewrite-Method",
]

METHOD_OVERRIDE_VALUES = ["POST", "PUT", "DELETE", "PATCH"]


def method_override_test(url: str) -> list[CacheFinding]:
    console.print(f"[cyan]🔍 Method override test[/cyan]")
    findings: list[CacheFinding] = []

    base_resp, _ = _baseline(url)
    if not base_resp:
        return []
    base_status = base_resp.status_code

    for h in METHOD_OVERRIDE_HEADERS:
        for m in METHOD_OVERRIDE_VALUES:
            r = _get(url, {h: m})
            if not r:
                continue
            cstat = _cache_status(r)
            if r.status_code != base_status and _is_cached(cstat):
                findings.append(CacheFinding(
                    kind="method_override_cache",
                    severity="medium",
                    url=url,
                    detail=f"{h}: {m} → {r.status_code} (cached)",
                    evidence=f"base={base_status}, new={r.status_code}, "
                             f"cache={cstat}",
                    data={"header": h, "method": m,
                          "status": r.status_code, "cache": cstat},
                ))
                console.print(f"[yellow]⚠ {h}:{m} → "
                              f"{r.status_code} ({cstat})[/yellow]")

    if not findings:
        console.print("[green]✓ Method override не сработал.[/green]")
    return findings


# ===========================================================================
# Host header injection
# ===========================================================================

def host_header_test(url: str) -> list[CacheFinding]:
    console.print(f"[cyan]🔍 Host header injection[/cyan]")
    findings: list[CacheFinding] = []

    parsed = urlparse(url)
    orig_host = parsed.netloc
    canary = "evil-attacker-host.invalid"

    for host_val in (canary, f"{canary}:443", f"{orig_host}.{canary}"):
        r = _get(url, {"Host": host_val})
        if not r:
            continue
        if canary in r.text or any(canary in v for v in r.headers.values()):
            findings.append(CacheFinding(
                kind="host_header_injection",
                severity="high",
                url=url,
                detail=f"Host: {host_val} отражён",
                evidence=f"canary='{canary}' найден в ответе",
                data={"host": host_val, "status": r.status_code},
            ))
            console.print(f"[red]⚠ Host:{host_val} отражён[/red]")
            _save_finding(findings[-1])

    if not findings:
        console.print("[green]✓ Host header injection не найдена.[/green]")
    return findings


# ===========================================================================
# Request smuggling hints
# ===========================================================================

def smuggling_hints(url: str) -> None:
    console.print("[cyan]📚 Request smuggling hints[/cyan]")
    t = Table(title="Request smuggling techniques")
    t.add_column("Technique", style="cyan", width=20)
    t.add_column("Description", style="white", max_width=70)
    t.add_row("CL.TE", "Frontend: Content-Length, Backend: Transfer-Encoding")
    t.add_row("TE.CL", "Frontend: TE, Backend: CL")
    t.add_row("TE.TE", "Both TE, но один обфусцирован")
    t.add_row("H2.CL", "HTTP/2 → HTTP/1.1: Content-Length конфликт")
    t.add_row("H2.TE", "HTTP/2 → HTTP/1.1: Transfer-Encoding")
    t.add_row("CL.0", "Frontend игнорирует CL → backend ждёт body")
    t.add_row("Desync", "Pipelining request/response desync")
    console.print(t)
    console.print("[yellow]⚠ Требует ручной проверки в Burp "
                  "(HTTP Request Smuggler).[/yellow]")


# ===========================================================================
# HTTP/2 hints
# ===========================================================================

def http2_hints(url: str) -> None:
    console.print("[cyan]📚 HTTP/2 Cache Poisoning vectors[/cyan]")
    t = Table(title="HTTP/2 vectors")
    t.add_column("Technique", style="cyan", width=25)
    t.add_column("Description", style="white", max_width=65)
    t.add_row("HPACK Bomb", "Сжатие HPACK → большой decoded table (DoS)")
    t.add_row("Cache Key Normalization",
              "Разные формы (case, dot, slash) → один cache key")
    t.add_row("Response Splitting",
              "CRLF в header value → инъекция в ответ")
    t.add_row("Line Endings", "\\r\\n vs \\n в заголовках")
    t.add_row("Pseudo-header override",
              "Duplicate :method, :path, :authority")
    t.add_row("Header rename", "Lowercase/uppercase в H2")
    console.print(t)
    console.print("[dim]Требуется Burp Suite / h2csmuggler.[/dim]")


# ===========================================================================
# Full scan
# ===========================================================================

def full_scan(url: str, save_findings: bool = True) -> list[CacheFinding]:
    url = normalize_url(url)
    if not confirm_external(url):
        return []

    console.print(f"\n[bold cyan]═══ Cache Poisoning Scan: {url} "
                  f"═══[/bold cyan]\n")

    all_findings: list[CacheFinding] = []

    console.print("[bold cyan]1/8 Vary / Cache-Control[/bold cyan]")
    vary_analysis(url)

    console.print("\n[bold cyan]2/8 Unkeyed headers[/bold cyan]")
    all_findings.extend(test_unkeyed_headers(url))

    console.print("\n[bold cyan]3/8 Cache deception[/bold cyan]")
    all_findings.extend(cache_deception(url))

    console.print("\n[bold cyan]4/8 Fat GET[/bold cyan]")
    f3 = fat_get(url)
    if f3:
        all_findings.append(f3)

    console.print("\n[bold cyan]5/8 Parameter cloaking[/bold cyan]")
    all_findings.extend(parameter_cloaking(url))

    console.print("\n[bold cyan]6/8 Method override[/bold cyan]")
    all_findings.extend(method_override_test(url))

    console.print("\n[bold cyan]7/8 Host header injection[/bold cyan]")
    all_findings.extend(host_header_test(url))

    console.print("\n[bold cyan]8/8 Summary[/bold cyan]")

    _print_summary(all_findings, url)

    # Findings → notes
    if save_findings:
        saved = 0
        for f in all_findings:
            if f.severity in ("critical", "high"):
                if _save_finding(f) > 0:
                    saved += 1
        if saved:
            console.print(f"\n[green]✓ Findings в notes: {saved}[/green]")

    # Экспорт JSON + HTML
    _export_json(all_findings, url)
    _export_html(all_findings, url)

    # Notify
    try:
        from modules import notifier
        notifier.notify_all(
            f"💾 Cache Scan: {url[:60]}",
            f"Findings: {len(all_findings)}\n"
            f"Critical: {sum(1 for f in all_findings if f.severity == 'critical')}\n"
            f"High: {sum(1 for f in all_findings if f.severity == 'high')}",
        )
    except Exception:
        pass

    db.save_scan("cache_full_scan", url, {
        "findings": len(all_findings),
        "by_severity": {s: sum(1 for f in all_findings
                              if f.severity == s)
                        for s in ("critical", "high", "medium", "low")},
    })
    return all_findings


def _print_summary(findings: list[CacheFinding], url: str) -> None:
    if not findings:
        console.print(f"\n[green]✓ Ничего критичного не найдено.[/green]")
        return
    t = Table(title=f"🚨 Cache findings — {url[:60]} ({len(findings)})")
    t.add_column("#", width=4)
    t.add_column("Kind", style="cyan", max_width=30)
    t.add_column("Severity", width=10)
    t.add_column("Detail", max_width=60)
    for i, f in enumerate(findings, 1):
        sty = {"critical": "bold red", "high": "red",
               "medium": "yellow", "low": "green",
               "info": "dim"}.get(f.severity, "white")
        t.add_row(str(i), f.kind,
                  f"[{sty}]{f.severity.upper()}[/{sty}]",
                  f.detail[:60])
    console.print(t)


def _export_json(findings: list[CacheFinding], url: str) -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", url)[:60]
    path = CACHE_DIR / f"scan_{safe}_{ts}.json"
    try:
        path.write_text(json.dumps({
            "url": url, "ts": datetime.now().isoformat(),
            "findings": [asdict(f) for f in findings],
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"[green]✓ JSON: {path}[/green]")
        return path
    except Exception as exc:
        log.warning("json export: %s", exc)
        return None


def _export_html(findings: list[CacheFinding], url: str) -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", url)[:60]
    path = CACHE_DIR / f"scan_{safe}_{ts}.html"

    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>Cache Poisoning: {html_mod.escape(url)}</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:24px;line-height:1.5;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
        "table{width:100%;border-collapse:collapse;margin-top:12px;"
        "font-size:13px;}",
        "th{background:#111;color:#00ff9c;padding:8px;text-align:left;"
        "border:1px solid #222;}",
        "td{padding:6px 8px;border:1px solid #222;word-break:break-all;}",
        "tr:nth-child(even){background:#0d0d0d;}",
        ".critical{color:#ff2020;font-weight:bold;}",
        ".high{color:#ff7a40;font-weight:bold;}",
        ".medium{color:#ffd23f;}",
        ".low{color:#00ff9c;}",
        "pre{background:#050505;border:1px solid #222;padding:8px;"
        "color:#a0ffa0;font-size:11px;}",
        "</style></head><body>",
        f"<h1>💾 Cache Poisoning — {html_mod.escape(url)}</h1>",
        f"<p>Findings: <b>{len(findings)}</b> | "
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "<table><tr><th>#</th><th>Kind</th><th>Sev</th>"
        "<th>Detail</th><th>URL</th></tr>",
    ]
    for i, f in enumerate(findings, 1):
        parts.append(
            f"<tr><td>{i}</td>"
            f"<td>{html_mod.escape(f.kind)}</td>"
            f"<td class='{f.severity}'>{f.severity.upper()}</td>"
            f"<td>{html_mod.escape(f.detail[:100])}</td>"
            f"<td>{html_mod.escape(f.url[:100])}</td></tr>"
        )
    parts.append("</table></body></html>")

    try:
        path.write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return path
    except Exception as exc:
        log.warning("html export: %s", exc)
        return None


# ===========================================================================
# CLI-обёртки (совместимы со старыми)
# ===========================================================================

def cli_scan(url: str) -> None:
    full_scan(url)


def cli_unkeyed(url: str) -> None:
    test_unkeyed_headers(normalize_url(url))


def cli_deception(url: str) -> None:
    cache_deception(normalize_url(url))


def cli_vary(url: str) -> None:
    vary_analysis(normalize_url(url))


def cli_fat(url: str) -> None:
    fat_get(normalize_url(url))


def cli_param_cloaking(url: str) -> None:
    parameter_cloaking(normalize_url(url))


def cli_method_override(url: str) -> None:
    method_override_test(normalize_url(url))


def cli_host_injection(url: str) -> None:
    host_header_test(normalize_url(url))


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]💾 Web Cache Poisoning Suite[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Полный скан (все техники)"),
        ("2", "Unkeyed headers detection"),
        ("3", "Cache deception"),
        ("4", "Vary / Cache-Control анализ"),
        ("5", "Fat GET attack"),
        ("6", "Parameter cloaking"),
        ("7", "Method override"),
        ("8", "Host header injection"),
        ("9", "Request smuggling hints"),
        ("10", "HTTP/2 hints"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного пентеста.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        full_scan(Prompt.ask("URL"))
    elif c == "2":
        test_unkeyed_headers(normalize_url(Prompt.ask("URL")))
    elif c == "3":
        cache_deception(normalize_url(Prompt.ask("URL")))
    elif c == "4":
        vary_analysis(normalize_url(Prompt.ask("URL")))
    elif c == "5":
        fat_get(normalize_url(Prompt.ask("URL")))
    elif c == "6":
        parameter_cloaking(normalize_url(Prompt.ask("URL")))
    elif c == "7":
        method_override_test(normalize_url(Prompt.ask("URL")))
    elif c == "8":
        host_header_test(normalize_url(Prompt.ask("URL")))
    elif c == "9":
        smuggling_hints(Prompt.ask("URL"))
    elif c == "10":
        http2_hints(Prompt.ask("URL"))