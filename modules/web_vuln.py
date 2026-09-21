"""Модуль веб-уязвимостей: headers, SSL, SQLi, XSS, LFI, dirb, CMS, redirect, CSRF."""
import ssl
import socket
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from core.config import config, WORDLIST_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, normalize_url

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
log = get_logger(__name__)

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR \"\"=\"", "') OR ('1'='1"]
SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "you have an error in your sql",
    "unclosed quotation", "pg_query", "sqlite error", "ora-",
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><svg/onload=alert(1)>",
    "'><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
]
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "/etc/passwd%00",
]
OPEN_REDIRECT_PAYLOADS = ["//evil.com", "https://evil.com", "/\\evil.com"]


def _req(url: str, method: str = "GET", **kwargs) -> requests.Response | None:
    try:
        return requests.request(
            method, url,
            headers={"User-Agent": config.USER_AGENT},
            timeout=config.REQUEST_TIMEOUT,
            allow_redirects=False,
            verify=False,
            **kwargs,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("HTTP ошибка %s: %s", url, exc)
        return None


def header_analyzer(target: str) -> None:
    """Проверка отсутствующих security-заголовков."""
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
    for h in SECURITY_HEADERS:
        val = r.headers.get(h)
        if val:
            table.add_row(h, "[green]OK[/green]", val[:80])
            findings[h] = val
        else:
            table.add_row(h, "[red]MISSING[/red]", "—")
            findings[h] = "MISSING"
    console.print(table)
    db.save_scan("http_headers", url, findings)


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
                }
        for k, v in info.items():
            console.print(f"  [cyan]{k}[/cyan]: {v}")
        db.save_scan("ssl", host, info)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]SSL ошибка: {exc}[/red]")


def _test_sqli(url: str) -> list[str]:
    hits: list[str] = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    for param in qs:
        for payload in SQLI_PAYLOADS:
            new_qs = dict(qs)
            new_qs[param] = payload
            new_url = urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))
            r = _req(new_url)
            if not r:
                continue
            body = r.text.lower()
            if any(err in body for err in SQLI_ERRORS):
                hits.append(f"param={param} payload={payload} (error-based)")
                break
    return hits


def sqli_scan(target: str) -> None:
    """Базовый error-based SQLi-скан."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    if "?" not in url:
        console.print("[yellow]URL без GET-параметров — нечего тестировать.[/yellow]")
        return
    hits = _test_sqli(url)
    if hits:
        for h in hits:
            console.print(f"[red]⚠ SQLi: {h}[/red]")
    else:
        console.print("[green]Явных признаков SQLi не найдено.[/green]")
    db.save_scan("sqli", url, hits)


def xss_scan(target: str) -> None:
    """Reflected XSS."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    if "?" not in url:
        console.print("[yellow]URL без GET-параметров.[/yellow]")
        return
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    hits: list[str] = []
    for param in qs:
        for payload in XSS_PAYLOADS:
            new_qs = dict(qs)
            new_qs[param] = payload
            new_url = urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))
            r = _req(new_url)
            if r and payload in r.text:
                hits.append(f"param={param} payload={payload}")
                console.print(f"[red]⚠ Отражение payload: {param} → {payload}[/red]")
                break
    if not hits:
        console.print("[green]Reflected XSS не обнаружен.[/green]")
    db.save_scan("xss", url, hits)


def lfi_scan(target: str) -> None:
    """LFI detector."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    hits: list[str] = []
    for param in qs:
        for payload in LFI_PAYLOADS:
            new_qs = dict(qs)
            new_qs[param] = payload
            new_url = urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))
            r = _req(new_url)
            if r and ("root:x:0:0" in r.text or "[extensions]" in r.text):
                hits.append(f"{param}={payload}")
                console.print(f"[red]⚠ LFI: {param} → {payload}[/red]")
                break
    if not hits:
        console.print("[green]LFI не обнаружен.[/green]")
    db.save_scan("lfi", url, hits)


def _check_path(base: str, path: str) -> tuple[int, str] | None:
    url = urljoin(base, path)
    r = _req(url)
    if r and r.status_code in (200, 301, 302, 401, 403):
        return r.status_code, url
    return None


def dir_bruteforce(target: str, threads: int = 30) -> None:
    """Directory brute-forcer."""
    if not confirm_external(target):
        return
    base = normalize_url(target).rstrip("/") + "/"
    wl = WORDLIST_DIR / "dirs.txt"
    if wl.exists():
        words = [w.strip() for w in wl.read_text().splitlines() if w.strip()]
    else:
        words = ["admin", "login", "robots.txt", ".git/", "backup", "api",
                 "uploads", "wp-admin", "config", "test"]
    console.print(f"[cyan]Сканирую {len(words)} путей на {base}[/cyan]")
    found: list[tuple[int, str]] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_check_path, base, w) for w in words]
        for f in as_completed(futures):
            res = f.result()
            if res:
                found.append(res)
                console.print(f"[green]{res[0]}[/green]  {res[1]}")
    db.save_scan("dirbrute", base, found)


def cms_scanner(target: str) -> None:
    """Определение CMS по типовым путям."""
    if not confirm_external(target):
        return
    url = normalize_url(target).rstrip("/")
    results: dict[str, str] = {}
    checks = {
        "WordPress": ["/wp-login.php", "/wp-content/", "/readme.html"],
        "Joomla": ["/administrator/", "/components/", "/language/en-GB/"],
        "Drupal": ["/CHANGELOG.txt", "/core/CHANGELOG.txt", "/user/login"],
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


def open_redirect(target: str) -> None:
    """Поиск open redirect."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    hits: list[str] = []
    for param in qs:
        for payload in OPEN_REDIRECT_PAYLOADS:
            new_qs = dict(qs)
            new_qs[param] = payload
            new_url = urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))
            r = _req(new_url)
            if r and r.status_code in (301, 302) and "evil.com" in r.headers.get("Location", ""):
                hits.append(f"{param} → {payload}")
                console.print(f"[red]⚠ Open Redirect: {param}[/red]")
                break
    if not hits:
        console.print("[green]Open Redirect не обнаружен.[/green]")
    db.save_scan("open_redirect", url, hits)


def csrf_checker(target: str) -> None:
    """Проверка наличия CSRF-токенов в формах."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    r = _req(url)
    if not r:
        return
    body = r.text.lower()
    has_form = "<form" in body
    has_token = any(t in body for t in ["csrf", "_token", "authenticity_token", "xsrf"])
    console.print(f"[cyan]Форма найдена:[/cyan] {has_form}")
    console.print(f"[cyan]CSRF-токен:[/cyan] {'[green]есть[/green]' if has_token else '[red]нет[/red]'}")
    db.save_scan("csrf", url, {"has_form": has_form, "has_csrf_token": has_token})


def menu() -> None:
    """Меню модуля Web."""
    table = Table(title="[bold]Web Vulnerabilities[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "HTTP header analyzer"),
        ("2", "SSL/TLS checker"),
        ("3", "SQL Injection scan"),
        ("4", "XSS scan"),
        ("5", "LFI detector"),
        ("6", "Directory brute-force"),
        ("7", "CMS scanner"),
        ("8", "Open redirect"),
        ("9", "CSRF token checker"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])
    target = Prompt.ask("URL/цель")
    {
        "1": header_analyzer,
        "2": ssl_checker,
        "3": sqli_scan,
        "4": xss_scan,
        "5": lfi_scan,
        "6": dir_bruteforce,
        "7": cms_scanner,
        "8": open_redirect,
        "9": csrf_checker,
    }[c](target)