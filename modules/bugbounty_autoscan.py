"""
Bug Bounty Auto-Scan — единый пайплайн.
Author: idqwixxa

Пайплайн (6 стадий):
    1. Subdomain discovery    — crt.sh + hackertarget + wordlist brute + wildcard filter
    2. Port scan              — async TCP scan топовых портов (top-100 / top-1000 / full)
    3. HTTP probe             — async GET на живые URL, сбор статуса/title/server/len
    4. Tech fingerprint       — по заголовкам + HTML-маркерам (nginx, WP, React, Cloudflare...)
    5. Security hints         — missing headers, sensitive files, уязвимые ссылки
    6. Screenshots + Report   — playwright скриншоты + HTML/JSON отчёт

Профили:
    --profile quick   — 500 subs, top-100 ports, без скриншотов (1–3 мин)
    --profile full    — 5000 subs, top-1000 ports, скриншоты (5–15 мин)
    --profile deep    — 20000 subs, top-100 ports + доп. проверки (20+ мин)

Возможности:
    - Прогресс по стадиям в реальном времени
    - Промежуточное сохранение в БД (можно прервать и посмотреть)
    - HTML-отчёт с тёмной темой (DedSec style)
    - JSON-отчёт для машинной обработки
    - Возобновление: если пайплайн падал — можно досчитать

⚠ Только для bug bounty / CTF / собственных доменов.
"""
import asyncio
import concurrent.futures
import csv
import html as html_mod
import json
import re
import socket
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse, urlunparse

import aiohttp
import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn,
)

from core.config import config, REPORT_DIR, WORDLIST_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import normalize_url, extract_host

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AUTOSCAN_DIR = REPORT_DIR / "autoscan"
AUTOSCAN_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Профили
# ===========================================================================

PROFILES = {
    "quick": {
        "max_subs": 500,
        "wordlist": "subdomains.txt",
        "ports": "top100",
        "screenshot": False,
        "sensitive_files": False,
        "threads_subs": 40,
        "threads_ports": 300,
        "threads_http": 40,
        "timeout": 8,
    },
    "full": {
        "max_subs": 5000,
        "wordlist": "subdomains-top1million-5000.txt",
        "ports": "top1000",
        "screenshot": True,
        "sensitive_files": True,
        "threads_subs": 60,
        "threads_ports": 500,
        "threads_http": 60,
        "timeout": 10,
    },
    "deep": {
        "max_subs": 20000,
        "wordlist": "subdomains-top1million-20000.txt",
        "ports": "top1000",
        "screenshot": True,
        "sensitive_files": True,
        "threads_subs": 80,
        "threads_ports": 800,
        "threads_http": 80,
        "timeout": 12,
    },
}


# Топ-100 портов (самые частые в bug bounty)
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 162, 179,
    389, 443, 445, 465, 514, 515, 548, 554, 587, 631, 636, 873, 990, 993,
    995, 1025, 1026, 1027, 1080, 1086, 1111, 1433, 1434, 1521, 1723,
    2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2222, 2375, 2376,
    2480, 3000, 3128, 3306, 3389, 4000, 4443, 4444, 4505, 4506, 5000,
    5001, 5432, 5555, 5601, 5672, 5900, 5901, 5984, 6000, 6379, 6443,
    6666, 7001, 7077, 7443, 7474, 8000, 8001, 8008, 8010, 8043, 8069,
    8080, 8081, 8082, 8088, 8090, 8099, 8161, 8180, 8200, 8300, 8333,
    8443, 8500, 8529, 8834, 8888, 9000, 9001, 9042, 9060, 9090, 9092,
    9100, 9200, 9300, 9443, 9500, 9800, 9981, 9999, 10000, 10250,
    11211, 15672, 16379, 27017, 27018, 28017, 50000, 50030, 50060,
    50070, 50075, 50090,
]

# Топ-1000 = топ-100 + стандартный диапазон
TOP_1000_PORTS = sorted(set(
    TOP_100_PORTS
    + list(range(1, 1025))  # стандартный nmap-диапазон
))


# Sensitive files (для security hints)
SENSITIVE_PATHS = [
    "/.git/HEAD", "/.git/config", "/.env", "/.env.bak", "/.env.local",
    "/.svn/entries", "/.hg/", "/.DS_Store", "/.htaccess",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
    "/dump.sql", "/database.sql", "/backup/", "/backups/",
    "/admin/", "/admin.php", "/administrator/", "/wp-admin/",
    "/phpmyadmin/", "/pma/", "/mysql/", "/dbadmin/",
    "/.well-known/security.txt", "/security.txt",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/api/", "/api/v1/", "/api/v2/", "/swagger.json", "/openapi.json",
    "/swagger-ui.html", "/api-docs", "/v2/api-docs",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/server-status", "/server-info", "/status",
    "/phpinfo.php", "/info.php", "/test.php", "/debug",
    "/console/", "/.idea/", "/.vscode/", "/config.json", "/config.yml",
    "/package.json", "/composer.json", "/Dockerfile", "/docker-compose.yml",
    "/jenkins/", "/.jenkins/", "/grafana/", "/kibana/",
]

SECURITY_HEADERS_CHECK = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

TECH_MARKERS = {
    "WordPress": ["wp-content", "wp-includes", "wp-json"],
    "Joomla": ["/components/com_", "/media/jui/", "joomla"],
    "Drupal": ["drupalsettings", "/sites/default/files", "drupal"],
    "React": ["react", "data-reactroot", "_next/static"],
    "Vue.js": ["vue.js", "vue.min.js", "data-v-"],
    "Angular": ["ng-version", "angular.min.js"],
    "jQuery": ["jquery.min.js", "jquery-"],
    "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
    "Tailwind": ["tailwind", "tw-"],
    "Cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
    "Nginx": ["nginx"],
    "Apache": ["apache"],
    "IIS": ["iis", "microsoft-iis"],
    "LiteSpeed": ["litespeed"],
    "Nginx-Unit": ["nginx-unit"],
    "PHP": ["x-powered-by: php", ".php"],
    "ASP.NET": ["asp.net", "x-aspnet-version"],
    "Node.js": ["express", "x-powered-by: express"],
    "Django": ["csrftoken", "django"],
    "Flask": ["werkzeug", "flask"],
    "Spring": ["spring", "jsessionid"],
    "GraphQL": ["/graphql", "__schema"],
    "Swagger": ["swagger-ui", "openapi"],
    "Elasticsearch": ["elasticsearch", "you know, for search"],
    "Kibana": ["kibana"],
    "Grafana": ["grafana"],
}


# ===========================================================================
# Модели
# ===========================================================================

@dataclass
class SubDomain:
    name: str
    ip: str = ""
    source: str = ""      # crt.sh | hackertarget | brute | manual
    cname: str = ""


@dataclass
class HostResult:
    subdomain: str
    ip: str = ""
    open_ports: list[int] = field(default_factory=list)
    http_ports: list[int] = field(default_factory=list)
    services: dict = field(default_factory=dict)
    error: str = ""


@dataclass
class UrlResult:
    url: str
    host: str
    port: int
    scheme: str
    status: int = 0
    title: str = ""
    server: str = ""
    tech: list[str] = field(default_factory=list)
    length: int = 0
    headers: dict = field(default_factory=dict)
    redirect_to: str = ""
    missing_headers: list[str] = field(default_factory=list)
    sensitive: list[dict] = field(default_factory=list)   # {path, status, size}
    screenshot: str = ""
    error: str = ""


@dataclass
class PipelineResult:
    domain: str
    profile: str
    started: str
    finished: str = ""
    duration_sec: float = 0.0
    subdomains: list[SubDomain] = field(default_factory=list)
    hosts: list[HostResult] = field(default_factory=list)
    urls: list[UrlResult] = field(default_factory=list)
    wildcard_ips: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    report_html: str = ""
    report_json: str = ""
    report_csv: str = ""

    @property
    def live_urls(self) -> list[UrlResult]:
        return [u for u in self.urls if not u.error and u.status > 0]

    @property
    def interesting_urls(self) -> list[UrlResult]:
        """URL'ы, достойные внимания (не 404, есть tech или sensitive)."""
        out = []
        for u in self.live_urls:
            if u.status in (401, 403):
                out.append(u)
            elif u.status >= 500:
                out.append(u)
            elif u.tech:
                out.append(u)
            elif u.missing_headers:
                out.append(u)
            elif u.sensitive:
                out.append(u)
        return out


# ===========================================================================
# Стадия 1: Subdomain discovery
# ===========================================================================

def _crtsh(domain: str) -> set[str]:
    """crt.sh Certificate Transparency log."""
    subs: set[str] = set()
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=30, verify=False,
            headers={"User-Agent": config.USER_AGENT},
        )
        if r.status_code == 200:
            data = r.json()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name and "*" not in name and name.endswith(domain):
                        subs.add(name)
    except Exception as exc:  # noqa: BLE001
        log.debug("crt.sh: %s", exc)
    return subs


def _hackertarget(domain: str) -> set[str]:
    """HackerTarget hostsearch API."""
    subs: set[str] = set()
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=20, verify=False,
            headers={"User-Agent": config.USER_AGENT},
        )
        if r.status_code == 200:
            for line in r.text.splitlines():
                if "," in line:
                    host = line.split(",")[0].strip().lower()
                    if host and host.endswith(domain):
                        subs.add(host)
    except Exception as exc:  # noqa: BLE001
        log.debug("hackertarget: %s", exc)
    return subs


def _brute_subdomains(domain: str, wordlist: str,
                      max_subs: int, threads: int) -> set[str]:
    """Брут поддоменов по словарю."""
    wl = WORDLIST_DIR / wordlist
    if not wl.exists():
        # fallback: минимальный встроенный список
        words = [
            "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1",
            "ns2", "ns3", "dns", "dns1", "dns2", "admin", "administrator",
            "api", "app", "apps", "dev", "development", "test", "testing",
            "stage", "staging", "prod", "production", "beta", "demo",
            "portal", "login", "auth", "sso", "id", "account", "my",
            "shop", "store", "blog", "news", "forum", "community",
            "support", "help", "docs", "wiki", "static", "assets", "cdn",
            "media", "img", "images", "video", "stream", "m", "mobile",
            "old", "new", "backup", "bak", "temp", "tmp", "cache",
            "monitor", "status", "health", "metrics", "stats", "grafana",
            "jenkins", "ci", "cd", "git", "gitlab", "github", "gitlab",
            "jira", "confluence", "wiki", "mattermost", "slack",
            "vpn", "remote", "rdp", "ssh", "ftp", "sftp", "db",
            "mysql", "postgres", "redis", "mongo", "elastic",
            "kibana", "grafana", "prometheus", "jenkins", "nexus",
            "sonar", "sentry", "s3", "storage", "files", "cloud",
            "gateway", "edge", "proxy", "lb", "waf", "internal",
            "intranet", "extranet", "partner", "client", "vendor",
        ]
    else:
        try:
            words = [
                w.strip() for w in wl.read_text(encoding="utf-8",
                                                errors="ignore").splitlines()
                if w.strip() and not w.startswith("#")
            ]
        except Exception as exc:  # noqa: BLE001
            log.warning("wordlist %s: %s", wl, exc)
            return set()

    words = words[:max_subs]
    subs: set[str] = set()

    def _check(w: str) -> str | None:
        fqdn = f"{w}.{domain}"
        try:
            socket.gethostbyname(fqdn)
            return fqdn
        except socket.gaierror:
            return None
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_check, w) for w in words]
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        ) as p:
            task = p.add_task("brute subs", total=len(words))
            for f in concurrent.futures.as_completed(futures):
                p.advance(task)
                r = f.result()
                if r:
                    subs.add(r)
    return subs


def _detect_wildcard(domain: str) -> list[str]:
    """Определить wildcard DNS — возвращает список IP, на которые резолвится *."""
    import random
    import string
    ips: set[str] = set()
    probes = 3
    for _ in range(probes):
        rand = "".join(random.choices(string.ascii_lowercase + string.digits,
                                      k=16))
        try:
            ip = socket.gethostbyname(f"{rand}.{domain}")
            ips.add(ip)
        except Exception:
            pass
    # wildcard если все 3 probes резолвнулись
    return sorted(ips) if len(ips) > 0 and len(ips) == probes else []


def discover_subdomains(domain: str, profile_cfg: dict) -> tuple[list[SubDomain], list[str]]:
    """Стадия 1: собрать поддомены. Возвращает (subs, wildcard_ips)."""
    console.print("\n[bold cyan]▶ Стадия 1/6: Subdomain discovery[/bold cyan]")

    domain = extract_host(domain).lower()
    subs: dict[str, SubDomain] = {}

    # Passive: crt.sh
    console.print("[cyan]  · crt.sh…[/cyan]")
    crtsh = _crtsh(domain)
    console.print(f"    → {len(crtsh)} subs")
    for s in crtsh:
        subs[s] = SubDomain(name=s, source="crt.sh")

    # Passive: hackertarget
    console.print("[cyan]  · hackertarget…[/cyan]")
    ht = _hackertarget(domain)
    console.print(f"    → {len(ht)} subs")
    for s in ht:
        if s not in subs:
            subs[s] = SubDomain(name=s, source="hackertarget")

    # Active: brute
    console.print(f"[cyan]  · wordlist brute ({profile_cfg['wordlist']}, "
                  f"max {profile_cfg['max_subs']}, threads {profile_cfg['threads_subs']})…[/cyan]")
    br = _brute_subdomains(
        domain, profile_cfg["wordlist"],
        profile_cfg["max_subs"], profile_cfg["threads_subs"],
    )
    console.print(f"    → {len(br)} subs")
    for s in br:
        if s not in subs:
            subs[s] = SubDomain(name=s, source="brute")

    # Always include domain itself
    if domain not in subs:
        subs[domain] = SubDomain(name=domain, source="root")

    # Wildcard detection
    console.print("[cyan]  · wildcard DNS check…[/cyan]")
    wildcard_ips = _detect_wildcard(domain)
    if wildcard_ips:
        console.print(f"    [yellow]⚠ wildcard detected → "
                      f"{', '.join(wildcard_ips)}[/yellow]")

    # Resolve all subs
    console.print(f"[cyan]  · resolving {len(subs)} subs…[/cyan]")
    sub_list = list(subs.values())

    def _resolve(sd: SubDomain) -> None:
        try:
            sd.ip = socket.gethostbyname(sd.name)
        except Exception:
            sd.ip = ""

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=profile_cfg["threads_subs"]
    ) as ex:
        list(ex.map(_resolve, sub_list))

    # Filter wildcard IPs
    if wildcard_ips:
        before = len(sub_list)
        sub_list = [s for s in sub_list if s.ip not in wildcard_ips
                    or s.name == domain]
        filtered = before - len(sub_list)
        if filtered:
            console.print(f"    [yellow]filtered {filtered} wildcard "
                          f"matches[/yellow]")

    console.print(f"[green]  ✓ Unique subs: {len(sub_list)}[/green]")

    db.save_scan("autoscan_subs", domain, {
        "count": len(sub_list),
        "wildcard_ips": wildcard_ips,
        "subdomains": [{"name": s.name, "ip": s.ip, "src": s.source}
                       for s in sub_list],
    })
    return sub_list, wildcard_ips


# ===========================================================================
# Стадия 2: Port scan
# ===========================================================================

def _tcp_connect(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def _scan_host_ports(host: str, ports: list[int],
                     threads: int, timeout: float) -> list[int]:
    open_ports: list[int] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_tcp_connect, host, p, timeout): p for p in ports}
        for f in concurrent.futures.as_completed(futs):
            try:
                if f.result():
                    open_ports.append(futs[f])
            except Exception:
                pass
    return sorted(open_ports)


def scan_hosts(subdomains: list[SubDomain], profile_cfg: dict,
               top_ports: list[int]) -> list[HostResult]:
    """Стадия 2: сканируем порты на каждом поддомене."""
    console.print(f"\n[bold cyan]▶ Стадия 2/6: Port scan "
                  f"({len(top_ports)} портов × {len(subdomains)} хостов)[/bold cyan]")

    # группируем по IP (чтобы не сканировать один и тот же IP дважды)
    by_ip: dict[str, list[str]] = {}
    for sd in subdomains:
        if sd.ip:
            by_ip.setdefault(sd.ip, []).append(sd.name)

    console.print(f"[cyan]  · {len(by_ip)} уникальных IP[/cyan]")

    host_results: list[HostResult] = []
    total = len(by_ip)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as p:
        task = p.add_task("port scan", total=total)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=8
        ) as ex:
            futs = {
                ex.submit(_scan_host_ports, ip, top_ports,
                          profile_cfg["threads_ports"],
                          profile_cfg["timeout"] / 2): (ip, names)
                for ip, names in by_ip.items()
            }
            for f in concurrent.futures.as_completed(futs):
                p.advance(task)
                ip, names = futs[f]
                try:
                    open_ports = f.result()
                except Exception as exc:  # noqa: BLE001
                    log.warning("scan %s: %s", ip, exc)
                    open_ports = []

                # Определяем HTTP-порты
                http_ports = [p_ for p_ in open_ports
                              if p_ in (80, 443, 8080, 8000, 8081, 8443,
                                        8888, 8008, 8088, 9090, 9443, 9080,
                                        7001, 3000, 5000, 4000, 9000)]

                for name in names:
                    hr = HostResult(
                        subdomain=name, ip=ip,
                        open_ports=open_ports,
                        http_ports=http_ports,
                    )
                    host_results.append(hr)
                    if open_ports:
                        console.print(
                            f"    [green]✓[/green] {name:<40} "
                            f"[magenta]{ip}[/magenta] → "
                            f"[cyan]{','.join(map(str, open_ports[:10]))}"
                            f"{'…' if len(open_ports) > 10 else ''}[/cyan]"
                        )

    live = [h for h in host_results if h.open_ports]
    console.print(f"[green]  ✓ Live hosts: {len(live)}/{len(host_results)}[/green]")

    db.save_scan("autoscan_ports", subdomains[0].name.split(".", 1)[-1]
                 if subdomains else "unknown",
                 {"hosts": [
                     {"sub": h.subdomain, "ip": h.ip,
                      "ports": h.open_ports}
                     for h in host_results
                 ]})
    return host_results


# ===========================================================================
# Стадия 3: HTTP probe
# ===========================================================================

async def _probe_url(session: aiohttp.ClientSession, url: str,
                     sem: asyncio.Semaphore, timeout: float) -> UrlResult:
    host = ""
    port = 0
    scheme = ""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        scheme = parsed.scheme
        port = parsed.port or (443 if scheme == "https" else 80)
    except Exception:
        pass

    result = UrlResult(url=url, host=host, port=port, scheme=scheme)

    async with sem:
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=False, ssl=False,
            ) as r:
                result.status = r.status
                result.server = r.headers.get("Server", "")
                result.headers = dict(r.headers)
                body = await r.text(errors="ignore")
                result.length = len(body)

                # redirect
                loc = r.headers.get("Location", "")
                if loc and r.status in (301, 302, 303, 307, 308):
                    result.redirect_to = loc
                    # follow one redirect for title
                    try:
                        from urllib.parse import urljoin
                        next_url = urljoin(url, loc)
                        async with session.get(
                            next_url,
                            timeout=aiohttp.ClientTimeout(total=timeout),
                            allow_redirects=False, ssl=False,
                        ) as r2:
                            body2 = await r2.text(errors="ignore")
                            body = body2
                            result.status = r2.status if r2.status < 400 else r.status
                    except Exception:
                        pass

                # title
                low = body.lower()
                if "<title>" in low:
                    start = low.index("<title>") + 7
                    end = low.find("</title>", start)
                    if end > start:
                        result.title = body[start:end].strip()[:120]

                # missing security headers
                missing = [h for h in SECURITY_HEADERS_CHECK
                           if h not in r.headers]
                result.missing_headers = missing

                # tech markers
                combined = (body[:50000].lower() +
                            " " + " ".join(f"{k}: {v}".lower()
                                           for k, v in r.headers.items()))
                for tech, markers in TECH_MARKERS.items():
                    for m in markers:
                        if m.lower() in combined:
                            if tech not in result.tech:
                                result.tech.append(tech)
                            break

        except asyncio.TimeoutError:
            result.error = "timeout"
        except aiohttp.ClientConnectorError as exc:
            result.error = f"conn: {str(exc)[:60]}"
        except Exception as exc:  # noqa: BLE001
            result.error = str(exc)[:80]

    return result


async def _probe_all(urls: list[str], threads: int,
                     timeout: float) -> list[UrlResult]:
    sem = asyncio.Semaphore(threads)
    connector = aiohttp.TCPConnector(ssl=False, limit=threads,
                                     force_close=True)
    headers = {"User-Agent": config.USER_AGENT}
    out: list[UrlResult] = []
    async with aiohttp.ClientSession(headers=headers,
                                     connector=connector) as session:
        tasks = [_probe_url(session, u, sem, timeout) for u in urls]
        total = len(tasks)
        done = 0
        for coro in asyncio.as_completed(tasks):
            r = await coro
            done += 1
            out.append(r)
            if r.status and not r.error:
                tech_str = f" [{','.join(r.tech[:3])}]" if r.tech else ""
                console.print(
                    f"    [green]{r.status:<3}[/green] "
                    f"[cyan]{r.url[:70]:<70}[/cyan]"
                    f" [dim]{r.title[:40]}{tech_str}[/dim]"
                )
    return out


def probe_urls(hosts: list[HostResult], profile_cfg: dict) -> list[UrlResult]:
    """Стадия 3: HTTP probe."""
    console.print("\n[bold cyan]▶ Стадия 3/6: HTTP probe[/bold cyan]")

    # Собираем URL'ы: для каждого хоста + открытый http-порт
    urls: list[str] = []
    seen: set[str] = set()

    for h in hosts:
        if not h.open_ports:
            continue
        # Определяем схему по порту
        for p_ in h.open_ports:
            if p_ in (80, 8080, 8000, 8081, 8008, 8088, 8888, 9090, 3000,
                      5000, 4000, 9000, 7001, 9080):
                scheme = "http"
            elif p_ in (443, 8443, 9443, 4443, 6443, 7443, 8043):
                scheme = "https"
            else:
                continue
            if scheme == "http" and p_ == 80:
                url = f"http://{h.subdomain}"
            elif scheme == "https" and p_ == 443:
                url = f"https://{h.subdomain}"
            else:
                url = f"{scheme}://{h.subdomain}:{p_}"
            if url not in seen:
                seen.add(url)
                urls.append(url)

    if not urls:
        console.print("[yellow]  ⚠ нет HTTP-портов, пропускаем[/yellow]")
        return []

    console.print(f"[cyan]  · probing {len(urls)} URLs[/cyan]")
    try:
        results = asyncio.run(_probe_all(
            urls, profile_cfg["threads_http"],
            profile_cfg["timeout"] + 5,
        ))
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]  probe error: {exc}[/red]")
        return []

    live = [r for r in results if not r.error and r.status > 0]
    console.print(f"[green]  ✓ Live URLs: {len(live)}/{len(results)}[/green]")

    db.save_scan("autoscan_http", urls[0] if urls else "unknown", {
        "count": len(live),
        "urls": [{"url": r.url, "status": r.status, "title": r.title[:80],
                  "tech": r.tech} for r in live[:200]],
    })
    return results


# ===========================================================================
# Стадия 4: Security hints (sensitive files + missing headers)
# ===========================================================================

def _check_sensitive(base_url: str, paths: list[str],
                     threads: int, timeout: float) -> list[dict]:
    """Проверить sensitive files на базовом URL."""
    found: list[dict] = []
    base = base_url.rstrip("/")

    def _one(path: str) -> dict | None:
        url = f"{base}{path}"
        try:
            r = requests.head(url, timeout=timeout, verify=False,
                              allow_redirects=False,
                              headers={"User-Agent": config.USER_AGENT})
            # HEAD может не работать — пробуем GET если 405/501
            if r.status_code in (405, 501):
                r = requests.get(url, timeout=timeout, verify=False,
                                 allow_redirects=False, stream=True,
                                 headers={"User-Agent": config.USER_AGENT})
            if r.status_code in (200, 301, 302, 401, 403):
                return {
                    "path": path,
                    "status": r.status_code,
                    "size": r.headers.get("Content-Length", "?"),
                }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(_one, p_) for p_ in paths]
        for f in concurrent.futures.as_completed(futs):
            try:
                r = f.result()
                if r:
                    found.append(r)
            except Exception:
                pass
    return found


def security_hints(urls: list[UrlResult], profile_cfg: dict) -> None:
    """Стадия 4: sensitive files + security headers analysis."""
    console.print("\n[bold cyan]▶ Стадия 4/6: Security hints[/bold cyan]")

    if not profile_cfg["sensitive_files"]:
        console.print("[dim]  (profile: sensitive_files выключены)[/dim]")
        return

    # Проверяем только по 1 URL на хост (по самому популярному)
    seen_hosts: set[str] = set()
    to_check: list[UrlResult] = []
    for u in urls:
        if u.error or u.status == 0:
            continue
        if u.host in seen_hosts:
            continue
        seen_hosts.add(u.host)
        to_check.append(u)

    console.print(f"[cyan]  · проверяю {len(to_check)} хостов × "
                  f"{len(SENSITIVE_PATHS)} путей[/cyan]")

    total_found = 0
    for u in to_check:
        base = f"{u.scheme}://{u.host}"
        if u.port and u.port not in (80, 443):
            base += f":{u.port}"
        found = _check_sensitive(base, SENSITIVE_PATHS,
                                 profile_cfg["threads_http"] // 2,
                                 profile_cfg["timeout"])
        if found:
            u.sensitive = found
            total_found += len(found)
            for f in found[:5]:
                console.print(f"    [yellow]⚠[/yellow] {base}{f['path']} "
                              f"[dim]({f['status']}, {f['size']})[/dim]")
            if len(found) > 5:
                console.print(f"    [dim]… и ещё {len(found)-5}[/dim]")

    console.print(f"[green]  ✓ Sensitive files: {total_found}[/green]")


# ===========================================================================
# Стадия 5: Screenshots
# ===========================================================================

def take_screenshots(urls: list[UrlResult], profile_cfg: dict) -> None:
    """Стадия 5: скриншоты для interesting URLs."""
    console.print("\n[bold cyan]▶ Стадия 5/6: Screenshots[/bold cyan]")

    if not profile_cfg["screenshot"]:
        console.print("[dim]  (profile: screenshots выключены)[/dim]")
        return

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        console.print("[yellow]  ⚠ playwright не установлен — пропускаю[/yellow]")
        console.print("[dim]  pip install playwright && playwright install chromium[/dim]")
        return

    interesting = [u for u in urls if not u.error and u.status > 0
                   and u.status not in (404,)]
    if not interesting:
        console.print("[yellow]  ⚠ нет интересных URL[/yellow]")
        return

    # Лимит на скриншоты — не более 30 (иначе долго)
    interesting = interesting[:30]

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    screenshot_dir = AUTOSCAN_DIR / f"shots_{ts}"
    screenshot_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[cyan]  · снимаю {len(interesting)} URL → "
                  f"{screenshot_dir.name}[/cyan]")

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(
                viewport={"width": 1440, "height": 900},
                ignore_https_errors=True,
                user_agent=config.USER_AGENT,
            )
            for i, u in enumerate(interesting, 1):
                safe = re.sub(r"[^A-Za-z0-9._-]", "_", u.url)[:60]
                out = screenshot_dir / f"{i:03d}_{safe}.png"
                try:
                    page = context.new_page()
                    page.goto(u.url, timeout=20000,
                              wait_until="domcontentloaded")
                    page.screenshot(path=str(out), full_page=False)
                    page.close()
                    u.screenshot = str(out)
                    console.print(f"    [green]✓[/green] {u.url[:70]}")
                except PWTimeout:
                    console.print(f"    [yellow]timeout[/yellow] {u.url[:70]}")
                except Exception as exc:  # noqa: BLE001
                    console.print(f"    [red]err[/red] {u.url[:70]}: "
                                  f"{str(exc)[:40]}")
            context.close()
            browser.close()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]  playwright error: {exc}[/red]")


# ===========================================================================
# Стадия 6: Report (HTML + JSON + CSV)
# ===========================================================================

HTML_CSS = """
*{box-sizing:border-box;}
body{background:#0a0a0a;color:#c8c8c8;margin:0;padding:32px;
     font-family:'JetBrains Mono','Fira Code',Consolas,monospace;
     line-height:1.5;}
.container{max-width:1400px;margin:0 auto;}
h1{color:#00ff9c;border-bottom:2px solid #00ff9c;padding-bottom:8px;
   margin-top:0;}
h2{color:#00ff9c;margin-top:40px;border-left:4px solid #00ff9c;
   padding-left:12px;}
h3{color:#7ad9ff;margin-top:24px;}
.cover{border:2px solid #00ff9c;padding:24px;margin-bottom:24px;
       background:#080808;}
.cover .title{font-size:26px;color:#00ff9c;font-weight:bold;}
.cover .meta{color:#888;margin-top:8px;font-size:13px;}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
         gap:12px;margin:20px 0;}
.card{background:#0d0d0d;border:1px solid #222;padding:14px;
      border-radius:4px;}
.card .num{font-size:26px;color:#00ff9c;font-weight:bold;}
.card .label{font-size:12px;color:#888;margin-top:4px;}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px;}
th{background:#111;color:#00ff9c;text-align:left;padding:8px;
   border:1px solid #222;}
td{padding:6px 8px;border:1px solid #222;vertical-align:top;}
tr:nth-child(even){background:#0d0d0d;}
pre{background:#050505;border:1px solid #222;padding:10px;
    overflow-x:auto;color:#a0ffa0;font-size:12px;border-radius:4px;}
.tag{display:inline-block;background:#003322;color:#00ff9c;
     padding:2px 8px;border-radius:3px;font-size:11px;margin-right:4px;}
.warn{color:#ff7a40;font-weight:bold;}
.crit{color:#ff2020;font-weight:bold;}
.ok{color:#00ff9c;}
.muted{color:#666;}
.footer{margin-top:40px;padding-top:16px;border-top:1px solid #222;
        color:#555;font-size:12px;text-align:center;}
img{max-width:100%;border:1px solid #222;border-radius:4px;
    margin:6px 0;background:#0a0a0a;max-height:400px;}
.section{padding:8px 0;}
"""


def _esc(v: Any) -> str:
    return html_mod.escape(str(v if v is not None else ""))


def _status_color(s: int) -> str:
    if s == 0: return "muted"
    if s < 300: return "ok"
    if s < 400: return "warn"
    if s == 401 or s == 403: return "crit"
    if s >= 500: return "crit"
    return "muted"


def _make_html_report(r: PipelineResult) -> str:
    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>Auto-Scan — {_esc(r.domain)}</title>",
        f"<style>{HTML_CSS}</style></head><body><div class='container'>",
        f"<div class='cover'>",
        f"<div class='title'>🛰 Auto-Scan — {_esc(r.domain)}</div>",
        f"<div class='meta'>Профиль: <b>{_esc(r.profile)}</b> &nbsp;•&nbsp; "
        f"Запущен: {_esc(r.started)} &nbsp;•&nbsp; "
        f"Длительность: {r.duration_sec:.1f}s</div>",
        "</div>",
    ]

    # Summary
    parts.append("<h2>📊 Сводка</h2><div class='summary'>")
    stats = [
        ("Поддомены", len(r.subdomains)),
        ("Живых хостов", len([h for h in r.hosts if h.open_ports])),
        ("Открытых портов", sum(len(h.open_ports) for h in r.hosts)),
        ("HTTP URLs", len(r.live_urls)),
        ("Интересных URL", len(r.interesting_urls)),
        ("Sensitive files", sum(len(u.sensitive) for u in r.urls)),
        ("Скриншотов", len([u for u in r.urls if u.screenshot])),
    ]
    for label, num in stats:
        parts.append(f"<div class='card'><div class='num'>{num}</div>"
                     f"<div class='label'>{_esc(label)}</div></div>")
    parts.append("</div>")

    # Subdomains
    parts.append(f"<h2>🌐 Поддомены ({len(r.subdomains)})</h2>")
    if r.wildcard_ips:
        parts.append(f"<p class='warn'>⚠ Wildcard DNS → "
                     f"{_esc(', '.join(r.wildcard_ips))}</p>")
    parts.append("<table><tr><th>#</th><th>Subdomain</th><th>IP</th>"
                 "<th>Source</th></tr>")
    for i, s in enumerate(sorted(r.subdomains, key=lambda x: x.name), 1):
        parts.append(f"<tr><td>{i}</td><td>{_esc(s.name)}</td>"
                     f"<td>{_esc(s.ip) or '—'}</td>"
                     f"<td class='muted'>{_esc(s.source)}</td></tr>")
    parts.append("</table>")

    # Live hosts
    live = [h for h in r.hosts if h.open_ports]
    parts.append(f"<h2>🔌 Живые хосты ({len(live)})</h2>")
    if live:
        parts.append("<table><tr><th>Subdomain</th><th>IP</th>"
                     "<th>Open ports</th></tr>")
        for h in sorted(live, key=lambda x: x.subdomain):
            ports_str = ", ".join(str(p) for p in h.open_ports)
            parts.append(f"<tr><td>{_esc(h.subdomain)}</td>"
                         f"<td>{_esc(h.ip)}</td>"
                         f"<td><code>{_esc(ports_str)}</code></td></tr>")
        parts.append("</table>")

    # URLs
    parts.append(f"<h2>🌍 HTTP URLs ({len(r.live_urls)})</h2>")
    if r.live_urls:
        parts.append("<table><tr><th>URL</th><th>Status</th><th>Title</th>"
                     "<th>Server</th><th>Tech</th></tr>")
        for u in sorted(r.live_urls, key=lambda x: (x.status, x.url)):
            tech = " ".join(f"<span class='tag'>{_esc(t)}</span>"
                            for t in u.tech) if u.tech else "—"
            parts.append(
                f"<tr><td><a href='{_esc(u.url)}' target='_blank' "
                f"style='color:#7ad9ff;'>{_esc(u.url)}</a></td>"
                f"<td class='{_status_color(u.status)}'>{u.status}</td>"
                f"<td>{_esc(u.title or '—')}</td>"
                f"<td>{_esc(u.server or '—')}</td>"
                f"<td>{tech}</td></tr>"
            )
        parts.append("</table>")

    # Interesting URLs
    interesting = r.interesting_urls
    parts.append(f"<h2>⭐ Интересные URL ({len(interesting)})</h2>")
    for u in interesting:
        parts.append(f"<div class='section'>")
        parts.append(f"<h3>{_esc(u.url)} "
                     f"[{_status_color(u.status)}]{u.status}[/]</h3>")
        parts.append(f"<p>Title: <b>{_esc(u.title or '—')}</b> &nbsp; "
                     f"Server: <code>{_esc(u.server or '—')}</code> &nbsp; "
                     f"Len: {u.length}</p>")
        if u.tech:
            parts.append("<p>Tech: " +
                         " ".join(f"<span class='tag'>{_esc(t)}</span>"
                                  for t in u.tech) + "</p>")
        if u.missing_headers:
            parts.append(f"<p class='warn'>Missing headers: "
                         f"{_esc(', '.join(u.missing_headers))}</p>")
        if u.redirect_to:
            parts.append(f"<p class='muted'>Redirect → "
                         f"{_esc(u.redirect_to)}</p>")
        if u.sensitive:
            parts.append("<p><b>Sensitive files:</b></p><ul>")
            for f in u.sensitive:
                parts.append(f"<li><code>{_esc(f['path'])}</code> → "
                             f"<span class='warn'>{f['status']}</span> "
                             f"({f['size']})</li>")
            parts.append("</ul>")
        if u.screenshot:
            import base64
            try:
                b64 = base64.b64encode(Path(u.screenshot).read_bytes()).decode()
                parts.append(f"<img src='data:image/png;base64,{b64}'>")
            except Exception:
                pass
        parts.append("</div>")

    # Footer
    parts.append(f"<div class='footer'>CyberSec Toolkit — "
                 f"Bug Bounty Auto-Scan &nbsp;•&nbsp; by idqwixa "
                 f"&nbsp;•&nbsp; "
                 f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>")
    parts.append("</div></body></html>")
    return "\n".join(parts)


def make_report(r: PipelineResult, out_dir: Path | None = None) -> None:
    """Стадия 6: сформировать HTML + JSON + CSV отчёт."""
    console.print("\n[bold cyan]▶ Стадия 6/6: Report[/bold cyan]")

    if not out_dir:
        out_dir = AUTOSCAN_DIR
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", r.domain)
    base = out_dir / f"autoscan_{safe}_{ts}"

    # HTML
    try:
        html = _make_html_report(r)
        (base.with_suffix(".html")).write_text(html, encoding="utf-8")
        r.report_html = str(base.with_suffix(".html"))
        size_kb = base.with_suffix(".html").stat().st_size / 1024
        console.print(f"[green]  ✓ HTML: {r.report_html} ({size_kb:.1f} KB)[/green]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]  HTML error: {exc}[/red]")

    # JSON
    try:
        data = asdict(r)
        # Не тащим большие поля
        (base.with_suffix(".json")).write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        r.report_json = str(base.with_suffix(".json"))
        console.print(f"[green]  ✓ JSON: {r.report_json}[/green]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]  JSON error: {exc}[/red]")

    # CSV (URLs)
    try:
        with open(base.with_suffix(".csv"), "w", newline="",
                  encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["url", "host", "port", "status", "title",
                        "server", "tech", "length", "missing_headers",
                        "sensitive"])
            for u in r.live_urls:
                w.writerow([
                    u.url, u.host, u.port, u.status, u.title,
                    u.server, ";".join(u.tech), u.length,
                    ";".join(u.missing_headers),
                    ";".join(f"{s['path']}({s['status']})"
                             for s in u.sensitive),
                ])
        r.report_csv = str(base.with_suffix(".csv"))
        console.print(f"[green]  ✓ CSV: {r.report_csv}[/green]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]  CSV error: {exc}[/red]")


# ===========================================================================
# Оркестратор
# ===========================================================================

def run_pipeline(domain: str, profile: str = "full",
                 out_dir: str | None = None,
                 skip_stages: list[str] | None = None) -> PipelineResult:
    """Запустить полный пайплайн."""
    if profile not in PROFILES:
        console.print(f"[red]Профиль '{profile}' не найден.[/red]")
        console.print(f"[dim]Доступно: {', '.join(PROFILES.keys())}[/dim]")
        return PipelineResult(domain=domain, profile=profile,
                              started=datetime.now().isoformat())

    cfg = PROFILES[profile]
    skip = set(skip_stages or [])

    domain = extract_host(domain).lower()
    console.print(f"\n[bold cyan]🚀 Auto-Scan: [white]{domain}[/white] "
                  f"({profile})[/bold cyan]")
    console.print(f"[dim]Профиль: max_subs={cfg['max_subs']}, "
                  f"ports={cfg['ports']}, screenshot={cfg['screenshot']}[/dim]")

    started = datetime.now()
    r = PipelineResult(
        domain=domain, profile=profile,
        started=started.isoformat(timespec="seconds"),
    )

    # Определяем порты по профилю
    if cfg["ports"] == "top100":
        top_ports = TOP_100_PORTS
    elif cfg["ports"] == "top1000":
        top_ports = TOP_1000_PORTS
    else:
        top_ports = TOP_100_PORTS

    try:
        # 1. Subs
        if "subs" not in skip:
            subs, wildcard = discover_subdomains(domain, cfg)
            r.subdomains = subs
            r.wildcard_ips = wildcard
        else:
            subs = []
            console.print("[dim]  (subs skipped)[/dim]")

        # 2. Ports
        if "ports" not in skip and subs:
            hosts = scan_hosts(subs, cfg, top_ports)
            r.hosts = hosts
        else:
            hosts = []

        # 3. HTTP probe
        if "http" not in skip and hosts:
            urls = probe_urls(hosts, cfg)
            r.urls = urls
        else:
            urls = []

        # 4. Security hints
        if "hints" not in skip and urls:
            security_hints(r.urls, cfg)

        # 5. Screenshots
        if "screenshots" not in skip and urls:
            take_screenshots(r.urls, cfg)

        # 6. Report
        if "report" not in skip:
            make_report(r, Path(out_dir) if out_dir else None)

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Прервано пользователем — "
                      "сохраняю что есть…[/yellow]")
        r.errors.append("interrupted")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка пайплайна: {exc}[/red]")
        log.exception("pipeline")
        r.errors.append(str(exc)[:200])

    finished = datetime.now()
    r.finished = finished.isoformat(timespec="seconds")
    r.duration_sec = (finished - started).total_seconds()

    # Итоговая таблица
    console.print()
    t = Table(title=f"🏁 Auto-Scan завершён за {r.duration_sec:.1f}s")
    t.add_column("Метрика", style="cyan")
    t.add_column("Значение", style="green")
    t.add_row("Домен", domain)
    t.add_row("Профиль", profile)
    t.add_row("Поддоменов", str(len(r.subdomains)))
    t.add_row("Живых хостов",
              str(len([h for h in r.hosts if h.open_ports])))
    t.add_row("Открытых портов",
              str(sum(len(h.open_ports) for h in r.hosts)))
    t.add_row("HTTP URLs", str(len(r.live_urls)))
    t.add_row("Интересных URL", str(len(r.interesting_urls)))
    t.add_row("Sensitive files",
              str(sum(len(u.sensitive) for u in r.urls)))
    t.add_row("Скриншотов", str(len([u for u in r.urls if u.screenshot])))
    if r.report_html:
        t.add_row("HTML", r.report_html)
    if r.report_json:
        t.add_row("JSON", r.report_json)
    console.print(t)

    # Сохранить в БД
    db.save_scan("autoscan_done", domain, {
        "profile": profile,
        "duration": r.duration_sec,
        "subs": len(r.subdomains),
        "live_hosts": len([h for h in r.hosts if h.open_ports]),
        "urls": len(r.live_urls),
        "interesting": len(r.interesting_urls),
        "report_html": r.report_html,
        "report_json": r.report_json,
    })

    return r


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🟢 Bug Bounty Auto-Scan[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Quick scan (500 subs, top-100 ports, без скринов)"),
        ("2", "Full scan (5000 subs, top-1000 ports, скрины)"),
        ("3", "Deep scan (20000 subs, top-1000, скрины + hints)"),
        ("4", "Показать профили"),
        ("5", "Показать результаты прошлых сканов"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованных bug bounty программ "
                  "и собственных доменов.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c in ("1", "2", "3"):
        profile_map = {"1": "quick", "2": "full", "3": "deep"}
        profile = profile_map[c]
        domain = Prompt.ask("Домен (например example.com)")
        if not Confirm.ask(f"Запустить {profile} скан для {domain}?",
                           default=False):
            return
        r = run_pipeline(domain, profile=profile)
        if r.report_html and Confirm.ask("Открыть HTML отчёт?",
                                         default=True):
            _open_file(Path(r.report_html))
    elif c == "4":
        show_profiles()
    elif c == "5":
        show_past_results()


def show_profiles() -> None:
    t = Table(title="Профили Auto-Scan")
    t.add_column("Профиль", style="cyan")
    t.add_column("Subs", style="green")
    t.add_column("Ports", style="magenta")
    t.add_column("Screens", style="yellow")
    t.add_column("Hints", style="red")
    for name, cfg in PROFILES.items():
        t.add_row(
            name,
            str(cfg["max_subs"]),
            cfg["ports"],
            "✓" if cfg["screenshot"] else "—",
            "✓" if cfg["sensitive_files"] else "—",
        )
    console.print(t)


def show_past_results() -> None:
    """Список прошлых autoscan_done."""
    try:
        cur = db.conn.cursor()
        cur.execute(
            "SELECT id, target, result, created_at FROM scans "
            "WHERE module='autoscan_done' ORDER BY id DESC LIMIT 30"
        )
        rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return
    if not rows:
        console.print("[yellow]Нет результатов.[/yellow]")
        return
    t = Table(title=f"Прошлые Auto-Scan ({len(rows)})")
    t.add_column("ID", style="cyan")
    t.add_column("Домен", style="green")
    t.add_column("Профиль", style="magenta")
    t.add_column("Subs", style="yellow")
    t.add_column("URLs", style="yellow")
    t.add_column("Дата", style="white")
    for r in rows:
        try:
            data = json.loads(r["result"])
        except Exception:
            data = {}
        t.add_row(
            str(r["id"]),
            str(r["target"]),
            data.get("profile", "?"),
            str(data.get("subs", "?")),
            str(data.get("urls", "?")),
            str(r["created_at"])[:19],
        )
    console.print(t)
    console.print("\n[dim]Полные отчёты: reports/autoscan/[/dim]")


def _open_file(path: Path) -> None:
    import os
    import sys
    try:
        if sys.platform == "win32":
            os.startfile(str(path))  # noqa: S606
        elif sys.platform == "darwin":
            os.system(f'open "{path}"')
        else:
            os.system(f'xdg-open "{path}" >/dev/null 2>&1 &')
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]Не удалось открыть: {exc}[/yellow]")


# ===========================================================================
# CLI-обёртки
# ===========================================================================

def cli_scan(domain: str, profile: str = "full",
             out_dir: str | None = None,
             skip: str | None = None) -> None:
    skip_stages = [s.strip() for s in (skip or "").split(",") if s.strip()]
    r = run_pipeline(domain, profile=profile, out_dir=out_dir,
                     skip_stages=skip_stages)
    return r


def cli_profiles() -> None:
    show_profiles()


def cli_past() -> None:
    show_past_results()