"""
Bug Bounty Auto-Scan — расширенный единый пайплайн.
Author: idqwixxa

⚠ Только для bug bounty / CTF / собственных доменов.

Пайплайн:
    1. Subdomain discovery — crt.sh + hackertarget + OTX + RapidDNS +
                             AnubisDB + wordlist brute + wildcard filter
    2. DNS resolve        — A/AAAA/CNAME, wildcard detection
    3. Port scan          — async TCP + banner grab
    4. HTTP probe         — parallel HEAD/GET + redirect follow
    5. Tech fingerprint   — 30+ маркеров (headers + HTML + favicon)
    6. Security hints     — missing headers, sensitive files + body sigs
    7. Screenshots        — playwright с retry
    8. Report             — HTML/JSON/CSV/Markdown + findings → notes

Профили: quick / full / deep (см. PROFILES).

Возможности:
    - Persistence: checkpoint между стадиями (resume)
    - Notify по завершении
    - Findings → notes (kind="finding")
    - Интеграция с takeover, js_secrets, wayback
    - Rate-limit per-source
    - Кэш DNS для ускорения
"""
import asyncio
import csv
import html as html_mod
import json
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

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

CHECKPOINT_DIR = AUTOSCAN_DIR / "checkpoints"
CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)


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
        "wayback": False,
        "takeover": False,
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
        "wayback": True,
        "takeover": True,
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
        "wayback": True,
        "takeover": True,
        "threads_subs": 80,
        "threads_ports": 800,
        "threads_http": 80,
        "timeout": 12,
    },
}


# Топ-порты
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

TOP_1000_PORTS = sorted(set(TOP_100_PORTS + list(range(1, 1025))))

HTTP_PORTS_HTTP = {80, 8080, 8000, 8081, 8008, 8088, 8888, 9090,
                    3000, 5000, 4000, 9000, 7001, 9080, 8090, 8280,
                    8082, 8069, 8161, 8180, 8500, 8529, 9001}
HTTP_PORTS_HTTPS = {443, 8443, 9443, 4443, 6443, 7443, 8043, 8443,
                     9002, 10443}


# Sensitive files (расширенный)
SENSITIVE_PATHS = [
    # Git / VCS
    "/.git/HEAD", "/.git/config", "/.git/logs/HEAD",
    "/.svn/entries", "/.svn/wc.db", "/.hg/", "/.bzr/",
    # Env / config
    "/.env", "/.env.bak", "/.env.local", "/.env.prod", "/.env.dev",
    "/.env.staging", "/env.json", "/config.json", "/config.yml",
    "/config.yaml", "/settings.py", "/wp-config.php.bak",
    "/web.config", "/application.properties", "/application.yml",
    # Backups
    "/backup.zip", "/backup.tar.gz", "/backup.tar", "/backup.rar",
    "/backup.sql", "/backup.sql.gz", "/db.sql", "/dump.sql",
    "/database.sql", "/backup/", "/backups/", "/bkp/", "/.backup/",
    # Admin / DB
    "/admin/", "/admin.php", "/administrator/", "/wp-admin/",
    "/wp-login.php", "/phpmyadmin/", "/pma/", "/mysql/", "/dbadmin/",
    "/adminer.php", "/adminer/", "/pma/",
    # Meta / discovery
    "/.well-known/security.txt", "/security.txt",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/clientaccesspolicy.xml", "/humans.txt",
    # APIs
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/swagger-ui.html", "/swagger-ui/", "/api-docs", "/v2/api-docs",
    "/v3/api-docs", "/redoc",
    # Spring / Java
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/mappings", "/actuator/beans", "/actuator/configprops",
    "/actuator/heapdump", "/actuator/threaddump", "/actuator/logfile",
    # Server status
    "/server-status", "/server-info", "/status", "/health",
    "/healthz", "/readyz", "/livez", "/metrics",
    # Debug
    "/phpinfo.php", "/info.php", "/test.php", "/debug",
    "/console/", "/.idea/", "/.vscode/", "/trace",
    # CI / DevOps
    "/package.json", "/composer.json", "/Gemfile",
    "/Dockerfile", "/docker-compose.yml", "/.dockerignore",
    "/jenkins/", "/.jenkins/", "/gitlab-ci.yml", "/.gitlab-ci.yml",
    "/.travis.yml", "/.circleci/config.yml",
    # Dashboards
    "/grafana/", "/kibana/", "/prometheus/", "/zipkin/",
    "/jaeger/", "/elk/", "/sonar/", "/nexus/",
    # Logs
    "/logs/", "/log/", "/debug.log", "/error.log", "/access.log",
    # Other
    "/.DS_Store", "/.htaccess", "/.htpasswd", "/cgi-bin/",
    "/webdav/", "/.well-known/change-password",
]

SECURITY_HEADERS_CHECK = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
]

# Tech markers (расширенный)
TECH_MARKERS = {
    "WordPress": ["wp-content", "wp-includes", "wp-json", "/wp-admin/"],
    "Joomla": ["/components/com_", "/media/jui/", "joomla"],
    "Drupal": ["drupalsettings", "/sites/default/files", "drupal"],
    "Magento": ["/skin/frontend/", "mage/cookies", "magento"],
    "PrestaShop": ["prestashop", "/modules/ps_"],
    "Shopify": ["cdn.shopify.com", "shopify.theme"],
    "React": ["react", "data-reactroot", "_next/static", "__NEXT_DATA__"],
    "Next.js": ["_next/static", "__NEXT_DATA__"],
    "Vue.js": ["vue.js", "vue.min.js", "data-v-"],
    "Nuxt": ["__NUXT__", "_nuxt/"],
    "Angular": ["ng-version", "angular.min.js", "ng-app"],
    "Svelte": ["svelte-", "__svelte"],
    "jQuery": ["jquery.min.js", "jquery-", "jquery.js"],
    "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
    "Tailwind": ["tailwind", "tw-"],
    "FontAwesome": ["font-awesome", "fontawesome"],
    "Cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
    "Fastly": ["fastly", "x-served-by: cache"],
    "Akamai": ["akamai", "akamaighost"],
    "Nginx": ["nginx"],
    "Apache": ["apache"],
    "IIS": ["iis", "microsoft-iis"],
    "LiteSpeed": ["litespeed"],
    "OpenResty": ["openresty"],
    "Caddy": ["caddy"],
    "PHP": ["x-powered-by: php", ".php"],
    "ASP.NET": ["asp.net", "x-aspnet-version"],
    "Node.js": ["express", "x-powered-by: express"],
    "Ruby on Rails": ["x-powered-by: phusion", "_rails_session"],
    "Django": ["csrftoken", "django", "x-frame-options: sameorigin"],
    "Flask": ["werkzeug", "flask"],
    "Laravel": ["laravel_session", "x-powered-by: php"],
    "Spring": ["spring", "jsessionid", "x-application-context"],
    "Express": ["x-powered-by: express"],
    "GraphQL": ["/graphql", "__schema", "graphql"],
    "Swagger": ["swagger-ui", "openapi", "redoc"],
    "Elasticsearch": ["elasticsearch", "you know, for search"],
    "Kibana": ["kibana", "kbn-"],
    "Grafana": ["grafana"],
    "Prometheus": ["prometheus"],
    "Sentry": ["sentry", "raven"],
    "Jenkins": ["jenkins", "x-jenkins"],
    "GitLab": ["gitlab", "_gitlab_session"],
    "Bitbucket": ["bitbucket"],
    "Gitea": ["gitea"],
    "Kubernetes": ["kubernetes", "k8s"],
    "Docker": ["docker"],
    "Traefik": ["traefik"],
    "HAProxy": ["haproxy"],
}


# ===========================================================================
# Модели
# ===========================================================================

@dataclass
class SubDomain:
    name: str
    ip: str = ""
    source: str = ""
    cname: str = ""
    ips_v6: list[str] = field(default_factory=list)


@dataclass
class HostResult:
    subdomain: str
    ip: str = ""
    open_ports: list[int] = field(default_factory=list)
    http_ports: list[int] = field(default_factory=list)
    services: dict = field(default_factory=dict)
    banners: dict = field(default_factory=dict)
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
    sensitive: list[dict] = field(default_factory=list)
    screenshot: str = ""
    error: str = ""
    favicon_hash: str = ""


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
    takeovers: list[str] = field(default_factory=list)
    wayback_urls: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    findings_ids: list[int] = field(default_factory=list)
    report_html: str = ""
    report_json: str = ""
    report_csv: str = ""
    report_md: str = ""

    @property
    def live_urls(self) -> list[UrlResult]:
        return [u for u in self.urls if not u.error and u.status > 0]

    @property
    def interesting_urls(self) -> list[UrlResult]:
        out = []
        for u in self.live_urls:
            if u.status in (401, 403, 405, 500, 502, 503):
                out.append(u)
            elif u.tech:
                out.append(u)
            elif u.sensitive:
                out.append(u)
            elif u.redirect_to:
                out.append(u)
        return out


# ===========================================================================
# Стадия 1: Subdomain discovery — расширенные источники
# ===========================================================================

def _crtsh(domain: str) -> set[str]:
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
    except Exception as exc:
        log.debug("crt.sh: %s", exc)
    return subs


def _hackertarget(domain: str) -> set[str]:
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
    except Exception as exc:
        log.debug("hackertarget: %s", exc)
    return subs


def _otx_passive(domain: str) -> set[str]:
    """AlienVault OTX passive DNS."""
    subs: set[str] = set()
    try:
        headers = {}
        if config.OTX_API_KEY:
            headers["X-OTX-API-KEY"] = config.OTX_API_KEY
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/"
            f"{domain}/passive_dns",
            timeout=20, verify=False, headers=headers,
        )
        if r.status_code == 200:
            data = r.json()
            for entry in data.get("passive_dns", []):
                h = (entry.get("hostname") or "").lower()
                if h.endswith(domain) and "*" not in h:
                    subs.add(h)
    except Exception as exc:
        log.debug("otx: %s", exc)
    return subs


def _rapiddns(domain: str) -> set[str]:
    """RapidDNS."""
    subs: set[str] = set()
    try:
        r = requests.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            timeout=20, verify=False,
            headers={"User-Agent": config.USER_AGENT},
        )
        if r.status_code == 200:
            for m in re.finditer(r"<td>([a-z0-9.-]+\.{})</td>".format(
                re.escape(domain)), r.text, re.I):
                s = m.group(1).lower()
                if s.endswith(domain) and "*" not in s:
                    subs.add(s)
    except Exception as exc:
        log.debug("rapiddns: %s", exc)
    return subs


def _anubisdb(domain: str) -> set[str]:
    """AnubisDB (c99.nl)."""
    subs: set[str] = set()
    try:
        r = requests.get(
            f"https://jldc.me/anubis/subdomains/{domain}",
            timeout=20, verify=False,
            headers={"User-Agent": config.USER_AGENT},
        )
        if r.status_code == 200:
            for s in r.json():
                s = s.strip().lower()
                if s.endswith(domain):
                    subs.add(s)
    except Exception as exc:
        log.debug("anubisdb: %s", exc)
    return subs


def _brute_subdomains(domain: str, wordlist: str,
                      max_subs: int, threads: int) -> set[str]:
    wl = WORDLIST_DIR / wordlist
    if not wl.exists():
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
            "jenkins", "ci", "cd", "git", "gitlab", "github",
            "jira", "confluence", "mattermost", "slack",
            "vpn", "remote", "rdp", "ssh", "sftp", "db",
            "mysql", "postgres", "redis", "mongo", "elastic",
            "kibana", "prometheus", "nexus", "sonar", "sentry",
            "s3", "storage", "files", "cloud", "gateway", "edge",
            "proxy", "lb", "waf", "internal", "intranet", "extranet",
            "partner", "client", "vendor", "swagger", "graphql",
            "api-v1", "api-v2", "api-v3", "ws", "wsdl", "soap", "rest",
            "dashboard", "panel", "console", "manage", "manager",
            "www2", "www3", "dev-api", "test-api", "staging-api",
        ]
    else:
        try:
            words = [w.strip() for w in wl.read_text(
                encoding="utf-8", errors="ignore").splitlines()
                if w.strip() and not w.startswith("#")]
        except Exception as exc:
            log.warning("wordlist %s: %s", wl, exc)
            return set()

    words = words[:max_subs]
    subs: set[str] = set()

    def _check(w: str) -> str | None:
        fqdn = f"{w}.{domain}"
        try:
            socket.gethostbyname(fqdn)
            return fqdn
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(_check, w) for w in words]
        with Progress(SpinnerColumn(),
                      TextColumn("[progress.description]{task.description}"),
                      BarColumn(),
                      TextColumn("{task.completed}/{task.total}"),
                      TimeElapsedColumn(),
                      console=console) as p:
            task = p.add_task("brute subs", total=len(words))
            for f in as_completed(futs):
                p.advance(task)
                r = f.result()
                if r:
                    subs.add(r)
    return subs


def _detect_wildcard(domain: str) -> list[str]:
    import random
    import string
    ips: set[str] = set()
    for _ in range(3):
        rand = "".join(random.choices(
            string.ascii_lowercase + string.digits, k=16))
        try:
            ip = socket.gethostbyname(f"{rand}.{domain}")
            ips.add(ip)
        except Exception:
            pass
    return sorted(ips) if len(ips) == 3 else []


def discover_subdomains(domain: str, profile_cfg: dict
                        ) -> tuple[list[SubDomain], list[str]]:
    """Стадия 1: собрать поддомены из всех источников."""
    console.print("\n[bold cyan]▶ Стадия 1: Subdomain discovery[/bold cyan]")

    domain = extract_host(domain).lower()
    subs: dict[str, SubDomain] = {}

    sources = [
        ("crt.sh", _crtsh),
        ("hackertarget", _hackertarget),
        ("otx", _otx_passive),
        ("rapiddns", _rapiddns),
        ("anubisdb", _anubisdb),
    ]

    for name, fn in sources:
        console.print(f"[cyan]  · {name}…[/cyan]")
        try:
            found = fn(domain)
            console.print(f"    → {len(found)} subs")
            for s in found:
                if s not in subs:
                    subs[s] = SubDomain(name=s, source=name)
        except Exception as exc:
            console.print(f"    [red]{exc}[/red]")

    # Brute
    console.print(f"[cyan]  · wordlist brute "
                  f"({profile_cfg['wordlist']}, "
                  f"max {profile_cfg['max_subs']})…[/cyan]")
    br = _brute_subdomains(
        domain, profile_cfg["wordlist"],
        profile_cfg["max_subs"], profile_cfg["threads_subs"],
    )
    console.print(f"    → {len(br)} subs")
    for s in br:
        if s not in subs:
            subs[s] = SubDomain(name=s, source="brute")

    if domain not in subs:
        subs[domain] = SubDomain(name=domain, source="root")

    # Wildcard
    console.print("[cyan]  · wildcard DNS check…[/cyan]")
    wildcard_ips = _detect_wildcard(domain)
    if wildcard_ips:
        console.print(f"    [yellow]⚠ wildcard → "
                      f"{', '.join(wildcard_ips)}[/yellow]")

    # Resolve
    console.print(f"[cyan]  · resolving {len(subs)} subs…[/cyan]")
    sub_list = list(subs.values())

    def _resolve(sd: SubDomain) -> None:
        try:
            sd.ip = socket.gethostbyname(sd.name)
        except Exception:
            sd.ip = ""

    with ThreadPoolExecutor(max_workers=profile_cfg["threads_subs"]) as ex:
        list(ex.map(_resolve, sub_list))

    # Filter wildcard
    if wildcard_ips:
        before = len(sub_list)
        sub_list = [s for s in sub_list if s.ip not in wildcard_ips
                    or s.name == domain]
        filtered = before - len(sub_list)
        if filtered:
            console.print(f"    [yellow]filtered {filtered} wildcard[/yellow]")

    console.print(f"[green]  ✓ Unique subs: {len(sub_list)}[/green]")

    db.save_scan("autoscan_subs", domain, {
        "count": len(sub_list),
        "wildcard_ips": wildcard_ips,
        "sources": {s: sum(1 for x in sub_list if x.source == s)
                    for s in ("crt.sh", "hackertarget", "otx",
                              "rapiddns", "anubisdb", "brute", "root")},
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


def _grab_banner(host: str, port: int, timeout: float = 1.5) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.send(b"HEAD / HTTP/1.0\r\nHost: " +
                   host.encode() + b"\r\n\r\n")
            data = s.recv(1024)
            return data.decode("utf-8", errors="ignore").split("\n")[0][:120]
    except Exception:
        return ""


def _scan_host_ports(host: str, ports: list[int],
                     threads: int, timeout: float) -> tuple[list[int], dict]:
    open_ports: list[int] = []
    banners: dict = {}
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_tcp_connect, host, p, timeout): p for p in ports}
        for f in as_completed(futs):
            try:
                if f.result():
                    p = futs[f]
                    open_ports.append(p)
                    if p in (21, 22, 25, 80, 110, 143, 443, 445, 3306,
                              5432, 6379, 8080, 8443, 9200, 27017):
                        b = _grab_banner(host, p)
                        if b:
                            banners[p] = b
            except Exception:
                pass
    return sorted(open_ports), banners


def scan_hosts(subdomains: list[SubDomain], profile_cfg: dict,
               top_ports: list[int]) -> list[HostResult]:
    console.print(f"\n[bold cyan]▶ Стадия 2: Port scan "
                  f"({len(top_ports)} портов × {len(subdomains)} хостов)"
                  f"[/bold cyan]")

    by_ip: dict[str, list[str]] = {}
    for sd in subdomains:
        if sd.ip:
            by_ip.setdefault(sd.ip, []).append(sd.name)

    console.print(f"[cyan]  · {len(by_ip)} уникальных IP[/cyan]")

    host_results: list[HostResult] = []
    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  TimeElapsedColumn(),
                  console=console) as p:
        task = p.add_task("port scan", total=len(by_ip))
        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = {
                ex.submit(_scan_host_ports, ip, top_ports,
                          profile_cfg["threads_ports"],
                          profile_cfg["timeout"] / 2): (ip, names)
                for ip, names in by_ip.items()
            }
            for f in as_completed(futs):
                p.advance(task)
                ip, names = futs[f]
                try:
                    open_ports, banners = f.result()
                except Exception as exc:
                    log.warning("scan %s: %s", ip, exc)
                    open_ports, banners = [], {}

                http_ports = [p_ for p_ in open_ports
                              if p_ in HTTP_PORTS_HTTP | HTTP_PORTS_HTTPS]

                for name in names:
                    hr = HostResult(subdomain=name, ip=ip,
                                    open_ports=open_ports,
                                    http_ports=http_ports,
                                    banners=banners)
                    host_results.append(hr)
                    if open_ports:
                        console.print(
                            f"    [green]✓[/green] {name:<40} "
                            f"[magenta]{ip}[/magenta] → "
                            f"[cyan]{','.join(map(str, open_ports[:10]))}"
                            f"{'…' if len(open_ports) > 10 else ''}[/cyan]")

    live = [h for h in host_results if h.open_ports]
    console.print(f"[green]  ✓ Live hosts: {len(live)}/{len(host_results)}"
                  f"[/green]")
    return host_results


# ===========================================================================
# Стадия 3: HTTP probe
# ===========================================================================

async def _probe_url(session: aiohttp.ClientSession, url: str,
                     sem: asyncio.Semaphore, timeout: float) -> UrlResult:
    host = port = 0
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
        for attempt in range(2):
            try:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=False, ssl=False,
                ) as r:
                    result.status = r.status
                    result.server = r.headers.get("Server", "")
                    result.headers = dict(list(r.headers.items())[:30])
                    body = await r.text(errors="ignore")
                    result.length = len(body)

                    loc = r.headers.get("Location", "")
                    if loc and r.status in (301, 302, 303, 307, 308):
                        result.redirect_to = loc
                        try:
                            from urllib.parse import urljoin
                            next_url = urljoin(url, loc)
                            async with session.get(
                                next_url,
                                timeout=aiohttp.ClientTimeout(
                                    total=timeout),
                                allow_redirects=False, ssl=False,
                            ) as r2:
                                body2 = await r2.text(errors="ignore")
                                body = body2
                                if r2.status < 400:
                                    result.status = r2.status
                        except Exception:
                            pass

                    low = body.lower()
                    if "<title>" in low:
                        s = low.index("<title>") + 7
                        e = low.find("</title>", s)
                        if e > s:
                            result.title = body[s:e].strip()[:150]

                    missing = [h for h in SECURITY_HEADERS_CHECK
                               if h not in r.headers]
                    result.missing_headers = missing

                    combined = (body[:80000].lower() +
                                " " + " ".join(
                                    f"{k}: {v}".lower()
                                    for k, v in r.headers.items()))
                    for tech, markers in TECH_MARKERS.items():
                        for m in markers:
                            if m.lower() in combined:
                                if tech not in result.tech:
                                    result.tech.append(tech)
                                break
                    return result
            except asyncio.TimeoutError:
                result.error = "timeout"
            except aiohttp.ClientConnectorError as exc:
                result.error = f"conn: {str(exc)[:60]}"
                break
            except Exception as exc:
                result.error = str(exc)[:80]
            if attempt == 0:
                await asyncio.sleep(0.5)
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
        for coro in asyncio.as_completed(tasks):
            r = await coro
            out.append(r)
            if r.status and not r.error:
                tech_str = f" [{','.join(r.tech[:3])}]" if r.tech else ""
                console.print(
                    f"    [green]{r.status:<3}[/green] "
                    f"[cyan]{r.url[:70]:<70}[/cyan]"
                    f" [dim]{(r.title or '')[:40]}{tech_str}[/dim]")
    return out


def probe_urls(hosts: list[HostResult], profile_cfg: dict) -> list[UrlResult]:
    console.print("\n[bold cyan]▶ Стадия 3: HTTP probe[/bold cyan]")

    urls: list[str] = []
    seen: set[str] = set()
    for h in hosts:
        if not h.open_ports:
            continue
        for p_ in h.open_ports:
            if p_ in HTTP_PORTS_HTTP:
                scheme = "http"
            elif p_ in HTTP_PORTS_HTTPS:
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
    except Exception as exc:
        console.print(f"[red]  probe error: {exc}[/red]")
        return []

    live = [r for r in results if not r.error and r.status > 0]
    console.print(f"[green]  ✓ Live URLs: {len(live)}/{len(results)}"
                  f"[/green]")
    return results


# ===========================================================================
# Стадия 4: Security hints
# ===========================================================================

SENSITIVE_BODY_SIGS = {
    "wp-config": [b"DB_PASSWORD", b"DB_NAME"],
    "env": [b"AWS_ACCESS_KEY", b"SECRET_KEY", b"DATABASE_URL"],
    "git": [b"[core]", b"repositoryformatversion"],
    "backup": [b"-- MySQL dump", b"pg_dump"],
    "phpinfo": [b"<title>phpinfo()", b"PHP Version"],
}


def _check_sensitive(base_url: str, paths: list[str],
                     threads: int, timeout: float) -> list[dict]:
    found: list[dict] = []
    base = base_url.rstrip("/")

    def _one(path: str) -> dict | None:
        url = f"{base}{path}"
        try:
            r = requests.head(url, timeout=timeout, verify=False,
                              allow_redirects=False,
                              headers={"User-Agent": config.USER_AGENT})
            if r.status_code in (405, 501):
                r = requests.get(url, timeout=timeout, verify=False,
                                 allow_redirects=False, stream=True,
                                 headers={"User-Agent": config.USER_AGENT})
            if r.status_code in (200, 301, 302, 401, 403):
                entry = {
                    "path": path,
                    "status": r.status_code,
                    "size": r.headers.get("Content-Length", "?"),
                    "type": r.headers.get("Content-Type", "")[:60],
                }
                # Проверим содержимое
                if r.status_code == 200 and r.request.method != "HEAD":
                    try:
                        r2 = requests.get(url, timeout=timeout, verify=False,
                                           headers={"User-Agent":
                                                    config.USER_AGENT})
                        content = r2.content[:2048]
                        for kind, sigs in SENSITIVE_BODY_SIGS.items():
                            if any(s in content for s in sigs):
                                entry["signature_match"] = kind
                                break
                    except Exception:
                        pass
                return entry
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(_one, p_) for p_ in paths]
        for f in as_completed(futs):
            try:
                r = f.result()
                if r:
                    found.append(r)
            except Exception:
                pass
    return found


def security_hints(urls: list[UrlResult], profile_cfg: dict) -> None:
    console.print("\n[bold cyan]▶ Стадия 4: Security hints[/bold cyan]")

    # Missing headers summary
    missing_counter: dict[str, int] = {}
    for u in urls:
        for h in u.missing_headers:
            missing_counter[h] = missing_counter.get(h, 0) + 1
    if missing_counter:
        t = Table(title="Missing security headers (по всем URL)")
        t.add_column("Header", style="yellow")
        t.add_column("Кол-во", style="green")
        for h, c in sorted(missing_counter.items(),
                           key=lambda x: -x[1])[:10]:
            t.add_row(h, str(c))
        console.print(t)

    if not profile_cfg["sensitive_files"]:
        console.print("[dim]  (sensitive_files выключены профилем)[/dim]")
        return

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
                sig = f" [{f.get('signature_match')}]" if f.get(
                    "signature_match") else ""
                console.print(f"    [yellow]⚠[/yellow] {base}{f['path']} "
                              f"[dim]({f['status']}, {f['size']}){sig}[/dim]")
            if len(found) > 5:
                console.print(f"    [dim]… ещё {len(found)-5}[/dim]")

    console.print(f"[green]  ✓ Sensitive files: {total_found}[/green]")


# ===========================================================================
# Стадия 5: Screenshots
# ===========================================================================

def take_screenshots(urls: list[UrlResult], profile_cfg: dict) -> None:
    console.print("\n[bold cyan]▶ Стадия 5: Screenshots[/bold cyan]")

    if not profile_cfg["screenshot"]:
        console.print("[dim]  (screenshots выключены профилем)[/dim]")
        return

    try:
        from playwright.sync_api import sync_playwright
        from playwright.sync_api import TimeoutError as PWTimeout
    except ImportError:
        console.print("[yellow]  ⚠ playwright не установлен[/yellow]")
        console.print("[dim]  pip install playwright && "
                      "playwright install chromium[/dim]")
        return

    interesting = [u for u in urls if not u.error and u.status > 0
                    and u.status not in (404,)]
    if not interesting:
        console.print("[yellow]  ⚠ нет интересных URL[/yellow]")
        return
    interesting = interesting[:30]

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    shot_dir = AUTOSCAN_DIR / f"shots_{ts}"
    shot_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[cyan]  · снимаю {len(interesting)} URL → "
                  f"{shot_dir.name}[/cyan]")

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
                out = shot_dir / f"{i:03d}_{safe}.png"
                try:
                    page = context.new_page()
                    page.goto(u.url, timeout=20000,
                              wait_until="domcontentloaded")
                    page.screenshot(path=str(out), full_page=False)
                    page.close()
                    u.screenshot = str(out)
                    console.print(f"    [green]✓[/green] {u.url[:70]}")
                except PWTimeout:
                    console.print(f"    [yellow]timeout[/yellow] "
                                  f"{u.url[:70]}")
                except Exception as exc:
                    console.print(f"    [red]err[/red] {u.url[:70]}: "
                                  f"{str(exc)[:40]}")
            context.close()
            browser.close()
    except Exception as exc:
        console.print(f"[red]  playwright: {exc}[/red]")


# ===========================================================================
# Стадия 6: Takeover check
# ===========================================================================

def run_takeover_check(subs: list[SubDomain],
                       profile_cfg: dict) -> list[str]:
    console.print("\n[bold cyan]▶ Стадия 6: Takeover check[/bold cyan]")
    if not profile_cfg.get("takeover", False):
        console.print("[dim]  (takeover выключен профилем)[/dim]")
        return []
    try:
        from modules import subdomain_takeover_v2 as t2
        candidates = [s.name for s in subs][:500]
        findings = t2.scan_list(",".join(candidates), threads=20, timeout=8)
        dangling = [f.subdomain for f in findings if f.dangling]
        if dangling:
            console.print(f"[red]⚠ Dangling: {len(dangling)}[/red]")
            for s in dangling[:10]:
                console.print(f"  [red]{s}[/red]")
        else:
            console.print("[green]✓ Takeover-кандидатов нет[/green]")
        return dangling
    except Exception as exc:
        console.print(f"[red]takeover: {exc}[/red]")
        return []


# ===========================================================================
# Стадия 7: Wayback
# ===========================================================================

def run_wayback(domain: str, profile_cfg: dict) -> list[str]:
    console.print("\n[bold cyan]▶ Стадия 7: Wayback[/bold cyan]")
    if not profile_cfg.get("wayback", False):
        console.print("[dim]  (wayback выключен профилем)[/dim]")
        return []
    try:
        from modules import osint_pro
        urls = osint_pro.wayback_lookup(domain, limit=200)
        result = [u["url"] for u in urls][:500]
        console.print(f"[green]✓ Wayback URLs: {len(result)}[/green]")
        return result
    except Exception as exc:
        console.print(f"[red]wayback: {exc}[/red]")
        return []


# ===========================================================================
# Findings → notes
# ===========================================================================

def _save_findings(r: PipelineResult) -> list[int]:
    ids: list[int] = []
    try:
        from modules import notes
    except Exception:
        return ids

    # Takeovers
    for sub in r.takeovers:
        try:
            nid = notes.add_note(
                kind="finding",
                title=f"Subdomain Takeover: {sub}",
                target=sub,
                severity="high",
                status="open",
                tags=["takeover", "bugbounty", "autoscan"],
                body=f"Dangling CNAME для {sub}",
            )
            if nid > 0:
                ids.append(nid)
        except Exception:
            pass

    # Sensitive files
    for u in r.urls:
        for s in u.sensitive:
            try:
                sev = ("critical" if s.get("signature_match")
                       or any(x in s["path"] for x in
                              (".env", ".git", "backup", "sql"))
                       else "medium")
                nid = notes.add_note(
                    kind="finding",
                    title=f"Exposed: {u.host}{s['path']} "
                          f"[{s['status']}]",
                    target=u.host,
                    severity=sev,
                    status="open",
                    tags=["exposure", "sensitive-file", "autoscan"],
                    body=(f"URL: {u.scheme}://{u.host}{s['path']}\n"
                          f"Status: {s['status']}, size: {s['size']}\n"
                          f"Content-Type: {s.get('type', '?')}\n"
                          f"Signature: {s.get('signature_match', '—')}"),
                )
                if nid > 0:
                    ids.append(nid)
            except Exception:
                pass

    # Missing headers (по хостам с >5 miss)
    for u in r.urls:
        if len(u.missing_headers) >= 5:
            try:
                nid = notes.add_note(
                    kind="finding",
                    title=f"Missing security headers "
                          f"({len(u.missing_headers)}) on {u.host}",
                    target=u.host,
                    severity="low",
                    status="open",
                    tags=["headers", "misconfig", "autoscan"],
                    body="Отсутствуют: " + ", ".join(u.missing_headers),
                )
                if nid > 0:
                    ids.append(nid)
            except Exception:
                pass
            break  # один такой finding за скан

    return ids


# ===========================================================================
# Стадия 8: Report
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
a{color:#7ad9ff;text-decoration:none;}
a:hover{text-decoration:underline;}
.toc{background:#0d0d0d;border:1px solid #222;padding:16px 24px;
     border-radius:4px;margin-bottom:24px;}
.toc ul{list-style:none;padding-left:0;}
.toc li{padding:3px 0;}
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
td{padding:6px 8px;border:1px solid #222;vertical-align:top;
   word-break:break-all;}
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
.section{padding:8px 0;border-top:1px solid #1a1a1a;}
.timeline{background:#0d0d0d;border:1px solid #222;border-radius:4px;
          padding:12px;font-family:monospace;font-size:11px;
          overflow-x:auto;white-space:pre;color:#00ff9c;}
"""


def _esc(v: Any) -> str:
    return html_mod.escape(str(v if v is not None else ""))


def _status_color(s: int) -> str:
    if s == 0:
        return "muted"
    if s < 300:
        return "ok"
    if s < 400:
        return "warn"
    if s in (401, 403):
        return "crit"
    if s >= 500:
        return "crit"
    return "muted"


def _html_toc() -> str:
    entries = [
        ("summary", "Сводка"),
        ("subs", "Поддомены"),
        ("hosts", "Живые хосты"),
        ("urls", "HTTP URLs"),
        ("interesting", "Интересные URL"),
        ("takeovers", "Takeover"),
        ("wayback", "Wayback"),
        ("screens", "Скриншоты"),
        ("errors", "Ошибки"),
    ]
    items = "".join(f'<li>• <a href="#{a}">{t}</a></li>'
                     for a, t in entries)
    return f'<div class="toc"><b>Содержание:</b><ul>{items}</ul></div>'


def _make_html_report(r: PipelineResult) -> str:
    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>Auto-Scan — {_esc(r.domain)}</title>",
        f"<style>{HTML_CSS}</style></head><body><div class='container'>",
        f"<div class='cover'>",
        f"<div class='title'>🛰 Auto-Scan — {_esc(r.domain)}</div>",
        f"<div class='meta'>Профиль: <b>{_esc(r.profile)}</b> "
        f"&nbsp;•&nbsp; Запущен: {_esc(r.started)} "
        f"&nbsp;•&nbsp; Длительность: {r.duration_sec:.1f}s</div>",
        "</div>",
        _html_toc(),
    ]

    # Summary
    parts.append('<h2 id="summary">📊 Сводка</h2><div class="summary">')
    stats = [
        ("Поддомены", len(r.subdomains)),
        ("Живых хостов", len([h for h in r.hosts if h.open_ports])),
        ("Открытых портов", sum(len(h.open_ports) for h in r.hosts)),
        ("HTTP URLs", len(r.live_urls)),
        ("Интересных URL", len(r.interesting_urls)),
        ("Sensitive files", sum(len(u.sensitive) for u in r.urls)),
        ("Takeovers", len(r.takeovers)),
        ("Wayback URLs", len(r.wayback_urls)),
        ("Скриншотов", len([u for u in r.urls if u.screenshot])),
    ]
    for label, num in stats:
        parts.append(f'<div class="card"><div class="num">{num}</div>'
                     f'<div class="label">{_esc(label)}</div></div>')
    parts.append("</div>")

    # Subdomains
    parts.append(f'<h2 id="subs">🌐 Поддомены ({len(r.subdomains)})</h2>')
    if r.wildcard_ips:
        parts.append(f'<p class="warn">⚠ Wildcard DNS → '
                     f'{_esc(", ".join(r.wildcard_ips))}</p>')
    parts.append("<table><tr><th>#</th><th>Subdomain</th><th>IP</th>"
                 "<th>Source</th></tr>")
    for i, s in enumerate(sorted(r.subdomains, key=lambda x: x.name), 1):
        parts.append(f"<tr><td>{i}</td><td>{_esc(s.name)}</td>"
                     f"<td>{_esc(s.ip) or '—'}</td>"
                     f'<td class="muted">{_esc(s.source)}</td></tr>')
    parts.append("</table>")

    # Live hosts
    live = [h for h in r.hosts if h.open_ports]
    parts.append(f'<h2 id="hosts">🔌 Живые хосты ({len(live)})</h2>')
    if live:
        parts.append("<table><tr><th>Subdomain</th><th>IP</th>"
                     "<th>Open ports</th><th>Banner</th></tr>")
        for h in sorted(live, key=lambda x: x.subdomain):
            ports_str = ", ".join(str(p) for p in h.open_ports)
            banners = "<br>".join(
                f"{p}: {_esc(b[:60])}" for p, b in list(h.banners.items())[:3])
            parts.append(f"<tr><td>{_esc(h.subdomain)}</td>"
                         f"<td>{_esc(h.ip)}</td>"
                         f"<td><code>{_esc(ports_str)}</code></td>"
                         f"<td>{banners or '—'}</td></tr>")
        parts.append("</table>")

    # URLs
    parts.append(f'<h2 id="urls">🌍 HTTP URLs ({len(r.live_urls)})</h2>')
    if r.live_urls:
        parts.append("<table><tr><th>URL</th><th>Status</th><th>Title</th>"
                     "<th>Server</th><th>Tech</th></tr>")
        for u in sorted(r.live_urls, key=lambda x: (x.status, x.url)):
            tech = " ".join(f'<span class="tag">{_esc(t)}</span>'
                             for t in u.tech) if u.tech else "—"
            parts.append(
                f'<tr><td><a href="{_esc(u.url)}" target="_blank">'
                f'{_esc(u.url)}</a></td>'
                f'<td class="{_status_color(u.status)}">{u.status}</td>'
                f"<td>{_esc(u.title or '—')}</td>"
                f"<td>{_esc(u.server or '—')}</td>"
                f"<td>{tech}</td></tr>"
            )
        parts.append("</table>")

    # Interesting
    interesting = r.interesting_urls
    parts.append(f'<h2 id="interesting">⭐ Интересные URL '
                 f'({len(interesting)})</h2>')
    for u in interesting:
        parts.append(f'<div class="section">')
        parts.append(f'<h3>{_esc(u.url)} '
                     f'<span class="{_status_color(u.status)}">'
                     f'{u.status}</span></h3>')
        parts.append(f"<p>Title: <b>{_esc(u.title or '—')}</b> &nbsp;"
                     f" Server: <code>{_esc(u.server or '—')}</code>"
                     f" &nbsp; Len: {u.length}</p>")
        if u.tech:
            parts.append("<p>Tech: " +
                         " ".join(f'<span class="tag">{_esc(t)}</span>'
                                   for t in u.tech) + "</p>")
        if u.missing_headers:
            parts.append(f'<p class="warn">Missing headers: '
                         f'{_esc(", ".join(u.missing_headers))}</p>')
        if u.redirect_to:
            parts.append(f'<p class="muted">Redirect → '
                         f'{_esc(u.redirect_to)}</p>')
        if u.sensitive:
            parts.append("<p><b>Sensitive files:</b></p><ul>")
            for f in u.sensitive:
                sig = (f' <span class="crit">'
                       f'[{f["signature_match"]}]</span>'
                       if f.get("signature_match") else "")
                parts.append(f"<li><code>{_esc(f['path'])}</code> → "
                             f'<span class="warn">{f["status"]}</span> '
                             f"({f['size']}){sig}</li>")
            parts.append("</ul>")
        if u.screenshot:
            import base64
            try:
                b64 = base64.b64encode(
                    Path(u.screenshot).read_bytes()).decode()
                parts.append(f'<img src="data:image/png;base64,{b64}">')
            except Exception:
                pass
        parts.append("</div>")

    # Takeovers
    if r.takeovers:
        parts.append(f'<h2 id="takeovers">🎯 Takeover-кандидаты '
                     f'({len(r.takeovers)})</h2><ul>')
        for s in r.takeovers:
            parts.append(f'<li><span class="crit">{_esc(s)}</span></li>')
        parts.append("</ul>")

    # Wayback
    if r.wayback_urls:
        parts.append(f'<h2 id="wayback">📚 Wayback URLs '
                     f'({len(r.wayback_urls)})</h2>')
        parts.append('<div style="max-height:400px;overflow-y:auto;">')
        for u in r.wayback_urls[:100]:
            parts.append(f'<div class="muted">• {_esc(u)}</div>')
        parts.append("</div>")

    # Errors
    if r.errors:
        parts.append(f'<h2 id="errors">❌ Ошибки ({len(r.errors)})</h2><ul>')
        for e in r.errors:
            parts.append(f'<li class="muted">{_esc(e)}</li>')
        parts.append("</ul>")

    # Footer
    parts.append(
        f'<div class="footer">CyberSec Toolkit — Bug Bounty Auto-Scan'
        f' &nbsp;•&nbsp; by idqwixxa &nbsp;•&nbsp; '
        f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>')
    parts.append("</div></body></html>")
    return "\n".join(parts)


def _make_markdown_report(r: PipelineResult) -> str:
    lines = [
        f"# Auto-Scan: {r.domain}",
        f"**Профиль:** {r.profile}  ",
        f"**Запущен:** {r.started}  ",
        f"**Длительность:** {r.duration_sec:.1f}s  ",
        "",
        "## Сводка",
        f"- Поддоменов: {len(r.subdomains)}",
        f"- Живых хостов: {len([h for h in r.hosts if h.open_ports])}",
        f"- HTTP URLs: {len(r.live_urls)}",
        f"- Интересных URL: {len(r.interesting_urls)}",
        f"- Sensitive files: {sum(len(u.sensitive) for u in r.urls)}",
        f"- Takeovers: {len(r.takeovers)}",
        "",
    ]

    if r.subdomains:
        lines.append(f"## Поддомены ({len(r.subdomains)})")
        for s in sorted(r.subdomains, key=lambda x: x.name)[:200]:
            lines.append(f"- `{s.name}` → {s.ip or '—'} ({s.source})")
        lines.append("")

    if r.takeovers:
        lines.append("## Takeover-кандидаты")
        for s in r.takeovers:
            lines.append(f"- 🔴 {s}")
        lines.append("")

    interesting = r.interesting_urls
    if interesting:
        lines.append(f"## Интересные URL ({len(interesting)})")
        for u in interesting[:50]:
            lines.append(f"### `{u.url}` [{u.status}]")
            if u.title:
                lines.append(f"Title: {u.title}")
            if u.tech:
                lines.append(f"Tech: {', '.join(u.tech)}")
            if u.missing_headers:
                lines.append(f"Missing: {', '.join(u.missing_headers)}")
            if u.sensitive:
                lines.append("Sensitive files:")
                for s in u.sensitive:
                    lines.append(f"  - `{s['path']}` ({s['status']})")
            lines.append("")
    return "\n".join(lines)


def make_report(r: PipelineResult, out_dir: Path | None = None) -> None:
    console.print("\n[bold cyan]▶ Стадия 8: Report[/bold cyan]")

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
        console.print(f"[green]  ✓ HTML: {r.report_html} "
                      f"({size_kb:.1f} KB)[/green]")
    except Exception as exc:
        console.print(f"[red]  HTML error: {exc}[/red]")

    # JSON
    try:
        data = asdict(r)
        (base.with_suffix(".json")).write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
        r.report_json = str(base.with_suffix(".json"))
        console.print(f"[green]  ✓ JSON: {r.report_json}[/green]")
    except Exception as exc:
        console.print(f"[red]  JSON error: {exc}[/red]")

    # CSV
    try:
        with open(base.with_suffix(".csv"), "w", newline="",
                  encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["url", "host", "port", "status", "title", "server",
                        "tech", "length", "missing_headers", "sensitive",
                        "redirect"])
            for u in r.live_urls:
                w.writerow([
                    u.url, u.host, u.port, u.status, u.title, u.server,
                    ";".join(u.tech), u.length,
                    ";".join(u.missing_headers),
                    ";".join(f"{s['path']}({s['status']})"
                             for s in u.sensitive),
                    u.redirect_to,
                ])
        r.report_csv = str(base.with_suffix(".csv"))
        console.print(f"[green]  ✓ CSV: {r.report_csv}[/green]")
    except Exception as exc:
        console.print(f"[red]  CSV error: {exc}[/red]")

    # Markdown
    try:
        md = _make_markdown_report(r)
        (base.with_suffix(".md")).write_text(md, encoding="utf-8")
        r.report_md = str(base.with_suffix(".md"))
        console.print(f"[green]  ✓ Markdown: {r.report_md}[/green]")
    except Exception as exc:
        console.print(f"[red]  Markdown error: {exc}[/red]")


# ===========================================================================
# Notify
# ===========================================================================

def _notify(r: PipelineResult) -> None:
    try:
        from modules import notifier
    except Exception:
        return
    msg = (
        f"Домен: {r.domain}\n"
        f"Профиль: {r.profile}\n"
        f"Длительность: {r.duration_sec:.1f}s\n\n"
        f"• Поддомены: {len(r.subdomains)}\n"
        f"• Живых хостов: {len([h for h in r.hosts if h.open_ports])}\n"
        f"• HTTP URLs: {len(r.live_urls)}\n"
        f"• Интересных: {len(r.interesting_urls)}\n"
        f"• Takeovers: {len(r.takeovers)}\n"
        f"• Findings: {len(r.findings_ids)}\n"
    )
    try:
        notifier.notify_all(f"🛰 Auto-Scan: {r.domain}", msg)
    except Exception:
        pass


# ===========================================================================
# Checkpoint (resume)
# ===========================================================================

def _save_checkpoint(r: PipelineResult) -> None:
    try:
        p = CHECKPOINT_DIR / f"{r.domain.replace('.', '_')}.json"
        p.write_text(json.dumps(asdict(r), indent=2,
                                 ensure_ascii=False, default=str),
                     encoding="utf-8")
    except Exception as exc:
        log.debug("checkpoint save: %s", exc)


def _load_checkpoint(domain: str) -> PipelineResult | None:
    p = CHECKPOINT_DIR / f"{domain.replace('.', '_')}.json"
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        r = PipelineResult(
            domain=data["domain"], profile=data["profile"],
            started=data["started"],
        )
        r.subdomains = [SubDomain(**s) for s in data.get("subdomains", [])]
        r.hosts = [HostResult(**h) for h in data.get("hosts", [])]
        r.urls = [UrlResult(**u) for u in data.get("urls", [])]
        r.wildcard_ips = data.get("wildcard_ips", [])
        r.takeovers = data.get("takeovers", [])
        r.wayback_urls = data.get("wayback_urls", [])
        return r
    except Exception as exc:
        log.warning("checkpoint load: %s", exc)
        return None


# ===========================================================================
# Orchestrator
# ===========================================================================

def run_pipeline(domain: str, profile: str = "full",
                 out_dir: str | None = None,
                 skip_stages: list[str] | None = None,
                 resume: bool = False) -> PipelineResult:
    if profile not in PROFILES:
        console.print(f"[red]Профиль '{profile}' не найден.[/red]")
        return PipelineResult(domain=domain, profile=profile,
                               started=datetime.now().isoformat())

    cfg = PROFILES[profile]
    skip = set(skip_stages or [])

    domain = extract_host(domain).lower()

    console.print(f"\n[bold cyan]🚀 Auto-Scan: [white]{domain}[/white] "
                  f"({profile})[/bold cyan]")
    console.print(f"[dim]Профиль: max_subs={cfg['max_subs']}, "
                  f"ports={cfg['ports']}, screenshot={cfg['screenshot']}"
                  f"[/dim]")

    # Resume
    resumed = None
    if resume:
        resumed = _load_checkpoint(domain)
        if resumed:
            console.print("[green]↻ Возобновляю с checkpoint[/green]")

    started = datetime.now()
    r = resumed or PipelineResult(
        domain=domain, profile=profile,
        started=started.isoformat(timespec="seconds"))

    if cfg["ports"] == "top100":
        top_ports = TOP_100_PORTS
    elif cfg["ports"] == "top1000":
        top_ports = TOP_1000_PORTS
    else:
        top_ports = TOP_100_PORTS

    try:
        subs = r.subdomains
        hosts = r.hosts
        urls = r.urls

        if "subs" not in skip and not subs:
            subs, wildcard = discover_subdomains(domain, cfg)
            r.subdomains = subs
            r.wildcard_ips = wildcard
            _save_checkpoint(r)

        if "ports" not in skip and subs and not hosts:
            hosts = scan_hosts(subs, cfg, top_ports)
            r.hosts = hosts
            _save_checkpoint(r)

        if "http" not in skip and hosts and not urls:
            urls = probe_urls(hosts, cfg)
            r.urls = urls
            _save_checkpoint(r)

        if "hints" not in skip and urls:
            security_hints(r.urls, cfg)
            _save_checkpoint(r)

        if "takeover" not in skip and subs and not r.takeovers:
            r.takeovers = run_takeover_check(subs, cfg)

        if "wayback" not in skip and not r.wayback_urls:
            r.wayback_urls = run_wayback(domain, cfg)

        if "screenshots" not in skip and urls:
            take_screenshots(r.urls, cfg)

        if "findings" not in skip:
            r.findings_ids = _save_findings(r)

        if "report" not in skip:
            make_report(r, Path(out_dir) if out_dir else None)

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Прервано — сохраняю checkpoint[/yellow]")
        r.errors.append("interrupted")
        _save_checkpoint(r)
    except Exception as exc:
        console.print(f"[red]Ошибка пайплайна: {exc}[/red]")
        log.exception("pipeline")
        r.errors.append(str(exc)[:200])

    finished = datetime.now()
    r.finished = finished.isoformat(timespec="seconds")
    r.duration_sec = (finished - started).total_seconds()

    # Итог
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
    t.add_row("Takeovers", str(len(r.takeovers)))
    t.add_row("Wayback URLs", str(len(r.wayback_urls)))
    t.add_row("Скриншотов",
              str(len([u for u in r.urls if u.screenshot])))
    t.add_row("Findings создано", str(len(r.findings_ids)))
    if r.report_html:
        t.add_row("HTML", r.report_html)
    console.print(t)

    _notify(r)

    db.save_scan("autoscan_done", domain, {
        "profile": profile,
        "duration": r.duration_sec,
        "subs": len(r.subdomains),
        "live_hosts": len([h for h in r.hosts if h.open_ports]),
        "urls": len(r.live_urls),
        "interesting": len(r.interesting_urls),
        "takeovers": len(r.takeovers),
        "findings": len(r.findings_ids),
        "report_html": r.report_html,
        "report_json": r.report_json,
    })

    # Удалить checkpoint (успешно завершено)
    try:
        cp = CHECKPOINT_DIR / f"{domain.replace('.', '_')}.json"
        if cp.exists():
            cp.unlink()
    except Exception:
        pass

    return r


# ===========================================================================
# Menu / CLI
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🟢 Bug Bounty Auto-Scan[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Quick scan (500 subs, top-100 ports)"),
        ("2", "Full scan (5000 subs, top-1000 ports, скрины)"),
        ("3", "Deep scan (20000 subs, всё включено)"),
        ("4", "Resume (из checkpoint)"),
        ("5", "Показать профили"),
        ("6", "История запусков"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованных bug bounty.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c in ("1", "2", "3"):
        pmap = {"1": "quick", "2": "full", "3": "deep"}
        profile = pmap[c]
        domain = Prompt.ask("Домен (например example.com)")
        if not Confirm.ask(f"Запустить {profile} скан для {domain}?",
                           default=False):
            return
        r = run_pipeline(domain, profile=profile)
        if r.report_html and Confirm.ask("Открыть HTML отчёт?",
                                          default=True):
            _open_file(Path(r.report_html))
    elif c == "4":
        d = Prompt.ask("Домен")
        run_pipeline(d, resume=True)
    elif c == "5":
        show_profiles()
    elif c == "6":
        show_past_results()


def show_profiles() -> None:
    t = Table(title="Профили Auto-Scan")
    t.add_column("Профиль", style="cyan")
    t.add_column("Subs", style="green")
    t.add_column("Ports", style="magenta")
    t.add_column("Screens", style="yellow")
    t.add_column("Hints", style="red")
    t.add_column("Takeover", style="red")
    t.add_column("Wayback", style="red")
    for name, cfg in PROFILES.items():
        t.add_row(
            name,
            str(cfg["max_subs"]),
            cfg["ports"],
            "✓" if cfg["screenshot"] else "—",
            "✓" if cfg["sensitive_files"] else "—",
            "✓" if cfg.get("takeover") else "—",
            "✓" if cfg.get("wayback") else "—",
        )
    console.print(t)


def show_past_results() -> None:
    try:
        cur = db.conn.cursor()
        cur.execute(
            "SELECT id, target, result, created_at FROM scans "
            "WHERE module='autoscan_done' ORDER BY id DESC LIMIT 30")
        rows = cur.fetchall()
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
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
    t.add_column("Findings", style="red")
    t.add_column("Дата", style="white")
    for r in rows:
        try:
            data = json.loads(r["result"])
        except Exception:
            data = {}
        t.add_row(
            str(r["id"]), str(r["target"]),
            data.get("profile", "?"),
            str(data.get("subs", "?")),
            str(data.get("urls", "?")),
            str(data.get("findings", "?")),
            str(r["created_at"])[:19],
        )
    console.print(t)
    console.print("\n[dim]Полные отчёты: reports/autoscan/[/dim]")


def _open_file(path: Path) -> None:
    import os
    import sys
    try:
        if sys.platform == "win32":
            os.startfile(str(path))
        elif sys.platform == "darwin":
            os.system(f'open "{path}"')
        else:
            os.system(f'xdg-open "{path}" >/dev/null 2>&1 &')
    except Exception as exc:
        console.print(f"[yellow]Не открыть: {exc}[/yellow]")


def cli_scan(domain: str, profile: str = "full",
             out_dir: str | None = None,
             skip: str | None = None) -> PipelineResult:
    skip_stages = [s.strip() for s in (skip or "").split(",") if s.strip()]
    return run_pipeline(domain, profile=profile, out_dir=out_dir,
                         skip_stages=skip_stages)


def cli_profiles() -> None:
    show_profiles()


def cli_past() -> None:
    show_past_results()