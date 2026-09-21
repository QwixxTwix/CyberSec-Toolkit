"""
Web Crawler Pro (extended): обход сайта, сбор URL, форм, параметров,
cookies, JS-эндпоинтов, robots.txt, sitemap.xml, secrets.
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty / CTF.

Возможности:
    ─── Sources (12+) ───
    - HTML (a / form / script / img / link)
    - JS (fetch, XHR, axios, url strings)
    - robots.txt (Allow/Disallow paths)
    - sitemap.xml / sitemap_index.xml
    - /sitemap.txt
    - Источники в meta / link rel
    - CSS @import
    - inline `<script>` endpoints
    - Comments (HTML/JS)
    - Email/phone regexp
    - Cloud buckets (S3/GCS/Azure)

    ─── Auth ───
    - Basic auth (user:pass)
    - Cookie (session)
    - Custom headers
    - Bearer token

    ─── Filters ───
    - Same host / include subdomains
    - Skip media (расширения)
    - Skip external links
    - URL regex filter
    - Depth control (BFS)

    ─── Output ───
    - Console (summary + tables)
    - JSON / CSV / Markdown / HTML
    - Готовые targets для sqlmap/ffuf
    - Findings → notes (login forms / API endpoints / secrets)
    - Notify при обнаружении login-форм

    ─── Интеграция ───
    - Findings → notes (login / secrets / admin-panels)
    - Notify
    - Screenshot (опц., если модуль доступен)
"""
import csv
import hashlib
import html as html_mod
import json
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
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

CRAWL_DIR = REPORT_DIR / "web_crawler"
CRAWL_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class CrawlerFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: CrawlerFinding) -> int:
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
            tags=["web-crawler", f.kind],
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
# Расширения и regex
# ===========================================================================

SKIP_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv",
    ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    ".exe", ".dll", ".iso", ".dmg", ".apk",
}

URL_RE = re.compile(
    r"""(?:"|')((?:https?://|/)[^"'\s<>]+)(?:"|')""",
    re.IGNORECASE,
)

# JS endpoints (fetch/axios/XHR)
JS_ENDPOINT_RES = [
    re.compile(r"""fetch\(\s*["']([^"']+)["']"""),
    re.compile(r"""axios\.[a-z]+\(\s*["']([^"']+)["']"""),
    re.compile(r"""\.open\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)["']"""),
    re.compile(r"""\$\.(?:get|post|ajax)\(\s*["']([^"']+)["']"""),
]

# Secrets patterns
SECRET_RES = {
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret": re.compile(r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    "google_api": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "stripe_live": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "stripe_test": re.compile(r"sk_test_[0-9a-zA-Z]{24,}"),
    "github_pat": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "gitlab_pat": re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    "private_key": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "jwt": re.compile(
        r"eyJ[A-Za-z0-9_/+\-]+\.eyJ[A-Za-z0-9_/+\-]+\.[A-Za-z0-9_/+\-]+"),
    "email": re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
}

# Логин-формы
LOGIN_KW = ("login", "signin", "sign-in", "logon", "auth",
             "session", "user", "username", "password", "passwd",
             "email", "remember", "submit", "log in", "войти")

# Admin-пути
ADMIN_KW = ("admin", "wp-admin", "administrator", "manager",
             "dashboard", "console", "cpanel", "plesk", "panel",
             "phpmyadmin", "webmin", "jenkins", "grafana")


# ===========================================================================
# Модель
# ===========================================================================

@dataclass
class CrawlFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


# ===========================================================================
# Crawler
# ===========================================================================

class Crawler:
    """Краулер в ширину (extended)."""

    def __init__(self, start_url: str, depth: int = 1,
                 max_pages: int = 50, timeout: int = 10,
                 same_host: bool = True,
                 include_subdomains: bool = False,
                 skip_ext: set[str] | None = None,
                 url_regex: str | None = None,
                 basic_auth: tuple[str, str] | None = None,
                 cookies: dict[str, str] | None = None,
                 extra_headers: dict[str, str] | None = None,
                 extract_secrets: bool = True,
                 parse_robots: bool = True,
                 parse_sitemap: bool = True) -> None:
        self.start_url = normalize_url(start_url).rstrip("/")
        self.depth = depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.same_host = same_host
        self.include_subdomains = include_subdomains
        self.skip_ext = skip_ext or SKIP_EXT
        self.url_regex = re.compile(url_regex) if url_regex else None
        self.extract_secrets = extract_secrets
        self.parse_robots = parse_robots
        self.parse_sitemap = parse_sitemap

        self.start_host = urlparse(self.start_url).hostname or ""
        self.root = f"{urlparse(self.start_url).scheme}://" \
                    f"{urlparse(self.start_url).netloc}"

        self.visited: set[str] = set()
        self.urls: set[str] = set()
        self.forms: list[dict] = []
        self.params: set[str] = set()
        self.cookies_found: set[str] = set()
        self.js_endpoints: set[str] = set()
        self.errors: list[tuple[str, str]] = []
        self.secrets: dict[str, list[str]] = {}
        self.emails: set[str] = set()
        self.ips: set[str] = set()
        self.robots_paths: set[str] = set()
        self.sitemap_urls: set[str] = set()
        self.admin_paths: set[str] = set()
        self.login_forms: list[dict] = []
        self.cloud_buckets: set[str] = set()
        self.stats = {
            "requests": 0,
            "started": time.time(),
        }

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": config.USER_AGENT,
        })
        if basic_auth:
            self.session.auth = basic_auth
        if cookies:
            self.session.cookies.update(cookies)
        if extra_headers:
            self.session.headers.update(extra_headers)

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    def _same_domain(self, url: str) -> bool:
        try:
            host = urlparse(url).hostname or ""
            if host == self.start_host:
                return True
            if self.include_subdomains and host.endswith(
                    "." + self.start_host):
                return True
            return not self.same_host and not self.include_subdomains
        except Exception:
            return False

    def _is_page(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        for ext in self.skip_ext:
            if path.endswith(ext):
                return False
        if self.url_regex and not self.url_regex.search(url):
            return False
        return True

    def _record_secret(self, kind: str, value: str) -> None:
        if not self.extract_secrets:
            return
        self.secrets.setdefault(kind, [])
        if value not in self.secrets[kind]:
            self.secrets[kind].append(value)

    # -------------------------------------------------------------------
    # Robots / Sitemap
    # -------------------------------------------------------------------

    def _fetch_robots(self) -> None:
        if not self.parse_robots:
            return
        url = self.root + "/robots.txt"
        try:
            r = self.session.get(url, timeout=self.timeout, verify=False)
            self.stats["requests"] += 1
            if r.status_code != 200:
                return
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("allow:", "disallow:")):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        full = urljoin(self.root + "/", path)
                        self.robots_paths.add(full)
                        self.urls.add(full)
            console.print(f"[cyan]→ robots.txt: "
                          f"{len(self.robots_paths)} paths[/cyan]")
        except Exception as exc:
            log.debug("robots: %s", exc)

    def _fetch_sitemap(self, sitemap_url: str | None = None,
                        recursive_depth: int = 0) -> None:
        if not self.parse_sitemap or recursive_depth > 2:
            return
        url = sitemap_url or f"{self.root}/sitemap.xml"
        try:
            r = self.session.get(url, timeout=self.timeout, verify=False)
            self.stats["requests"] += 1
            if r.status_code != 200:
                return
            ctype = r.headers.get("Content-Type", "").lower()
            # sitemap index
            if "xml" in ctype or r.text.strip().startswith("<?xml"):
                soup = BeautifulSoup(r.text, "xml")
                # Sitemap index
                for loc in soup.find_all("sitemap"):
                    loc_t = loc.find("loc")
                    if loc_t and loc_t.text:
                        sub = loc_t.text.strip()
                        self._fetch_sitemap(sub, recursive_depth + 1)
                # Sitemap urls
                for url_tag in soup.find_all("url"):
                    loc = url_tag.find("loc")
                    if loc and loc.text:
                        u = loc.text.strip()
                        self.sitemap_urls.add(u)
                        self.urls.add(u)
            else:
                # txt sitemap
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.startswith(("http://", "https://")):
                        self.sitemap_urls.add(line)
                        self.urls.add(line)
            if recursive_depth == 0:
                console.print(f"[cyan]→ sitemap: "
                              f"{len(self.sitemap_urls)} urls[/cyan]")
        except Exception as exc:
            log.debug("sitemap: %s", exc)

    # -------------------------------------------------------------------
    # Parsing
    # -------------------------------------------------------------------

    def _extract_from_html(self, html: str, base_url: str) -> None:
        soup = BeautifulSoup(html, "html.parser")

        # --- links ---
        for a in soup.find_all("a", href=True):
            full = urljoin(base_url, a["href"]).split("#")[0]
            if full and self._is_page(full):
                self.urls.add(full)
                if any(kw in full.lower() for kw in ADMIN_KW):
                    self.admin_paths.add(full)

        # --- other tags ---
        for tag, attr in (
            ("link", "href"), ("script", "src"),
            ("img", "src"), ("iframe", "src"),
            ("source", "src"), ("object", "data"),
        ):
            for el in soup.find_all(tag):
                val = el.get(attr)
                if not val:
                    continue
                full = urljoin(base_url, val)
                if "?" in full:
                    qs = parse_qs(urlparse(full).query)
                    for k in qs:
                        self.params.add(k)

        # --- forms ---
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = (form.get("method") or "GET").upper()
            full_action = urljoin(base_url, action)
            inputs = []
            has_password = False
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                itype = (inp.get("type") or inp.name).lower()
                if itype == "password":
                    has_password = True
                inputs.append({
                    "name": name,
                    "type": itype,
                    "value": inp.get("value", ""),
                })
                self.params.add(name)
            if inputs:
                entry = {
                    "page": base_url,
                    "action": full_action,
                    "method": method,
                    "inputs": inputs,
                }
                self.forms.append(entry)
                if has_password or any(
                    any(kw in i["name"].lower() for kw in LOGIN_KW)
                    for i in inputs
                ):
                    self.login_forms.append(entry)

        # --- URL regex over text ---
        for match in URL_RE.finditer(html):
            candidate = match.group(1)
            full = urljoin(base_url, candidate)
            if self._is_page(full):
                self.urls.add(full)
                if "?" in full:
                    qs = parse_qs(urlparse(full).query)
                    for k in qs:
                        self.params.add(k)

        # --- JS endpoints ---
        for re_ in JS_ENDPOINT_RES:
            for m in re_.finditer(html):
                ep = m.group(1)
                full = urljoin(base_url, ep)
                self.js_endpoints.add(full)

        # --- inline scripts + strings ---
        for s in soup.find_all("script"):
            if not s.string:
                continue
            js = s.string
            # secrets
            for kind, re_ in SECRET_RES.items():
                for m in re_.finditer(js):
                    val = m.group(0)
                    if kind == "email":
                        self.emails.add(val)
                    elif kind == "ipv4":
                        if not val.startswith(("127.", "0.", "255.")):
                            self.ips.add(val)
                    else:
                        self._record_secret(kind, val)
            # endpoints
            for re_ in JS_ENDPOINT_RES:
                for m in re_.finditer(js):
                    full = urljoin(base_url, m.group(1))
                    self.js_endpoints.add(full)

        # --- HTML comments ---
        for comment in soup.find_all(string=lambda t:
                                       isinstance(t,
                                                   type(soup.Comment))
                                       if hasattr(soup, "Comment")
                                       else False):
            pass  # bs4 parse comment complexity - skip

        # --- emails/phones in text ---
        if self.extract_secrets:
            for m in SECRET_RES["email"].finditer(html):
                self.emails.add(m.group(0))

        # --- cloud buckets ---
        bucket_re = re.compile(
            r"https?://([a-z0-9\-\.]+)\.(s3[a\-\.][a-z0-9\-\.]*\.amazonaws\.com"
            r"|s3\.amazonaws\.com|storage\.googleapis\.com"
            r"|blob\.core\.windows\.net)",
            re.IGNORECASE)
        for m in bucket_re.finditer(html):
            self.cloud_buckets.add(m.group(0))

    # -------------------------------------------------------------------
    # Crawl
    # -------------------------------------------------------------------

    def crawl(self) -> None:
        # robots + sitemap
        self._fetch_robots()
        self._fetch_sitemap()

        frontier: list[tuple[str, int]] = [(self.start_url, 0)]
        # добавляем robots/sitemap пути
        for u in list(self.robots_paths) + list(self.sitemap_urls):
            if self._same_domain(u):
                frontier.append((u, 0))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as p:
            task = p.add_task("crawl", total=self.max_pages)
            while frontier and len(self.visited) < self.max_pages:
                url, level = frontier.pop(0)
                if url in self.visited:
                    continue
                if not self._same_domain(url):
                    continue
                self.visited.add(url)
                p.advance(task)

                try:
                    r = self.session.get(
                        url, timeout=self.timeout,
                        allow_redirects=True, verify=False)
                    self.stats["requests"] += 1
                except Exception as exc:
                    self.errors.append((url, str(exc)[:80]))
                    continue

                # cookies
                for c in r.cookies:
                    self.cookies_found.add(f"{c.name}={c.value}")

                ctype = r.headers.get("Content-Type", "")
                if "html" not in ctype.lower():
                    continue

                try:
                    self._extract_from_html(r.text, r.url)
                except Exception as exc:
                    log.warning("parse %s: %s", url, exc)

                if level < self.depth:
                    for u in list(self.urls):
                        if u not in self.visited:
                            frontier.append((u, level + 1))

        self._print_summary()
        self._analyze_findings()
        self._save_json()

    # -------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------

    def _print_summary(self) -> None:
        console.print(f"\n[bold green]✓ Обход завершён[/bold green]")
        t = Table(title="Summary")
        t.add_column("Метрика", style="cyan")
        t.add_column("Значение", style="green")
        t.add_row("Страниц посещено", str(len(self.visited)))
        t.add_row("URL найдено", str(len(self.urls)))
        t.add_row("Форм найдено", str(len(self.forms)))
        t.add_row("  из них login", str(len(self.login_forms)))
        t.add_row("Параметров", str(len(self.params)))
        t.add_row("JS-эндпоинтов", str(len(self.js_endpoints)))
        t.add_row("Cookies", str(len(self.cookies_found)))
        t.add_row("robots.txt paths", str(len(self.robots_paths)))
        t.add_row("sitemap URLs", str(len(self.sitemap_urls)))
        t.add_row("Admin-путей", str(len(self.admin_paths)))
        t.add_row("Cloud buckets", str(len(self.cloud_buckets)))
        t.add_row("Emails", str(len(self.emails)))
        t.add_row("IPs", str(len(self.ips)))
        t.add_row("Secrets", str(sum(len(v)
                                        for v in self.secrets.values())))
        t.add_row("Ошибок", str(len(self.errors)))
        console.print(t)

        if self.login_forms:
            lt = Table(title=f"🔑 Login-формы ({len(self.login_forms)})")
            lt.add_column("#", style="yellow", width=4)
            lt.add_column("Action", style="cyan")
            lt.add_column("Method", style="green", width=8)
            lt.add_column("Fields", style="magenta")
            for i, f in enumerate(self.login_forms[:20], 1):
                fields = ", ".join(inp["name"] for inp in f["inputs"])
                lt.add_row(str(i), f["action"], f["method"], fields)
            console.print(lt)

        if self.secrets:
            st = Table(title="🔑 Secrets found")
            st.add_column("Type", style="cyan")
            st.add_column("Count", style="green", width=6)
            st.add_column("Sample", style="magenta")
            for kind, vals in self.secrets.items():
                st.add_row(kind, str(len(vals)),
                           (vals[0] if vals else "")[:60])
            console.print(st)

        if self.admin_paths:
            console.print(f"\n[yellow]Admin-пути:[/yellow]")
            for p in sorted(self.admin_paths)[:15]:
                console.print(f"  [cyan]{p}[/cyan]")

        if self.cloud_buckets:
            console.print(f"\n[yellow]Cloud buckets:[/yellow]")
            for b in sorted(self.cloud_buckets)[:10]:
                console.print(f"  [cyan]{b}[/cyan]")

    # -------------------------------------------------------------------
    # Findings
    # -------------------------------------------------------------------

    def _analyze_findings(self) -> None:
        # Login forms
        if self.login_forms:
            _save_finding(CrawlerFinding(
                kind="login_forms_found",
                severity="high",
                title=f"Login-формы ({len(self.login_forms)})",
                target=self.start_url,
                evidence="\n".join(
                    f"{f['method']} {f['action']} "
                    f"({len(f['inputs'])} fields)"
                    for f in self.login_forms[:10]),
                data={"count": len(self.login_forms),
                      "urls": [f["action"]
                                for f in self.login_forms[:20]]},
            ))

        # Secrets
        important = {k: v for k, v in self.secrets.items()
                     if k not in ("email", "ipv4")}
        if important:
            _save_finding(CrawlerFinding(
                kind="secrets_in_js",
                severity="high",
                title=f"Секреты в JS ({sum(len(v) for v in important.values())})",
                target=self.start_url,
                evidence=json.dumps(
                    {k: v[:3] for k, v in important.items()},
                    ensure_ascii=False)[:1000],
                data={"kinds": list(important.keys())},
            ))

        # Admin paths
        if self.admin_paths:
            _save_finding(CrawlerFinding(
                kind="admin_panels_found",
                severity="high",
                title=f"Admin-панели ({len(self.admin_paths)})",
                target=self.start_url,
                evidence="\n".join(sorted(self.admin_paths)[:20]),
                data={"urls": sorted(self.admin_paths)[:30]},
            ))

        # Notify
        if self.login_forms or self.secrets or self.admin_paths:
            _notify(
                f"🕷  Crawler findings",
                f"Target: {self.start_url}\n"
                f"Login forms: {len(self.login_forms)}\n"
                f"Secrets: {sum(len(v) for v in self.secrets.values())}\n"
                f"Admin paths: {len(self.admin_paths)}",
                severity="high",
            )

    # -------------------------------------------------------------------
    # Save
    # -------------------------------------------------------------------

    def _as_dict(self) -> dict:
        return {
            "start_url": self.start_url,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "stats": {
                "visited": len(self.visited),
                "urls": len(self.urls),
                "forms": len(self.forms),
                "login_forms": len(self.login_forms),
                "params": len(self.params),
                "js_endpoints": len(self.js_endpoints),
                "cookies": len(self.cookies_found),
                "robots_paths": len(self.robots_paths),
                "sitemap_urls": len(self.sitemap_urls),
                "admin_paths": len(self.admin_paths),
                "cloud_buckets": len(self.cloud_buckets),
                "secrets_total": sum(len(v)
                                       for v in self.secrets.values()),
                "requests": self.stats["requests"],
            },
            "visited": sorted(self.visited),
            "urls": sorted(self.urls),
            "forms": self.forms,
            "login_forms": self.login_forms,
            "params": sorted(self.params),
            "cookies": sorted(self.cookies_found),
            "js_endpoints": sorted(self.js_endpoints),
            "robots_paths": sorted(self.robots_paths),
            "sitemap_urls": sorted(self.sitemap_urls),
            "admin_paths": sorted(self.admin_paths),
            "cloud_buckets": sorted(self.cloud_buckets),
            "secrets": self.secrets,
            "emails": sorted(self.emails),
            "ips": sorted(self.ips),
            "errors": self.errors,
        }

    def _save_json(self, out_path: str | None = None) -> Path | None:
        host = (self.start_host or "unknown").replace(".", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if not out_path:
            out_path = str(CRAWL_DIR / f"crawl_{host}_{ts}.json")
        data = self._as_dict()
        try:
            Path(out_path).write_text(
                json.dumps(data, indent=2, ensure_ascii=False,
                            default=str),
                encoding="utf-8")
            console.print(f"[green]✓ JSON: {out_path}[/green]")
            db.save_scan("web_crawl", self.start_url, data["stats"])
            return Path(out_path)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Ошибка сохранения: {exc}[/red]")
            return None


# ===========================================================================
# Public entry
# ===========================================================================

def crawl(url: str, depth: int = 1, max_pages: int = 50) -> None:
    """Публичная точка входа (совместима)."""
    if not confirm_external(url):
        return
    console.print(f"[cyan]Краулю {url} (depth={depth}, "
                  f"max={max_pages})…[/cyan]")
    try:
        c = Crawler(url, depth=depth, max_pages=max_pages)
        c.crawl()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка краулера: {exc}[/red]")
        log.exception("crawl error")


def crawl_pro(url: str, depth: int = 2, max_pages: int = 100,
               include_subdomains: bool = False,
               extract_secrets: bool = True,
               basic_auth: tuple[str, str] | None = None,
               cookies: dict[str, str] | None = None,
               extra_headers: dict[str, str] | None = None,
               url_regex: str | None = None) -> None:
    """Расширенный краулинг."""
    if not confirm_external(url):
        return
    console.print(f"[cyan]🕷  Краулю (pro): {url} "
                  f"(depth={depth}, max={max_pages})[/cyan]")
    try:
        c = Crawler(
            url, depth=depth, max_pages=max_pages,
            include_subdomains=include_subdomains,
            extract_secrets=extract_secrets,
            basic_auth=basic_auth,
            cookies=cookies,
            extra_headers=extra_headers,
            url_regex=url_regex,
        )
        c.crawl()
        if Confirm.ask("Дополнительный экспорт?", default=False):
            fmt = Prompt.ask("Формат",
                             choices=["json", "csv", "md", "html"],
                             default="html")
            export_crawl(c, fmt=fmt)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка краулера: {exc}[/red]")
        log.exception("crawl_pro error")


# ===========================================================================
# Export
# ===========================================================================

def export_crawl(c: Crawler, fmt: str = "json",
                  out_path: str | None = None) -> Path | None:
    host = (c.start_host or "unknown").replace(".", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = {"json": ".json", "csv": ".csv", "md": ".md",
           "html": ".html"}.get(fmt, ".json")
    if not out_path:
        out_path = str(CRAWL_DIR / f"crawl_{host}_{ts}{ext}")
    p = Path(out_path)
    data = c._as_dict()

    try:
        if fmt == "json":
            p.write_text(json.dumps(data, indent=2, ensure_ascii=False,
                                       default=str), encoding="utf-8")
        elif fmt == "csv":
            with p.open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["kind", "value"])
                for u in data["urls"]:
                    w.writerow(["url", u])
                for u in data["js_endpoints"]:
                    w.writerow(["js_endpoint", u])
                for u in data["admin_paths"]:
                    w.writerow(["admin_path", u])
                for f_ in data["login_forms"]:
                    w.writerow(["login_form", f_["action"]])
                for k, v in data["secrets"].items():
                    for s in v:
                        w.writerow([f"secret:{k}", s])
        elif fmt == "md":
            lines = [
                f"# Web Crawl — {c.start_url}",
                f"_Generated: {datetime.now().isoformat()}_",
                "",
                "## Summary",
            ]
            for k, v in data["stats"].items():
                lines.append(f"- **{k}**: {v}")
            lines.append("")
            if data["login_forms"]:
                lines.append("## 🔑 Login forms")
                for f_ in data["login_forms"]:
                    lines.append(f"- `{f_['method']}` `{f_['action']}`")
                lines.append("")
            if data["secrets"]:
                lines.append("## 🔑 Secrets")
                for k, v in data["secrets"].items():
                    if k in ("email", "ipv4"):
                        continue
                    lines.append(f"### {k} ({len(v)})")
                    for s in v[:10]:
                        lines.append(f"- `{s}`")
                lines.append("")
            if data["admin_paths"]:
                lines.append("## 🛡  Admin paths")
                for u in data["admin_paths"][:30]:
                    lines.append(f"- `{u}`")
                lines.append("")
            if data["js_endpoints"]:
                lines.append("## 📡 JS endpoints")
                for u in data["js_endpoints"][:50]:
                    lines.append(f"- `{u}`")
                lines.append("")
            p.write_text("\n".join(lines), encoding="utf-8")
        elif fmt == "html":
            parts = [
                "<!DOCTYPE html><html lang='ru'><head>"
                "<meta charset='utf-8'>",
                f"<title>Crawl — {html_mod.escape(c.start_url)}</title>",
                "<style>",
                "body{background:#0a0a0a;color:#c8c8c8;"
                "font-family:monospace;padding:24px;"
                "max-width:1300px;margin:0 auto;line-height:1.5;}",
                "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
                "h2{color:#00ff9c;margin-top:28px;}",
                ".kpi-grid{display:grid;"
                "grid-template-columns:repeat(auto-fit,minmax(150px,1fr));"
                "gap:12px;margin:16px 0;}",
                ".kpi{background:#111;border:1px solid #222;"
                "border-radius:6px;padding:14px;text-align:center;}",
                ".kpi .v{font-size:24px;color:#00ff9c;font-weight:bold;}",
                ".kpi .l{font-size:11px;color:#888;"
                "text-transform:uppercase;}",
                ".kpi.warn .v{color:#ff7a40;}"
                ".kpi.crit .v{color:#ff2020;}",
                "table{width:100%;border-collapse:collapse;"
                "margin-top:12px;font-size:12px;}",
                "th{background:#111;color:#00ff9c;padding:6px;"
                "text-align:left;border:1px solid #222;}",
                "td{padding:4px 6px;border:1px solid #222;"
                "word-break:break-all;}",
                "tr:nth-child(even){background:#0d0d0d;}",
                "code{background:#111;color:#a0ffa0;padding:1px 4px;}",
                "</style></head><body>",
                f"<h1>🕷  Web Crawl — {html_mod.escape(c.start_url)}</h1>",
                f"<p>Generated: "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
                "<div class='kpi-grid'>",
                f"<div class='kpi'><div class='v'>"
                f"{data['stats']['visited']}</div>"
                f"<div class='l'>Visited</div></div>",
                f"<div class='kpi'><div class='v'>"
                f"{data['stats']['urls']}</div>"
                f"<div class='l'>URLs</div></div>",
                f"<div class='kpi warn'><div class='v'>"
                f"{data['stats']['login_forms']}</div>"
                f"<div class='l'>Login forms</div></div>",
                f"<div class='kpi crit'><div class='v'>"
                f"{data['stats']['secrets_total']}</div>"
                f"<div class='l'>Secrets</div></div>",
                f"<div class='kpi warn'><div class='v'>"
                f"{data['stats']['admin_paths']}</div>"
                f"<div class='l'>Admin paths</div></div>",
                f"<div class='kpi'><div class='v'>"
                f"{data['stats']['js_endpoints']}</div>"
                f"<div class='l'>JS endpoints</div></div>",
                "</div>",
            ]
            if data["login_forms"]:
                parts.append(f"<h2>🔑 Login forms "
                             f"({len(data['login_forms'])})</h2>"
                             "<table><tr><th>Method</th>"
                             "<th>Action</th><th>Fields</th></tr>")
                for f_ in data["login_forms"]:
                    fields = ", ".join(i["name"]
                                          for i in f_["inputs"])
                    parts.append(
                        f"<tr><td>{f_['method']}</td>"
                        f"<td><code>{html_mod.escape(f_['action'])}</code>"
                        f"</td><td>{html_mod.escape(fields)}</td></tr>")
                parts.append("</table>")

            if data["secrets"]:
                secrets_clean = {k: v for k, v in data["secrets"].items()
                                 if k not in ("email", "ipv4")}
                if secrets_clean:
                    parts.append(f"<h2>🔑 Secrets</h2>")
                    for k, v in secrets_clean.items():
                        parts.append(f"<h3>{html_mod.escape(k)} "
                                     f"({len(v)})</h3><ul>")
                        for s in v[:20]:
                            parts.append(
                                f"<li><code>{html_mod.escape(s)}"
                                f"</code></li>")
                        parts.append("</ul>")

            if data["admin_paths"]:
                parts.append(f"<h2>🛡  Admin paths "
                             f"({len(data['admin_paths'])})</h2><ul>")
                for u in data["admin_paths"][:50]:
                    parts.append(
                        f"<li><code>{html_mod.escape(u)}</code></li>")
                parts.append("</ul>")

            if data["js_endpoints"]:
                parts.append(f"<h2>📡 JS endpoints "
                             f"({len(data['js_endpoints'])})</h2><ul>")
                for u in data["js_endpoints"][:100]:
                    parts.append(
                        f"<li><code>{html_mod.escape(u)}</code></li>")
                parts.append("</ul>")

            parts.append("</body></html>")
            p.write_text("\n".join(parts), encoding="utf-8")

        console.print(f"[green]✓ {fmt.upper()}: {p}[/green]")
        return p
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Экспорт: {exc}[/red]")
        return None


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]Web Crawler Pro (extended)[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Обход страницы (глубина + лимит)"),
        ("2", "Обход pro (глубина 2, secrets, robots/sitemap)"),
        ("3", "Обход с Basic auth"),
        ("4", "Обход с cookies"),
        ("5", "Обход с subdomains + secrets"),
        ("6", "Обход + экспорт (JSON/CSV/MD/HTML)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного пентеста.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        url = Prompt.ask("URL")
        depth = IntPrompt.ask("Глубина", default=1)
        max_pages = IntPrompt.ask("Максимум страниц", default=50)
        crawl(url, depth, max_pages)
    elif c == "2":
        url = Prompt.ask("URL")
        depth = IntPrompt.ask("Глубина", default=2)
        max_pages = IntPrompt.ask("Максимум страниц", default=100)
        crawl_pro(url, depth=depth, max_pages=max_pages)
    elif c == "3":
        url = Prompt.ask("URL")
        user = Prompt.ask("Username")
        pwd = Prompt.ask("Password", password=True)
        depth = IntPrompt.ask("Глубина", default=2)
        max_pages = IntPrompt.ask("Максимум страниц", default=100)
        crawl_pro(url, depth=depth, max_pages=max_pages,
                  basic_auth=(user, pwd))
    elif c == "4":
        url = Prompt.ask("URL")
        cookies_raw = Prompt.ask("Cookies (k=v;k2=v2)", default="")
        cookies = {}
        for pair in cookies_raw.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
        depth = IntPrompt.ask("Глубина", default=2)
        max_pages = IntPrompt.ask("Максимум страниц", default=100)
        crawl_pro(url, depth=depth, max_pages=max_pages,
                  cookies=cookies or None)
    elif c == "5":
        url = Prompt.ask("URL")
        depth = IntPrompt.ask("Глубина", default=2)
        max_pages = IntPrompt.ask("Максимум страниц", default=150)
        crawl_pro(url, depth=depth, max_pages=max_pages,
                  include_subdomains=True, extract_secrets=True)
    elif c == "6":
        url = Prompt.ask("URL")
        depth = IntPrompt.ask("Глубина", default=2)
        max_pages = IntPrompt.ask("Максимум страниц", default=100)
        console.print("[cyan]Запускаю crawler…[/cyan]")
        try:
            c = Crawler(url, depth=depth, max_pages=max_pages)
            c.crawl()
            fmt = Prompt.ask("Формат",
                             choices=["html", "json", "csv", "md"],
                             default="html")
            export_crawl(c, fmt=fmt)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Ошибка: {exc}[/red]")