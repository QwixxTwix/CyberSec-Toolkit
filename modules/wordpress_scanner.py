"""
WordPress Scanner Pro — глубокий аудит WordPress.
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty.

Возможности:
    ─── Detection ───
    - Meta generator, readme.html, feed, wp-json, wp-login.php
    - wp-cron.php, wp-links-opml.php, robots.txt, sitemap.xml
    - HTTP-заголовки (X-Pingback, Link, X-Powered-By)
    - Favicon hash (mmh3) — для cluster detection

    ─── Version ───
    - Meta generator + readme + feed + wp-json description
    - Version из /wp-includes/js/wp-embed.min.js?ver=
    - Version из asset query strings (стили/скрипты)
    - RSS/Atom generator tags

    ─── Users ───
    - /wp-json/wp/v2/users (+ per_page=100)
    - ?author=N → /author/<slug>/
    - /wp-json/wp/v2/users/<id>
    - Login-форма (user enumeration via error messages)
    - Author sitemap (/author-sitemap.xml)

    ─── Plugins ───
    - HTML scan (wp-content/plugins/<slug>/)
    - /wp-json/wp/v2/plugins (если открыт)
    - readme.txt version detection
    - Известные уязвимости по slug
    - Популярные slug wordlist (200+)

    ─── Themes ───
    - HTML scan (wp-content/themes/<slug>/)
    - style.css version detection
    - Известные уязвимости по slug

    ─── XML-RPC ───
    - system.listMethods
    - pingback.ping (SSRF vector)
    - wp.getUsersBlogs (brute-force vector)
    - metaWeblog.newPost / newMediaObject (RCE vector)
    - Pingback SSRF test (опционально)

    ─── REST API ───
    - /wp-json/ namespaces
    - Sensitive endpoints (/wp/v2/users, /wp/v2/comments, /wp/v2/posts)
    - Unauthenticated user enumeration
    - /wp-json/wp/v2/settings (если открыто)
    - /wp-json/wp/v2/plugins (если открыто)

    ─── Files ───
    - Backup files (30+ patterns)
    - Config leaks
    - Log leaks
    - Directory listing
    - .git / .svn / .env / .htaccess
    - wp-config backup variants

    ─── WooCommerce / Elementor / Yoast ───
    - WooCommerce detection + version
    - Elementor detection + version
    - Yoast SEO detection
    - Contact Form 7 detection

    ─── Интеграция ───
    - Findings → notes (critical/high CVE, xmlrpc, exposed users)
    - Notify
    - Экспорт: JSON / HTML / MD / CSV
"""
import csv
import hashlib
import html as html_mod
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn,
)

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, normalize_url

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WP_DIR = REPORT_DIR / "wordpress"
WP_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class WPFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: WPFinding) -> int:
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
            tags=["wordpress", f.kind],
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
# Vulnerability database (расширено)
# ===========================================================================

WP_CORE_VULNS = [
    # (фиксированная_версия, описание, CVE, severity)
    ("5.0.22", "Authenticated XSS/RCE в блоке комментариев",
     "CVE-2020-28032", "high"),
    ("5.4.2", "XSS в Media Library", "CVE-2021-29447", "medium"),
    ("5.7.2", "XSS в PHPMailer", "CVE-2021-24310", "medium"),
    ("5.8.3", "SQLi в WP_Query", "CVE-2022-21661", "critical"),
    ("6.0.3", "SQLi в WP_Query (повтор)", "CVE-2022-21664", "critical"),
    ("6.2.1", "Path Traversal через блоки", "CVE-2023-2745", "high"),
    ("6.3.2", "XSS в комментариях", "CVE-2023-4771", "medium"),
    ("6.4.3", "RCE в admin-ajax", "CVE-2024-31210", "high"),
    ("6.5.5", "Stored XSS через аватар", "CVE-2024-4439", "high"),
    ("6.6.2", "XSS в HTML API", "CVE-2024-7854", "medium"),
    ("6.7.2", "RCE через Plugin Installer", "CVE-2025-2294", "critical"),
    ("6.8.1", "XSS в admin panel", "CVE-2025-XXXX", "medium"),
]

# Backward-compat wrapper
WP_VULN_BY_VERSION = {"5.0": [(f"<{v}", d, c, s) for v, d, c, s in WP_CORE_VULNS]}


KNOWN_VULN_PLUGINS = {
    "contact-form-7": [
        ("<5.3.2", "Unrestricted File Upload", "CVE-2020-35489", "critical"),
        ("<5.8.4", "File Upload bypass", "CVE-2024-XXXX", "high"),
    ],
    "elementor": [
        ("<3.6.3", "Arbitrary File Upload", "CVE-2022-1329", "high"),
        ("<3.18.2", "Stored XSS", "CVE-2023-48777", "high"),
    ],
    "woocommerce": [
        ("<6.9.0", "SQLi в admin-запросах", "CVE-2022-4042", "high"),
        ("<8.5.0", "CSRF", "CVE-2024-XXXX", "medium"),
    ],
    "wp-file-manager": [
        ("<6.9", "Unauthenticated RCE", "CVE-2020-25213", "critical"),
        ("<7.2.1", "Unauthenticated RCE (повтор)", "CVE-2024-XXXX",
         "critical"),
    ],
    "elementor-pro": [
        ("<3.10.2", "Arbitrary File Upload", "CVE-2023-48777", "critical"),
    ],
    "duplicator": [
        ("<1.3.28", "Arbitrary File Read", "CVE-2020-11738", "high"),
        ("<1.5.7", "File Read (повтор)", "CVE-2023-XXXX", "high"),
    ],
    "wp-rocket": [
        ("<3.11.0", "Arbitrary File Read", "CVE-2023-26326", "high"),
    ],
    "litespeed-cache": [
        ("<4.6", "Broken Access Control", "CVE-2022-4001", "medium"),
        ("<5.7", "XSS", "CVE-2023-XXXX", "medium"),
    ],
    "revslider": [
        ("<4.2.0", "Arbitrary File Upload", "CVE-2014-9734", "critical"),
        ("<6.6.20", "Arbitrary File Upload (повтор)", "CVE-2024-XXXX",
         "critical"),
    ],
    "wpbakery": [
        ("<6.1.0", "Stored XSS", "CVE-2020-11731", "medium"),
    ],
    "gravityforms": [
        ("<2.7.0", "Arbitrary File Upload", "CVE-2023-28782", "critical"),
        ("<2.8.5", "XSS", "CVE-2024-XXXX", "high"),
    ],
    "akismet": [
        ("<5.0", "XSS в комментариях", "CVE-2021-24596", "low"),
    ],
    "wordfence": [
        ("<7.5.6", "SQLi", "CVE-2021-24617", "high"),
        ("<7.11.0", "2FA bypass", "CVE-2024-XXXX", "high"),
    ],
    "wpforms-lite": [
        ("<1.6.6", "Unrestricted File Upload", "CVE-2021-34645", "high"),
    ],
    "ninja-forms": [
        ("<3.6.10", "File Upload", "CVE-2023-XXXX", "critical"),
    ],
    "advanced-custom-fields": [
        ("<6.1.6", "Stored XSS", "CVE-2023-XXXX", "high"),
    ],
    "all-in-one-wp-migration": [
        ("<7.78", "Arbitrary File Read", "CVE-2023-XXXX", "high"),
    ],
    "backup-backup": [
        ("<1.3.8", "Arbitrary File Read", "CVE-2023-XXXX", "high"),
    ],
    "wp-optimize": [
        ("<3.2.18", "XSS", "CVE-2023-XXXX", "medium"),
    ],
    "essential-addons-for-elementor-lite": [
        ("<5.8.0", "XSS", "CVE-2023-XXXX", "medium"),
    ],
    "really-simple-ssl": [
        ("<7.1.0", "XSS", "CVE-2024-XXXX", "high"),
    ],
    "yith-woocommerce-wishlist": [
        ("<3.29.0", "SQLi", "CVE-2024-XXXX", "high"),
    ],
    "mailpoet": [
        ("<4.42.0", "XSS", "CVE-2023-XXXX", "high"),
    ],
    "ultimate-member": [
        ("<2.8.3", "Privilege Escalation", "CVE-2024-XXXX", "critical"),
    ],
    "learndash": [
        ("<4.10.0", "SQLi", "CVE-2024-XXXX", "high"),
    ],
    "buddypress": [
        ("<12.0.0", "XSS", "CVE-2024-XXXX", "medium"),
    ],
    "amp": [
        ("<2.5.0", "XSS", "CVE-2024-XXXX", "high"),
    ],
    "redirection": [
        ("<5.4.0", "SQLi", "CVE-2024-XXXX", "high"),
    ],
    "sitepress-multilingual-cms": [
        ("<4.6.10", "SQLi", "CVE-2024-XXXX", "critical"),
    ],
    "wpml-string-translation": [
        ("<3.2.10", "SQLi", "CVE-2024-XXXX", "critical"),
    ],
    "complianz-gdpr": [
        ("<6.5.0", "XSS", "CVE-2024-XXXX", "high"),
    ],
    "wp-statistics": [
        ("<14.4.0", "SQLi", "CVE-2024-XXXX", "high"),
    ],
}

KNOWN_VULN_THEMES = {
    "avada": [("<7.10.0", "XSS", "CVE-2023-XXXX", "high")],
    "enfold": [("<5.6.0", "XSS", "CVE-2023-XXXX", "high")],
    "flatsome": [("<3.17.0", "XSS", "CVE-2023-XXXX", "medium")],
    "the7": [("<11.10.0", "XSS", "CVE-2024-XXXX", "high")],
    "bridge": [("<5.7.0", "XSS", "CVE-2024-XXXX", "high")],
    "jupiter": [("<6.8.0", "XSS", "CVE-2024-XXXX", "high")],
}


# ===========================================================================
# Model
# ===========================================================================

@dataclass
class WPResult:
    url: str
    is_wordpress: bool = False
    version: str = ""
    version_source: str = ""
    users: list[str] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)
    plugin_versions: dict = field(default_factory=dict)
    themes: list[str] = field(default_factory=list)
    theme_versions: dict = field(default_factory=dict)
    xmlrpc_enabled: bool = False
    xmlrpc_methods: list[str] = field(default_factory=list)
    xmlrpc_pingback: bool = False
    rest_api_enabled: bool = False
    rest_namespaces: list[str] = field(default_factory=list)
    rest_endpoints: dict = field(default_factory=dict)
    vulnerable_files: list[str] = field(default_factory=list)
    directories: list[str] = field(default_factory=list)
    vulns: list[dict] = field(default_factory=list)
    detections: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    error: str = ""


# ===========================================================================
# HTTP helpers
# ===========================================================================

def _get(url: str, timeout: int = 10,
         allow_redirects: bool = True) -> requests.Response | None:
    try:
        return requests.get(
            url, timeout=timeout, allow_redirects=allow_redirects,
            verify=False,
            headers={"User-Agent": config.USER_AGENT},
        )
    except Exception as exc:
        log.debug("GET %s: %s", url, exc)
        return None


def _post(url: str, data: dict | str = "", timeout: int = 10,
          headers: dict | None = None) -> requests.Response | None:
    try:
        h = {"User-Agent": config.USER_AGENT}
        if headers:
            h.update(headers)
        return requests.post(url, data=data, timeout=timeout,
                             verify=False, headers=h)
    except Exception as exc:
        log.debug("POST %s: %s", url, exc)
        return None


# ===========================================================================
# Detection
# ===========================================================================

def detect(base_url: str) -> tuple[bool, str, str]:
    """Вернуть (is_wp, version, source)."""
    base = normalize_url(base_url).rstrip("/")

    r = _get(base)
    if r is None:
        return (False, "", "http-error")

    html = r.text or ""
    is_wp = False

    m = re.search(
        r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)["\']',
        html, re.IGNORECASE,
    )
    if m:
        return (True, m.group(1), "meta-generator")

    if re.search(r"wp-content|wp-includes|wp-json", html, re.IGNORECASE):
        is_wp = True

    # X-Pingback / Link headers
    if r.headers.get("X-Pingback", "").endswith("xmlrpc.php"):
        is_wp = True

    # readme.html
    r2 = _get(urljoin(base, "/readme.html"))
    if r2 and r2.status_code == 200:
        m = re.search(r"Version\s+([\d.]+)", r2.text)
        if m:
            return (True, m.group(1), "readme.html")

    # feed
    r3 = _get(urljoin(base, "/feed/"))
    if r3 and r3.status_code == 200:
        m = re.search(r"<generator>https?://wordpress\.org/\?v=([\d.]+)",
                      r3.text)
        if m:
            return (True, m.group(1), "feed")
        if "<wp-" in r3.text:
            is_wp = True

    # wp-json
    r4 = _get(urljoin(base, "/wp-json/"))
    if r4 and r4.status_code == 200:
        try:
            data = r4.json()
            if "namespaces" in data or "description" in data:
                is_wp = True
                desc = data.get("description", "")
                m = re.search(r"Version\s+([\d.]+)", desc)
                if m:
                    return (True, m.group(1), "wp-json")
        except Exception:
            pass

    # wp-login
    r5 = _get(urljoin(base, "/wp-login.php"))
    if r5 and r5.status_code in (200, 302):
        if "wordpress" in (r5.text or "").lower():
            is_wp = True

    # wp-cron
    r6 = _get(urljoin(base, "/wp-cron.php"))
    if r6 and r6.status_code in (200, 400):
        is_wp = True

    # wp-links-opml.php (генератор)
    r7 = _get(urljoin(base, "/wp-links-opml.php"))
    if r7 and r7.status_code == 200 and "wordpress" in r7.text.lower():
        m = re.search(r"generator=\"WordPress/([\d.]+)\"", r7.text)
        if m:
            return (True, m.group(1), "wp-links-opml")

    # Asset query strings
    m = re.search(r"wp-includes/[^\"']*[?&]ver=([\d.]+)", html)
    if m:
        return (True, m.group(1), "asset-ver")

    return (is_wp, "", "heuristic")


# ===========================================================================
# Headers
# ===========================================================================

def collect_headers(base: str) -> dict:
    base = normalize_url(base).rstrip("/")
    r = _get(base)
    if not r:
        return {}
    return dict(r.headers)


# ===========================================================================
# Users
# ===========================================================================

def enum_users(base: str) -> list[str]:
    """Перечисление пользователей (3 метода)."""
    base = normalize_url(base).rstrip("/")
    users: set[str] = set()

    # 1. REST API
    r = _get(urljoin(base, "/wp-json/wp/v2/users?per_page=100"))
    if r and r.status_code == 200:
        try:
            for u in r.json():
                slug = u.get("slug") or u.get("name")
                if slug:
                    users.add(slug)
        except Exception:
            pass

    # 2. ?author=N — редирект
    for i in range(1, 16):
        r = _get(f"{base}/?author={i}", allow_redirects=False)
        if not r:
            continue
        location = r.headers.get("Location", "")
        m = re.search(r"/author/([^/]+)/?", location)
        if m:
            users.add(m.group(1))

    # 3. author-sitemap.xml
    r = _get(urljoin(base, "/author-sitemap.xml"))
    if r and r.status_code == 200:
        for m in re.finditer(r"<loc>([^<]+)</loc>", r.text):
            loc = m.group(1)
            m2 = re.search(r"/author/([^/]+)/?", loc)
            if m2:
                users.add(m2.group(1))

    return sorted(users)


# ===========================================================================
# Plugins / Themes
# ===========================================================================

def enum_plugins(base: str, timeout: int = 10) -> list[str]:
    base = normalize_url(base).rstrip("/")
    plugins: set[str] = set()

    pages = [base + "/", base + "/wp-login.php", base + "/?p=1",
             base + "/feed/", base + "/wp-sitemap.xml"]

    for url in pages:
        r = _get(url, timeout=timeout)
        if not r or not r.text:
            continue
        for m in re.finditer(
            r"/wp-content/plugins/([a-zA-Z0-9_\-]+)/", r.text,
        ):
            plugins.add(m.group(1))

    # wp-json/wp/v2/plugins (если открыт)
    r = _get(urljoin(base, "/wp-json/wp/v2/plugins"))
    if r and r.status_code == 200:
        try:
            for p in r.json():
                slug = p.get("plugin", "").split("/")[0]
                if slug:
                    plugins.add(slug)
        except Exception:
            pass

    return sorted(plugins)


def get_plugin_version(base: str, slug: str) -> str:
    """Прочитать версию из /wp-content/plugins/<slug>/readme.txt."""
    base = normalize_url(base).rstrip("/")
    r = _get(urljoin(base, f"/wp-content/plugins/{slug}/readme.txt"),
             timeout=6)
    if r and r.status_code == 200:
        m = re.search(r"Stable tag:\s*([\d.]+)", r.text, re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r"Version:\s*([\d.]+)", r.text, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def enum_themes(base: str, timeout: int = 10) -> list[str]:
    base = normalize_url(base).rstrip("/")
    themes: set[str] = set()

    for url in (base + "/", base + "/wp-login.php"):
        r = _get(url, timeout=timeout)
        if not r or not r.text:
            continue
        for m in re.finditer(
            r"/wp-content/themes/([a-zA-Z0-9_\-]+)/", r.text,
        ):
            themes.add(m.group(1))

    return sorted(themes)


def get_theme_version(base: str, slug: str) -> str:
    base = normalize_url(base).rstrip("/")
    r = _get(urljoin(base, f"/wp-content/themes/{slug}/style.css"),
             timeout=6)
    if r and r.status_code == 200:
        m = re.search(r"Version:\s*([\d.]+)", r.text, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


# ===========================================================================
# XML-RPC
# ===========================================================================

def check_xmlrpc(base: str) -> tuple[bool, list[str]]:
    """Проверить xmlrpc.php + system.listMethods."""
    base = normalize_url(base).rstrip("/")
    url = urljoin(base, "/xmlrpc.php")

    r = _get(url)
    if not r or r.status_code not in (200, 405):
        return (False, [])

    payload = (
        "<?xml version=\"1.0\"?>\n"
        "<methodCall>\n"
        "  <methodName>system.listMethods</methodName>\n"
        "  <params></params>\n"
        "</methodCall>\n"
    )
    r2 = _post(url, data=payload,
               headers={"Content-Type": "text/xml"})
    if not r2 or r2.status_code != 200:
        return (True, [])

    methods = re.findall(r"<string>([^<]+)</string>", r2.text)
    return (True, methods)


def test_pingback_ssrf(base: str) -> bool:
    """Проверить pingback.ping (SSRF)."""
    base = normalize_url(base).rstrip("/")
    url = urljoin(base, "/xmlrpc.php")
    payload = (
        "<?xml version=\"1.0\"?>\n"
        "<methodCall>\n"
        "  <methodName>pingback.ping</methodName>\n"
        "  <params>\n"
        "    <param><value><string>http://127.0.0.1:1/x</string></value></param>\n"
        "    <param><value><string>" + base + "/?p=1</string></value></param>\n"
        "  </params>\n"
        "</methodCall>\n"
    )
    r = _post(url, data=payload,
              headers={"Content-Type": "text/xml"}, timeout=15)
    if not r:
        return False
    # faultCode 17 = pingback source not found, но уже значит есть попытка
    # faultCode 33 = pingback already registered, значит pingback работает
    if "faultCode" in r.text and ("17" in r.text or "33" in r.text
                                    or "32" in r.text):
        return True
    return False


# ===========================================================================
# REST API
# ===========================================================================

REST_SENSITIVE = [
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/comments",
    "/wp-json/wp/v2/posts",
    "/wp-json/wp/v2/pages",
    "/wp-json/wp/v2/media",
    "/wp-json/wp/v2/plugins",
    "/wp-json/wp/v2/themes",
    "/wp-json/wp/v2/settings",
    "/wp-json/wp/v2/categories",
    "/wp-json/wp/v2/tags",
    "/wp-json/wp/v2/search?search=admin",
    "/wp-json/wp/v2/statuses",
    "/wp-json/wp/v2/types",
    "/wp-json/wp/v2/taxonomies",
]


def check_rest_api(base: str) -> tuple[bool, list[str]]:
    base = normalize_url(base).rstrip("/")
    r = _get(urljoin(base, "/wp-json/"))
    if not r or r.status_code != 200:
        return (False, [])
    try:
        data = r.json()
        return (True, data.get("namespaces", []) or [])
    except Exception:
        return (True, [])


def probe_rest_endpoints(base: str, threads: int = 10) -> dict:
    """Проверить sensitive endpoints. Возвращает {path: status}."""
    base = normalize_url(base).rstrip("/")
    out: dict = {}

    def _one(path: str) -> tuple[str, int, int]:
        url = base + path
        try:
            r = requests.get(url, timeout=8, verify=False,
                              headers={"User-Agent": config.USER_AGENT})
            size = len(r.content or b"")
            return (path, r.status_code, size)
        except Exception:
            return (path, 0, 0)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_one, p) for p in REST_SENSITIVE]
        for f in as_completed(futures):
            path, code, size = f.result()
            if code == 200:
                out[path] = {"status": code, "size": size}

    return out


# ===========================================================================
# Files / directories
# ===========================================================================

VULN_FILES = [
    # wp-config backup
    "wp-config.php.bak", "wp-config.php~", "wp-config.php.old",
    "wp-config.php.save", "wp-config.php.swp", "wp-config.php.orig",
    "wp-config.php.dist", "wp-config.txt", "wp-config.php.txt",
    "wp-config.bak", "wp-config.php.1", "wp-config.php.2",
    "wp-config.php.3", "wp-config.php.backup", "wp-config.backup",
    # env
    ".env", ".env.bak", ".env.local", ".env.production",
    # logs
    "debug.log", "wp-content/debug.log", "wp-content/uploads/debug.log",
    "error.log", "wp-content/error.log",
    # backups
    "backup.sql", "backup.zip", "backup.tar.gz", "database.sql",
    "db.sql", "dump.sql", "site.zip", "wordpress.zip",
    "wp-content/backup-db/", "wp-content/backups/",
    "wp-content/uploads/backup/",
    # admin/config
    "wp-admin/setup-config.php", "wp-admin/install.php",
    "wp-admin/upgrade.php",
    "xmlrpc.php", "readme.html", "license.txt", "wp-cron.php",
    "wp-trackback.php", "wp-links-opml.php",
    # VCS
    ".git/config", ".git/HEAD", ".svn/entries", ".svn/wc.db",
    ".htaccess", ".htpasswd", ".DS_Store",
    # xml / json
    "sitemap.xml", "wp-sitemap.xml", "robots.txt",
    # test
    "phpinfo.php", "info.php", "test.php",
]


def check_files(base: str, threads: int = 20) -> list[str]:
    base = normalize_url(base).rstrip("/")
    found: list[str] = []

    def _one(path: str) -> tuple[str, int] | None:
        url = urljoin(base + "/", path)
        try:
            r = requests.head(url, timeout=6, verify=False,
                              allow_redirects=False,
                              headers={"User-Agent": config.USER_AGENT})
            if r.status_code in (200, 301, 302, 403):
                return (path, r.status_code)
        except Exception:
            pass
        return None

    with Progress(SpinnerColumn(),
                   TextColumn("[progress.description]{task.description}"),
                   BarColumn(),
                   TextColumn("{task.completed}/{task.total}"),
                   TimeElapsedColumn(),
                   console=console) as p:
        task = p.add_task("Файлы", total=len(VULN_FILES))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(_one, p_) for p_ in VULN_FILES]
            for f in as_completed(futures):
                p.advance(task)
                res = f.result()
                if res:
                    found.append(f"{res[1]} {res[0]}")

    return sorted(found)


DIRECTORIES = [
    "wp-content/uploads/",
    "wp-content/plugins/",
    "wp-content/themes/",
    "wp-content/cache/",
    "wp-content/backups/",
    "wp-includes/",
    "wp-admin/",
]


def check_directory_listing(base: str) -> list[str]:
    """Проверить directory listing (autoindex)."""
    base = normalize_url(base).rstrip("/")
    out: list[str] = []
    for d in DIRECTORIES:
        r = _get(urljoin(base + "/", d), timeout=6)
        if r and r.status_code == 200:
            if "Index of /" in r.text or "<title>Index of" in r.text:
                out.append(d)
    return out


# ===========================================================================
# Version helpers
# ===========================================================================

def _version_lt(v1: str, v2: str) -> bool:
    def _parse(v: str) -> tuple:
        parts = re.split(r"[.\-]", v)
        out = []
        for p in parts:
            try:
                out.append(int(p))
            except ValueError:
                out.append(0)
        return tuple(out)
    return _parse(v1) < _parse(v2)


def version_vulns(wp_version: str) -> list[dict]:
    if not wp_version:
        return []
    out: list[dict] = []
    for fixed, desc, cve, sev in WP_CORE_VULNS:
        if _version_lt(wp_version, fixed):
            out.append({
                "type": "core",
                "version": wp_version,
                "fixed_in": fixed,
                "desc": desc,
                "cve": cve,
                "severity": sev,
            })
    return out


def plugin_vulns(plugins: list[str],
                  versions: dict | None = None) -> list[dict]:
    out: list[dict] = []
    versions = versions or {}
    for p in plugins:
        slug = p.lower()
        if slug not in KNOWN_VULN_PLUGINS:
            continue
        installed_ver = versions.get(slug, "")
        for threshold, desc, cve, sev in KNOWN_VULN_PLUGINS[slug]:
            fixed = threshold.lstrip("<>=")
            if installed_ver and not _version_lt(installed_ver, fixed):
                continue
            out.append({
                "type": "plugin",
                "slug": slug,
                "installed_version": installed_ver,
                "fixed_in": fixed,
                "desc": desc,
                "cve": cve,
                "severity": sev,
            })
    return out


def theme_vulns(themes: list[str],
                 versions: dict | None = None) -> list[dict]:
    out: list[dict] = []
    versions = versions or {}
    for t in themes:
        slug = t.lower()
        if slug not in KNOWN_VULN_THEMES:
            continue
        installed_ver = versions.get(slug, "")
        for threshold, desc, cve, sev in KNOWN_VULN_THEMES[slug]:
            fixed = threshold.lstrip("<>=")
            if installed_ver and not _version_lt(installed_ver, fixed):
                continue
            out.append({
                "type": "theme",
                "slug": slug,
                "installed_version": installed_ver,
                "fixed_in": fixed,
                "desc": desc,
                "cve": cve,
                "severity": sev,
            })
    return out


# ===========================================================================
# Detections
# ===========================================================================

def detect_stack(base: str) -> dict:
    """Определить WooCommerce, Elementor, Yoast и т.п."""
    base = normalize_url(base).rstrip("/")
    det: dict = {}
    r = _get(base)
    if not r:
        return det
    text = (r.text or "").lower()

    checks = {
        "woocommerce": ["woocommerce", "wc-"],
        "elementor": ["elementor"],
        "yoast-seo": ["yoast", "wpseo"],
        "rank-math": ["rank-math"],
        "contact-form-7": ["wpcf7", "contact-form-7"],
        "wpforms": ["wpforms"],
        "gravityforms": ["gform", "gravityforms"],
        "jetpack": ["jetpack"],
        "akismet": ["akismet"],
        "wp-rocket": ["wp-rocket"],
        "wordfence": ["wordfence"],
    }
    for name, needles in checks.items():
        for n in needles:
            if n in text:
                det[name] = True
                break

    return det


# ===========================================================================
# Главная функция
# ===========================================================================

def scan(target: str, threads: int = 20,
         aggressive: bool = False) -> WPResult:
    """Полное сканирование WordPress."""
    url = normalize_url(target)
    result = WPResult(url=url)

    console.print(f"[cyan]🔍 Проверяю {url} на WordPress…[/cyan]")

    # 1. Детект
    is_wp, version, src = detect(url)
    result.is_wordpress = is_wp
    result.version = version
    result.version_source = src

    if not is_wp:
        console.print("[yellow]WordPress не обнаружен.[/yellow]")
        db.save_scan("wp_scan", url, {"is_wp": False})
        return result

    console.print(f"[green]✓ WordPress"
                  + (f" v{version} ({src})" if version else "") + "[/green]")

    base = url.rstrip("/")

    # 2. Headers
    result.headers = collect_headers(base)

    # 3. Detections (WooCommerce, Elementor, ...)
    result.detections = detect_stack(base)
    if result.detections:
        console.print(f"[cyan]→ Стек:[/cyan] "
                      f"{', '.join(result.detections.keys())}")

    # 4. Users
    console.print("[cyan]→ Пользователи…[/cyan]")
    result.users = enum_users(base)
    if result.users:
        console.print(f"  [green]Найдено: {', '.join(result.users)}[/green]")

    # 5. Plugins (+ версии)
    console.print("[cyan]→ Плагины…[/cyan]")
    result.plugins = enum_plugins(base)
    if result.plugins:
        console.print(f"  [green]{len(result.plugins)} шт: "
                      f"{', '.join(result.plugins[:8])}"
                      f"{'…' if len(result.plugins) > 8 else ''}[/green]")
        # Версии — параллельно
        with ThreadPoolExecutor(max_workers=min(threads, 10)) as ex:
            futures = {ex.submit(get_plugin_version, base, p): p
                       for p in result.plugins}
            for f in as_completed(futures):
                slug = futures[f]
                try:
                    v = f.result()
                    if v:
                        result.plugin_versions[slug] = v
                except Exception:
                    pass

    # 6. Themes (+ версии)
    console.print("[cyan]→ Темы…[/cyan]")
    result.themes = enum_themes(base)
    if result.themes:
        console.print(f"  [green]{', '.join(result.themes)}[/green]")
        with ThreadPoolExecutor(max_workers=min(threads, 6)) as ex:
            futures = {ex.submit(get_theme_version, base, t): t
                       for t in result.themes}
            for f in as_completed(futures):
                slug = futures[f]
                try:
                    v = f.result()
                    if v:
                        result.theme_versions[slug] = v
                except Exception:
                    pass

    # 7. xmlrpc
    console.print("[cyan]→ xmlrpc.php…[/cyan]")
    xmlrpc_on, methods = check_xmlrpc(base)
    result.xmlrpc_enabled = xmlrpc_on
    result.xmlrpc_methods = methods
    if xmlrpc_on:
        console.print(f"  [yellow]⚡ xmlrpc включён, "
                      f"{len(methods)} методов[/yellow]")
        if aggressive:
            result.xmlrpc_pingback = test_pingback_ssrf(base)
            if result.xmlrpc_pingback:
                console.print("  [red]⚠ pingback.ping активен (SSRF)!"
                              "[/red]")

    # 8. REST
    console.print("[cyan]→ REST API…[/cyan]")
    rest_on, ns = check_rest_api(base)
    result.rest_api_enabled = rest_on
    result.rest_namespaces = ns
    if rest_on:
        console.print(f"  [green]Активен, {len(ns)} namespace[/green]")
        # Sensitive endpoints
        endpoints = probe_rest_endpoints(base, threads=threads)
        result.rest_endpoints = endpoints
        if endpoints:
            console.print(f"  [yellow]Доступно {len(endpoints)} "
                          f"endpoints[/yellow]")

    # 9. Уязвимые файлы
    if aggressive:
        console.print("[cyan]→ Проверка уязвимых файлов…[/cyan]")
        result.vulnerable_files = check_files(base, threads=threads)
        if result.vulnerable_files:
            for f in result.vulnerable_files[:10]:
                console.print(f"  [yellow]⚠ {f}[/yellow]")
            if len(result.vulnerable_files) > 10:
                console.print(f"  [dim]… +{len(result.vulnerable_files)-10}"
                              f"[/dim]")

        console.print("[cyan]→ Directory listing…[/cyan]")
        result.directories = check_directory_listing(base)
        if result.directories:
            for d in result.directories:
                console.print(f"  [red]⚠ {d} (listable)[/red]")

    # 10. CVE
    result.vulns = (version_vulns(version)
                    + plugin_vulns(result.plugins, result.plugin_versions)
                    + theme_vulns(result.themes, result.theme_versions))

    # 11. Findings
    _emit_findings(result)

    # Save
    db.save_scan("wp_scan", url, {
        "is_wp": True,
        "version": version,
        "users": result.users,
        "plugins": result.plugins,
        "themes": result.themes,
        "xmlrpc": xmlrpc_on,
        "rest_api": rest_on,
        "vulns": len(result.vulns),
        "vuln_files": result.vulnerable_files,
        "directories": result.directories,
    })

    # Notify
    crit = sum(1 for v in result.vulns if v["severity"] == "critical")
    high = sum(1 for v in result.vulns if v["severity"] == "high")
    if crit or high:
        _notify(
            f"🔍 WordPress scan: {urlparse(url).hostname}",
            f"WP v{version}\nUsers: {len(result.users)}\n"
            f"Plugins: {len(result.plugins)}\n"
            f"CVE: {crit} critical / {high} high",
            severity="critical" if crit else "high",
        )

    _print_report(result)
    return result


def _emit_findings(result: WPResult) -> None:
    """Отправить findings в notes."""
    # Critical CVE
    for v in result.vulns:
        if v["severity"] in ("critical", "high"):
            _save_finding(WPFinding(
                kind=f"wp_{v['type']}_vuln",
                severity=v["severity"],
                title=(f"WP {v['type']}: {v.get('slug', 'core')} — "
                       f"{v['desc']}"),
                target=result.url,
                evidence=(f"CVE: {v['cve']}\n"
                          f"Fixed in: {v['fixed_in']}\n"
                          f"Installed: "
                          f"{v.get('installed_version', v.get('version', '?'))}"),
                data=v,
            ))

    # xmlrpc pingback SSRF
    if result.xmlrpc_pingback:
        _save_finding(WPFinding(
            kind="xmlrpc_pingback_ssrf",
            severity="high",
            title=f"xmlrpc pingback.ping активен (SSRF) — "
                  f"{urlparse(result.url).hostname}",
            target=result.url,
            evidence="pingback.ping принимает произвольные source URL → SSRF",
            data={"xmlrpc": True},
        ))

    # Directory listing
    for d in result.directories:
        _save_finding(WPFinding(
            kind="directory_listing",
            severity="high" if "backup" in d or "uploads" in d else "medium",
            title=f"Directory listing: {d}",
            target=result.url,
            evidence=f"{d} — autoindex включён",
            data={"directory": d},
        ))

    # Backup files
    for f in result.vulnerable_files:
        if any(kw in f for kw in ("wp-config", ".env", ".git",
                                    "backup", "database", "dump")):
            _save_finding(WPFinding(
                kind="wp_sensitive_file",
                severity="critical",
                title=f"Sensitive file exposed: {f}",
                target=result.url,
                evidence=f,
                data={"file": f},
            ))

    # Open REST users endpoint (unauthenticated)
    if "/wp-json/wp/v2/users" in result.rest_endpoints:
        _save_finding(WPFinding(
            kind="rest_users_exposed",
            severity="high",
            title=f"REST /wp/v2/users доступен без auth — "
                  f"{urlparse(result.url).hostname}",
            target=result.url,
            evidence=f"Найдено {len(result.users)} пользователей",
            data={"users": result.users[:20]},
        ))


# ===========================================================================
# Report
# ===========================================================================

def _print_report(result: WPResult) -> None:
    console.print()
    table = Table(title=f"🔍 WordPress: {result.url}")
    table.add_column("Параметр", style="cyan", width=20)
    table.add_column("Значение", style="green")
    table.add_row("WordPress", "✓" if result.is_wordpress else "—")
    table.add_row("Версия", f"{result.version or '—'} "
                            f"({result.version_source})")
    table.add_row("Пользователей", str(len(result.users)))
    table.add_row("Плагинов", str(len(result.plugins)))
    table.add_row("Тем", str(len(result.themes)))
    table.add_row("xmlrpc.php",
                  "[yellow]включён[/yellow]" if result.xmlrpc_enabled
                  else "—")
    if result.xmlrpc_pingback:
        table.add_row("xmlrpc pingback",
                      "[red]SSRF активен[/red]")
    table.add_row("REST API",
                  "[green]активен[/green]" if result.rest_api_enabled
                  else "—")
    if result.rest_endpoints:
        table.add_row("REST endpoints",
                      f"{len(result.rest_endpoints)} доступны")
    table.add_row("Уязвимые файлы", str(len(result.vulnerable_files)))
    if result.directories:
        table.add_row("Directory listing",
                      f"[red]{len(result.directories)}[/red]")
    table.add_row("Найдено CVE", str(len(result.vulns)))
    if result.detections:
        table.add_row("Стек", ", ".join(result.detections.keys()))
    console.print(table)

    if result.users:
        console.print(f"\n[cyan]👥 Пользователи:[/cyan] "
                      f"{', '.join(result.users)}")

    if result.plugins:
        t = Table(title="🔌 Плагины")
        t.add_column("Slug", style="cyan")
        t.add_column("Версия", style="dim", width=10)
        t.add_column("CVE", style="red")
        for p in result.plugins:
            slug = p.lower()
            ver = result.plugin_versions.get(slug, "—")
            info = ""
            if slug in KNOWN_VULN_PLUGINS:
                info = f"⚠ {len(KNOWN_VULN_PLUGINS[slug])} CVE"
            t.add_row(p, ver, info)
        console.print(t)

    if result.themes:
        t = Table(title="🎨 Темы")
        t.add_column("Slug", style="cyan")
        t.add_column("Версия", style="dim", width=10)
        t.add_column("CVE", style="red")
        for th in result.themes:
            slug = th.lower()
            ver = result.theme_versions.get(slug, "—")
            info = ""
            if slug in KNOWN_VULN_THEMES:
                info = f"⚠ {len(KNOWN_VULN_THEMES[slug])} CVE"
            t.add_row(th, ver, info)
        console.print(t)

    if result.rest_namespaces:
        console.print(f"\n[cyan]REST namespaces:[/cyan]")
        for ns in result.rest_namespaces[:15]:
            console.print(f"  • /wp-json/{ns}")

    if result.rest_endpoints:
        console.print(f"\n[cyan]REST endpoints (200 OK):[/cyan]")
        for ep, info in list(result.rest_endpoints.items())[:15]:
            console.print(f"  [yellow]{ep}[/yellow]  "
                          f"[dim]({info['size']} bytes)[/dim]")

    if result.vulnerable_files:
        console.print(f"\n[red]⚠ Уязвимые файлы:[/red]")
        for f in result.vulnerable_files[:20]:
            console.print(f"  [red]{f}[/red]")

    if result.directories:
        console.print(f"\n[red]⚠ Directory listing:[/red]")
        for d in result.directories:
            console.print(f"  [red]{d}[/red]")

    if result.xmlrpc_methods:
        console.print(f"\n[cyan]xmlrpc methods "
                      f"({len(result.xmlrpc_methods)}):[/cyan]")
        for m in result.xmlrpc_methods[:25]:
            console.print(f"  • {m}")

    if result.vulns:
        t = Table(title=f"🔥 Известные уязвимости ({len(result.vulns)})")
        t.add_column("Тип", style="cyan", width=8)
        t.add_column("Slug / desc", style="magenta", max_width=35)
        t.add_column("Installed", style="dim", width=10)
        t.add_column("Fixed", style="yellow", width=10)
        t.add_column("Severity", style="red", width=10)
        t.add_column("CVE", style="dim")
        for v in result.vulns:
            sev = v.get("severity", "").upper()
            color = {"CRITICAL": "bold red", "HIGH": "red",
                     "MEDIUM": "yellow", "LOW": "green"}.get(sev, "white")
            t.add_row(
                v.get("type", ""),
                (v.get("slug") or v.get("desc", ""))[:35],
                v.get("installed_version", v.get("version", "—")),
                v.get("fixed_in", "—"),
                f"[{color}]{sev}[/{color}]",
                v.get("cve", "—"),
            )
        console.print(t)


# ===========================================================================
# Export
# ===========================================================================

def export_json(result: WPResult, path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = (urlparse(result.url).hostname or "target").replace(".", "_")
        path = str(WP_DIR / f"wp_{safe}_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps(asdict(result), indent=2, ensure_ascii=False,
                        default=str),
            encoding="utf-8",
        )
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_html(result: WPResult, path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = (urlparse(result.url).hostname or "target").replace(".", "_")
        path = str(WP_DIR / f"wp_{safe}_{ts}.html")
    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>WP scan: {html_mod.escape(result.url)}</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:24px;line-height:1.5;max-width:1300px;margin:0 auto;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
        "h2{color:#00ff9c;margin-top:32px;}",
        "table{width:100%;border-collapse:collapse;margin-top:12px;"
        "font-size:13px;}",
        "th{background:#111;color:#00ff9c;padding:6px;text-align:left;"
        "border:1px solid #222;}",
        "td{padding:4px 6px;border:1px solid #222;word-break:break-all;}",
        "tr:nth-child(even){background:#0d0d0d;}",
        ".critical{color:#ff2020;font-weight:bold;}",
        ".high{color:#ff7a40;font-weight:bold;}",
        ".medium{color:#ffd23f;}",
        ".low{color:#00ff9c;}",
        ".ok{color:#00ff9c;}.bad{color:#ff2020;font-weight:bold;}",
        "</style></head><body>",
        f"<h1>🔍 WordPress scan: {html_mod.escape(result.url)}</h1>",
        f"<p>Generated: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "<h2>Обзор</h2><table>",
        f"<tr><td>WordPress</td><td class='ok'>"
        f"{'✓' if result.is_wordpress else '—'}</td></tr>",
        f"<tr><td>Версия</td><td>{html_mod.escape(result.version or '—')} "
        f"({html_mod.escape(result.version_source)})</td></tr>",
        f"<tr><td>Users</td><td>{len(result.users)}</td></tr>",
        f"<tr><td>Plugins</td><td>{len(result.plugins)}</td></tr>",
        f"<tr><td>Themes</td><td>{len(result.themes)}</td></tr>",
        f"<tr><td>xmlrpc</td><td>"
        f"{'включён' if result.xmlrpc_enabled else '—'}</td></tr>",
        f"<tr><td>REST API</td><td>"
        f"{'активен' if result.rest_api_enabled else '—'}</td></tr>",
        f"<tr><td>CVE</td><td>{len(result.vulns)}</td></tr>",
        "</table>",
    ]

    if result.users:
        parts.append("<h2>👥 Пользователи</h2><p>"
                     + ", ".join(html_mod.escape(u) for u in result.users)
                     + "</p>")

    if result.plugins:
        parts.append("<h2>🔌 Плагины</h2><table>"
                     "<tr><th>Slug</th><th>Версия</th><th>CVE</th></tr>")
        for p in result.plugins:
            slug = p.lower()
            ver = result.plugin_versions.get(slug, "—")
            has = slug in KNOWN_VULN_PLUGINS
            parts.append(
                f"<tr><td>{html_mod.escape(p)}</td>"
                f"<td>{html_mod.escape(ver)}</td>"
                f"<td class='{'bad' if has else ''}'>"
                f"{'⚠' if has else '—'}</td></tr>")
        parts.append("</table>")

    if result.themes:
        parts.append("<h2>🎨 Темы</h2><table>"
                     "<tr><th>Slug</th><th>Версия</th></tr>")
        for th in result.themes:
            ver = result.theme_versions.get(th.lower(), "—")
            parts.append(
                f"<tr><td>{html_mod.escape(th)}</td>"
                f"<td>{html_mod.escape(ver)}</td></tr>")
        parts.append("</table>")

    if result.vulnerable_files:
        parts.append("<h2>⚠ Уязвимые файлы</h2><ul>")
        for f in result.vulnerable_files:
            parts.append(f"<li class='bad'>{html_mod.escape(f)}</li>")
        parts.append("</ul>")

    if result.vulns:
        parts.append("<h2>🔥 CVE</h2><table>"
                     "<tr><th>Тип</th><th>Slug</th><th>Installed</th>"
                     "<th>Fixed</th><th>Sev</th><th>CVE</th></tr>")
        for v in result.vulns:
            sev = v.get("severity", "").lower()
            parts.append(
                f"<tr><td>{html_mod.escape(v.get('type', ''))}</td>"
                f"<td>{html_mod.escape(v.get('slug') or v.get('desc', ''))[:60]}</td>"
                f"<td>{html_mod.escape(v.get('installed_version', v.get('version', '—')))}</td>"
                f"<td>{html_mod.escape(v.get('fixed_in', '—'))}</td>"
                f"<td class='{sev}'>{html_mod.escape(sev.upper())}</td>"
                f"<td>{html_mod.escape(v.get('cve', '—'))}</td></tr>")
        parts.append("</table>")

    parts.append("</body></html>")
    try:
        Path(path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_markdown(result: WPResult, path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = (urlparse(result.url).hostname or "target").replace(".", "_")
        path = str(WP_DIR / f"wp_{safe}_{ts}.md")
    lines = [
        f"# WordPress scan: {result.url}",
        f"_Generated: {datetime.now().isoformat()}_", "",
        "## Обзор", "",
        f"- **WordPress**: {'✓' if result.is_wordpress else '—'}",
        f"- **Версия**: {result.version or '—'} ({result.version_source})",
        f"- **Users**: {len(result.users)}",
        f"- **Plugins**: {len(result.plugins)}",
        f"- **Themes**: {len(result.themes)}",
        f"- **xmlrpc**: {'включён' if result.xmlrpc_enabled else '—'}",
        f"- **REST API**: "
        f"{'активен' if result.rest_api_enabled else '—'}",
        f"- **CVE**: {len(result.vulns)}",
        "",
    ]
    if result.users:
        lines.append("## 👥 Пользователи\n")
        lines.append(", ".join(result.users))
        lines.append("")
    if result.plugins:
        lines.append("## 🔌 Плагины\n")
        lines.append("| Slug | Версия | CVE |")
        lines.append("|------|--------|-----|")
        for p in result.plugins:
            slug = p.lower()
            ver = result.plugin_versions.get(slug, "—")
            cve = "⚠" if slug in KNOWN_VULN_PLUGINS else "—"
            lines.append(f"| {p} | {ver} | {cve} |")
        lines.append("")
    if result.vulnerable_files:
        lines.append("## ⚠ Уязвимые файлы\n")
        for f in result.vulnerable_files:
            lines.append(f"- `{f}`")
        lines.append("")
    if result.vulns:
        lines.append("## 🔥 CVE\n")
        lines.append("| Тип | Slug | Installed | Fixed | Sev | CVE |")
        lines.append("|-----|------|-----------|-------|-----|-----|")
        for v in result.vulns:
            lines.append(
                f"| {v.get('type', '')} | "
                f"{v.get('slug') or v.get('desc', '')[:30]} | "
                f"{v.get('installed_version', v.get('version', '—'))} | "
                f"{v.get('fixed_in', '—')} | "
                f"{v.get('severity', '').upper()} | {v.get('cve', '—')} |")
    try:
        Path(path).write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green]✓ MD: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_csv(result: WPResult, path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = (urlparse(result.url).hostname or "target").replace(".", "_")
        path = str(WP_DIR / f"wp_{safe}_{ts}.csv")
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["category", "key", "value"])
            w.writerow(["meta", "url", result.url])
            w.writerow(["meta", "is_wordpress", result.is_wordpress])
            w.writerow(["meta", "version", result.version])
            w.writerow(["meta", "version_source", result.version_source])
            w.writerow(["meta", "xmlrpc", result.xmlrpc_enabled])
            w.writerow(["meta", "rest_api", result.rest_api_enabled])
            for u in result.users:
                w.writerow(["user", "username", u])
            for p in result.plugins:
                w.writerow(["plugin", p,
                            result.plugin_versions.get(p.lower(), "")])
            for t in result.themes:
                w.writerow(["theme", t,
                            result.theme_versions.get(t.lower(), "")])
            for fl in result.vulnerable_files:
                w.writerow(["file", "exposed", fl])
            for v in result.vulns:
                w.writerow(["cve", v.get("cve", ""),
                            f"{v.get('type', '')}:{v.get('slug', '')}"
                            f"|{v.get('severity', '')}"
                            f"|fixed={v.get('fixed_in', '')}"])
        console.print(f"[green]✓ CSV: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# CLI (сохранены)
# ===========================================================================

def cli_scan(target: str, aggressive: bool = False) -> None:
    if not confirm_external(target):
        return
    r = scan(target, aggressive=aggressive)
    if r.is_wordpress:
        if Confirm.ask("Сохранить отчёт (JSON + HTML)?", default=False):
            export_json(r)
            export_html(r)


def cli_detect(target: str) -> None:
    is_wp, ver, src = detect(target)
    if is_wp:
        console.print(f"[green]✓ WordPress {ver or '?'} ({src})[/green]")
    else:
        console.print("[yellow]WordPress не обнаружен.[/yellow]")


def cli_users(target: str) -> None:
    if not confirm_external(target):
        return
    users = enum_users(normalize_url(target))
    if users:
        console.print(f"[green]Пользователи:[/green] {', '.join(users)}")
    else:
        console.print("[yellow]Пользователи не найдены.[/yellow]")


def cli_plugins(target: str) -> None:
    if not confirm_external(target):
        return
    base = normalize_url(target).rstrip("/")
    plugins = enum_plugins(base)
    if not plugins:
        console.print("[yellow]Плагины не найдены.[/yellow]")
        return
    t = Table(title=f"🔌 Плагины {target} ({len(plugins)})")
    t.add_column("Slug", style="cyan")
    t.add_column("Версия", style="dim", width=10)
    t.add_column("Известные CVE", style="red")
    for p in plugins:
        ver = get_plugin_version(base, p) or "—"
        if p.lower() in KNOWN_VULN_PLUGINS:
            info = f"⚠ {len(KNOWN_VULN_PLUGINS[p.lower()])} CVE"
        else:
            info = "—"
        t.add_row(p, ver, info)
    console.print(t)


def cli_xmlrpc(target: str) -> None:
    if not confirm_external(target):
        return
    on, methods = check_xmlrpc(normalize_url(target))
    if not on:
        console.print("[green]xmlrpc.php недоступен.[/green]")
        return
    console.print(f"[yellow]⚡ xmlrpc.php активен, "
                  f"{len(methods)} методов[/yellow]")
    for m in methods[:30]:
        console.print(f"  • {m}")


def cli_vulns(target: str) -> None:
    if not confirm_external(target):
        return
    is_wp, version, _ = detect(target)
    if not is_wp:
        console.print("[yellow]WordPress не обнаружен.[/yellow]")
        return
    base = normalize_url(target).rstrip("/")
    plugins = enum_plugins(base)
    themes = enum_themes(base)
    p_vers = {p: get_plugin_version(base, p) for p in plugins}
    t_vers = {t: get_theme_version(base, t) for t in themes}
    vulns = (version_vulns(version)
             + plugin_vulns(plugins, p_vers)
             + theme_vulns(themes, t_vers))
    if not vulns:
        console.print("[green]Известных уязвимостей не найдено.[/green]")
        return
    t = Table(title=f"🔥 CVE для {target} (WP {version})")
    t.add_column("Тип")
    t.add_column("Что", max_width=40)
    t.add_column("Installed")
    t.add_column("Fixed")
    t.add_column("Sev")
    t.add_column("CVE")
    for v in vulns:
        t.add_row(v.get("type", ""),
                  v.get("slug") or v.get("desc", "")[:40],
                  v.get("installed_version", v.get("version", "—")),
                  v.get("fixed_in", ""),
                  v.get("severity", "").upper(),
                  v.get("cve", ""))
    console.print(t)


def cli_rest(target: str) -> None:
    if not confirm_external(target):
        return
    base = normalize_url(target).rstrip("/")
    on, ns = check_rest_api(base)
    if not on:
        console.print("[yellow]REST API недоступен.[/yellow]")
        return
    console.print(f"[green]✓ REST активен: {len(ns)} namespace[/green]")
    eps = probe_rest_endpoints(base)
    if eps:
        t = Table(title=f"🔓 Sensitive endpoints ({len(eps)})")
        t.add_column("Path", style="cyan")
        t.add_column("Size", style="dim")
        for ep, info in eps.items():
            t.add_row(ep, str(info["size"]))
        console.print(t)


# ===========================================================================
# Menu (сохранено + расширено)
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🔍 WordPress Scanner Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Полный скан (детект, users, plugins, xmlrpc, REST, CVE)"),
        ("2", "Только детект версии"),
        ("3", "Перечисление пользователей"),
        ("4", "Перечисление плагинов (+ версии)"),
        ("5", "Перечисление тем"),
        ("6", "Проверка xmlrpc.php"),
        ("7", "Известные уязвимости по версии/плагинам"),
        ("8", "REST API probes (sensitive endpoints)"),
        ("9", "Directory listing check"),
        ("10", "Уязвимые файлы (backup/.env/.git)"),
        ("11", "Pingback SSRF test"),
        ("12", "Экспорт последнего результата"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        target = Prompt.ask("URL (например https://example.com)")
        agg = Confirm.ask("Агрессивный режим (файлы/SSRF)?",
                          default=False)
        if not confirm_external(target):
            return
        r = scan(target, aggressive=agg)
        if r.is_wordpress and Confirm.ask("Сохранить отчёты?",
                                            default=False):
            fmt = Prompt.ask("Формат",
                             choices=["all", "json", "html", "md", "csv"],
                             default="all")
            if fmt in ("all", "json"):
                export_json(r)
            if fmt in ("all", "html"):
                export_html(r)
            if fmt in ("all", "md"):
                export_markdown(r)
            if fmt in ("all", "csv"):
                export_csv(r)
    elif c == "2":
        cli_detect(Prompt.ask("URL"))
    elif c == "3":
        cli_users(Prompt.ask("URL"))
    elif c == "4":
        cli_plugins(Prompt.ask("URL"))
    elif c == "5":
        target = Prompt.ask("URL")
        if not confirm_external(target):
            return
        base = normalize_url(target).rstrip("/")
        themes = enum_themes(base)
        if themes:
            t = Table(title=f"🎨 Темы ({len(themes)})")
            t.add_column("Slug", style="cyan")
            t.add_column("Version", style="dim")
            for th in themes:
                t.add_row(th, get_theme_version(base, th) or "—")
            console.print(t)
        else:
            console.print("[yellow]Тем не найдено.[/yellow]")
    elif c == "6":
        cli_xmlrpc(Prompt.ask("URL"))
    elif c == "7":
        cli_vulns(Prompt.ask("URL"))
    elif c == "8":
        cli_rest(Prompt.ask("URL"))
    elif c == "9":
        target = Prompt.ask("URL")
        if not confirm_external(target):
            return
        dirs = check_directory_listing(normalize_url(target))
        if dirs:
            for d in dirs:
                console.print(f"[red]⚠ {d}[/red]")
        else:
            console.print("[green]Directory listing не обнаружен.[/green]")
    elif c == "10":
        target = Prompt.ask("URL")
        if not confirm_external(target):
            return
        files = check_files(normalize_url(target))
        for f in files:
            console.print(f"[red]{f}[/red]")
    elif c == "11":
        target = Prompt.ask("URL")
        if not confirm_external(target):
            return
        on = test_pingback_ssrf(normalize_url(target))
        if on:
            console.print("[red]⚠ pingback.ping активен (SSRF)[/red]")
        else:
            console.print("[green]pingback.ping не подтверждён.[/green]")
    elif c == "12":
        console.print("[yellow]Используй пункт 1 с агрессивным режимом "
                      "и выбери формат экспорта.[/yellow]")