"""
WordPress Scanner — специализированный сканер WP.
Author: idqwixxa

Возможности:
    - Детект WordPress (meta generator, /wp-login.php, /wp-json/)
    - Определение версии (meta, readme.html, feed, /wp-json/)
    - Перечисление пользователей (wp-json, author-id, ?author=N)
    - Перечисление плагинов (по HTML-ссылкам, /wp-content/plugins/)
    - Перечисление тем (по HTML-ссылкам, /wp-content/themes/)
    - Проверка xmlrpc.php (pingback, system.listMethods)
    - Проверка wp-json / REST API (endpoints)
    - Известные уязвимости по версии (встроенный справочник)
    - Проверка уязвимых файлов (wp-config.php.bak, .env, debug.log, readme)
"""
import re
import json
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
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, normalize_url

console = Console()
log = get_logger(__name__)

# Отключаем SSL-предупреждения
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ===========================================================================
# Справочник известных уязвимостей (мини-база)
# ===========================================================================

WP_VULN_BY_VERSION = {
    # версия: [(порог, описание, CVE, severity)]
    "5.0": [
        ("<5.0.22", "Authenticated XSS/RCE в блоке комментариев",
         "CVE-2020-28032", "high"),
        ("<5.4.2", "XSS в Media Library", "CVE-2021-29447", "medium"),
        ("<5.7.2", "XSS в PHPMailer", "CVE-2021-24310", "medium"),
        ("<5.8.3", "SQLi в WP_Query", "CVE-2022-21661", "critical"),
        ("<6.0.3", "SQLi в WP_Query (повтор)", "CVE-2022-21664", "critical"),
        ("<6.2.1", "Path Traversal через блоки", "CVE-2023-2745", "high"),
        ("<6.3.2", "XSS в комментариях", "CVE-2023-4771", "medium"),
        ("<6.4.3", "RCE в admin-ajax", "CVE-2024-31210", "high"),
        ("<6.5.5", "Stored XSS через аватар", "CVE-2024-4439", "high"),
    ],
}

# Известные плагины с уязвимостями (упрощённый справочник)
KNOWN_VULN_PLUGINS = {
    "contact-form-7": [
        ("<5.3.2", "Unrestricted File Upload", "CVE-2020-35489", "critical"),
    ],
    "elementor": [
        ("<3.6.3", "Arbitrary File Upload", "CVE-2022-1329", "high"),
    ],
    "woocommerce": [
        ("<6.9.0", "SQLi в admin-запросах", "CVE-2022-4042", "high"),
    ],
    "wp-file-manager": [
        ("<6.9", "Unauthenticated RCE", "CVE-2020-25213", "critical"),
    ],
    "elementor-pro": [
        ("<3.10.2", "Arbitrary File Upload", "CVE-2023-48777", "critical"),
    ],
    "duplicator": [
        ("<1.3.28", "Arbitrary File Read", "CVE-2020-11738", "high"),
    ],
    "wp-rocket": [
        ("<3.11.0", "Arbitrary File Read", "CVE-2023-26326", "high"),
    ],
    "litespeed-cache": [
        ("<4.6", "Broken Access Control", "CVE-2022-4001", "medium"),
    ],
    "revslider": [
        ("<4.2.0", "Arbitrary File Upload", "CVE-2014-9734", "critical"),
    ],
    "wpbakery": [
        ("<6.1.0", "Stored XSS", "CVE-2020-11731", "medium"),
    ],
    "gravityforms": [
        ("<2.7.0", "Arbitrary File Upload", "CVE-2023-28782", "critical"),
    ],
    "akismet": [
        ("<5.0", "XSS в комментариях", "CVE-2021-24596", "low"),
    ],
    "wordfence": [
        ("<7.5.6", "SQLi", "CVE-2021-24617", "high"),
    ],
    "wpforms-lite": [
        ("<1.6.6", "Unrestricted File Upload", "CVE-2021-34645", "high"),
    ],
}


# ===========================================================================
# Модель
# ===========================================================================

@dataclass
class WPResult:
    url: str
    is_wordpress: bool = False
    version: str = ""
    version_source: str = ""
    users: list[str] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)
    themes: list[str] = field(default_factory=list)
    xmlrpc_enabled: bool = False
    xmlrpc_methods: list[str] = field(default_factory=list)
    rest_api_enabled: bool = False
    rest_namespaces: list[str] = field(default_factory=list)
    vulnerable_files: list[str] = field(default_factory=list)
    vulns: list[dict] = field(default_factory=list)
    error: str = ""


# ===========================================================================
# HTTP-хелперы
# ===========================================================================

def _get(url: str, timeout: int = 10,
         allow_redirects: bool = True) -> requests.Response | None:
    try:
        return requests.get(
            url, timeout=timeout, allow_redirects=allow_redirects,
            verify=False,
            headers={"User-Agent": config.USER_AGENT},
        )
    except Exception as exc:  # noqa: BLE001
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
    except Exception as exc:  # noqa: BLE001
        log.debug("POST %s: %s", url, exc)
        return None


# ===========================================================================
# Детект WordPress
# ===========================================================================

def detect(base_url: str) -> tuple[bool, str, str]:
    """Вернуть (is_wp, version, source)."""
    base = normalize_url(base_url).rstrip("/")

    # 1. Meta generator
    r = _get(base)
    if r is None:
        return (False, "", "http-error")

    html = r.text or ""
    m = re.search(
        r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)["\']',
        html, re.IGNORECASE,
    )
    if m:
        return (True, m.group(1), "meta-generator")

    if re.search(r"wp-content|wp-includes|wp-json", html, re.IGNORECASE):
        is_wp = True
    else:
        is_wp = False

    # 2. readme.html
    r2 = _get(urljoin(base, "/readme.html"))
    if r2 and r2.status_code == 200:
        m = re.search(r"Version\s+([\d.]+)", r2.text)
        if m:
            return (True, m.group(1), "readme.html")

    # 3. /feed/
    r3 = _get(urljoin(base, "/feed/"))
    if r3 and r3.status_code == 200:
        m = re.search(r"<generator>https?://wordpress\.org/\?v=([\d.]+)",
                      r3.text)
        if m:
            return (True, m.group(1), "feed")
        if "<wp-" in r3.text:
            is_wp = True

    # 4. wp-json
    r4 = _get(urljoin(base, "/wp-json/"))
    if r4 and r4.status_code == 200:
        try:
            data = r4.json()
            if "namespaces" in data or "description" in data:
                is_wp = True
                # generator из описания
                desc = data.get("description", "")
                m = re.search(r"Version\s+([\d.]+)", desc)
                if m:
                    return (True, m.group(1), "wp-json")
        except Exception:
            pass

    # 5. /wp-login.php
    r5 = _get(urljoin(base, "/wp-login.php"))
    if r5 and r5.status_code in (200, 302):
        if "wordpress" in (r5.text or "").lower():
            is_wp = True

    return (is_wp, "", "heuristic")


# ===========================================================================
# Пользователи
# ===========================================================================

def enum_users(base: str) -> list[str]:
    """Перечисление пользователей через /wp-json/wp/v2/users и ?author=N."""
    base = normalize_url(base).rstrip("/")
    users: set[str] = set()

    # 1. REST API
    r = _get(urljoin(base, "/wp-json/wp/v2/users?per_page=100"))
    if r and r.status_code == 200:
        try:
            data = r.json()
            for u in data:
                slug = u.get("slug") or u.get("name")
                if slug:
                    users.add(slug)
        except Exception:
            pass

    # 2. ?author=N — редирект на /author/<slug>/
    for i in range(1, 11):
        r = _get(f"{base}/?author={i}", allow_redirects=False)
        if not r:
            continue
        location = r.headers.get("Location", "")
        m = re.search(r"/author/([^/]+)/?", location)
        if m:
            users.add(m.group(1))

    return sorted(users)


# ===========================================================================
# Плагины / темы
# ===========================================================================

def enum_plugins(base: str, timeout: int = 10) -> list[str]:
    """Плагины из HTML (wp-content/plugins/<slug>/)."""
    base = normalize_url(base).rstrip("/")
    plugins: set[str] = set()

    for url in (base + "/", base + "/wp-login.php", base + "/?p=1"):
        r = _get(url, timeout=timeout)
        if not r or not r.text:
            continue
        for m in re.finditer(
            r"/wp-content/plugins/([a-zA-Z0-9_\-]+)/", r.text,
        ):
            plugins.add(m.group(1))

    return sorted(plugins)


def enum_themes(base: str, timeout: int = 10) -> list[str]:
    """Темы из HTML (wp-content/themes/<slug>/)."""
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


# ===========================================================================
# xmlrpc
# ===========================================================================

def check_xmlrpc(base: str) -> tuple[bool, list[str]]:
    """Проверить xmlrpc.php и получить список методов."""
    base = normalize_url(base).rstrip("/")
    url = urljoin(base, "/xmlrpc.php")

    # HEAD/GET для проверки наличия
    r = _get(url)
    if not r or r.status_code not in (200, 405):
        return (False, [])

    # POST system.listMethods
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


# ===========================================================================
# REST API
# ===========================================================================

def check_rest_api(base: str) -> tuple[bool, list[str]]:
    """Проверить /wp-json/ и вернуть namespaces."""
    base = normalize_url(base).rstrip("/")
    r = _get(urljoin(base, "/wp-json/"))
    if not r or r.status_code != 200:
        return (False, [])
    try:
        data = r.json()
        return (True, data.get("namespaces", []) or [])
    except Exception:
        return (True, [])


# ===========================================================================
# Уязвимые файлы
# ===========================================================================

VULN_FILES = [
    "wp-config.php.bak",
    "wp-config.php~",
    "wp-config.php.old",
    "wp-config.php.save",
    "wp-config.txt",
    ".wp-config.php.swp",
    "wp-config.php.orig",
    "wp-config.php.dist",
    ".env",
    "debug.log",
    "wp-content/debug.log",
    "wp-content/uploads/",
    "wp-content/backup-db/",
    "wp-content/backups/",
    "wp-content/uploads/backup/",
    "backup.sql",
    "backup.zip",
    "database.sql",
    "wp-admin/setup-config.php",
    "xmlrpc.php",
    "readme.html",
    "license.txt",
    "wp-cron.php",
    "wp-trackback.php",
]


def check_files(base: str, threads: int = 20) -> list[str]:
    """Проверить наличие подозрительных/уязвимых файлов."""
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

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_one, p) for p in VULN_FILES]
        for f in as_completed(futures):
            res = f.result()
            if res:
                found.append(f"{res[1]} {res[0]}")

    return sorted(found)


# ===========================================================================
# Уязвимости по версии
# ===========================================================================

def _version_lt(v1: str, v2: str) -> bool:
    """v1 < v2 (semantic-ish)."""
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
    """Вернуть список CVE для данной версии."""
    if not wp_version:
        return []
    out: list[dict] = []
    for ver, items in WP_VULN_BY_VERSION.items():
        for threshold, desc, cve, sev in items:
            # threshold вида "<5.4.2" или "<5.0.22"
            op = threshold[0]
            target = threshold[1:]
            if op == "<" and _version_lt(wp_version, target):
                out.append({
                    "type": "core",
                    "version": wp_version,
                    "fixed_in": target,
                    "desc": desc,
                    "cve": cve,
                    "severity": sev,
                })
    return out


def plugin_vulns(plugins: list[str]) -> list[dict]:
    """Проверить плагины по справочнику (по slug)."""
    out: list[dict] = []
    for p in plugins:
        slug = p.lower()
        if slug in KNOWN_VULN_PLUGINS:
            for threshold, desc, cve, sev in KNOWN_VULN_PLUGINS[slug]:
                out.append({
                    "type": "plugin",
                    "slug": slug,
                    "fixed_in": threshold[1:],
                    "desc": desc,
                    "cve": cve,
                    "severity": sev,
                })
    return out


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

    # 2. Users
    console.print("[cyan]→ Пользователи…[/cyan]")
    result.users = enum_users(base)
    if result.users:
        console.print(f"  [green]Найдено: {', '.join(result.users)}[/green]")

    # 3. Plugins
    console.print("[cyan]→ Плагины…[/cyan]")
    result.plugins = enum_plugins(base)
    if result.plugins:
        console.print(f"  [green]{len(result.plugins)} шт: "
                      f"{', '.join(result.plugins[:8])}"
                      f"{'…' if len(result.plugins) > 8 else ''}[/green]")

    # 4. Themes
    console.print("[cyan]→ Темы…[/cyan]")
    result.themes = enum_themes(base)
    if result.themes:
        console.print(f"  [green]{', '.join(result.themes)}[/green]")

    # 5. xmlrpc
    console.print("[cyan]→ xmlrpc.php…[/cyan]")
    xmlrpc_on, methods = check_xmlrpc(base)
    result.xmlrpc_enabled = xmlrpc_on
    result.xmlrpc_methods = methods
    if xmlrpc_on:
        console.print(f"  [yellow]⚡ xmlrpc включён, "
                      f"{len(methods)} методов[/yellow]")

    # 6. REST
    console.print("[cyan]→ REST API…[/cyan]")
    rest_on, ns = check_rest_api(base)
    result.rest_api_enabled = rest_on
    result.rest_namespaces = ns
    if rest_on:
        console.print(f"  [green]Активен, {len(ns)} namespace[/green]")

    # 7. Уязвимые файлы
    if aggressive:
        console.print("[cyan]→ Проверка уязвимых файлов…[/cyan]")
        result.vulnerable_files = check_files(base, threads=threads)
        if result.vulnerable_files:
            for f in result.vulnerable_files:
                console.print(f"  [yellow]⚠ {f}[/yellow]")

    # 8. Уязвимости по версии/плагинам
    result.vulns = version_vulns(version) + plugin_vulns(result.plugins)

    # Сохранение
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
    })

    # Отчёт
    _print_report(result)
    return result


def _print_report(result: WPResult) -> None:
    """Красивый отчёт."""
    console.print()
    table = Table(title=f"🔍 WordPress: {result.url}")
    table.add_column("Параметр", style="cyan", width=18)
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
    table.add_row("REST API",
                  "[green]активен[/green]" if result.rest_api_enabled
                  else "—")
    table.add_row("Уязвимые файлы", str(len(result.vulnerable_files)))
    table.add_row("Найдено CVE", str(len(result.vulns)))
    console.print(table)

    if result.users:
        console.print(f"\n[cyan]👥 Пользователи:[/cyan] "
                      f"{', '.join(result.users)}")

    if result.plugins:
        t = Table(title="🔌 Плагины")
        t.add_column("Slug", style="cyan")
        t.add_column("Известные уязвимости", style="red")
        for p in result.plugins:
            slug = p.lower()
            info = ""
            if slug in KNOWN_VULN_PLUGINS:
                info = f"⚠ {len(KNOWN_VULN_PLUGINS[slug])} CVE"
            t.add_row(p, info)
        console.print(t)

    if result.themes:
        console.print(f"\n[cyan]🎨 Темы:[/cyan] {', '.join(result.themes)}")

    if result.rest_namespaces:
        console.print(f"\n[cyan]REST endpoints:[/cyan]")
        for ns in result.rest_namespaces[:15]:
            console.print(f"  • /wp-json/{ns}")

    if result.vulnerable_files:
        console.print(f"\n[red]⚠ Уязвимые файлы:[/red]")
        for f in result.vulnerable_files:
            console.print(f"  [red]{f}[/red]")

    if result.vulns:
        t = Table(title=f"🔥 Известные уязвимости ({len(result.vulns)})")
        t.add_column("Тип", style="cyan", width=8)
        t.add_column("Что", style="magenta", max_width=35)
        t.add_column("Исправлено в", style="yellow", width=12)
        t.add_column("Severity", style="red", width=10)
        t.add_column("CVE", style="dim")
        for v in result.vulns:
            sev = v.get("severity", "").upper()
            color = {"CRITICAL": "bold red", "HIGH": "red",
                     "MEDIUM": "yellow", "LOW": "green"}.get(sev, "white")
            t.add_row(
                v.get("type", ""),
                v.get("slug") or v.get("desc", "")[:35],
                v.get("fixed_in", "—"),
                f"[{color}]{sev}[/{color}]",
                v.get("cve", "—"),
            )
        console.print(t)


# ===========================================================================
# Экспорт
# ===========================================================================

def export_result(result: WPResult, path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = urlparse(result.url).hostname or "target"
        safe = safe.replace(".", "_")
        path = str(REPORT_DIR / f"wp_{safe}_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps(asdict(result), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        console.print(f"[green]✓ Отчёт: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# CLI-функции
# ===========================================================================

def cli_scan(target: str, aggressive: bool = False) -> None:
    if not confirm_external(target):
        return
    r = scan(target, aggressive=aggressive)
    if r.is_wordpress and Confirm.ask("Сохранить JSON?", default=False):
        export_result(r)


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
    plugins = enum_plugins(normalize_url(target))
    if not plugins:
        console.print("[yellow]Плагины не найдены.[/yellow]")
        return
    t = Table(title=f"🔌 Плагины {target} ({len(plugins)})")
    t.add_column("Slug", style="cyan")
    t.add_column("Известные CVE", style="red")
    for p in plugins:
        if p.lower() in KNOWN_VULN_PLUGINS:
            info = f"⚠ {len(KNOWN_VULN_PLUGINS[p.lower()])} CVE"
        else:
            info = "—"
        t.add_row(p, info)
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
    vulns = version_vulns(version) + plugin_vulns(plugins)
    if not vulns:
        console.print("[green]Известных уязвимостей не найдено.[/green]")
        return
    t = Table(title=f"🔥 CVE для {target} (WP {version})")
    t.add_column("Тип")
    t.add_column("Что", max_width=40)
    t.add_column("Fixed")
    t.add_column("Sev")
    t.add_column("CVE")
    for v in vulns:
        t.add_row(v.get("type", ""),
                  v.get("slug") or v.get("desc", "")[:40],
                  v.get("fixed_in", ""),
                  v.get("severity", "").upper(),
                  v.get("cve", ""))
    console.print(t)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🔍 WordPress Scanner[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Полный скан (детект, users, plugins, xmlrpc, REST, CVE)"),
        ("2", "Только детект версии"),
        ("3", "Перечисление пользователей"),
        ("4", "Перечисление плагинов"),
        ("5", "Проверка xmlrpc.php"),
        ("6", "Известные уязвимости по версии/плагинам"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        target = Prompt.ask("URL (например https://example.com)")
        agg = Confirm.ask("Агрессивный режим (проверка уязвимых файлов)?",
                          default=False)
        if not confirm_external(target):
            return
        r = scan(target, aggressive=agg)
        if r.is_wordpress and Confirm.ask("Сохранить JSON?", default=False):
            export_result(r)
    elif c == "2":
        cli_detect(Prompt.ask("URL"))
    elif c == "3":
        cli_users(Prompt.ask("URL"))
    elif c == "4":
        cli_plugins(Prompt.ask("URL"))
    elif c == "5":
        cli_xmlrpc(Prompt.ask("URL"))
    elif c == "6":
        cli_vulns(Prompt.ask("URL"))