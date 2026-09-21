"""
Subdomain Takeover Detector.
Author: idqwixxa

Проверяет поддомены на уязвимость к takeover:
    1. Резолвит CNAME-цепочку
    2. Сопоставляет CNAME с известными SaaS-сервисами
    3. Проверяет HTTP-ответ на fingerprint сервиса
    4. Если CNAME указывает на сервис И fingerprint найден — уязвим

Источник fingerprints: can-i-take-over-xyz (EdOverflow) + собственные наблюдения.

⚠ Только для этичного использования и CTF / bug-bounty.
"""
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

import dns.resolver
import requests
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.config import config, WORDLIST_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external

console = Console()
log = get_logger(__name__)


# ===========================================================================
# База известных сервисов
# ===========================================================================
# cname_patterns: подстроки, которые ищут в CNAME поддомена
# fingerprints:   подстроки, которые ищут в HTTP-ответе сервиса (когда он "свободен")
# service:        человекочитаемое имя
# status:         vulnerable | edge-case | safe

SERVICES: dict[str, dict[str, Any]] = {
    "github.io": {
        "service": "GitHub Pages",
        "cname_patterns": ["github.io", "github.com"],
        "fingerprints": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        "status": "vulnerable",
    },
    "herokuapp": {
        "service": "Heroku",
        "cname_patterns": ["herokuapp.com", "herokussl.com", "herokudns.com"],
        "fingerprints": [
            "No such app",
            "heroku | no such app",
            "no-such-app",
        ],
        "status": "vulnerable",
    },
    "s3": {
        "service": "AWS S3",
        "cname_patterns": [
            ".s3.amazonaws.com", ".s3-website", "s3-external-1.amazonaws.com",
            ".s3.dualstack", "s3-website",
        ],
        "fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
            "Code: NoSuchBucket",
        ],
        "status": "vulnerable",
    },
    "cloudfront": {
        "service": "AWS CloudFront",
        "cname_patterns": ["cloudfront.net"],
        "fingerprints": [
            "Bad request",
            "ERROR: The request could not be satisfied",
            "CloudFront attempted to establish a connection",
        ],
        "status": "edge-case",
    },
    "azure": {
        "service": "Azure (Web Apps / Cloud Services)",
        "cname_patterns": [
            ".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com",
            ".trafficmanager.net", ".blob.core.windows.net",
            ".azure-api.net", ".azurefd.net",
        ],
        "fingerprints": [
            "404 Web Site not found",
            "Error 404 - Web app not found",
            "The resource you are looking for has been removed",
        ],
        "status": "vulnerable",
    },
    "fastly": {
        "service": "Fastly",
        "cname_patterns": ["fastly.net", "fastlylb.net"],
        "fingerprints": [
            "Fastly error: unknown domain",
            "Please check that this domain has been added to a service",
        ],
        "status": "vulnerable",
    },
    "shopify": {
        "service": "Shopify",
        "cname_patterns": ["myshopify.com", "shopify.com"],
        "fingerprints": [
            "Sorry, this shop is currently unavailable",
            "Only one step left!",
        ],
        "status": "vulnerable",
    },
    "tumblr": {
        "service": "Tumblr",
        "cname_patterns": ["domains.tumblr.com", "tumblr.com"],
        "fingerprints": [
            "There's nothing here.",
            "Whatever you were looking for doesn't currently exist at this address",
        ],
        "status": "vulnerable",
    },
    "wordpress": {
        "service": "WordPress.com",
        "cname_patterns": ["wordpress.com"],
        "fingerprints": [
            "Do you want to register",
            "WordPress.com",
        ],
        "status": "vulnerable",
    },
    "zendesk": {
        "service": "Zendesk",
        "cname_patterns": ["zendesk.com"],
        "fingerprints": [
            "Help Center Closed",
            "Zendesk Support",
        ],
        "status": "vulnerable",
    },
    "bitbucket": {
        "service": "Bitbucket",
        "cname_patterns": ["bitbucket.io", "bitbucket.org"],
        "fingerprints": [
            "Repository not found",
            "The page you're looking for doesn't exist",
        ],
        "status": "vulnerable",
    },
    "netlify": {
        "service": "Netlify",
        "cname_patterns": ["netlify.app", "netlify.com"],
        "fingerprints": [
            "Not Found - Request ID",
            "Looks like you've followed a broken link",
        ],
        "status": "vulnerable",
    },
    "surge": {
        "service": "Surge.sh",
        "cname_patterns": ["surge.sh"],
        "fingerprints": [
            "project not found",
            "404 Not Found: project not found",
        ],
        "status": "vulnerable",
    },
    "pantheon": {
        "service": "Pantheon",
        "cname_patterns": ["pantheonsite.io"],
        "fingerprints": [
            "The gods are wise, but do not know of the site which you seek",
            "404: This page could not be found",
        ],
        "status": "vulnerable",
    },
    "ghost": {
        "service": "Ghost",
        "cname_patterns": ["ghost.io"],
        "fingerprints": [
            "Domain error",
            "The thing you were looking for is no longer here",
        ],
        "status": "vulnerable",
    },
    "cargo": {
        "service": "Cargo Collective",
        "cname_patterns": ["cargocollective.com"],
        "fingerprints": [
            "If you're the owner of this website",
            "404 Not Found",
        ],
        "status": "vulnerable",
    },
    "uservoice": {
        "service": "UserVoice",
        "cname_patterns": ["uservoice.com"],
        "fingerprints": [
            "This UserVoice subdomain is currently available!",
        ],
        "status": "vulnerable",
    },
    "feedpress": {
        "service": "Feedpress",
        "cname_patterns": ["feedpress.me"],
        "fingerprints": [
            "The feed has not been found.",
        ],
        "status": "vulnerable",
    },
    "readme": {
        "service": "Readme.io",
        "cname_patterns": ["readme.io"],
        "fingerprints": [
            "Project doesnt exist... yet!",
        ],
        "status": "vulnerable",
    },
    "statuspage": {
        "service": "Atlassian Statuspage",
        "cname_patterns": ["statuspage.io"],
        "fingerprints": [
            "You are being redirected",
            "This page is used to test",
        ],
        "status": "edge-case",
    },
    "smugmug": {
        "service": "SmugMug",
        "cname_patterns": ["smugmug.com"],
        "fingerprints": [
            "404 Not Found",
            "The page you're looking for doesn't exist",
        ],
        "status": "vulnerable",
    },
    "cargocollective": {
        "service": "Cargo",
        "cname_patterns": ["cargocollective.com"],
        "fingerprints": ["404 Not Found"],
        "status": "vulnerable",
    },
    "tictail": {
        "service": "Tictail",
        "cname_patterns": ["tictail.com"],
        "fingerprints": [
            "to target URL: https://tictail.com",
            "Starting a store takes seconds",
        ],
        "status": "vulnerable",
    },
    "smartling": {
        "service": "Smartling",
        "cname_patterns": ["smartling.com"],
        "fingerprints": ["Domain is not configured"],
        "status": "vulnerable",
    },
    "acquia": {
        "service": "Acquia",
        "cname_patterns": ["acquia-sites.com"],
        "fingerprints": [
            "The site you are looking for could not be found",
        ],
        "status": "vulnerable",
    },
    "fly": {
        "service": "Fly.io",
        "cname_patterns": ["fly.dev"],
        "fingerprints": [
            "404 Not Found",
            "This site is not configured",
        ],
        "status": "edge-case",
    },
    "vercel": {
        "service": "Vercel",
        "cname_patterns": ["vercel.app", "vercel.com", "now.sh"],
        "fingerprints": [
            "The deployment you are looking for",
            "404: NOT_FOUND",
        ],
        "status": "edge-case",
    },
    "render": {
        "service": "Render",
        "cname_patterns": ["onrender.com", "render.com"],
        "fingerprints": [
            "not found",
            "The page you're looking for doesn't exist",
        ],
        "status": "edge-case",
    },
    "helpscout": {
        "service": "Help Scout",
        "cname_patterns": ["helpscoutdocs.com"],
        "fingerprints": [
            "No settings were found for this company",
        ],
        "status": "vulnerable",
    },
    "launchrock": {
        "service": "LaunchRock",
        "cname_patterns": ["launchrock.com"],
        "fingerprints": [
            "It looks like you may have taken a wrong turn",
        ],
        "status": "vulnerable",
    },
    "strikingly": {
        "service": "Strikingly",
        "cname_patterns": ["strikingly.com", "s.strikinglydns.com"],
        "fingerprints": [
            "page not found",
            "But if you're looking to build your own",
        ],
        "status": "vulnerable",
    },
    "udemy": {
        "service": "Udemy",
        "cname_patterns": ["udemy.com"],
        "fingerprints": [
            "This site is not currently available",
        ],
        "status": "vulnerable",
    },
    "wix": {
        "service": "Wix",
        "cname_patterns": ["wix.com"],
        "fingerprints": [
            "site is not currently available",
        ],
        "status": "vulnerable",
    },
    "hatenablog": {
        "service": "HatenaBlog",
        "cname_patterns": ["hatenablog.com"],
        "fingerprints": [
            "404 Blog Not Found",
        ],
        "status": "vulnerable",
    },
    "pingdom": {
        "service": "Pingdom",
        "cname_patterns": ["pingdom.com"],
        "fingerprints": [
            "This public report page has been disabled",
        ],
        "status": "vulnerable",
    },
}


# ===========================================================================
# Модель результата
# ===========================================================================

@dataclass
class TakeoverResult:
    subdomain: str
    cname: str = ""
    service: str = ""
    status: str = "safe"        # vulnerable | edge-case | safe | error
    http_status: int = 0
    fingerprint: str = ""
    error: str = ""
    ip: str = ""


# ===========================================================================
# Проверка
# ===========================================================================

def _resolve_cname(subdomain: str) -> str:
    """Резолв CNAME-цепочки; возвращает финальный target."""
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME", lifetime=5)
        # Раскрутим цепочку
        target = str(answers[0].target).rstrip(".")
        for _ in range(10):
            try:
                next_ans = dns.resolver.resolve(target, "CNAME", lifetime=5)
                next_target = str(next_ans[0].target).rstrip(".")
                if next_target == target:
                    break
                target = next_target
            except Exception:
                break
        return target
    except Exception:
        return ""


def _match_service(cname: str) -> dict | None:
    """Найти сервис по подстроке CNAME."""
    lc = cname.lower()
    for svc_key, data in SERVICES.items():
        for pattern in data["cname_patterns"]:
            if pattern.lower() in lc:
                return {"key": svc_key, **data}
    return None


def _http_probe(url: str, timeout: int = 10) -> tuple[int, str]:
    """GET-запрос, вернуть (status, body[:4096])."""
    try:
        r = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": config.USER_AGENT},
        )
        return r.status_code, r.text[:8192]
    except requests.exceptions.SSLError:
        # Попробуем http
        try:
            r = requests.get(url.replace("https://", "http://", 1),
                             timeout=timeout, allow_redirects=True,
                             headers={"User-Agent": config.USER_AGENT})
            return r.status_code, r.text[:8192]
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"http fallback failed: {exc}")
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(str(exc)[:80])


def check_subdomain(subdomain: str, timeout: int = 10,
                    verbose: bool = False) -> TakeoverResult:
    """
    Полная проверка одного поддомена:
        1) резолв CNAME
        2) матчинг сервиса
        3) HTTP-probe
        4) сверка fingerprint
    """
    result = TakeoverResult(subdomain=subdomain)

    # 1. CNAME
    cname = _resolve_cname(subdomain)
    if not cname:
        result.error = "no CNAME"
        return result
    result.cname = cname

    # 2. Матч сервиса
    svc = _match_service(cname)
    if not svc:
        result.service = "(unknown)"
        result.error = "not a known service"
        return result
    result.service = svc["service"]

    # 3. HTTP-probe
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            status, body = _http_probe(url, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            if scheme == "http":
                result.error = str(exc)[:100]
                return result
            continue

        result.http_status = status

        # 4. Fingerprint
        body_lc = body.lower()
        for fp in svc["fingerprints"]:
            if fp.lower() in body_lc:
                result.fingerprint = fp
                result.status = svc["status"]
                return result

        # Fingerprint не найден
        result.status = "safe"
        return result

    result.status = "safe"
    return result


# ===========================================================================
# Пакетная проверка
# ===========================================================================

def check_many(subdomains: list[str], threads: int = 20,
               timeout: int = 10) -> list[TakeoverResult]:
    """Параллельная проверка списка поддоменов."""
    results: list[TakeoverResult] = []
    total = len(subdomains)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check_subdomain, sd, timeout): sd
                   for sd in subdomains}
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as p:
            task = p.add_task(f"Проверяю {total} поддоменов…", total=total)
            for f in as_completed(futures):
                try:
                    results.append(f.result())
                except Exception as exc:  # noqa: BLE001
                    sd = futures[f]
                    results.append(TakeoverResult(subdomain=sd,
                                                  error=str(exc)[:80]))
                p.advance(task)
    return results


def _print_results(results: list[TakeoverResult], title: str = "Takeover") -> None:
    """Красивая таблица результатов."""
    vulnerable = [r for r in results if r.status == "vulnerable"]
    edge = [r for r in results if r.status == "edge-case"]
    safe = [r for r in results if r.status == "safe"]

    if vulnerable:
        table = Table(title=f"🔴 {title} — УЯЗВИМЫ ({len(vulnerable)})",
                      border_style="red")
        table.add_column("Subdomain", style="cyan")
        table.add_column("CNAME", style="yellow", max_width=40)
        table.add_column("Сервис", style="magenta")
        table.add_column("HTTP", width=5)
        table.add_column("Fingerprint", max_width=50)
        for r in vulnerable:
            table.add_row(r.subdomain, r.cname, r.service,
                          str(r.http_status), r.fingerprint[:50])
        console.print(table)

    if edge:
        table = Table(title=f"🟡 {title} — возможно ({len(edge)})",
                      border_style="yellow")
        table.add_column("Subdomain", style="cyan")
        table.add_column("CNAME", style="yellow", max_width=40)
        table.add_column("Сервис", style="magenta")
        table.add_column("HTTP", width=5)
        for r in edge:
            table.add_row(r.subdomain, r.cname, r.service, str(r.http_status))
        console.print(table)

    if safe:
        console.print(f"\n[green]✓ Безопасных: {len(safe)}[/green]")
        if len(safe) <= 20:
            for r in safe:
                console.print(f"  [dim]{r.subdomain} → "
                              f"{r.service or r.cname or r.error}[/dim]")

    if not (vulnerable or edge or safe):
        console.print("[yellow]Ничего не проверено.[/yellow]")


# ===========================================================================
# Сканирование домена (брут по словарю + проверка)
# ===========================================================================

def scan_domain(domain: str, wordlist: str | None = None,
                threads: int = 30, timeout: int = 10) -> list[TakeoverResult]:
    """
    Брут поддоменов по словарю + проверка каждого на takeover.
    """
    if not confirm_external(domain):
        return []

    wl_name = wordlist or "subdomains.txt"
    wl_path = WORDLIST_DIR / wl_name
    if not wl_path.exists():
        console.print(f"[red]Словарь {wl_path} не найден.[/red]")
        return []

    words = [w.strip() for w in wl_path.read_text(
        encoding="utf-8", errors="ignore").splitlines() if w.strip()]
    subs = [f"{w}.{domain}" for w in words]

    console.print(f"[cyan]🔍 Проверяю {len(subs)} поддоменов {domain} "
                  f"на takeover…[/cyan]")

    # Сначала быстро — только CNAME-резолв
    def _cname_only(sd: str) -> str | None:
        c = _resolve_cname(sd)
        if not c:
            return None
        if _match_service(c):
            return sd
        return None

    candidates: list[str] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_cname_only, sd): sd for sd in subs}
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as p:
            task = p.add_task("Резолв CNAME…", total=len(subs))
            for f in as_completed(futures):
                r = f.result()
                if r:
                    candidates.append(r)
                p.advance(task)

    console.print(f"[cyan]Кандидатов (CNAME → сервис): {len(candidates)}[/cyan]")
    if not candidates:
        console.print("[green]Подозрительных поддоменов нет.[/green]")
        db.save_scan("takeover", domain,
                     {"scanned": len(subs), "candidates": 0})
        return []

    # Полная проверка кандидатов
    results = check_many(candidates, threads=threads, timeout=timeout)
    _print_results(results, title=f"Takeover {domain}")

    db.save_scan("takeover", domain, {
        "scanned": len(subs),
        "candidates": len(candidates),
        "vulnerable": [r.subdomain for r in results
                       if r.status == "vulnerable"],
        "edge": [r.subdomain for r in results if r.status == "edge-case"],
    })
    return results


def scan_list(path_or_list: str, threads: int = 20,
              timeout: int = 10) -> list[TakeoverResult]:
    """
    Проверка списка поддоменов из файла или строки через запятую.
    """
    import os
    subs: list[str] = []
    if os.path.isfile(path_or_list):
        try:
            subs = [l.strip() for l in open(path_or_list,
                                            encoding="utf-8",
                                            errors="ignore")
                    if l.strip() and not l.startswith("#")]
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Не могу прочитать файл: {exc}[/red]")
            return []
    else:
        subs = [s.strip() for s in path_or_list.split(",") if s.strip()]

    if not subs:
        console.print("[red]Пустой список.[/red]")
        return []

    console.print(f"[cyan]🔍 Проверяю {len(subs)} поддоменов…[/cyan]")
    results = check_many(subs, threads=threads, timeout=timeout)
    _print_results(results, title="Takeover batch")

    db.save_scan("takeover_list", f"{len(subs)} subs", {
        "vulnerable": [r.subdomain for r in results
                       if r.status == "vulnerable"],
    })
    return results


def list_services() -> None:
    """Показать базу поддерживаемых сервисов."""
    table = Table(title=f"📚 Сервисы ({len(SERVICES)})")
    table.add_column("#", style="yellow", width=4)
    table.add_column("Сервис", style="cyan")
    table.add_column("CNAME patterns", style="green", max_width=50)
    table.add_column("Статус", style="magenta", width=12)
    for i, (key, data) in enumerate(SERVICES.items(), 1):
        table.add_row(
            str(i),
            data["service"],
            ", ".join(data["cname_patterns"])[:50],
            data["status"],
        )
    console.print(table)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🎯 Subdomain Takeover Detector[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Скан домена (брут по словарю + проверка)"),
        ("2", "Проверить один поддомен"),
        ("3", "Проверить список (из файла или через запятую)"),
        ("4", "Показать базу сервисов"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        domain = Prompt.ask("Домен")
        wl = Prompt.ask("Словарь", default="subdomains.txt")
        threads = IntPrompt.ask("Потоков", default=30)
        scan_domain(domain, wordlist=wl, threads=threads)
    elif c == "2":
        sub = Prompt.ask("Поддомен (например old.example.com)")
        if not confirm_external(sub):
            return
        r = check_subdomain(sub, verbose=True)
        _print_results([r], title=sub)
    elif c == "3":
        src = Prompt.ask("Файл или список через запятую")
        threads = IntPrompt.ask("Потоков", default=20)
        scan_list(src, threads=threads)
    elif c == "4":
        list_services()


# ===========================================================================
# CLI-функции (без интерактива)
# ===========================================================================

def cli_scan(domain: str, wordlist: str = "subdomains.txt",
             threads: int = 30) -> None:
    scan_domain(domain, wordlist=wordlist, threads=threads)


def cli_check(subdomain: str) -> None:
    r = check_subdomain(subdomain)
    _print_results([r], title=subdomain)


def cli_batch(source: str, threads: int = 20) -> None:
    scan_list(source, threads=threads)


def cli_services() -> None:
    list_services()