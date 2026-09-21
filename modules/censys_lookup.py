"""
Censys API Integration — расширенный.
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty.

Возможности:
    ─── Hosts ───
    - Поиск хостов по Censys query (язык запросов Censys)
    - Детальная информация по IP (порты, сервисы, banners, TLS)
    - Reverse DNS / ASN / Geolocation
    - История сканов (если доступно в тарифе)

    ─── Certificates ───
    - Поиск по SHA-256 fingerprint
    - Парсинг names / issuer / validity / SAN
    - Поиск связанных доменов через CT

    ─── Aggregations ───
    - Top ASN, countries, services
    - Графики распределения

    ─── Интеграция ───
    - Экспорт JSON / CSV / HTML
    - Кэш с TTL (rate-limit friendly)
    - Findings → notes (для критичных находок)
    - Уведомления через notifier
    - Rate-limit (429) с auto-retry и экспоненциальной задержкой

    Требуется CENSYS_API_ID + CENSYS_API_SECRET в .env.
    Документация: https://search.censys.io/api
"""
import base64
import csv
import html as html_mod
import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

CENSYS_DIR = REPORT_DIR / "censys"
CENSYS_DIR.mkdir(parents=True, exist_ok=True)

CACHE_FILE = CENSYS_DIR / "_cache.json"
CACHE_TTL = 3600  # 1 час


# ===========================================================================
# API endpoints
# ===========================================================================

CENSYS_SEARCH_URL = "https://search.censys.io/api/v2/hosts/search"
CENSYS_HOST_URL = "https://search.censys.io/api/v2/hosts/{ip}"
CENSYS_CERT_URL = "https://search.censys.io/api/v2/certificates/{sha}"
CENSYS_CERT_SEARCH_URL = "https://search.censys.io/api/v2/certificates/search"
CENSYS_AGGREGATE_URL = "https://search.censys.io/api/v2/hosts/aggregate"


# ===========================================================================
# Кэш (rate-limit friendly)
# ===========================================================================

def _load_cache() -> dict:
    if not CACHE_FILE.exists():
        return {}
    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        now = time.time()
        # Удалим просроченные
        return {k: v for k, v in data.items()
                if now - v.get("_ts", 0) < CACHE_TTL}
    except Exception:
        return {}


def _save_cache(cache: dict) -> None:
    try:
        CACHE_FILE.write_text(
            json.dumps(cache, ensure_ascii=False, default=str),
            encoding="utf-8")
    except Exception as exc:
        log.debug("cache save: %s", exc)


# ===========================================================================
# Auth
# ===========================================================================

def _auth_header() -> dict[str, str] | None:
    if not config.CENSYS_API_ID or not config.CENSYS_API_SECRET:
        console.print(
            "[yellow]CENSYS_API_ID / CENSYS_API_SECRET не заданы в .env"
            "[/yellow]"
        )
        console.print(
            "[cyan]Получить ключи: https://search.censys.io/account/api"
            "[/cyan]"
        )
        return None
    token = base64.b64encode(
        f"{config.CENSYS_API_ID}:{config.CENSYS_API_SECRET}".encode()
    ).decode()
    return {
        "Authorization": f"Basic {token}",
        "Accept": "application/json",
        "User-Agent": config.USER_AGENT,
    }


# ===========================================================================
# Request with retry + cache
# ===========================================================================

def _request(url: str, params: dict | None = None,
             use_cache: bool = True,
             max_retries: int = 3) -> dict[str, Any] | None:
    """GET-запрос к Censys с retry + кэшем."""
    cache_key = url + "?" + str(sorted((params or {}).items()))
    cache = _load_cache() if use_cache else {}
    if use_cache and cache_key in cache:
        log.debug("cache hit: %s", cache_key[:80])
        return cache[cache_key].get("data")

    headers = _auth_header()
    if not headers:
        return None

    delay = 2.0
    for attempt in range(max_retries):
        try:
            r = requests.get(url, headers=headers, params=params or {},
                             timeout=config.REQUEST_TIMEOUT)
        except requests.exceptions.RequestException as exc:
            log.warning("Censys network: %s", exc)
            time.sleep(delay)
            delay *= 2
            continue

        if r.status_code == 401:
            console.print("[red]401 Unauthorized — проверь "
                          "CENSYS_API_ID / SECRET[/red]")
            return None
        if r.status_code == 404:
            log.debug("Censys 404: %s", url)
            return None
        if r.status_code == 429:
            console.print(f"[yellow]429 rate-limit — пауза {delay:.0f}s"
                          f"[/yellow]")
            time.sleep(delay)
            delay *= 2
            continue
        if r.status_code >= 500:
            time.sleep(delay)
            delay *= 2
            continue

        try:
            r.raise_for_status()
            data = r.json()
        except Exception as exc:
            console.print(f"[red]Censys parse: {exc}[/red]")
            return None

        if use_cache:
            cache[cache_key] = {"_ts": time.time(), "data": data}
            _save_cache(cache)
        return data

    console.print(f"[red]Censys: all {max_retries} retries failed[/red]")
    return None


# ===========================================================================
# Модели (для findings)
# ===========================================================================

@dataclass
class CensysFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: CensysFinding) -> int:
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f.title,
            target=f.target,
            severity=f.severity,
            status="open",
            tags=["censys", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:2000]}\n```"),
        )
    except Exception:
        return -1


# ===========================================================================
# Search hosts
# ===========================================================================

def censys_search(query: str, per_page: int = 25,
                  save_findings: bool = False) -> list[dict]:
    """Поиск хостов в Censys."""
    console.print(f"[cyan]🔍 Censys search: {query}[/cyan]")
    data = _request(CENSYS_SEARCH_URL,
                    {"q": query, "per_page": per_page})
    if not data:
        return []

    result = data.get("result", {})
    total = result.get("total", 0)
    hits = result.get("hits", []) or []

    console.print(f"[green]Всего найдено: {total}[/green]")

    table = Table(title=f"Censys: {query[:60]}")
    table.add_column("#", style="dim", width=4)
    table.add_column("IP", style="cyan")
    table.add_column("Country", style="green", width=8)
    table.add_column("Services", style="magenta", max_width=40)
    table.add_column("ASN / Org", max_width=30)

    for i, h in enumerate(hits[:per_page], 1):
        ip = h.get("ip", "?")
        loc = h.get("location", {}) or {}
        country = loc.get("country", "?")
        services = h.get("services", []) or []
        svc = ", ".join(
            f"{s.get('port')}/{s.get('service_name', '?')}"
            for s in services[:5])
        asn = h.get("autonomous_system", {}) or {}
        as_str = f"AS{asn.get('asn', '?')} {asn.get('name', '')[:20]}"
        table.add_row(str(i), ip, country, svc or "—", as_str)

    console.print(table)

    # Аномалии
    if save_findings:
        for h in hits[:50]:
            services = h.get("services", []) or []
            ports = {s.get("port") for s in services}
            # Открытые базы данных
            dangerous = {27017, 6379, 9200, 11211, 5984, 2375, 5432, 3306,
                          1433, 9042, 2379}
            exposed = dangerous & ports
            if exposed:
                _save_finding(CensysFinding(
                    kind="exposed_database",
                    severity="high",
                    title=f"Censys: exposed DB ports on {h.get('ip')}",
                    target=h.get("ip", ""),
                    evidence=f"Ports: {sorted(exposed)}",
                    data={"ports": list(exposed)},
                ))

    db.save_scan("censys_search", query,
                 {"total": total, "hits_count": len(hits)})
    return hits


# ===========================================================================
# Aggregation
# ===========================================================================

def censys_aggregate(query: str, field_: str = "autonomous_system.asn",
                     num_buckets: int = 20) -> dict:
    """Агрегация Censys (top ASN / countries / services)."""
    console.print(f"[cyan]📊 Censys aggregate: {query} "
                  f"by {field_}[/cyan]")
    data = _request(CENSYS_AGGREGATE_URL, {
        "q": query,
        "field": field_,
        "num_buckets": num_buckets,
    })
    if not data:
        return {}

    result = data.get("result", {})
    buckets = result.get("buckets", []) or []

    table = Table(title=f"Aggregate: {field_}")
    table.add_column("Value", style="cyan")
    table.add_column("Count", style="green", width=10)
    for b in buckets[:num_buckets]:
        table.add_row(str(b.get("key", "?")), str(b.get("doc_count", 0)))
    console.print(table)

    db.save_scan("censys_aggregate", query,
                 {"field": field_, "buckets": buckets[:num_buckets]})
    return {"field": field_, "buckets": buckets}


# ===========================================================================
# Host
# ===========================================================================

def _format_banner(svc: dict) -> str:
    """Красивый banner для порта."""
    parts = []
    if svc.get("service_name"):
        parts.append(svc["service_name"])
    if svc.get("software"):
        for sw in svc["software"][:2]:
            parts.append(f"{sw.get('product', '?')}"
                         f" {sw.get('version', '')}".strip())
    if svc.get("banner"):
        b = svc["banner"].replace("\n", " ").replace("\r", "")[:60]
        parts.append(b)
    return " | ".join(parts)[:120]


def censys_host(ip: str) -> dict:
    """Информация о конкретном хосте."""
    console.print(f"[cyan]🔍 Censys host: {ip}[/cyan]")
    data = _request(CENSYS_HOST_URL.format(ip=ip))
    if not data:
        console.print(f"[yellow]Не найдено в Censys: {ip}[/yellow]")
        return {}

    result = data.get("result", {})
    loc = result.get("location", {}) or {}
    asn = result.get("autonomous_system", {}) or {}

    # Мета
    meta = Table(title=f"🌐 Censys host: {ip}")
    meta.add_column("Поле", style="cyan", width=18)
    meta.add_column("Значение", style="green")
    meta.add_row("IP", ip)
    meta.add_row("Country", loc.get("country", "?"))
    meta.add_row("City", loc.get("city", "—"))
    meta.add_row("ASN", f"AS{asn.get('asn', '?')}")
    meta.add_row("AS Name", asn.get("name", "—"))
    meta.add_row("OS", (result.get("operating_system") or {}).get(
        "product", "—"))
    if result.get("last_updated_at"):
        meta.add_row("Last updated", result["last_updated_at"])
    console.print(meta)

    # Порты
    services = result.get("services", []) or []
    t = Table(title=f"🔌 Порты ({len(services)})")
    t.add_column("Port", style="cyan", width=6)
    t.add_column("Proto", width=6)
    t.add_column("Service", style="magenta", width=12)
    t.add_column("Banner", max_width=80)
    for svc in services:
        t.add_row(
            str(svc.get("port", "?")),
            svc.get("transport_protocol", "tcp"),
            svc.get("service_name", "?")[:12],
            _format_banner(svc),
        )
    console.print(t)

    # Находки
    ports = {s.get("port") for s in services}
    dangerous = {27017, 6379, 9200, 11211, 5984, 2375, 5432, 3306,
                  1433, 9042, 2379, 7001, 8443}
    exposed = dangerous & ports
    if exposed:
        console.print(f"[red]⚠ Опасные порты: {sorted(exposed)}[/red]")
        _save_finding(CensysFinding(
            kind="exposed_services",
            severity="high",
            title=f"Censys: {ip} exposes {len(exposed)} sensitive ports",
            target=ip,
            evidence=f"Ports: {sorted(exposed)}",
            data={"ports": list(exposed)},
        ))

    db.save_scan("censys_host", ip, {
        "ports": sorted(ports),
        "services_count": len(services),
        "country": loc.get("country"),
        "asn": asn.get("asn"),
    })
    return result


# ===========================================================================
# Certificate
# ===========================================================================

def censys_cert(sha256: str) -> dict:
    """Информация о сертификате по SHA-256."""
    console.print(f"[cyan]🔍 Censys certificate: {sha256[:32]}…[/cyan]")
    data = _request(CENSYS_CERT_URL.format(sha=sha256))
    if not data:
        console.print("[yellow]Сертификат не найден.[/yellow]")
        return {}

    result = data.get("result", {})
    names = result.get("names", []) or []
    issuer = (result.get("issuer") or {}).get("common_name", "?")
    subject = (result.get("subject") or {}).get("common_name", "?")

    t = Table(title="📜 Сертификат")
    t.add_column("Поле", style="cyan", width=18)
    t.add_column("Значение", style="green")
    t.add_row("Subject CN", subject)
    t.add_row("Issuer CN", issuer)
    t.add_row("Valid from", result.get("validity", {}).get(
        "start", "—"))
    t.add_row("Valid to", result.get("validity", {}).get("end", "—"))
    t.add_row("Names count", str(len(names)))
    t.add_row("Fingerprint", sha256[:32] + "…")
    console.print(t)

    if names:
        nt = Table(title=f"🌐 SAN / Names ({len(names)})")
        nt.add_column("#", style="dim", width=4)
        nt.add_column("Name", style="cyan")
        for i, n in enumerate(names[:50], 1):
            nt.add_row(str(i), n)
        console.print(nt)

    db.save_scan("censys_cert", sha256[:32], {
        "names": names[:200],
        "issuer": issuer,
        "subject": subject,
    })
    return result


def censys_cert_search(query: str, per_page: int = 20) -> list[dict]:
    """Поиск сертификатов по query."""
    console.print(f"[cyan]🔍 Censys cert search: {query}[/cyan]")
    data = _request(CENSYS_CERT_SEARCH_URL,
                    {"q": query, "per_page": per_page})
    if not data:
        return []

    result = data.get("result", {})
    total = result.get("total", 0)
    hits = result.get("hits", []) or []

    console.print(f"[green]Найдено сертификатов: {total}[/green]")

    t = Table(title=f"Certificates: {query[:60]}")
    t.add_column("#", style="dim", width=4)
    t.add_column("SHA-256", style="cyan", width=20)
    t.add_column("Issuer", style="green", max_width=25)
    t.add_column("Names", style="magenta", max_width=40)
    for i, h in enumerate(hits[:per_page], 1):
        sha = h.get("fingerprint_sha256", "?")
        iss = (h.get("issuer") or {}).get("common_name", "?")
        names = h.get("names", []) or []
        t.add_row(str(i), sha[:20] + "…", iss[:25],
                  ", ".join(names[:3])[:40])
    console.print(t)

    db.save_scan("censys_cert_search", query,
                 {"total": total, "hits": hits[:per_page]})
    return hits


# ===========================================================================
# Full scan (комбо)
# ===========================================================================

def full_scan(query: str, save_findings: bool = True) -> dict:
    """Поиск + агрегации + анализ опасных сервисов."""
    console.print(f"\n[bold cyan]═══ Censys Full Scan: {query} "
                  f"═══[/bold cyan]\n")

    hits = censys_search(query, per_page=50, save_findings=save_findings)

    console.print()
    aggregate_asn = censys_aggregate(query, "autonomous_system.asn", 10)
    console.print()
    aggregate_country = censys_aggregate(query, "location.country", 10)

    result = {
        "query": query,
        "hits": hits,
        "aggregate_asn": aggregate_asn,
        "aggregate_country": aggregate_country,
        "ts": datetime.now().isoformat(),
    }

    # Save JSON
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(c if c.isalnum() else "_" for c in query)[:40]
    out = CENSYS_DIR / f"full_{safe}_{ts}.json"
    try:
        out.write_text(json.dumps(result, indent=2, ensure_ascii=False,
                                   default=str), encoding="utf-8")
        console.print(f"\n[green]✓ {out}[/green]")
    except Exception as exc:
        log.warning("save: %s", exc)

    return result


# ===========================================================================
# Export
# ===========================================================================

def export_json(data: Any, name: str,
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(CENSYS_DIR / f"{name}_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]JSON: {exc}[/red]")
        return None


def export_csv(hits: list[dict], name: str = "censys",
               path: str | None = None) -> Path | None:
    if not hits:
        return None
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(CENSYS_DIR / f"{name}_{ts}.csv")
    cols = ["ip", "country", "city", "asn", "as_name",
            "ports", "services_count"]
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for h in hits:
                loc = h.get("location") or {}
                asn = h.get("autonomous_system") or {}
                services = h.get("services") or []
                w.writerow([
                    h.get("ip", ""),
                    loc.get("country", ""),
                    loc.get("city", ""),
                    asn.get("asn", ""),
                    asn.get("name", ""),
                    ";".join(str(s.get("port")) for s in services),
                    len(services),
                ])
        console.print(f"[green]✓ CSV: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]CSV: {exc}[/red]")
        return None


def export_html(hits: list[dict], query: str,
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = "".join(c if c.isalnum() else "_" for c in query)[:40]
        path = str(CENSYS_DIR / f"search_{safe}_{ts}.html")

    html = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>Censys: {html_mod.escape(query)}</title>",
        "<style>body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:24px;}h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}"
        "table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px;}"
        "th{background:#111;color:#00ff9c;padding:8px;border:1px solid #222;text-align:left;}"
        "td{padding:6px 8px;border:1px solid #222;word-break:break-all;}"
        "tr:nth-child(even){background:#0d0d0d;}"
        "</style></head><body>",
        f"<h1>🔍 Censys: {html_mod.escape(query)}</h1>",
        f"<p>Hits: {len(hits)}</p>",
        "<table><tr><th>IP</th><th>Country</th><th>City</th>"
        "<th>ASN</th><th>Ports</th></tr>",
    ]
    for h in hits:
        loc = h.get("location") or {}
        asn = h.get("autonomous_system") or {}
        services = h.get("services") or []
        ports = ", ".join(str(s.get("port")) for s in services)
        html.append(
            f"<tr><td>{html_mod.escape(h.get('ip', ''))}</td>"
            f"<td>{html_mod.escape(loc.get('country', ''))}</td>"
            f"<td>{html_mod.escape(loc.get('city', ''))}</td>"
            f"<td>AS{html_mod.escape(str(asn.get('asn', '')))} "
            f"{html_mod.escape(asn.get('name', '')[:30])}</td>"
            f"<td>{html_mod.escape(ports)}</td></tr>")
    html.append("</table></body></html>")
    try:
        Path(path).write_text("\n".join(html), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]HTML: {exc}[/red]")
        return None


# ===========================================================================
# CLI-обёртки (совместимы со старыми)
# ===========================================================================

def cli_search(query: str) -> None:
    hits = censys_search(query)
    if hits and Confirm.ask("Экспорт CSV?", default=False):
        export_csv(hits, name="search")


def cli_host(ip: str) -> None:
    censys_host(ip)


def cli_cert(sha: str) -> None:
    censys_cert(sha)


def cli_cert_search(query: str) -> None:
    censys_cert_search(query)


def cli_aggregate(query: str, field_: str = "autonomous_system.asn") -> None:
    censys_aggregate(query, field_)


def cli_full(query: str) -> None:
    full_scan(query)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🔍 Censys Integration[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Поиск хостов (query)"),
        ("2", "Инфо о хосте по IP"),
        ("3", "Инфо о сертификате по SHA-256"),
        ("4", "Поиск сертификатов (по CN/SAN)"),
        ("5", "Агрегация (top ASN)"),
        ("6", "Агрегация (top countries)"),
        ("7", "Full scan (search + agg + findings)"),
        ("8", "Экспорт CSV / JSON / HTML"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного пентеста.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        censys_search(Prompt.ask("Censys query",
                                  default="services.service_name: HTTP"))
    elif c == "2":
        censys_host(Prompt.ask("IP"))
    elif c == "3":
        censys_cert(Prompt.ask("SHA-256"))
    elif c == "4":
        censys_cert_search(Prompt.ask("Cert query (напр. "
                                       "names: example.com)"))
    elif c == "5":
        censys_aggregate(Prompt.ask("Query"), "autonomous_system.asn")
    elif c == "6":
        censys_aggregate(Prompt.ask("Query"), "location.country")
    elif c == "7":
        full_scan(Prompt.ask("Query"))
    elif c == "8":
        fmt = Prompt.ask("Формат", choices=["csv", "json", "html"],
                          default="csv")
        query = Prompt.ask("Query (или IP)")
        if fmt == "csv":
            hits = censys_search(query)
            export_csv(hits, name="search")
        elif fmt == "json":
            hits = censys_search(query)
            export_json(hits, "search")
        else:
            hits = censys_search(query)
            export_html(hits, query)