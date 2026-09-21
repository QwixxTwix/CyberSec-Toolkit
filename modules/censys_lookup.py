"""
Censys API интеграция: поиск хостов, сервисов, сертификатов.
Требует CENSYS_API_ID и CENSYS_API_SECRET в .env
Документация: https://search.censys.io/api
"""
import base64
from typing import Any

import requests
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from core.config import config
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

CENSYS_SEARCH_URL = "https://search.censys.io/api/v2/hosts/search"
CENSYS_HOST_URL = "https://search.censys.io/api/v2/hosts/{ip}"
CENSYS_CERT_URL = "https://search.censys.io/api/v2/certificates/{sha}"


def _auth_header() -> dict[str, str] | None:
    """Собрать Basic Auth для Censys."""
    if not config.CENSYS_API_ID or not config.CENSYS_API_SECRET:
        console.print(
            "[yellow]CENSYS_API_ID / CENSYS_API_SECRET не заданы в .env[/yellow]"
        )
        console.print(
            "[cyan]Получить ключи: https://search.censys.io/account/api[/cyan]"
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


def _request(url: str, params: dict | None = None) -> dict[str, Any] | None:
    """Запрос к Censys."""
    headers = _auth_header()
    if not headers:
        return None
    try:
        r = requests.get(
            url,
            headers=headers,
            params=params or {},
            timeout=config.REQUEST_TIMEOUT,
        )
        if r.status_code == 401:
            console.print("[red]401 Unauthorized: проверь CENSYS_API_ID / SECRET[/red]")
            return None
        if r.status_code == 429:
            console.print("[red]429 Too Many Requests: превышен лимит Censys[/red]")
            return None
        r.raise_for_status()
        return r.json()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Censys ошибка: {exc}[/red]")
        log.error("Censys error: %s", exc)
        return None


def censys_search(query: str) -> None:
    """Поиск хостов в Censys."""
    console.print(f"[cyan]Censys search: {query}[/cyan]")
    data = _request(CENSYS_SEARCH_URL, {"q": query, "per_page": 25})
    if not data:
        return

    result = data.get("result", {})
    total = result.get("total", 0)
    hits = result.get("hits", [])

    console.print(f"[green]Всего найдено: {total}[/green]")

    table = Table(title=f"Censys: {query}")
    table.add_column("IP", style="cyan")
    table.add_column("Country", style="green")
    table.add_column("Services", style="magenta")
    table.add_column("ASN / Org")

    for h in hits[:25]:
        ip = h.get("ip", "?")
        loc = h.get("location", {}) or {}
        country = loc.get("country", "?")
        services = h.get("services", []) or []
        svc = ", ".join(
            f"{s.get('port')}/{s.get('service_name', '?')}" for s in services[:5]
        )
        asn = h.get("autonomous_system", {}) or {}
        as_str = f"{asn.get('asn', '?')} / {asn.get('name', '?')}"
        table.add_row(ip, country, svc or "—", as_str)
    console.print(table)

    db.save_scan("censys_search", query, {"total": total, "hits": hits[:25]})


def censys_host(ip: str) -> None:
    """Информация о конкретном хосте."""
    console.print(f"[cyan]Censys host: {ip}[/cyan]")
    data = _request(CENSYS_HOST_URL.format(ip=ip))
    if not data:
        return
    result = data.get("result", {})
    console.print(f"[bold green]Host: {ip}[/bold green]")

    table = Table(title=f"Порты {ip}")
    table.add_column("Порт", style="cyan")
    table.add_column("Сервис", style="green")
    table.add_column("Banner / Product")

    for svc in result.get("services", []) or []:
        port = svc.get("port", "?")
        name = svc.get("service_name", "?")
        banner = (svc.get("banner") or "").replace("\n", " ")[:100]
        table.add_row(str(port), name, banner)
    console.print(table)

    loc = result.get("location", {}) or {}
    console.print(
        f"[cyan]Country:[/cyan] {loc.get('country', '?')}  "
        f"[cyan]City:[/cyan] {loc.get('city', '?')}  "
        f"[cyan]ASN:[/cyan] {(result.get('autonomous_system') or {}).get('asn', '?')}"
    )
    db.save_scan("censys_host", ip, result)


def censys_cert(sha256: str) -> None:
    """Информация о сертификате по SHA-256."""
    console.print(f"[cyan]Censys certificate: {sha256}[/cyan]")
    data = _request(CENSYS_CERT_URL.format(sha=sha256))
    if not data:
        return
    result = data.get("result", {})
    names = result.get("names", []) or []
    issuer = (result.get("issuer") or {}).get("common_name", "?")
    console.print(f"[green]Issuer:[/green] {issuer}")
    console.print(f"[green]Имён в сертификате:[/green] {len(names)}")
    for n in names[:50]:
        console.print(f"  [cyan]{n}[/cyan]")
    db.save_scan("censys_cert", sha256, result)


def menu() -> None:
    """Меню Censys."""
    table = Table(title="[bold]Censys[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Поиск хостов (query)"),
        ("2", "Инфо о хосте по IP"),
        ("3", "Инфо о сертификате по SHA-256"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])
    if c == "1":
        censys_search(Prompt.ask("Censys query", default="services.service_name: HTTP"))
    elif c == "2":
        censys_host(Prompt.ask("IP"))
    elif c == "3":
        censys_cert(Prompt.ask("SHA-256 сертификата"))