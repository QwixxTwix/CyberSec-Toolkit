"""Пример плагина: информация об IP (ASN, страна, reverse DNS)."""
import socket
import requests

from rich.console import Console
from rich.table import Table

from core.config import config
from core.database import db
from core.logger import get_logger

log = get_logger(__name__)


PLUGIN_INFO = {
    "name": "ip_info",
    "version": "1.0",
    "author": "idqwixxa",
    "description": "Дополнительная информация об IP через ipapi.co",
}


def lookup(ip: str) -> None:
    """Расширенный lookup IP."""
    console = Console()
    ip = ip.strip()
    if not ip:
        console.print("[red]Пустой IP.[/red]")
        return

    console.print(f"[cyan]🔍 Смотрю информацию о {ip}…[/cyan]")
    data: dict = {}
    try:
        r = requests.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=config.REQUEST_TIMEOUT,
            headers={"User-Agent": config.USER_AGENT},
        )
        r.raise_for_status()
        data = r.json()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка запроса: {exc}[/red]")
        return

    if data.get("error"):
        console.print(f"[red]ipapi.co: {data.get('reason', 'ошибка')}[/red]")
        return

    table = Table(title=f"🌍 IP Info — {ip}")
    table.add_column("Поле", style="cyan")
    table.add_column("Значение", style="green")
    for k in ("ip", "version", "city", "region", "country_name",
              "country_code", "postal", "latitude", "longitude",
              "timezone", "org", "asn", "currency", "languages"):
        if k in data and data[k] is not None:
            table.add_row(k, str(data[k]))

    # reverse DNS
    try:
        reverse = socket.gethostbyaddr(ip)[0]
        table.add_row("reverse_dns", reverse)
    except Exception:  # noqa: BLE001
        table.add_row("reverse_dns", "—")

    console.print(table)
    db.save_scan("plugin", f"ip_info.lookup:{ip}", data)


ACTIONS = [
    {
        "name": "lookup",
        "description": "Информация об IP (ASN, страна, DNS)",
        "func": lookup,
        "arg_hint": "ip",
    },
]