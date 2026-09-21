"""Пример плагина: приветствие + информация о системе."""
import platform
import socket
from datetime import datetime

from rich.console import Console
from rich.table import Table

from core.database import db
from core.config import config


PLUGIN_INFO = {
    "name": "hello",
    "version": "1.0",
    "author": "idqwixxa",
    "description": "Приветствие и информация о системе",
}


def say_hi() -> None:
    """Просто здоровается."""
    console = Console()
    console.print("[bold cyan]╔══ Hello from plugin! ══╗[/bold cyan]")
    console.print(f"[magenta]by idqwixxa  •  {datetime.now():%Y-%m-%d %H:%M}[/magenta]")
    db.save_scan("plugin", "hello.say_hi", {"ts": datetime.now().isoformat()})


def sys_info() -> None:
    """Информация о системе."""
    console = Console()
    table = Table(title="🖥  System Info")
    table.add_column("Параметр", style="cyan")
    table.add_column("Значение", style="green")
    table.add_row("OS", platform.platform())
    table.add_row("Python", platform.python_version())
    table.add_row("Hostname", socket.gethostname())
    try:
        table.add_row("Local IP", socket.gethostbyname(socket.gethostname()))
    except Exception:  # noqa: BLE001
        table.add_row("Local IP", "—")
    table.add_row("Notify enabled", "✓" if config.NOTIFY_ENABLED else "—")
    table.add_row("Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    console.print(table)
    db.save_scan("plugin", "hello.sys_info", {"host": socket.gethostname()})


def greet(name: str) -> None:
    """Поздороваться по имени."""
    console = Console()
    console.print(f"[bold green]Привет, {name}! 👋[/bold green]")
    console.print("[dim]Рад видеть тебя в CyberSec Toolkit.[/dim]")
    db.save_scan("plugin", f"hello.greet:{name}", {"name": name})


ACTIONS = [
    {
        "name": "hi",
        "description": "Приветствие",
        "func": say_hi,
        "arg_hint": "none",
    },
    {
        "name": "sysinfo",
        "description": "Информация о системе",
        "func": sys_info,
        "arg_hint": "none",
    },
    {
        "name": "greet",
        "description": "Поздороваться по имени",
        "func": greet,
        "arg_hint": "username",
    },
]