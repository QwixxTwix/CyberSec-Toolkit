"""
ШАБЛОН ПЛАГИНА CyberSec Toolkit.

Как использовать:
  1. Скопируй этот файл в plugins/my_plugin.py (убери _).
  2. Измени PLUGIN_INFO.
  3. Определи функции-действия.
  4. Заполни ACTIONS.
  5. Перезапусти toolkit (или нажми в TUI «reload»).

Действие должно принимать либо 0 аргументов, либо 1 (str).
Если плагин требует аргумент — укажи arg_hint (например "url", "target",
"hash", "path", "none").
"""

from rich.console import Console
from core.database import db


PLUGIN_INFO = {
    "name": "my_plugin",
    "version": "1.0",
    "author": "idqwixxa",
    "description": "Мой первый плагин",
}


def example_noarg() -> None:
    """Действие без аргументов."""
    console = Console()
    console.print("[green]Hello from my plugin![/green]")
    db.save_scan("plugin", "my_plugin.example_noarg", {"ok": True})


def example_witharg(target: str) -> None:
    """Действие с одним строковым аргументом."""
    console = Console()
    console.print(f"[cyan]Получен аргумент:[/cyan] {target}")
    db.save_scan("plugin", f"my_plugin.example_witharg:{target}", {"ok": True})


ACTIONS = [
    {
        "name": "hello",
        "description": "Показать приветствие",
        "func": example_noarg,
        "arg_hint": "none",
    },
    {
        "name": "echo",
        "description": "Повторить аргумент",
        "func": example_witharg,
        "arg_hint": "target",
    },
]