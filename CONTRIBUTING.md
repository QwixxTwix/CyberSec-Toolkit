# Contributing

Спасибо, что хочешь помочь! 🎉

## Как добавить новый модуль

1. Создай `modules/my_module.py`:

```python
"""Мой модуль."""
from rich.console import Console
from rich.prompt import Prompt
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


def my_feature(target: str) -> None:
    """Что делает функция."""
    console.print(f"[cyan]Обрабатываю {target}...[/cyan]")
    result = {"ok": True}
    db.save_scan("my_module", target, result)


def menu() -> None:
    """Меню (для CLI-интеграции)."""
    target = Prompt.ask("Target")
    my_feature(target)