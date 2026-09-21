"""
Загрузчик плагинов CyberSec Toolkit.

Плагин — это .py файл в папке `plugins/`, в котором определены:
    PLUGIN_INFO = {
        "name": "my_plugin",
        "version": "1.0",
        "author": "your_name",
        "description": "Что делает плагин",
    }

    ACTIONS = [
        {
            "name": "hello",                # уникальное имя действия
            "description": "Поздороваться", # показывается в меню
            "func": hello_func,             # callable(arg: str|None)
            "arg_hint": "none",             # none | target | url | hash | path | ...
        },
        ...
    ]

Загрузчик:
    - сканирует plugins/
    - импортирует каждый .py
    - собирает все ACTIONS
    - поддерживает hot-reload (reload_plugins())
"""
import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Callable, Any

from core.config import BASE_DIR
from core.logger import get_logger

log = get_logger(__name__)

PLUGINS_DIR = BASE_DIR / "plugins"
PLUGINS_DIR.mkdir(exist_ok=True)

# Глобальный реестр: {plugin_name: {info, actions, path, module}}
_registry: dict[str, dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------

def _load_plugin_module(path: Path) -> Any | None:
    """Импортировать модуль плагина из файла."""
    if not path.exists():
        return None
    mod_name = f"cybertoolkit_plugins_{path.stem}"
    try:
        # Если уже импортирован — перезагрузим
        if mod_name in sys.modules:
            return importlib.reload(sys.modules[mod_name])

        spec = importlib.util.spec_from_file_location(mod_name, path)
        if spec is None or spec.loader is None:
            log.warning("Не удалось создать spec для %s", path)
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = module
        spec.loader.exec_module(module)
        return module
    except Exception as exc:  # noqa: BLE001
        log.exception("Ошибка загрузки плагина %s: %s", path.name, exc)
        return None


def _validate_action(action: dict) -> bool:
    """Проверить корректность объявления действия."""
    required = ("name", "description", "func")
    if not isinstance(action, dict):
        return False
    for key in required:
        if key not in action:
            return False
    if not callable(action["func"]):
        return False
    return True


# ---------------------------------------------------------------------------
# Публичный API
# ---------------------------------------------------------------------------

def load_plugins(force_reload: bool = False) -> dict[str, dict[str, Any]]:
    """
    Сканировать plugins/ и собрать реестр.
    force_reload=True — перечитать все модули заново (hot-reload).
    Возвращает реестр.
    """
    global _registry
    _registry = {}

    if force_reload:
        # Удалим старые модули из sys.modules, чтобы importlib перечитал их
        for name in list(sys.modules.keys()):
            if name.startswith("cybertoolkit_plugins_"):
                del sys.modules[name]

    py_files = sorted(p for p in PLUGINS_DIR.glob("*.py")
                      if not p.name.startswith("_"))

    for path in py_files:
        module = _load_plugin_module(path)
        if module is None:
            continue

        info = getattr(module, "PLUGIN_INFO", {}) or {}
        actions_raw = getattr(module, "ACTIONS", []) or []

        plugin_name = info.get("name") or path.stem
        actions: list[dict] = []

        for a in actions_raw:
            if not _validate_action(a):
                log.warning("Плагин %s: некорректное действие %r",
                            plugin_name, a)
                continue
            actions.append({
                "name": a["name"],
                "description": a.get("description", ""),
                "func": a["func"],
                "arg_hint": a.get("arg_hint", "none"),
            })

        _registry[plugin_name] = {
            "name": plugin_name,
            "version": info.get("version", "?"),
            "author": info.get("author", "anon"),
            "description": info.get("description", ""),
            "path": str(path),
            "module": module,
            "actions": actions,
        }
        log.info("Плагин загружен: %s (%d действий)",
                 plugin_name, len(actions))

    return _registry


def reload_plugins() -> dict[str, dict[str, Any]]:
    """Hot-reload всех плагинов."""
    return load_plugins(force_reload=True)


def get_registry() -> dict[str, dict[str, Any]]:
    """Вернуть текущий реестр (или загрузить, если пусто)."""
    if not _registry:
        load_plugins()
    return _registry


def get_plugin(name: str) -> dict[str, Any] | None:
    """Найти плагин по имени."""
    return get_registry().get(name)


def get_all_actions() -> list[dict]:
    """
    Плоский список всех действий из всех плагинов.
    Каждое: {"plugin": ..., "action": ..., "description": ...,
             "func": ..., "arg_hint": ...}
    """
    out: list[dict] = []
    for pname, pdata in get_registry().items():
        for act in pdata["actions"]:
            out.append({
                "plugin": pname,
                "action": act["name"],
                "description": act["description"],
                "func": act["func"],
                "arg_hint": act["arg_hint"],
                "key": f"plugin.{pname}.{act['name']}",
            })
    return out


def run_action(plugin_name: str, action_name: str,
               arg: str | None = None) -> bool:
    """
    Запустить действие плагина.
    Возвращает True, если удалось.
    """
    plugin = get_plugin(plugin_name)
    if not plugin:
        return False
    act = next((a for a in plugin["actions"] if a["name"] == action_name), None)
    if not act:
        return False
    try:
        func: Callable = act["func"]
        if arg is None:
            func()
        else:
            func(arg)
        return True
    except Exception as exc:  # noqa: BLE001
        log.exception("Плагин %s.%s: %s", plugin_name, action_name, exc)
        return False


def plugin_menu() -> None:
    """Интерактивное меню плагинов (для CLI)."""
    from rich.console import Console
    from rich.table import Table
    from rich.prompt import Prompt

    console = Console()
    reload_plugins()

    table = Table(title="[bold]🧩 Плагины CyberSec Toolkit[/bold]")
    table.add_column("#", style="yellow", width=4)
    table.add_column("Плагин", style="cyan")
    table.add_column("Версия", style="dim")
    table.add_column("Автор", style="magenta")
    table.add_column("Действий", style="green")
    table.add_column("Описание", style="white")

    plugins = list(get_registry().values())
    if not plugins:
        console.print("[yellow]Плагинов нет.[/yellow]")
        console.print(f"[dim]Клади .py в: {PLUGINS_DIR}[/dim]")
        console.print("[dim]Шаблон: plugins/_template.py[/dim]")
        return

    for i, p in enumerate(plugins, 1):
        table.add_row(
            str(i),
            p["name"],
            p["version"],
            p["author"],
            str(len(p["actions"])),
            p["description"][:50] or "—",
        )
    console.print(table)

    # --- Второй уровень: действия выбранного плагина ---
    choice = Prompt.ask("Плагин (номер или Enter для выхода)",
                        default="").strip()
    if not choice.isdigit():
        return
    idx = int(choice) - 1
    if not (0 <= idx < len(plugins)):
        console.print("[red]Неверный номер.[/red]")
        return
    plugin = plugins[idx]

    if not plugin["actions"]:
        console.print("[yellow]У плагина нет действий.[/yellow]")
        return

    act_table = Table(title=f"[bold]{plugin['name']}[/bold] — действия")
    act_table.add_column("#", style="yellow", width=4)
    act_table.add_column("Действие", style="cyan")
    act_table.add_column("Описание", style="white")
    act_table.add_column("Аргумент", style="dim")
    for i, a in enumerate(plugin["actions"], 1):
        act_table.add_row(str(i), a["name"], a["description"], a["arg_hint"])
    console.print(act_table)

    act_choice = Prompt.ask("Действие", default="").strip()
    if not act_choice.isdigit():
        return
    aidx = int(act_choice) - 1
    if not (0 <= aidx < len(plugin["actions"])):
        console.print("[red]Неверный номер.[/red]")
        return
    action = plugin["actions"][aidx]

    arg: str | None = None
    if action["arg_hint"] != "none":
        arg = Prompt.ask(f"Аргумент ({action['arg_hint']})").strip() or None

    console.print(f"\n[cyan]▶ {plugin['name']}.{action['name']}[/cyan]\n")
    try:
        if arg is None:
            action["func"]()
        else:
            action["func"](arg)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")


def list_plugins_cli() -> None:
    """Просто вывести список плагинов (для CLI-команды)."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    reload_plugins()
    plugins = list(get_registry().values())
    if not plugins:
        console.print("[yellow]Плагинов нет.[/yellow]")
        console.print(f"[dim]Папка: {PLUGINS_DIR}[/dim]")
        return
    table = Table(title="🧩 Плагины")
    table.add_column("Плагин", style="cyan")
    table.add_column("Версия")
    table.add_column("Автор", style="magenta")
    table.add_column("Действия", style="green")
    for p in plugins:
        actions = ", ".join(a["name"] for a in p["actions"]) or "—"
        table.add_row(p["name"], p["version"], p["author"], actions)
    console.print(table)


def run_plugin_cli(key: str, arg: str | None = None) -> bool:
    """
    Запустить плагин по ключу 'plugin_name.action_name' (CLI).
    Например: run_plugin_cli("hello.say_hi")
    """
    from rich.console import Console

    console = Console()
    reload_plugins()
    if "." not in key:
        console.print(f"[red]Формат: <plugin>.<action>, получено: {key}[/red]")
        return False
    plugin_name, action_name = key.split(".", 1)
    console.print(f"[cyan]▶ {plugin_name}.{action_name}[/cyan]\n")
    ok = run_action(plugin_name, action_name, arg)
    if not ok:
        console.print("[red]Плагин или действие не найдены.[/red]")
        console.print("[dim]Список: python main.py plugins[/dim]")
    return ok