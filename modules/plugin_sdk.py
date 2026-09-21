"""
Plugin SDK Pro — генератор плагинов + marketplace-стиль.
Author: idqwixxa

Возможности:
    ─── Templates ───
    - basic     — hello-world плагин
    - network   — скан портов
    - web       — HTTP/headers/links
    - crypto    — хеширование / кодирование
    - forensics — IOC analysis
    - recon     — внешний recon (DNS/whois)
    - custom    — пустой скелет

    ─── Generator ───
    - Создание с авто-валидацией синтаксиса
    - Опциональная авто-загрузка в loader
    - Оverwrite warning + backup

    ─── Validation ───
    - Проверка PLUGIN_INFO / ACTIONS / callable
    - Проверка arg_hint против whitelist
    - Проверка на дубликаты name
    - Синтаксическая проверка (py_compile)

    ─── Export / Import ───
    - Экспорт всех плагинов в zip
    - Импорт из zip
    - Экспорт одного плагина в JSON (для шаринга)

    ─── Documentation ───
    - Встроенный гайд API
    - Примеры каждой категории

⚠ Только для авторизованного пентеста / CTF.
"""
import json
import py_compile
import re
import shutil
import zipfile
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.syntax import Syntax

from core.config import BASE_DIR, REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

PLUGINS_DIR = BASE_DIR / "plugins"
PLUGINS_DIR.mkdir(exist_ok=True)

SDK_DIR = REPORT_DIR / "plugin_sdk"
SDK_DIR.mkdir(parents=True, exist_ok=True)

# Whitelist arg_hint'ов (синхронизировано с tui/app.py)
ARG_HINTS = (
    "none", "target", "url", "host", "domain", "hash", "path",
    "query", "username", "email", "phone", "ip", "sha", "network",
    "word", "number", "any",
)


# ===========================================================================
# Templates
# ===========================================================================

TEMPLATE_BASIC = '''"""
{description}
Author: {author}
Generated: {date}
"""
from rich.console import Console
from rich.table import Table

from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


PLUGIN_INFO = {{
    "name": "{name}",
    "version": "1.0",
    "author": "{author}",
    "description": "{description}",
}}


def hello() -> None:
    """Пример действия без аргументов."""
    console.print(f"[bold green]Hello from {name}![/bold green]")
    db.save_scan("plugin", "{name}.hello", {{"ok": True}})


def process(target: str) -> None:
    """Пример действия с аргументом.

    Args:
        target: домен / URL / IP / hash — что угодно
    """
    console.print(f"[cyan]Обрабатываю:[/cyan] {{target}}")
    result = {{"target": target, "processed": True}}
    db.save_scan("plugin", f"{name}.process:{{target}}", result)
    console.print(f"[green]✓ Готово[/green]")


ACTIONS = [
    {{
        "name": "hello",
        "description": "Приветствие",
        "func": hello,
        "arg_hint": "none",
    }},
    {{
        "name": "process",
        "description": "Обработка цели",
        "func": process,
        "arg_hint": "target",
    }},
]
'''


TEMPLATE_NETWORK = '''"""
{description}
Author: {author}
Network plugin — работает с сетевыми целями.
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.table import Table

from core.config import config
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


PLUGIN_INFO = {{
    "name": "{name}",
    "version": "1.0",
    "author": "{author}",
    "description": "{description}",
}}


def _check_port(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def scan(target: str) -> None:
    """Скан портов (top-20)."""
    host = target.split("/")[0].split(":")[0]
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
             3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]
    console.print(f"[cyan]Скан {{host}} ({{len(ports)}} портов)[/cyan]")

    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = {{ex.submit(_check_port, host, p): p for p in ports}}
        for f in as_completed(futs):
            if f.result():
                open_ports.append(futs[f])

    t = Table(title=f"Открытые порты {{host}}")
    t.add_column("Port", style="green")
    for p in sorted(open_ports):
        t.add_row(str(p))
    console.print(t)
    db.save_scan("plugin", f"{name}.scan:{{host}}",
                 {{"open_ports": sorted(open_ports)}})


ACTIONS = [
    {{
        "name": "scan",
        "description": "Скан портов",
        "func": scan,
        "arg_hint": "target",
    }},
]
'''


TEMPLATE_WEB = '''"""
{description}
Author: {author}
Web plugin — работает с URL.
"""
import re
import requests
from rich.console import Console
from rich.table import Table

from core.config import config
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


PLUGIN_INFO = {{
    "name": "{name}",
    "version": "1.0",
    "author": "{author}",
    "description": "{description}",
}}


def fetch(url: str) -> None:
    """Загрузить URL и показать заголовки."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        r = requests.get(url, timeout=15, verify=False,
                         headers={{"User-Agent": config.USER_AGENT}},
                         allow_redirects=True)
    except Exception as exc:
        console.print(f"[red]Ошибка: {{exc}}[/red]")
        return

    t = Table(title=f"{{url}} — {{r.status_code}}")
    t.add_column("Header", style="cyan")
    t.add_column("Value", style="green", max_width=70)
    for k, v in r.headers.items():
        t.add_row(k, v[:70])
    console.print(t)

    db.save_scan("plugin", f"{name}.fetch:{{url}}",
                 {{"status": r.status_code, "len": len(r.content)}})


def extract_links(url: str) -> None:
    """Извлечь все ссылки с страницы."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        r = requests.get(url, timeout=15, verify=False,
                         headers={{"User-Agent": config.USER_AGENT}})
    except Exception as exc:
        console.print(f"[red]{{exc}}[/red]")
        return
    links = sorted(set(re.findall(r'href=["\\']([^"\\']+)["\\']', r.text)))
    console.print(f"[cyan]Найдено {{len(links)}} ссылок[/cyan]")
    for l in links[:50]:
        console.print(f"  [green]{{l}}[/green]")
    db.save_scan("plugin", f"{name}.links:{{url}}",
                 {{"count": len(links)}})


ACTIONS = [
    {{
        "name": "fetch",
        "description": "Загрузить URL + заголовки",
        "func": fetch,
        "arg_hint": "url",
    }},
    {{
        "name": "links",
        "description": "Извлечь ссылки со страницы",
        "func": extract_links,
        "arg_hint": "url",
    }},
]
'''


TEMPLATE_CRYPTO = '''"""
{description}
Author: {author}
Crypto plugin — хеширование / кодирование / шифрование.
"""
import base64
import hashlib
import urllib.parse

from rich.console import Console
from rich.table import Table

from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


PLUGIN_INFO = {{
    "name": "{name}",
    "version": "1.0",
    "author": "{author}",
    "description": "{description}",
}}


def hash_all(text: str) -> None:
    """Все хеши строки."""
    b = text.encode("utf-8")
    t = Table(title=f"Hashes of '{{text[:30]}}'")
    t.add_column("Algo", style="cyan")
    t.add_column("Hash", style="green", max_width=70)
    algos = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512",
             "sha3_256", "sha3_512", "blake2b", "blake2s"]
    for a in algos:
        try:
            t.add_row(a, hashlib.new(a, b).hexdigest())
        except Exception:
            pass
    console.print(t)
    db.save_scan("plugin", f"{name}.hash:{{text[:20]}}", {{}})


def b64_all(text: str) -> None:
    """Base64/hex/url кодирование."""
    t = Table(title=f"Encoded '{{text[:30]}}'")
    t.add_column("Format", style="cyan")
    t.add_column("Value", style="green")
    t.add_row("base64",
              base64.b64encode(text.encode()).decode())
    t.add_row("base64url",
              base64.urlsafe_b64encode(text.encode()).decode())
    t.add_row("hex", text.encode().hex())
    t.add_row("url", urllib.parse.quote(text))
    t.add_row("url-double",
              urllib.parse.quote(urllib.parse.quote(text)))
    console.print(t)


ACTIONS = [
    {{
        "name": "hash",
        "description": "Все хеши строки",
        "func": hash_all,
        "arg_hint": "word",
    }},
    {{
        "name": "b64",
        "description": "Base64/hex/url кодирование",
        "func": b64_all,
        "arg_hint": "word",
    }},
]
'''


TEMPLATE_FORENSICS = '''"""
{description}
Author: {author}
Forensics plugin — IOC extractor из файлов.
"""
import re
from pathlib import Path

from rich.console import Console
from rich.table import Table

from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


PLUGIN_INFO = {{
    "name": "{name}",
    "version": "1.0",
    "author": "{author}",
    "description": "{description}",
}}


IOC_PATTERNS = {{
    "urls": re.compile(r"https?://[^\\s\\"'<>]{{6,200}}"),
    "ips": re.compile(r"\\b(?:\\d{{1,3}}\\.){{3}}\\d{{1,3}}\\b"),
    "emails": re.compile(r"[\\w.\\-]+@[\\w.\\-]+\\.[a-z]{{2,24}}"),
    "hashes": re.compile(r"\\b[a-fA-F0-9]{{32,128}}\\b"),
}}


def extract_ioc(path_str: str) -> None:
    """Извлечь IOC из файла."""
    p = Path(path_str)
    if not p.exists():
        console.print(f"[red]Не найден: {{path_str}}[/red]")
        return
    try:
        data = p.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        console.print(f"[red]{{exc}}[/red]")
        return

    for cat, pat in IOC_PATTERNS.items():
        hits = sorted(set(pat.findall(data)))
        if not hits:
            continue
        t = Table(title=f"{{cat}} ({{len(hits)}})")
        t.add_column("#", width=4)
        t.add_column("Value", style="green")
        for i, h in enumerate(hits[:50], 1):
            t.add_row(str(i), h[:100])
        console.print(t)

    db.save_scan("plugin", f"{name}.ioc:{{p.name}}", {{}})


ACTIONS = [
    {{
        "name": "ioc",
        "description": "Extract IOC from file",
        "func": extract_ioc,
        "arg_hint": "path",
    }},
]
'''


TEMPLATE_RECON = '''"""
{description}
Author: {author}
Recon plugin — DNS/WHOIS/simple enumeration.
"""
import socket

import dns.resolver
from rich.console import Console
from rich.table import Table

from core.database import db
from core.logger import get_logger
from utils.helpers import extract_host

console = Console()
log = get_logger(__name__)


PLUGIN_INFO = {{
    "name": "{name}",
    "version": "1.0",
    "author": "{author}",
    "description": "{description}",
}}


def dns_all(domain: str) -> None:
    """Все DNS-записи."""
    host = extract_host(domain)
    t = Table(title=f"DNS: {{host}}")
    t.add_column("Type", style="cyan", width=8)
    t.add_column("Value", style="green", max_width=80)
    found = 0
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
        try:
            answers = dns.resolver.resolve(host, rtype, lifetime=5)
            for a in answers:
                t.add_row(rtype, str(a)[:80])
                found += 1
        except Exception:
            continue
    console.print(t if found else "[yellow]Ничего не найдено.[/yellow]")
    db.save_scan("plugin", f"{name}.dns:{{host}}", {{}})


ACTIONS = [
    {{
        "name": "dns",
        "description": "DNS enumeration",
        "func": dns_all,
        "arg_hint": "domain",
    }},
]
'''


TEMPLATE_CUSTOM = '''"""
{description}
Author: {author}
Custom plugin — пустой скелет.

Документация API: python main.py sdk-docs
"""
from rich.console import Console

from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


PLUGIN_INFO = {{
    "name": "{name}",
    "version": "1.0",
    "author": "{author}",
    "description": "{description}",
}}


def my_action(arg: str) -> None:
    """Реализуй свою логику здесь.

    Args:
        arg: значение из поля ввода TUI/CLI
    """
    console.print(f"[cyan]Твой код → {{arg}}[/cyan]")
    # TODO: implement
    db.save_scan("plugin", f"{name}.my_action:{{arg}}", {{"arg": arg}})
    console.print("[green]✓ Done[/green]")


ACTIONS = [
    {{
        "name": "my_action",
        "description": "Описание действия",
        "func": my_action,
        "arg_hint": "any",
    }},
]
'''


TEMPLATES = {
    "basic": TEMPLATE_BASIC,
    "network": TEMPLATE_NETWORK,
    "web": TEMPLATE_WEB,
    "crypto": TEMPLATE_CRYPTO,
    "forensics": TEMPLATE_FORENSICS,
    "recon": TEMPLATE_RECON,
    "custom": TEMPLATE_CUSTOM,
}


# ===========================================================================
# Generator
# ===========================================================================

def _slugify(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_]", "_", name.lower()).strip("_")
    return s or "my_plugin"


def generate_plugin(name: str, template: str = "basic",
                    author: str = "anon",
                    description: str = "",
                    overwrite: bool = False) -> Path | None:
    """Сгенерировать новый плагин."""
    slug = _slugify(name)
    out = PLUGINS_DIR / f"{slug}.py"

    if out.exists() and not overwrite:
        console.print(f"[red]Плагин {out} уже существует.[/red]")
        if not Confirm.ask("Перезаписать (старая версия будет сохранена "
                           "как .bak)?", default=False):
            return None
        # Backup
        backup = out.with_suffix(".py.bak")
        try:
            shutil.copy(out, backup)
            console.print(f"[yellow]Backup: {backup}[/yellow]")
        except Exception as exc:
            console.print(f"[red]Backup fail: {exc}[/red]")

    tpl = TEMPLATES.get(template)
    if not tpl:
        console.print(f"[red]Шаблон {template} не найден.[/red]")
        console.print(f"[dim]Доступно: {', '.join(TEMPLATES)}[/dim]")
        return None

    if not description:
        description = f"Плагин {name}"

    try:
        content = tpl.format(
            name=slug,
            author=author,
            description=description,
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Шаблон format: {exc}[/red]")
        return None

    # Синтаксическая валидация (compile перед записью)
    try:
        compile(content, f"<generated:{slug}>", "exec")
    except SyntaxError as exc:
        console.print(f"[red]Шаблон содержит синтаксическую ошибку: {exc}[/red]")
        return None

    try:
        out.write_text(content, encoding="utf-8")
        console.print(f"[green]✓ Создан: {out}[/green]")
        console.print(f"\n[cyan]Что дальше:[/cyan]")
        console.print(f"  1. Открой файл: [green]{out}[/green]")
        console.print(f"  2. Реализуй функции в ACTIONS")
        console.print(f"  3. Перезагрузи плагины: "
                      f"[green]python main.py plugins-reload[/green]")
        console.print(f"  4. Запусти: "
                      f"[green]python main.py plugin-run {slug}.<action>[/green]")
        db.save_scan("plugin_sdk", f"generate:{slug}",
                     {"template": template, "path": str(out)})
        return out
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка записи: {exc}[/red]")
        return None


# ===========================================================================
# Validation
# ===========================================================================

@dataclass
class ValidationResult:
    file: str
    valid: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    actions_count: int = 0
    info: dict = field(default_factory=dict)


def validate_plugin(path: Path) -> ValidationResult:
    """Валидация структуры плагина."""
    r = ValidationResult(file=str(path))
    if not path.exists():
        r.errors.append("Файл не существует")
        return r

    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        r.errors.append(f"Чтение: {exc}")
        return r

    # 1. Синтаксическая проверка через compile (без исполнения)
    try:
        compile(text, str(path), "exec")
    except SyntaxError as exc:
        r.errors.append(f"Syntax error: {exc}")
        return r  # нет смысла идти дальше

    # 2. PLUGIN_INFO
    if "PLUGIN_INFO" not in text:
        r.errors.append("Нет PLUGIN_INFO")
    if "ACTIONS" not in text:
        r.errors.append("Нет ACTIONS")
    if r.errors:
        return r

    # 3. Динамический импорт (в отдельном namespace)
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            f"_sdk_validate_{path.stem}", path)
        if not spec or not spec.loader:
            r.errors.append("Не могу создать spec")
            return r
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except Exception as exc:  # noqa: BLE001
        r.errors.append(f"Import: {exc}")
        return r

    # PLUGIN_INFO checks
    info = getattr(mod, "PLUGIN_INFO", None)
    if not isinstance(info, dict):
        r.errors.append("PLUGIN_INFO не dict")
    else:
        for k in ("name", "version", "author", "description"):
            if k not in info:
                r.warnings.append(f"PLUGIN_INFO.{k} отсутствует")
        # name → slug check
        name = info.get("name", "")
        if name and name != _slugify(name):
            r.warnings.append(f"PLUGIN_INFO.name '{name}' не slug-friendly")
        r.info = dict(info)

    # ACTIONS checks
    actions = getattr(mod, "ACTIONS", None)
    if not isinstance(actions, list):
        r.errors.append("ACTIONS не list")
        return r

    r.actions_count = len(actions)
    seen_names: set[str] = set()
    for i, a in enumerate(actions):
        if not isinstance(a, dict):
            r.errors.append(f"ACTIONS[{i}] не dict")
            continue
        for k in ("name", "description", "func"):
            if k not in a:
                r.errors.append(f"ACTIONS[{i}].{k} отсутствует")
        if "func" in a and not callable(a["func"]):
            r.errors.append(f"ACTIONS[{i}].func не callable")
        if "arg_hint" not in a:
            r.warnings.append(f"ACTIONS[{i}].arg_hint не задан")
        elif a["arg_hint"] not in ARG_HINTS:
            r.warnings.append(
                f"ACTIONS[{i}].arg_hint='{a['arg_hint']}' "
                f"не в whitelist"
            )
        # Duplicate name check
        nm = a.get("name", "")
        if nm in seen_names:
            r.errors.append(f"ACTIONS[{i}].name '{nm}' дублируется")
        seen_names.add(nm)

    r.valid = not r.errors
    return r


def validate_all_plugins() -> None:
    """Валидация всех плагинов."""
    py_files = [p for p in PLUGINS_DIR.glob("*.py")
                if not p.name.startswith("_")]
    if not py_files:
        console.print("[yellow]Плагинов нет.[/yellow]")
        return

    t = Table(title=f"🔍 Validation ({len(py_files)} плагинов)")
    t.add_column("File", style="cyan")
    t.add_column("Status", width=10)
    t.add_column("Actions", width=8)
    t.add_column("Errors", style="red", max_width=40)
    t.add_column("Warnings", style="yellow", max_width=40)

    for f in py_files:
        r = validate_plugin(f)
        sty = "green" if r.valid else "red"
        t.add_row(
            f.name,
            f"[{sty}]{'OK' if r.valid else 'FAIL'}[/{sty}]",
            str(r.actions_count),
            "; ".join(r.errors)[:40] or "—",
            "; ".join(r.warnings)[:40] or "—",
        )
    console.print(t)


# ===========================================================================
# List plugins
# ===========================================================================

def list_plugins_detailed() -> None:
    """Детальный список плагинов."""
    py_files = [p for p in PLUGINS_DIR.glob("*.py")
                if not p.name.startswith("_")]
    if not py_files:
        console.print("[yellow]Плагинов нет.[/yellow]")
        console.print(f"[dim]Папка: {PLUGINS_DIR}[/dim]")
        return

    t = Table(title=f"🧩 Плагины ({len(py_files)})")
    t.add_column("Name", style="cyan")
    t.add_column("Version", width=10)
    t.add_column("Author", style="magenta", width=15)
    t.add_column("Actions", style="green", width=8)
    t.add_column("Description", style="white", max_width=40)
    t.add_column("Size", style="dim", width=8)

    for f in sorted(py_files):
        r = validate_plugin(f)
        size_kb = f.stat().st_size / 1024
        t.add_row(
            r.info.get("name", f.stem),
            r.info.get("version", "?"),
            (r.info.get("author", "?"))[:15],
            str(r.actions_count),
            (r.info.get("description", "") or "")[:40],
            f"{size_kb:.1f}KB",
        )
    console.print(t)


# ===========================================================================
# Documentation
# ===========================================================================

API_DOCS = """
[bold cyan]═══ Plugin SDK — API плагинов ═══[/bold cyan]

[bold yellow]📌 Структура плагина:[/bold yellow]

```python
PLUGIN_INFO = {
    "name": "my_plugin",       # обязательный (slug-friendly)
    "version": "1.0",          # желательный
    "author": "your_name",     # желательный
    "description": "..."       # желательный
}

def my_action(arg: str) -> None:
    ...

ACTIONS = [
    {
        "name": "my_action",           # CLI: plugin-run my_plugin.my_action
        "description": "Что делает",   # показывается в меню
        "func": my_action,             # callable
        "arg_hint": "url",             # см. whitelist
    },
]