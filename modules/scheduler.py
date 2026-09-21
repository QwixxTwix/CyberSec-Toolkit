"""
Простой планировщик задач: запускает сканы по расписанию из schedule.yaml.
После каждой задачи отправляет уведомление (если NOTIFY_ENABLED=true).
"""
import time
import threading
from datetime import datetime, timedelta

import yaml
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table

from core.config import BASE_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

SCHEDULE_PATH = BASE_DIR / "schedule.yaml"


# Доступные действия. Ключ → (модуль, функция, kind, описание)
ACTIONS = {
    "whois":      ("modules.recon", "whois_lookup", "target", "WHOIS lookup"),
    "dns":        ("modules.recon", "dns_enum", "target", "DNS enumeration"),
    "portscan":   ("modules.recon", "port_scan", "target", "Port scan 1-1024"),
    "geoip":      ("modules.recon", "ip_geolocation", "target", "IP geolocation"),
    "headers":    ("modules.web_vuln", "header_analyzer", "url", "HTTP headers"),
    "ssl":        ("modules.web_vuln", "ssl_checker", "host", "SSL/TLS check"),
    "asyncscan":  ("modules.async_engine", "async_port_scan", "target", "Async portscan"),
    "screenshot": ("modules.screenshot", "screenshot_one", "url", "Screenshot URL"),
}


def _load_schedule() -> dict:
    """Загрузить schedule.yaml."""
    if not SCHEDULE_PATH.exists():
        return {"jobs": []}
    try:
        data = yaml.safe_load(SCHEDULE_PATH.read_text(encoding="utf-8")) or {}
        if "jobs" not in data:
            data["jobs"] = []
        return data
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка чтения schedule.yaml: {exc}[/red]")
        return {"jobs": []}


def _save_schedule(data: dict) -> None:
    """Сохранить schedule.yaml."""
    try:
        SCHEDULE_PATH.write_text(
            yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка записи schedule.yaml: {exc}[/red]")


def _resolve_callable(action_key: str):
    """Вернуть python-функцию по ключу действия."""
    if action_key not in ACTIONS:
        return None
    mod_path, fn_name, _kind, _desc = ACTIONS[action_key]
    try:
        mod_name, _sub = mod_path.rsplit(".", 1)
        mod = __import__(f"{mod_name}", fromlist=[_sub])
        return getattr(mod, fn_name, None)
    except Exception as exc:  # noqa: BLE001
        log.error("resolve %s: %s", action_key, exc)
        return None


def _notify(action: str, arg: str, ok: bool, extra: str = "") -> None:
    """Отправить уведомление после выполнения задачи."""
    try:
        from modules import notifier
    except Exception:  # noqa: BLE001
        return
    status = "✓ OK" if ok else "✗ FAIL"
    title = f"CyberSec Toolkit — {status}"
    message = (
        f"Задача: {action}\n"
        f"Цель:   {arg}\n"
        f"Время:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    )
    if extra:
        message += f"\n{extra[:800]}"
    notifier.notify_all(title, message)


def _run_job(job: dict) -> None:
    """Выполнить одну задачу."""
    action = job.get("action", "")
    arg = job.get("arg", "")
    extra = job.get("extra", {}) or {}

    fn = _resolve_callable(action)
    if fn is None:
        console.print(f"[red]Неизвестное действие: {action}[/red]")
        _notify(action, arg, ok=False, extra="неизвестное действие")
        return

    console.print(
        f"[cyan]▶ [{datetime.now().strftime('%H:%M:%S')}] "
        f"{action} {arg}[/cyan]"
    )
    ok = True
    err = ""
    try:
        if extra:
            fn(arg, **extra)
        else:
            fn(arg)
        db.save_scan("scheduler", f"{action}:{arg}",
                     {"job": job, "ok": True})
    except Exception as exc:  # noqa: BLE001
        ok = False
        err = str(exc)
        console.print(f"[red]Ошибка задачи: {exc}[/red]")
        log.exception("scheduler job")
        db.save_scan("scheduler", f"{action}:{arg}",
                     {"job": job, "error": err})

    _notify(action, arg, ok=ok, extra=err)


def list_jobs() -> None:
    """Показать список задач."""
    data = _load_schedule()
    jobs = data.get("jobs", [])
    if not jobs:
        console.print("[yellow]Задач нет. Добавь через меню.[/yellow]")
        return
    table = Table(title="Задачи планировщика")
    table.add_column("#", style="yellow")
    table.add_column("Действие", style="cyan")
    table.add_column("Аргумент", style="green")
    table.add_column("Интервал (мин)", style="magenta")
    table.add_column("Последний запуск", style="white")
    for i, j in enumerate(jobs, 1):
        table.add_row(
            str(i),
            j.get("action", "?"),
            str(j.get("arg", "?")),
            str(j.get("every_minutes", "?")),
            str(j.get("last_run", "—")),
        )
    console.print(table)


def add_job() -> None:
    """Добавить задачу."""
    console.print("[cyan]Доступные действия:[/cyan]")
    for k, (_m, _f, _a, desc) in ACTIONS.items():
        console.print(f"  [green]{k:<12}[/green] — {desc}")
    action = Prompt.ask("Действие", choices=list(ACTIONS.keys()))
    arg = Prompt.ask("Аргумент (домен/URL/IP)")
    every = IntPrompt.ask("Интервал в минутах", default=60)

    data = _load_schedule()
    data.setdefault("jobs", []).append({
        "action": action,
        "arg": arg,
        "every_minutes": every,
        "last_run": None,
    })
    _save_schedule(data)
    console.print(f"[green]✓ Добавлено: {action} {arg} каждые {every} мин[/green]")


def remove_job() -> None:
    """Удалить задачу по номеру."""
    data = _load_schedule()
    jobs = data.get("jobs", [])
    if not jobs:
        console.print("[yellow]Задач нет.[/yellow]")
        return
    list_jobs()
    idx = IntPrompt.ask("Номер для удаления")
    if 1 <= idx <= len(jobs):
        removed = jobs.pop(idx - 1)
        _save_schedule(data)
        console.print(
            f"[green]✓ Удалено: {removed.get('action')} {removed.get('arg')}[/green]"
        )
    else:
        console.print("[red]Неверный номер.[/red]")


def _due(job: dict, now: datetime) -> bool:
    """Пора ли запускать задачу."""
    every = job.get("every_minutes", 60)
    last = job.get("last_run")
    if not last:
        return True
    try:
        last_dt = datetime.fromisoformat(last)
    except Exception:  # noqa: BLE001
        return True
    return now >= last_dt + timedelta(minutes=every)


def run_loop(stop_event: threading.Event) -> None:
    """Главный цикл планировщика."""
    console.print("[bold cyan]▶ Планировщик запущен. Ctrl+C — стоп.[/bold cyan]")
    while not stop_event.is_set():
        data = _load_schedule()
        jobs = data.get("jobs", [])
        now = datetime.now()
        changed = False
        for job in jobs:
            if _due(job, now):
                _run_job(job)
                job["last_run"] = now.isoformat(timespec="seconds")
                changed = True
        if changed:
            _save_schedule(data)
        for _ in range(30):
            if stop_event.is_set():
                return
            time.sleep(1)


def run_forever() -> None:
    """Обёртка с обработкой Ctrl+C."""
    stop_event = threading.Event()
    try:
        run_loop(stop_event)
    except KeyboardInterrupt:
        stop_event.set()
        console.print("\n[yellow]Планировщик остановлен.[/yellow]")


def menu() -> None:
    """Меню планировщика."""
    table = Table(title="[bold]Scheduler[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Показать задачи"),
        ("2", "Добавить задачу"),
        ("3", "Удалить задачу"),
        ("4", "Запустить сейчас (выполнить все 'due')"),
        ("5", "Запустить планировщик (Ctrl+C для стопа)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        list_jobs()
    elif c == "2":
        add_job()
    elif c == "3":
        remove_job()
    elif c == "4":
        data = _load_schedule()
        for job in data.get("jobs", []):
            _run_job(job)
            job["last_run"] = datetime.now().isoformat(timespec="seconds")
        _save_schedule(data)
    elif c == "5":
        if Confirm.ask("Запустить бесконечный цикл планировщика?", default=False):
            run_forever()