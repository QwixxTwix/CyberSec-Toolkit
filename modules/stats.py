"""
Graph & Statistics: визуализация истории сканов.
Генерирует PNG-графики через matplotlib и открывает их в системе.
Author: idqwixxa
"""
import os
import sys
import json
import webbrowser
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Проверка matplotlib
# ---------------------------------------------------------------------------

def _matplotlib_available() -> bool:
    try:
        import matplotlib  # noqa: F401
        return True
    except ImportError:
        return False


def _get_mpl():
    """Настроить matplotlib и вернуть модуль."""
    import matplotlib
    matplotlib.use("Agg")  # без GUI — рисуем в файл
    import matplotlib.pyplot as plt
    from matplotlib import rcParams

    # Кириллица
    rcParams["font.family"] = ["DejaVu Sans", "Arial", "sans-serif"]
    rcParams["axes.unicode_minus"] = False
    rcParams["figure.facecolor"] = "#0a0a0a"
    rcParams["axes.facecolor"] = "#0d0d0d"
    rcParams["axes.edgecolor"] = "#00ff9c"
    rcParams["axes.labelcolor"] = "#00ff9c"
    rcParams["text.color"] = "#c8c8c8"
    rcParams["xtick.color"] = "#c8c8c8"
    rcParams["ytick.color"] = "#c8c8c8"
    rcParams["grid.color"] = "#1a1a1a"
    rcParams["axes.titlecolor"] = "#00ff9c"
    return plt


# ---------------------------------------------------------------------------
# Извлечение данных
# ---------------------------------------------------------------------------

def _parse_history(limit: int = 5000) -> list[dict]:
    """Взять строки из БД и распарсить даты."""
    rows = db.history(limit)
    out: list[dict] = []
    for r in rows:
        try:
            created = str(r["created_at"])
            try:
                dt = datetime.fromisoformat(created.replace(" ", "T"))
            except ValueError:
                dt = datetime.strptime(created[:19], "%Y-%m-%d %H:%M:%S")
        except Exception:  # noqa: BLE001
            continue
        out.append({
            "id": r["id"],
            "module": r["module"],
            "target": r["target"],
            "created_at": dt,
            "result_len": len(str(r["result"] or "")),
        })
    return out


# ---------------------------------------------------------------------------
# Графики
# ---------------------------------------------------------------------------

def _save_fig(plt, fig, name: str) -> Path:
    """Сохранить график в reports/<name>.png."""
    ts = datetime.now().strftime("%Y%m%d")
    out = REPORT_DIR / f"{name}_{ts}.png"
    try:
        fig.savefig(out, dpi=110, bbox_inches="tight", facecolor="#0a0a0a")
        plt.close(fig)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка сохранения {name}: {exc}[/red]")
        return out
    console.print(f"[green]✓ {out}[/green]")
    return out


def plot_timeline(data: list[dict]) -> Path | None:
    """Линия: количество сканов по дням."""
    plt = _get_mpl()
    by_day: dict[str, int] = defaultdict(int)
    for r in data:
        by_day[r["created_at"].strftime("%Y-%m-%d")] += 1
    if not by_day:
        return None
    days = sorted(by_day.keys())
    counts = [by_day[d] for d in days]

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.plot(days, counts, color="#00ff9c", linewidth=2, marker="o",
            markersize=6, markerfacecolor="#00ff9c")
    ax.fill_between(range(len(days)), counts, color="#00ff9c", alpha=0.15)
    ax.set_title("Активность сканов по дням", fontsize=14, fontweight="bold")
    ax.set_xlabel("Дата")
    ax.set_ylabel("Количество сканов")
    ax.grid(True, linestyle="--", alpha=0.3)
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    fig.tight_layout()
    return _save_fig(plt, fig, "stats_timeline")


def plot_top_modules(data: list[dict], top: int = 12) -> Path | None:
    """Горизонтальный bar: топ модулей."""
    plt = _get_mpl()
    counts = Counter(r["module"] for r in data)
    if not counts:
        return None
    top_items = counts.most_common(top)
    modules = [m for m, _ in top_items][::-1]
    vals = [c for _, c in top_items][::-1]

    fig, ax = plt.subplots(figsize=(10, max(4, len(modules) * 0.4)))
    bars = ax.barh(modules, vals, color="#00ff9c", alpha=0.85)
    ax.set_title("Топ модулей по количеству сканов", fontsize=14,
                 fontweight="bold")
    ax.set_xlabel("Сканов")
    ax.grid(True, axis="x", linestyle="--", alpha=0.3)
    for b, v in zip(bars, vals):
        ax.text(b.get_width() + max(vals) * 0.01, b.get_y() + b.get_height() / 2,
                str(v), va="center", color="#00ff9c", fontsize=9)
    fig.tight_layout()
    return _save_fig(plt, fig, "stats_top_modules")


def plot_top_targets(data: list[dict], top: int = 12) -> Path | None:
    """Горизонтальный bar: топ целей."""
    plt = _get_mpl()
    counts = Counter(r["target"] for r in data)
    if not counts:
        return None
    top_items = counts.most_common(top)
    targets = [t[:40] + ("…" if len(t) > 40 else "") for t, _ in top_items][::-1]
    vals = [c for _, c in top_items][::-1]

    fig, ax = plt.subplots(figsize=(11, max(4, len(targets) * 0.4)))
    bars = ax.barh(targets, vals, color="#7ad9ff", alpha=0.85)
    ax.set_title("Топ целей по количеству сканов", fontsize=14,
                 fontweight="bold")
    ax.set_xlabel("Сканов")
    ax.grid(True, axis="x", linestyle="--", alpha=0.3)
    for b, v in zip(bars, vals):
        ax.text(b.get_width() + max(vals) * 0.01, b.get_y() + b.get_height() / 2,
                str(v), va="center", color="#7ad9ff", fontsize=9)
    fig.tight_layout()
    return _save_fig(plt, fig, "stats_top_targets")


def plot_hourly(data: list[dict]) -> Path | None:
    """Bar: распределение по часам суток."""
    plt = _get_mpl()
    hours = [0] * 24
    for r in data:
        hours[r["created_at"].hour] += 1
    if sum(hours) == 0:
        return None

    fig, ax = plt.subplots(figsize=(12, 4))
    bars = ax.bar(range(24), hours, color="#ff7ad9", alpha=0.85)
    ax.set_title("Активность по часам суток", fontsize=14, fontweight="bold")
    ax.set_xlabel("Час")
    ax.set_ylabel("Сканов")
    ax.set_xticks(range(24))
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)
    peak = hours.index(max(hours))
    bars[peak].set_color("#00ff9c")
    ax.text(peak, hours[peak], f" пик: {hours[peak]}", color="#00ff9c",
            fontsize=9, va="bottom", ha="left")
    fig.tight_layout()
    return _save_fig(plt, fig, "stats_hourly")


def plot_pie_modules(data: list[dict], top: int = 8) -> Path | None:
    """Pie: распределение сканов по модулям."""
    plt = _get_mpl()
    counts = Counter(r["module"] for r in data)
    if not counts:
        return None
    top_items = counts.most_common(top)
    rest = sum(counts.values()) - sum(c for _, c in top_items)
    labels = [m for m, _ in top_items]
    sizes = [c for _, c in top_items]
    if rest > 0:
        labels.append("прочее")
        sizes.append(rest)

    colors = ["#00ff9c", "#7ad9ff", "#ff7ad9", "#ffcc66", "#66ffcc",
              "#cc99ff", "#99ff66", "#ff9966", "#66ccff"]

    fig, ax = plt.subplots(figsize=(8, 8))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, autopct="%1.1f%%",
        startangle=90, colors=colors[:len(sizes)],
        textprops={"color": "#c8c8c8", "fontsize": 10},
        wedgeprops={"edgecolor": "#0a0a0a", "linewidth": 2},
    )
    for at in autotexts:
        at.set_color("#0a0a0a")
        at.set_fontweight("bold")
    ax.set_title("Распределение сканов по модулям", fontsize=14,
                 fontweight="bold", color="#00ff9c")
    fig.tight_layout()
    return _save_fig(plt, fig, "stats_pie_modules")


def plot_dashboard(data: list[dict]) -> Path | None:
    """Общий дашборд: 2×2 сетка графиков."""
    plt = _get_mpl()
    fig, axes = plt.subplots(2, 2, figsize=(16, 10))
    fig.suptitle("CyberSec Toolkit — Dashboard", fontsize=18,
                 fontweight="bold", color="#00ff9c")

    # 1. Timeline
    ax = axes[0][0]
    by_day: dict[str, int] = defaultdict(int)
    for r in data:
        by_day[r["created_at"].strftime("%Y-%m-%d")] += 1
    if by_day:
        days = sorted(by_day.keys())
        counts = [by_day[d] for d in days]
        ax.plot(days, counts, color="#00ff9c", marker="o")
        ax.fill_between(range(len(days)), counts, color="#00ff9c", alpha=0.15)
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right", fontsize=8)
    ax.set_title("Сканы по дням")
    ax.grid(True, linestyle="--", alpha=0.3)

    # 2. Top modules
    ax = axes[0][1]
    top_items = Counter(r["module"] for r in data).most_common(8)
    if top_items:
        mods = [m for m, _ in top_items][::-1]
        vals = [c for _, c in top_items][::-1]
        ax.barh(mods, vals, color="#00ff9c", alpha=0.85)
        ax.set_title("Топ модулей")
        ax.grid(True, axis="x", linestyle="--", alpha=0.3)

    # 3. Hourly
    ax = axes[1][0]
    hours = [0] * 24
    for r in data:
        hours[r["created_at"].hour] += 1
    ax.bar(range(24), hours, color="#ff7ad9", alpha=0.85)
    ax.set_title("Часы суток")
    ax.set_xticks(range(0, 24, 3))
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)

    # 4. Top targets
    ax = axes[1][1]
    top_t = Counter(r["target"] for r in data).most_common(8)
    if top_t:
        tgt = [t[:30] + ("…" if len(t) > 30 else "") for t, _ in top_t][::-1]
        vals = [c for _, c in top_t][::-1]
        ax.barh(tgt, vals, color="#7ad9ff", alpha=0.85)
        ax.set_title("Топ целей")
        ax.grid(True, axis="x", linestyle="--", alpha=0.3)

    fig.tight_layout(rect=(0, 0, 1, 0.96))
    return _save_fig(plt, fig, "stats_dashboard")


# ---------------------------------------------------------------------------
# Открытие файла в системе
# ---------------------------------------------------------------------------

def _open_file(path: Path) -> None:
    """Открыть PNG в дефолтном просмотрщике."""
    try:
        if sys.platform == "win32":
            os.startfile(str(path))  # noqa: S606
        elif sys.platform == "darwin":
            os.system(f'open "{path}"')
        else:
            os.system(f'xdg-open "{path}" >/dev/null 2>&1 &')
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]Не удалось открыть файл: {exc}[/yellow]")


# ---------------------------------------------------------------------------
# Текстовая сводка (для TUI и CLI)
# ---------------------------------------------------------------------------

def text_summary() -> None:
    """Показать текстовую сводку по истории (без графиков)."""
    data = _parse_history()
    if not data:
        console.print("[yellow]История пуста.[/yellow]")
        return

    table = Table(title="📊 Статистика CyberSec Toolkit")
    table.add_column("Показатель", style="cyan")
    table.add_column("Значение", style="green")

    table.add_row("Всего сканов", str(len(data)))
    table.add_row("Уникальных целей", str(len({r["target"] for r in data})))
    table.add_row("Уникальных модулей", str(len({r["module"] for r in data})))
    first = min(r["created_at"] for r in data)
    last = max(r["created_at"] for r in data)
    table.add_row("Первый скан", first.strftime("%Y-%m-%d %H:%M"))
    table.add_row("Последний скан", last.strftime("%Y-%m-%d %H:%M"))

    days = (last - first).days + 1
    table.add_row("Дней активности", str(days))
    table.add_row("Сканов в день (сред.)",
                  f"{len(data) / max(days, 1):.1f}")

    top_mod = Counter(r["module"] for r in data).most_common(3)
    table.add_row("Топ модулей",
                  ", ".join(f"{m} ({c})" for m, c in top_mod))
    top_tgt = Counter(r["target"] for r in data).most_common(3)
    table.add_row("Топ целей",
                  ", ".join(f"{t[:20]} ({c})" for t, c in top_tgt))
    console.print(table)


# ---------------------------------------------------------------------------
# Публичные операции
# ---------------------------------------------------------------------------

def generate_all(open_after: bool = False) -> None:
    """Сгенерировать все графики."""
    if not _matplotlib_available():
        console.print("[red]matplotlib не установлен.[/red]")
        console.print("[yellow]Установи: pip install matplotlib[/yellow]")
        return

    data = _parse_history()
    if not data:
        console.print("[yellow]История пуста — нечего строить.[/yellow]")
        return

    console.print(f"[cyan]Генерирую графики по {len(data)} сканам…[/cyan]\n")
    files: list[Path] = []

    for fn in (plot_timeline, plot_top_modules, plot_top_targets,
               plot_hourly, plot_pie_modules, plot_dashboard):
        try:
            p = fn(data)
            if p:
                files.append(p)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Ошибка {fn.__name__}: {exc}[/red]")
            log.exception("plot error")

    if not files:
        console.print("[red]Не удалось построить графики.[/red]")
        return

    console.print(f"\n[bold green]✓ Готово: {len(files)} графиков[/bold green]")
    console.print(f"[dim]Папка: {REPORT_DIR}[/dim]")

    db.save_scan("stats", "history", {"files": [str(p) for p in files]})

    if open_after and files:
        # Открываем дашборд — самый информативный
        dashboard = next((p for p in files if "dashboard" in p.name), files[0])
        console.print(f"[cyan]Открываю: {dashboard.name}[/cyan]")
        _open_file(dashboard)


def menu() -> None:
    """Меню статистики."""
    table = Table(title="[bold]Graph & Statistics[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Текстовая сводка"),
        ("2", "Timeline (сканы по дням)"),
        ("3", "Топ модулей"),
        ("4", "Топ целей"),
        ("5", "Активность по часам"),
        ("6", "Pie: распределение по модулям"),
        ("7", "Dashboard 2×2 (все сразу)"),
        ("8", "Всё + открыть dashboard"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        text_summary()
        return
    if not _matplotlib_available():
        console.print("[red]matplotlib не установлен: pip install matplotlib[/red]")
        return

    data = _parse_history()
    if not data:
        console.print("[yellow]История пуста.[/yellow]")
        return

    fn_map = {
        "2": plot_timeline,
        "3": plot_top_modules,
        "4": plot_top_targets,
        "5": plot_hourly,
        "6": plot_pie_modules,
        "7": plot_dashboard,
    }
    if c in fn_map:
        p = fn_map[c](data)
        if p and Confirm.ask("Открыть файл?", default=False):
            _open_file(p)
    elif c == "8":
        generate_all(open_after=True)