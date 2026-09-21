"""
Graph & Statistics Pro: расширенная визуализация истории сканов.
Author: idqwixxa

Возможности:
    ─── Текстовые отчёты ───
    - Полная сводка (сканы/цели/модули/CVE/notes/findings)
    - Топ-N с настройкой
    - Anomaly-детект (спайки, длинные цели, редкие модули)
    - Findings → notes при обнаружении аномалий

    ─── PNG-графики (matplotlib) ───
    - Timeline (по дням)
    - Top modules
    - Top targets
    - Hourly activity
    - Pie modules
    - Severity pie (findings)
    - Heatmap: hour × weekday
    - Cumulative growth
    - Dashboard 2×3 (всё сразу)

    ─── HTML-дашборд ───
    - Самодостаточный HTML с встроенными base64-PNG
    - KPI-карточки
    - Таблицы топ-N

    ─── Экспорт ───
    - JSON / CSV / Markdown
    - Findings → notes / Notify при аномалиях
"""
import base64
import csv
import html as html_mod
import io
import json
import os
import sys
import webbrowser
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table
from rich.panel import Panel

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

STATS_DIR = REPORT_DIR / "stats"
STATS_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

def _save_finding(kind: str, severity: str, title: str,
                  target: str = "", evidence: str = "",
                  data: dict | None = None) -> int:
    if severity not in ("critical", "high"):
        return -1
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=title,
            target=target,
            severity=severity,
            status="open",
            tags=["stats", kind],
            body=(f"**Kind:** {kind}\n"
                  f"**Target:** {target}\n\n"
                  f"**Evidence:**\n```\n{(evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(data or {}, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


def _notify(title: str, msg: str, severity: str = "high") -> None:
    try:
        from modules import notifier
        notifier.notify_all(title, msg, severity=severity)
    except Exception:
        pass


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
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib import rcParams

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


def _parse_findings() -> list[dict]:
    """Взять findings из notes."""
    try:
        from modules import notes
        return notes.list_notes(kind="finding")
    except Exception:
        return []


def _parse_cves_count() -> int:
    try:
        cur = db.conn.cursor()
        cur.execute("SELECT COUNT(*) as c FROM cves")
        return cur.fetchone()["c"]
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Графики
# ---------------------------------------------------------------------------

def _save_fig(plt, fig, name: str) -> Path:
    ts = datetime.now().strftime("%Y%m%d")
    out = STATS_DIR / f"{name}_{ts}.png"
    try:
        fig.savefig(out, dpi=110, bbox_inches="tight",
                     facecolor="#0a0a0a")
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
    ax.fill_between(range(len(days)), counts, color="#00ff9c",
                     alpha=0.15)
    ax.set_title("Активность сканов по дням", fontsize=14,
                 fontweight="bold")
    ax.set_xlabel("Дата")
    ax.set_ylabel("Количество сканов")
    ax.grid(True, linestyle="--", alpha=0.3)
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    fig.tight_layout()
    return _save_fig(plt, fig, "stats_timeline")


def plot_top_modules(data: list[dict], top: int = 12) -> Path | None:
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
        ax.text(b.get_width() + max(vals) * 0.01,
                b.get_y() + b.get_height() / 2,
                str(v), va="center", color="#00ff9c", fontsize=9)
    fig.tight_layout()
    return _save_fig(plt, fig, "stats_top_modules")


def plot_top_targets(data: list[dict], top: int = 12) -> Path | None:
    plt = _get_mpl()
    counts = Counter(r["target"] for r in data)
    if not counts:
        return None
    top_items = counts.most_common(top)
    targets = [t[:40] + ("…" if len(t) > 40 else "")
               for t, _ in top_items][::-1]
    vals = [c for _, c in top_items][::-1]

    fig, ax = plt.subplots(figsize=(11, max(4, len(targets) * 0.4)))
    bars = ax.barh(targets, vals, color="#7ad9ff", alpha=0.85)
    ax.set_title("Топ целей по количеству сканов", fontsize=14,
                 fontweight="bold")
    ax.set_xlabel("Сканов")
    ax.grid(True, axis="x", linestyle="--", alpha=0.3)
    for b, v in zip(bars, vals):
        ax.text(b.get_width() + max(vals) * 0.01,
                b.get_y() + b.get_height() / 2,
                str(v), va="center", color="#7ad9ff", fontsize=9)
    fig.tight_layout()
    return _save_fig(plt, fig, "stats_top_targets")


def plot_hourly(data: list[dict]) -> Path | None:
    plt = _get_mpl()
    hours = [0] * 24
    for r in data:
        hours[r["created_at"].hour] += 1
    if sum(hours) == 0:
        return None

    fig, ax = plt.subplots(figsize=(12, 4))
    bars = ax.bar(range(24), hours, color="#ff7ad9", alpha=0.85)
    ax.set_title("Активность по часам суток", fontsize=14,
                 fontweight="bold")
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


def plot_severity_pie(findings: list[dict]) -> Path | None:
    """Pie по severity из findings."""
    plt = _get_mpl()
    if not findings:
        return None
    counts = Counter((f.get("severity") or "info").lower()
                     for f in findings)
    order = ["critical", "high", "medium", "low", "info"]
    labels = [s for s in order if s in counts]
    sizes = [counts[s] for s in labels]
    colors_map = {
        "critical": "#ff2020", "high": "#ff7a40",
        "medium": "#ffd23f", "low": "#00ff9c", "info": "#7ad9ff",
    }
    colors = [colors_map.get(s, "#888") for s in labels]

    fig, ax = plt.subplots(figsize=(8, 8))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=[f"{s.upper()} ({counts[s]})" for s in labels],
        autopct="%1.0f%%",
        startangle=90, colors=colors,
        textprops={"color": "#c8c8c8", "fontsize": 10},
        wedgeprops={"edgecolor": "#0a0a0a", "linewidth": 2},
    )
    for at in autotexts:
        at.set_color("#0a0a0a")
        at.set_fontweight("bold")
    ax.set_title(f"Findings по severity ({len(findings)})",
                 fontsize=14, fontweight="bold", color="#00ff9c")
    fig.tight_layout()
    return _save_fig(plt, fig, "stats_severity_pie")


def plot_heatmap(data: list[dict]) -> Path | None:
    """Heatmap: час × день недели."""
    plt = _get_mpl()
    if not data:
        return None
    grid = [[0] * 24 for _ in range(7)]
    for r in data:
        grid[r["created_at"].weekday()][r["created_at"].hour] += 1
    if not any(any(row) for row in grid):
        return None

    fig, ax = plt.subplots(figsize=(14, 5))
    im = ax.imshow(grid, aspect="auto", cmap="Greens")
    ax.set_xticks(range(0, 24, 2))
    ax.set_yticks(range(7))
    ax.set_yticklabels(["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"])
    ax.set_xlabel("Час суток")
    ax.set_title("Heatmap: активность по дням недели × часам",
                 fontsize=14, fontweight="bold")
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label("Сканов", color="#c8c8c8")
    fig.tight_layout()
    return _save_fig(plt, fig, "stats_heatmap")


def plot_cumulative(data: list[dict]) -> Path | None:
    """Кумулятивный рост."""
    plt = _get_mpl()
    by_day: dict[str, int] = defaultdict(int)
    for r in data:
        by_day[r["created_at"].strftime("%Y-%m-%d")] += 1
    if not by_day:
        return None
    days = sorted(by_day.keys())
    daily = [by_day[d] for d in days]
    cum: list[int] = []
    total = 0
    for d in daily:
        total += d
        cum.append(total)

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.plot(days, cum, color="#ffcc66", linewidth=2)
    ax.fill_between(range(len(days)), cum, color="#ffcc66", alpha=0.15)
    ax.set_title("Кумулятивный рост сканов", fontsize=14,
                 fontweight="bold")
    ax.set_xlabel("Дата")
    ax.set_ylabel("Всего сканов")
    ax.grid(True, linestyle="--", alpha=0.3)
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    fig.tight_layout()
    return _save_fig(plt, fig, "stats_cumulative")


def plot_dashboard(data: list[dict]) -> Path | None:
    """Общий дашборд 2×3."""
    plt = _get_mpl()
    fig, axes = plt.subplots(2, 3, figsize=(20, 10))
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
        ax.plot(days, counts, color="#00ff9c", marker="o", markersize=4)
        ax.fill_between(range(len(days)), counts, color="#00ff9c",
                         alpha=0.15)
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right",
                 fontsize=8)
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
    ax = axes[0][2]
    hours = [0] * 24
    for r in data:
        hours[r["created_at"].hour] += 1
    ax.bar(range(24), hours, color="#ff7ad9", alpha=0.85)
    ax.set_title("Часы суток")
    ax.set_xticks(range(0, 24, 3))
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)

    # 4. Top targets
    ax = axes[1][0]
    top_t = Counter(r["target"] for r in data).most_common(8)
    if top_t:
        tgt = [t[:25] + ("…" if len(t) > 25 else "")
               for t, _ in top_t][::-1]
        vals = [c for _, c in top_t][::-1]
        ax.barh(tgt, vals, color="#7ad9ff", alpha=0.85)
        ax.set_title("Топ целей")
        ax.grid(True, axis="x", linestyle="--", alpha=0.3)

    # 5. Pie modules
    ax = axes[1][1]
    top_pie = Counter(r["module"] for r in data).most_common(6)
    if top_pie:
        labels = [m for m, _ in top_pie]
        sizes = [c for _, c in top_pie]
        colors = ["#00ff9c", "#7ad9ff", "#ff7ad9", "#ffcc66",
                   "#66ffcc", "#cc99ff"]
        ax.pie(sizes, labels=labels, autopct="%1.0f%%",
                startangle=90, colors=colors[:len(sizes)],
                textprops={"color": "#c8c8c8", "fontsize": 8},
                wedgeprops={"edgecolor": "#0a0a0a", "linewidth": 1})
    ax.set_title("Pie: модули")

    # 6. Cumulative
    ax = axes[1][2]
    if by_day:
        days = sorted(by_day.keys())
        daily = [by_day[d] for d in days]
        cum: list[int] = []
        s = 0
        for d in daily:
            s += d
            cum.append(s)
        ax.plot(days, cum, color="#ffcc66", linewidth=2)
        ax.fill_between(range(len(days)), cum, color="#ffcc66",
                         alpha=0.15)
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right",
                 fontsize=8)
    ax.set_title("Кумулятив")
    ax.grid(True, linestyle="--", alpha=0.3)

    fig.tight_layout(rect=(0, 0, 1, 0.96))
    return _save_fig(plt, fig, "stats_dashboard")


# ---------------------------------------------------------------------------
# Открытие файла
# ---------------------------------------------------------------------------

def _open_file(path: Path) -> None:
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
# Anomaly detection (NEW)
# ---------------------------------------------------------------------------

def _detect_anomalies(data: list[dict],
                       findings: list[dict]) -> list[dict]:
    """Найти аномалии в истории: спайки, редкие модули и т.д."""
    anomalies: list[dict] = []

    if len(data) >= 10:
        # Спайк по дням
        by_day: dict[str, int] = defaultdict(int)
        for r in data:
            by_day[r["created_at"].strftime("%Y-%m-%d")] += 1
        counts = list(by_day.values())
        avg = sum(counts) / len(counts)
        threshold = avg * 3
        for d, c in by_day.items():
            if c > threshold and c >= 5:
                anomalies.append({
                    "kind": "day_spike", "date": d,
                    "count": c, "avg": round(avg, 1),
                })

        # Редкие модули (использованы < 2 раз)
        mod_counts = Counter(r["module"] for r in data)
        rare = [m for m, c in mod_counts.items() if c <= 1]
        if 0 < len(rare) <= 5:
            anomalies.append({
                "kind": "rare_modules", "modules": rare,
            })

    # Критические findings
    crit = [f for f in findings
            if (f.get("severity") or "").lower() == "critical"]
    if len(crit) >= 3:
        anomalies.append({
            "kind": "many_critical_findings",
            "count": len(crit),
            "sample": [f.get("title") for f in crit[:5]],
        })
    return anomalies


def _report_anomalies(anomalies: list[dict]) -> None:
    if not anomalies:
        return
    console.print("\n[bold yellow]⚠ Аномалии:[/bold yellow]")
    for a in anomalies:
        kind = a.get("kind")
        if kind == "day_spike":
            console.print(f"  • Спайк {a['date']}: {a['count']} "
                          f"(avg {a['avg']})")
        elif kind == "rare_modules":
            console.print(f"  • Редкие модули: "
                          f"{', '.join(a['modules'][:5])}")
        elif kind == "many_critical_findings":
            console.print(f"  • {a['count']} critical findings: "
                          f"{', '.join(a['sample'][:3])}")

    for a in anomalies:
        if a["kind"] == "day_spike" and a["count"] >= 10:
            _save_finding(
                kind="scan_spike", severity="high",
                title=f"Аномальный спайк сканов: {a['date']}",
                target="stats", evidence=json.dumps(a, ensure_ascii=False),
                data=a,
            )
            _notify("📊 Spike detected",
                    f"{a['date']}: {a['count']} сканов (avg {a['avg']})",
                    severity="medium")


# ---------------------------------------------------------------------------
# Текстовая сводка
# ---------------------------------------------------------------------------

def text_summary() -> None:
    """Показать текстовую сводку по истории."""
    data = _parse_history()
    if not data:
        console.print("[yellow]История пуста.[/yellow]")
        return

    findings = _parse_findings()
    cves_count = _parse_cves_count()

    table = Table(title="📊 Статистика CyberSec Toolkit")
    table.add_column("Показатель", style="cyan")
    table.add_column("Значение", style="green")

    table.add_row("Всего сканов", str(len(data)))
    table.add_row("Уникальных целей",
                  str(len({r["target"] for r in data})))
    table.add_row("Уникальных модулей",
                  str(len({r["module"] for r in data})))
    first = min(r["created_at"] for r in data)
    last = max(r["created_at"] for r in data)
    table.add_row("Первый скан", first.strftime("%Y-%m-%d %H:%M"))
    table.add_row("Последний скан", last.strftime("%Y-%m-%d %H:%M"))

    days = (last - first).days + 1
    table.add_row("Дней активности", str(days))
    table.add_row("Сканов в день (сред.)",
                  f"{len(data) / max(days, 1):.1f}")
    table.add_row("CVE в базе", str(cves_count))
    table.add_row("Findings всего", str(len(findings)))
    sev_counter = Counter((f.get("severity") or "info").lower()
                           for f in findings)
    if sev_counter:
        table.add_row(
            "  critical / high / medium",
            f"{sev_counter.get('critical', 0)} / "
            f"{sev_counter.get('high', 0)} / "
            f"{sev_counter.get('medium', 0)}")

    top_mod = Counter(r["module"] for r in data).most_common(3)
    table.add_row("Топ модулей",
                  ", ".join(f"{m} ({c})" for m, c in top_mod))
    top_tgt = Counter(r["target"] for r in data).most_common(3)
    table.add_row("Топ целей",
                  ", ".join(f"{t[:20]} ({c})" for t, c in top_tgt))
    console.print(table)

    anomalies = _detect_anomalies(data, findings)
    _report_anomalies(anomalies)


# ---------------------------------------------------------------------------
# HTML dashboard (NEW)
# ---------------------------------------------------------------------------

def _fig_to_base64_png(fig, plt) -> str:
    buf = io.BytesIO()
    try:
        fig.savefig(buf, format="png", dpi=100, bbox_inches="tight",
                     facecolor="#0a0a0a")
        plt.close(fig)
    except Exception as exc:
        log.warning("fig to png: %s", exc)
        return ""
    return base64.b64encode(buf.getvalue()).decode()


def generate_html_dashboard(out_path: str | None = None) -> Path | None:
    """Самодостаточный HTML с embedded PNG."""
    if not _matplotlib_available():
        console.print("[red]matplotlib не установлен.[/red]")
        return None
    plt = _get_mpl()
    data = _parse_history()
    if not data:
        console.print("[yellow]История пуста.[/yellow]")
        return None

    findings = _parse_findings()
    cves_count = _parse_cves_count()

    console.print("[cyan]Строю графики для HTML…[/cyan]")

    # Build graphs (in memory → base64)
    imgs: dict[str, str] = {}

    # Timeline
    by_day: dict[str, int] = defaultdict(int)
    for r in data:
        by_day[r["created_at"].strftime("%Y-%m-%d")] += 1
    if by_day:
        fig, ax = plt.subplots(figsize=(12, 4))
        days = sorted(by_day.keys())
        counts = [by_day[d] for d in days]
        ax.plot(days, counts, color="#00ff9c", marker="o", markersize=5)
        ax.fill_between(range(len(days)), counts, color="#00ff9c",
                         alpha=0.15)
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right",
                 fontsize=8)
        ax.set_title("Активность по дням")
        ax.grid(True, linestyle="--", alpha=0.3)
        fig.tight_layout()
        imgs["timeline"] = _fig_to_base64_png(fig, plt)

    # Top modules
    top_items = Counter(r["module"] for r in data).most_common(10)
    if top_items:
        fig, ax = plt.subplots(figsize=(10, 5))
        mods = [m for m, _ in top_items][::-1]
        vals = [c for _, c in top_items][::-1]
        ax.barh(mods, vals, color="#00ff9c", alpha=0.85)
        ax.set_title("Топ модулей")
        ax.grid(True, axis="x", linestyle="--", alpha=0.3)
        fig.tight_layout()
        imgs["modules"] = _fig_to_base64_png(fig, plt)

    # Top targets
    top_t = Counter(r["target"] for r in data).most_common(10)
    if top_t:
        fig, ax = plt.subplots(figsize=(10, 5))
        tgt = [t[:30] + ("…" if len(t) > 30 else "")
               for t, _ in top_t][::-1]
        vals = [c for _, c in top_t][::-1]
        ax.barh(tgt, vals, color="#7ad9ff", alpha=0.85)
        ax.set_title("Топ целей")
        ax.grid(True, axis="x", linestyle="--", alpha=0.3)
        fig.tight_layout()
        imgs["targets"] = _fig_to_base64_png(fig, plt)

    # Hourly
    hours = [0] * 24
    for r in data:
        hours[r["created_at"].hour] += 1
    fig, ax = plt.subplots(figsize=(12, 3.5))
    ax.bar(range(24), hours, color="#ff7ad9", alpha=0.85)
    ax.set_title("Часы суток")
    ax.set_xticks(range(0, 24, 2))
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)
    fig.tight_layout()
    imgs["hourly"] = _fig_to_base64_png(fig, plt)

    # Severity (if findings)
    if findings:
        counts = Counter((f.get("severity") or "info").lower()
                         for f in findings)
        order = ["critical", "high", "medium", "low", "info"]
        labels = [s for s in order if s in counts]
        sizes = [counts[s] for s in labels]
        colors_map = {
            "critical": "#ff2020", "high": "#ff7a40",
            "medium": "#ffd23f", "low": "#00ff9c", "info": "#7ad9ff",
        }
        fig, ax = plt.subplots(figsize=(6, 6))
        ax.pie(sizes,
               labels=[f"{s.upper()} ({counts[s]})" for s in labels],
               autopct="%1.0f%%",
               startangle=90,
               colors=[colors_map[s] for s in labels],
               textprops={"color": "#c8c8c8", "fontsize": 9},
               wedgeprops={"edgecolor": "#0a0a0a", "linewidth": 2})
        ax.set_title(f"Findings по severity ({len(findings)})")
        fig.tight_layout()
        imgs["severity"] = _fig_to_base64_png(fig, plt)

    # KPI
    first = min(r["created_at"] for r in data)
    last = max(r["created_at"] for r in data)
    days = (last - first).days + 1
    top_mods = Counter(r["module"] for r in data).most_common(5)
    top_tgts = Counter(r["target"] for r in data).most_common(5)
    sev_counter = Counter((f.get("severity") or "info").lower()
                           for f in findings)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not out_path:
        out_path = str(STATS_DIR / f"dashboard_{ts}.html")

    parts = [
        "<!DOCTYPE html><html lang='ru'><head>",
        "<meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>CyberSec Toolkit — Dashboard</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:'Segoe UI',"
        "sans-serif;padding:24px;max-width:1300px;margin:0 auto;"
        "line-height:1.5;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;"
        "padding-bottom:8px;}",
        "h2{color:#00ff9c;margin-top:32px;}",
        ".kpi-grid{display:grid;"
        "grid-template-columns:repeat(auto-fit,minmax(160px,1fr));"
        "gap:14px;margin:20px 0;}",
        ".kpi{background:#111;border:1px solid #222;border-radius:8px;"
        "padding:16px;text-align:center;}",
        ".kpi .v{font-size:26px;color:#00ff9c;font-weight:bold;}",
        ".kpi .l{font-size:11px;color:#888;text-transform:uppercase;"
        "letter-spacing:1px;margin-top:4px;}",
        ".kpi.crit .v{color:#ff2020;}",
        ".kpi.high .v{color:#ff7a40;}",
        ".kpi.med .v{color:#ffd23f;}",
        ".kpi.info .v{color:#7ad9ff;}",
        ".img{background:#0d0d0d;border:1px solid #222;"
        "border-radius:8px;padding:12px;margin:12px 0;}",
        "table{width:100%;border-collapse:collapse;margin-top:12px;"
        "font-size:13px;}",
        "th{background:#111;color:#00ff9c;padding:8px;text-align:left;"
        "border:1px solid #222;}",
        "td{padding:6px 8px;border:1px solid #222;}",
        "tr:nth-child(even){background:#0d0d0d;}",
        ".footer{margin-top:40px;color:#666;text-align:center;"
        "font-size:12px;}",
        ".bar{height:4px;background:#00ff9c;margin-top:4px;border-radius:2px;}",
        "</style></head><body>",
        "<h1>📊 CyberSec Toolkit — Dashboard</h1>",
        f"<p>Generated: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  •  "
        f"by idqwixxa</p>",

        "<div class='kpi-grid'>",
        f"<div class='kpi'><div class='v'>{len(data)}</div>"
        f"<div class='l'>Сканов</div></div>",
        f"<div class='kpi'><div class='v'>{len({r['target'] for r in data})}</div>"
        f"<div class='l'>Целей</div></div>",
        f"<div class='kpi'><div class='v'>{len({r['module'] for r in data})}</div>"
        f"<div class='l'>Модулей</div></div>",
        f"<div class='kpi'><div class='v'>{days}</div>"
        f"<div class='l'>Дней</div></div>",
        f"<div class='kpi'><div class='v'>{cves_count}</div>"
        f"<div class='l'>CVE</div></div>",
        f"<div class='kpi'><div class='v'>{len(findings)}</div>"
        f"<div class='l'>Findings</div></div>",
        "</div>",

        "<div class='kpi-grid'>",
        f"<div class='kpi crit'><div class='v'>{sev_counter.get('critical',0)}</div>"
        f"<div class='l'>Critical</div></div>",
        f"<div class='kpi high'><div class='v'>{sev_counter.get('high',0)}</div>"
        f"<div class='l'>High</div></div>",
        f"<div class='kpi med'><div class='v'>{sev_counter.get('medium',0)}</div>"
        f"<div class='l'>Medium</div></div>",
        f"<div class='kpi info'><div class='v'>{sev_counter.get('low',0)}</div>"
        f"<div class='l'>Low</div></div>",
        "</div>",
    ]

    # Graphs
    for key, title in [("timeline", "Активность по дням"),
                        ("modules", "Топ модулей"),
                        ("targets", "Топ целей"),
                        ("hourly", "По часам"),
                        ("severity", "Findings по severity")]:
        if imgs.get(key):
            parts.append(f"<div class='img'><h2>{title}</h2>"
                         f"<img src='data:image/png;base64,{imgs[key]}' "
                         f"style='width:100%;height:auto;'></div>")

    # Top modules table
    parts.append("<h2>Топ модулей</h2><table>"
                 "<tr><th>#</th><th>Модуль</th><th>Сканов</th>"
                 "<th>Доля</th></tr>")
    total = len(data)
    for i, (m, c) in enumerate(top_mods, 1):
        pct = c / total * 100
        parts.append(
            f"<tr><td>{i}</td><td>{html_mod.escape(m)}</td>"
            f"<td>{c}</td>"
            f"<td>{pct:.1f}%<div class='bar' "
            f"style='width:{pct}%'></div></td></tr>")
    parts.append("</table>")

    # Top targets table
    parts.append("<h2>Топ целей</h2><table>"
                 "<tr><th>#</th><th>Цель</th><th>Сканов</th></tr>")
    for i, (t, c) in enumerate(top_tgts, 1):
        parts.append(
            f"<tr><td>{i}</td><td>{html_mod.escape(t)}</td>"
            f"<td>{c}</td></tr>")
    parts.append("</table>")

    # Anomalies
    anomalies = _detect_anomalies(data, findings)
    if anomalies:
        parts.append("<h2>⚠ Аномалии</h2><ul>")
        for a in anomalies:
            if a["kind"] == "day_spike":
                parts.append(f"<li>Спайк {a['date']}: {a['count']} "
                             f"(avg {a['avg']})</li>")
            elif a["kind"] == "rare_modules":
                parts.append(f"<li>Редкие модули: "
                             f"{', '.join(a['modules'][:5])}</li>")
            elif a["kind"] == "many_critical_findings":
                parts.append(f"<li>{a['count']} critical findings</li>")
        parts.append("</ul>")

    parts.append(f"<div class='footer'>CyberSec Toolkit — "
                 f"dashboard generated at "
                 f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>")
    parts.append("</body></html>")

    try:
        Path(out_path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML dashboard: {out_path}[/green]")
        db.save_scan("stats_html", "dashboard",
                     {"path": out_path, "count": len(data)})
        _save_finding(
            kind="stats_dashboard", severity="high",
            title=f"Статистический dashboard сформирован",
            target="stats", evidence=f"{len(data)} сканов, "
            f"{len(findings)} findings, {len(anomalies)} аномалий",
            data={"total": len(data), "findings": len(findings),
                  "anomalies": len(anomalies)},
        )
        return Path(out_path)
    except Exception as exc:
        console.print(f"[red]Ошибка HTML: {exc}[/red]")
        return None


# ---------------------------------------------------------------------------
# Экспорт CSV/MD (NEW)
# ---------------------------------------------------------------------------

def export_stats_csv(out_path: str | None = None) -> Path | None:
    """Экспорт статистики в CSV."""
    data = _parse_history()
    if not data:
        console.print("[yellow]История пуста.[/yellow]")
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not out_path:
        out_path = str(STATS_DIR / f"stats_{ts}.csv")
    try:
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["id", "module", "target", "created_at",
                        "result_len"])
            for r in data:
                w.writerow([r["id"], r["module"], r["target"],
                            r["created_at"].isoformat(),
                            r["result_len"]])
        console.print(f"[green]✓ CSV: {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:
        console.print(f"[red]CSV: {exc}[/red]")
        return None


def export_stats_md(out_path: str | None = None) -> Path | None:
    """Экспорт статистики в Markdown."""
    data = _parse_history()
    if not data:
        console.print("[yellow]История пуста.[/yellow]")
        return None
    findings = _parse_findings()
    cves_count = _parse_cves_count()
    first = min(r["created_at"] for r in data)
    last = max(r["created_at"] for r in data)
    days = (last - first).days + 1

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not out_path:
        out_path = str(STATS_DIR / f"stats_{ts}.md")

    top_mods = Counter(r["module"] for r in data).most_common(10)
    top_tgts = Counter(r["target"] for r in data).most_common(10)
    sev_counter = Counter((f.get("severity") or "info").lower()
                           for f in findings)

    lines = [
        "# CyberSec Toolkit — статистика",
        f"_Generated: {datetime.now().isoformat()}_",
        "",
        "## Общее",
        f"- Всего сканов: **{len(data)}**",
        f"- Уникальных целей: **{len({r['target'] for r in data})}**",
        f"- Уникальных модулей: **{len({r['module'] for r in data})}**",
        f"- Дней активности: **{days}**",
        f"- CVE в базе: **{cves_count}**",
        f"- Findings всего: **{len(findings)}**",
        "",
        "### Findings по severity",
        f"- critical: **{sev_counter.get('critical', 0)}**",
        f"- high: **{sev_counter.get('high', 0)}**",
        f"- medium: **{sev_counter.get('medium', 0)}**",
        f"- low: **{sev_counter.get('low', 0)}**",
        "",
        "## Топ модулей",
        "| # | Модуль | Сканов |",
        "|---|--------|--------|",
    ]
    for i, (m, c) in enumerate(top_mods, 1):
        lines.append(f"| {i} | `{m}` | {c} |")
    lines += ["", "## Топ целей", "| # | Цель | Сканов |",
              "|---|------|--------|"]
    for i, (t, c) in enumerate(top_tgts, 1):
        lines.append(f"| {i} | `{t}` | {c} |")

    anomalies = _detect_anomalies(data, findings)
    if anomalies:
        lines += ["", "## ⚠ Аномалии"]
        for a in anomalies:
            if a["kind"] == "day_spike":
                lines.append(f"- Спайк {a['date']}: {a['count']} "
                             f"(avg {a['avg']})")
            elif a["kind"] == "rare_modules":
                lines.append(f"- Редкие модули: "
                             f"{', '.join(a['modules'][:5])}")
            elif a["kind"] == "many_critical_findings":
                lines.append(f"- {a['count']} critical findings")

    try:
        Path(out_path).write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green]✓ Markdown: {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:
        console.print(f"[red]MD: {exc}[/red]")
        return None


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

    findings = _parse_findings()

    console.print(f"[cyan]Генерирую графики по {len(data)} сканам…"
                  f"[/cyan]\n")
    files: list[Path] = []

    # Graphs without findings
    for fn in (plot_timeline, plot_top_modules, plot_top_targets,
               plot_hourly, plot_pie_modules, plot_heatmap,
               plot_cumulative, plot_dashboard):
        try:
            p = fn(data)
            if p:
                files.append(p)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Ошибка {fn.__name__}: {exc}[/red]")
            log.exception("plot error")

    # Severity pie (needs findings)
    if findings:
        try:
            p = plot_severity_pie(findings)
            if p:
                files.append(p)
        except Exception as exc:  # noqa: BLE001
            log.warning("severity pie: %s", exc)

    if not files:
        console.print("[red]Не удалось построить графики.[/red]")
        return

    console.print(f"\n[bold green]✓ Готово: {len(files)} графиков"
                  f"[/bold green]")
    console.print(f"[dim]Папка: {STATS_DIR}[/dim]")

    db.save_scan("stats", "history",
                 {"files": [str(p) for p in files],
                  "count": len(data)})

    # Anomalies
    anomalies = _detect_anomalies(data, findings)
    _report_anomalies(anomalies)

    if open_after and files:
        dashboard = next(
            (p for p in files if "dashboard" in p.name), files[0])
        console.print(f"[cyan]Открываю: {dashboard.name}[/cyan]")
        _open_file(dashboard)


def menu() -> None:
    """Меню статистики."""
    table = Table(title="[bold]Graph & Statistics Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Текстовая сводка (+ аномалии)"),
        ("2", "Timeline (сканы по дням)"),
        ("3", "Топ модулей"),
        ("4", "Топ целей"),
        ("5", "Активность по часам"),
        ("6", "Pie: распределение по модулям"),
        ("7", "Heatmap (дни недели × часы)"),
        ("8", "Кумулятивный рост"),
        ("9", "Pie: findings по severity"),
        ("10", "Dashboard PNG 2×3 (все сразу)"),
        ("11", "HTML dashboard (self-contained)"),
        ("12", "Экспорт CSV"),
        ("13", "Экспорт Markdown"),
        ("14", "Всё + открыть dashboard"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        text_summary()
        return

    if c == "11":
        p = generate_html_dashboard()
        if p and Confirm.ask("Открыть в браузере?", default=False):
            _open_file(p)
        return
    if c == "12":
        export_stats_csv()
        return
    if c == "13":
        export_stats_md()
        return
    if c == "14":
        generate_all(open_after=True)
        return

    if not _matplotlib_available():
        console.print("[red]matplotlib не установлен: "
                      "pip install matplotlib[/red]")
        return

    data = _parse_history()
    if not data:
        console.print("[yellow]История пуста.[/yellow]")
        return

    findings = _parse_findings()

    fn_map = {
        "2": plot_timeline,
        "3": plot_top_modules,
        "4": plot_top_targets,
        "5": plot_hourly,
        "6": plot_pie_modules,
        "7": plot_heatmap,
        "8": plot_cumulative,
        "10": plot_dashboard,
    }
    if c == "9":
        if not findings:
            console.print("[yellow]Findings нет.[/yellow]")
            return
        p = plot_severity_pie(findings)
        if p and Confirm.ask("Открыть файл?", default=False):
            _open_file(p)
        return
    if c in fn_map:
        p = fn_map[c](data)
        if p and Confirm.ask("Открыть файл?", default=False):
            _open_file(p)


# ---------------------------------------------------------------------------
# CLI-обёртки (сохранены)
# ---------------------------------------------------------------------------

def cli_summary() -> None:
    text_summary()


def cli_graphs() -> None:
    generate_all(open_after=False)


def cli_html() -> None:
    generate_html_dashboard()


def cli_csv() -> None:
    export_stats_csv()


def cli_md() -> None:
    export_stats_md()


if __name__ == "__main__":
    menu()