"""
Report Export Pro — расширенный экспорт истории сканов.
Author: idqwixxa

Возможности:
    ─── HTML ───
    - Тёмная тема (DedSec-style)
    - TOC + якоря
    - Фильтр по модулю / цели / дате
    - Группировка по модулям (collapsible)
    - Summary-карточки (stats)
    - Timeline активности
    - Поиск/фильтр на странице (JS)
    - Экспорт в один self-contained файл

    ─── PDF (reportlab) ───
    - Титульная страница
    - TOC
    - Summary статистика
    - Разбивка по модулям
    - Ограничение по объёму (poster pages)

    ─── CSV ───
    - Плоская выгрузка всех сканов
    - Опциональная фильтрация по модулю / target / date

    ─── Markdown ───
    - Готовый MD-отчёт
    - Summary + таблица
    - Фильтры

    ─── JSON ───
    - Структурированный экспорт с meta

    ─── Фильтры ───
    - По модулю
    - По target
    - По датам (from / to)
    - По количеству

    ─── Интеграция ───
    - Notify по завершении
    - Findings (для больших выгрузок)

⚠ Только для этичного использования.
"""
import csv
import html as html_mod
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

EXPORT_DIR = REPORT_DIR / "exports"
EXPORT_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Общие хелперы
# ===========================================================================

def _fetch_scans(limit: int = 500, module_filter: str = "",
                 target_filter: str = "",
                 date_from: str = "", date_to: str = "") -> list[Any]:
    """Загрузить историю с фильтрами."""
    rows = db.history(limit)
    out: list[Any] = []
    for r in rows:
        m = str(r["module"] or "")
        t = str(r["target"] or "")
        ts = str(r["created_at"] or "")
        if module_filter and module_filter.lower() not in m.lower():
            continue
        if target_filter and target_filter.lower() not in t.lower():
            continue
        if date_from and ts < date_from:
            continue
        if date_to and ts > date_to:
            continue
        out.append(r)
    return out


def _group_by_module(rows: list[Any]) -> dict[str, list[Any]]:
    """Группировка строк по модулю."""
    out: dict[str, list[Any]] = defaultdict(list)
    for r in rows:
        out[str(r["module"])].append(r)
    return dict(sorted(out.items(),
                       key=lambda x: -len(x[1])))


def _summary_stats(rows: list[Any]) -> dict:
    """Агрегированная статистика."""
    stats: dict = {
        "total": len(rows),
        "modules": {},
        "targets": {},
        "first_ts": "",
        "last_ts": "",
    }
    if not rows:
        return stats
    mods: Counter = Counter()
    tgts: Counter = Counter()
    for r in rows:
        mods[str(r["module"])] += 1
        tgts[str(r["target"])] += 1
    stats["modules"] = dict(mods.most_common(20))
    stats["targets"] = dict(tgts.most_common(20))
    try:
        ts_list = sorted(str(r["created_at"]) for r in rows)
        stats["first_ts"] = ts_list[0]
        stats["last_ts"] = ts_list[-1]
    except Exception:
        pass
    return stats


def _timeline(rows: list[Any]) -> dict[str, int]:
    """Сканы по дням."""
    out: Counter = Counter()
    for r in rows:
        try:
            d = str(r["created_at"])[:10]
            out[d] += 1
        except Exception:
            continue
    return dict(sorted(out.items()))


# ===========================================================================
# HTML (расширенный)
# ===========================================================================

HTML_CSS = """
*{box-sizing:border-box;}
body{background:#0a0a0a;color:#c8c8c8;margin:0;padding:32px;
     font-family:'JetBrains Mono','Fira Code',Consolas,monospace;
     line-height:1.55;}
.container{max-width:1400px;margin:0 auto;}
h1{color:#00ff9c;border-bottom:2px solid #00ff9c;padding-bottom:8px;
   margin-top:0;}
h2{color:#00ff9c;margin-top:36px;border-left:4px solid #00ff9c;
   padding-left:12px;cursor:pointer;}
h2:hover{background:#0d0d0d;}
h3{color:#7ad9ff;margin-top:20px;}
.disclaimer{border:2px solid #ff4040;padding:10px 14px;
            color:#ff9090;margin-bottom:24px;background:#1a0000;
            border-radius:4px;}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
         gap:12px;margin:20px 0;}
.card{background:#0d0d0d;border:1px solid #222;padding:14px;
      border-radius:4px;}
.card .num{font-size:26px;color:#00ff9c;font-weight:bold;}
.card .label{font-size:12px;color:#888;margin-top:4px;}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px;}
th{background:#111;color:#00ff9c;text-align:left;padding:8px;
   border:1px solid #222;}
td{padding:6px 8px;border:1px solid #222;vertical-align:top;
   word-break:break-word;}
tr:nth-child(even){background:#0d0d0d;}
tr:hover{background:#141414;}
.module{color:#ff7ad9;}
.target{color:#7ad9ff;}
.ts{color:#888;width:170px;}
pre{background:#050505;border:1px solid #222;padding:10px;
    overflow-x:auto;color:#a0ffa0;font-size:11px;
    max-height:180px;border-radius:4px;margin:0;}
.meta{color:#888;font-size:12px;margin-bottom:16px;}
.toc{background:#0d0d0d;border:1px solid #222;padding:16px 24px;
     border-radius:4px;margin-bottom:24px;}
.toc ul{list-style:none;padding-left:0;columns:2;}
.toc a{color:#7ad9ff;text-decoration:none;}
.toc a:hover{text-decoration:underline;}
.filter{background:#0d0d0d;border:1px solid #222;padding:12px;
        border-radius:4px;margin-bottom:24px;display:flex;
        gap:12px;flex-wrap:wrap;align-items:center;}
.filter input,.filter select{background:#050505;color:#c8c8c8;
        border:1px solid #333;padding:6px 10px;border-radius:4px;
        font-family:inherit;}
.timeline{background:#0d0d0d;border:1px solid #222;border-radius:4px;
          padding:12px;font-family:monospace;font-size:11px;
          overflow-x:auto;white-space:pre;color:#00ff9c;}
.group{margin-top:16px;}
.footer{margin-top:40px;padding-top:16px;border-top:1px solid #222;
        color:#555;font-size:12px;text-align:center;}
.hidden{display:none;}
"""

HTML_JS = """
function toggle(id) {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('hidden');
}
function filterRows() {
    const mod = (document.getElementById('f-module')||{}).value?.toLowerCase()||'';
    const tgt = (document.getElementById('f-target')||{}).value?.toLowerCase()||'';
    document.querySelectorAll('tbody tr').forEach(tr => {
        const m = (tr.dataset.module||'').toLowerCase();
        const t = (tr.dataset.target||'').toLowerCase();
        tr.style.display = (m.includes(mod) && t.includes(tgt)) ? '' : 'none';
    });
}
"""


def _row_html(r: Any) -> str:
    """Одна строка таблицы."""
    result_str = str(r["result"])
    if len(result_str) > 1000:
        result_str = result_str[:1000] + " …"
    result = html_mod.escape(result_str)
    module = html_mod.escape(str(r["module"]))
    target = html_mod.escape(str(r["target"]))
    ts = html_mod.escape(str(r["created_at"]))
    return (
        f'<tr data-module="{module}" data-target="{target}">'
        f"<td>{r['id']}</td>"
        f'<td class="module">{module}</td>'
        f'<td class="target">{target}</td>'
        f'<td class="ts">{ts}</td>'
        f"<td><pre>{result}</pre></td>"
        f"</tr>"
    )


def export_html(limit: int = 500, module_filter: str = "",
                target_filter: str = "",
                date_from: str = "", date_to: str = "",
                out_path: str | None = None) -> Path | None:
    """HTML-экспорт с TOC, фильтрами, группировкой."""
    rows = _fetch_scans(limit, module_filter, target_filter,
                        date_from, date_to)
    if not rows:
        console.print("[yellow]Нет данных для экспорта.[/yellow]")
        return None

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    stats = _summary_stats(rows)
    timeline = _timeline(rows)
    by_module = _group_by_module(rows)

    # Summary cards
    cards = [
        ("Всего сканов", stats["total"]),
        ("Модулей", len(stats["modules"])),
        ("Уникальных целей", len(stats["targets"])),
        ("Самый активный модуль",
         next(iter(stats["modules"]), "—")),
        ("Самый популярный target",
         next(iter(stats["targets"]), "—")),
    ]
    cards_html = "".join(
        f'<div class="card"><div class="num">{html_mod.escape(str(v))}</div>'
        f'<div class="label">{html_mod.escape(k)}</div></div>'
        for k, v in cards
    )

    # TOC
    toc_items = "".join(
        f'<li>• <a href="#m-{html_mod.escape(mod)}">'
        f'{html_mod.escape(mod)} ({len(items)})</a></li>'
        for mod, items in by_module.items()
    )

    # Timeline ASCII
    timeline_html = ""
    if timeline:
        max_v = max(timeline.values()) or 1
        lines = []
        for day, cnt in timeline.items():
            bar = "█" * int(cnt / max_v * 40)
            lines.append(f"{day}  {bar}  {cnt}")
        timeline_html = (
            f'<h2 id="timeline">📅 Timeline</h2>'
            f'<div class="timeline">{html_mod.escape(chr(10).join(lines))}</div>'
        )

    # Rows grouped
    rows_html_parts = []
    for mod, items in by_module.items():
        anchor = f"m-{mod}"
        rows_html_parts.append(
            f'<h2 id="{html_mod.escape(anchor)}" '
            f'onclick="toggle(\'tbl-{html_mod.escape(anchor)}\')">'
            f'📦 {html_mod.escape(mod)} ({len(items)})</h2>'
        )
        rows_html_parts.append(
            f'<div id="tbl-{html_mod.escape(anchor)}" class="group">'
            f'<table><thead><tr>'
            f'<th>#</th><th>Модуль</th><th>Цель</th>'
            f'<th>Дата</th><th>Результат</th>'
            f'</tr></thead><tbody>'
        )
        for r in items[:200]:
            rows_html_parts.append(_row_html(r))
        rows_html_parts.append("</tbody></table></div>")

    body = "\n".join(rows_html_parts)

    html_str = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<title>CyberSec Toolkit — отчёт {ts}</title>
<style>{HTML_CSS}</style>
</head><body><div class="container">
<h1>🛡️ CyberSec Toolkit — отчёт</h1>
<div class="meta">Сгенерирован: {ts} | Сканов: {stats['total']}</div>
<div class="disclaimer">
    ⚠ Отчёт содержит результаты сканирования. Используй только в рамках
    этичного пентеста / CTF, с разрешения владельца цели.
</div>
<div class="summary">{cards_html}</div>

<div class="toc">
    <b>Содержание:</b>
    <ul>
        <li>• <a href="#timeline">Timeline</a></li>
        {toc_items}
    </ul>
</div>

<div class="filter">
    <label>Фильтр (live):</label>
    <input type="text" id="f-module" placeholder="модуль..."
           oninput="filterRows()">
    <input type="text" id="f-target" placeholder="target..."
           oninput="filterRows()">
    <button onclick="document.getElementById('f-module').value='';
                     document.getElementById('f-target').value='';
                     filterRows()">Сбросить</button>
</div>

{timeline_html}
{body}

<div class="footer">
    CyberSec Toolkit — by idqwixxa
</div>
</div>
<script>{HTML_JS}</script>
</body></html>
"""

    if not out_path:
        ts_file = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(EXPORT_DIR / f"report_{ts_file}.html")
    try:
        Path(out_path).write_text(html_str, encoding="utf-8")
        size = Path(out_path).stat().st_size / 1024
        console.print(f"[green]✓ HTML: {out_path} ({size:.1f} KB, "
                      f"{stats['total']} сканов)[/green]")
        db.save_scan("export_html", "history",
                     {"count": stats["total"], "path": str(out_path)})
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка записи: {exc}[/red]")
        return None


# ===========================================================================
# PDF
# ===========================================================================

def _pdf_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def export_pdf(limit: int = 300, module_filter: str = "",
               target_filter: str = "",
               date_from: str = "", date_to: str = "",
               out_path: str | None = None) -> Path | None:
    """PDF-экспорт через reportlab."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table as RLTable,
            TableStyle, PageBreak,
        )
    except ImportError:
        console.print("[red]reportlab не установлен.[/red]")
        console.print("[yellow]Установи: pip install reportlab[/yellow]")
        return None

    rows = _fetch_scans(limit, module_filter, target_filter,
                        date_from, date_to)
    if not rows:
        console.print("[yellow]Нет данных.[/yellow]")
        return None

    stats = _summary_stats(rows)
    by_module = _group_by_module(rows)

    if not out_path:
        ts_file = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(EXPORT_DIR / f"report_{ts_file}.pdf")

    try:
        doc = SimpleDocTemplate(
            out_path, pagesize=A4,
            leftMargin=15 * mm, rightMargin=15 * mm,
            topMargin=15 * mm, bottomMargin=15 * mm,
            title="CyberSec Toolkit Report",
            author="CyberSec Toolkit",
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]PDF init: {exc}[/red]")
        return None

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"],
                        textColor=colors.HexColor("#006633"))
    h2 = ParagraphStyle("H2", parent=styles["Heading2"],
                        textColor=colors.HexColor("#006633"))
    body = ParagraphStyle("Body", parent=styles["BodyText"],
                          fontSize=8, leading=10)
    warn = ParagraphStyle("Warn", parent=styles["BodyText"],
                          textColor=colors.red, fontSize=10, leading=13)

    story = []
    # Титульная
    story.append(Paragraph("CyberSec Toolkit — Report", h1))
    story.append(Paragraph(
        f"Сгенерирован: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        body))
    story.append(Paragraph(
        f"Сканов в отчёте: {stats['total']}", body))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        "⚠ Только для этичного использования и CTF. "
        "Сканы выполнены с разрешения владельца.", warn))
    story.append(Spacer(1, 8 * mm))

    # Summary
    story.append(Paragraph("Summary", h2))
    summary_data = [
        ["Метрика", "Значение"],
        ["Всего сканов", str(stats["total"])],
        ["Модулей", str(len(stats["modules"]))],
        ["Целей", str(len(stats["targets"]))],
        ["Первый скан", stats["first_ts"][:19]],
        ["Последний скан", stats["last_ts"][:19]],
    ]
    t = RLTable(summary_data, colWidths=[60 * mm, 80 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d0f0d8")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#004d26")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(t)

    # По модулям
    story.append(PageBreak())
    story.append(Paragraph("Сканы по модулям", h2))

    for mod, items in by_module.items():
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph(
            f"<b>{_pdf_escape(mod)}</b> ({len(items)})", body))
        data = [["#", "Цель", "Дата", "Результат"]]
        for r in items[:50]:
            result_str = str(r["result"])[:200]
            data.append([
                str(r["id"]),
                _pdf_escape(str(r["target"])[:40]),
                _pdf_escape(str(r["created_at"])[:19]),
                Paragraph(_pdf_escape(result_str), body),
            ])
        t = RLTable(data, colWidths=[10 * mm, 45 * mm, 35 * mm, 75 * mm],
                     repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d0f0d8")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#004d26")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ]))
        story.append(t)

    try:
        doc.build(story)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]PDF build: {exc}[/red]")
        log.exception("pdf build")
        return None

    size = Path(out_path).stat().st_size / 1024
    console.print(f"[green]✓ PDF: {out_path} ({size:.1f} KB)[/green]")
    db.save_scan("export_pdf", "history",
                 {"count": stats["total"], "path": out_path})
    return Path(out_path)


# ===========================================================================
# CSV
# ===========================================================================

def export_csv(limit: int = 5000, module_filter: str = "",
               target_filter: str = "",
               date_from: str = "", date_to: str = "",
               out_path: str | None = None) -> Path | None:
    """CSV-экспорт."""
    rows = _fetch_scans(limit, module_filter, target_filter,
                        date_from, date_to)
    if not rows:
        console.print("[yellow]Нет данных.[/yellow]")
        return None

    if not out_path:
        ts_file = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(EXPORT_DIR / f"history_{ts_file}.csv")

    try:
        cols = ["id", "module", "target", "created_at", "result"]
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for r in rows:
                w.writerow([
                    r["id"], r["module"], r["target"],
                    str(r["created_at"]),
                    str(r["result"])[:5000],
                ])
        size = Path(out_path).stat().st_size / 1024
        console.print(f"[green]✓ CSV: {out_path} ({size:.1f} KB, "
                      f"{len(rows)} записей)[/green]")
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]CSV: {exc}[/red]")
        return None


# ===========================================================================
# Markdown
# ===========================================================================

def export_markdown(limit: int = 1000, module_filter: str = "",
                    target_filter: str = "",
                    date_from: str = "", date_to: str = "",
                    out_path: str | None = None) -> Path | None:
    """Markdown-экспорт."""
    rows = _fetch_scans(limit, module_filter, target_filter,
                        date_from, date_to)
    if not rows:
        console.print("[yellow]Нет данных.[/yellow]")
        return None

    stats = _summary_stats(rows)
    by_module = _group_by_module(rows)

    if not out_path:
        ts_file = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(EXPORT_DIR / f"report_{ts_file}.md")

    lines: list[str] = [
        "# CyberSec Toolkit — Report",
        "",
        f"_Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_",
        "",
        "## Summary",
        "",
        f"- **Total scans:** {stats['total']}",
        f"- **Modules:** {len(stats['modules'])}",
        f"- **Unique targets:** {len(stats['targets'])}",
        f"- **First scan:** {stats['first_ts'][:19]}",
        f"- **Last scan:** {stats['last_ts'][:19]}",
        "",
        "## Timeline",
        "",
        "```",
    ]
    timeline = _timeline(rows)
    if timeline:
        max_v = max(timeline.values()) or 1
        for day, cnt in timeline.items():
            lines.append(f"{day}  {'█' * int(cnt / max_v * 40)}  {cnt}")
    lines.append("```")
    lines.append("")

    for mod, items in by_module.items():
        lines.append(f"## {mod} ({len(items)})")
        lines.append("")
        lines.append("| # | Target | Date |")
        lines.append("|---|--------|------|")
        for r in items[:100]:
            lines.append(
                f"| {r['id']} | `{r['target'][:40]}` | "
                f"{str(r['created_at'])[:19]} |"
            )
        lines.append("")

    try:
        Path(out_path).write_text("\n".join(lines), encoding="utf-8")
        size = Path(out_path).stat().st_size / 1024
        console.print(f"[green]✓ Markdown: {out_path} ({size:.1f} KB)"
                      f"[/green]")
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Markdown: {exc}[/red]")
        return None


# ===========================================================================
# JSON
# ===========================================================================

def export_json(limit: int = 5000, module_filter: str = "",
                target_filter: str = "",
                date_from: str = "", date_to: str = "",
                out_path: str | None = None) -> Path | None:
    """JSON-экспорт с meta."""
    rows = _fetch_scans(limit, module_filter, target_filter,
                        date_from, date_to)
    if not rows:
        console.print("[yellow]Нет данных.[/yellow]")
        return None

    if not out_path:
        ts_file = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(EXPORT_DIR / f"history_{ts_file}.json")

    data = {
        "meta": {
            "generated": datetime.now().isoformat(),
            "filters": {
                "module": module_filter,
                "target": target_filter,
                "date_from": date_from,
                "date_to": date_to,
                "limit": limit,
            },
            "summary": _summary_stats(rows),
        },
        "scans": [
            {
                "id": r["id"],
                "module": r["module"],
                "target": r["target"],
                "created_at": str(r["created_at"]),
                "result": r["result"],
            }
            for r in rows
        ],
    }
    try:
        Path(out_path).write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
        size = Path(out_path).stat().st_size / 1024
        console.print(f"[green]✓ JSON: {out_path} ({size:.1f} KB)[/green]")
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]JSON: {exc}[/red]")
        return None


# ===========================================================================
# Одиночный scan → Markdown
# ===========================================================================

def export_scan_markdown(scan_id: int,
                         out_path: str | None = None) -> Path | None:
    """Сохранить конкретный скан (по id) в Markdown."""
    rows = [r for r in db.history(2000) if r["id"] == scan_id]
    if not rows:
        console.print(f"[red]Скан #{scan_id} не найден.[/red]")
        return None
    r = rows[0]
    ts_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not out_path:
        out_path = str(EXPORT_DIR / f"scan_{scan_id}_{ts_file}.md")

    try:
        parsed = json.loads(r["result"])
    except Exception:
        parsed = r["result"]

    md = (
        f"# Scan #{r['id']}\n\n"
        f"- **Модуль:** {r['module']}\n"
        f"- **Цель:** {r['target']}\n"
        f"- **Дата:** {r['created_at']}\n\n"
        f"## Результат\n\n"
        f"```json\n"
        f"{json.dumps(parsed, indent=2, ensure_ascii=False, default=str)}\n"
        f"```\n"
    )
    try:
        Path(out_path).write_text(md, encoding="utf-8")
        console.print(f"[green]✓ {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# Notify
# ===========================================================================

def _notify(title: str, count: int, paths: list[Path]) -> None:
    """Notify о завершении экспорта."""
    try:
        from modules import notifier
        notifier.notify_all(
            f"📄 {title}",
            f"Сканов: {count}\n"
            f"Файлов: {len(paths)}",
        )
    except Exception:
        pass


# ===========================================================================
# Interactive menu
# ===========================================================================

def _ask_filters() -> dict:
    """Запросить фильтры."""
    console.print("\n[dim]Enter — без фильтра[/dim]")
    m = Prompt.ask("Модуль", default="").strip()
    t = Prompt.ask("Target", default="").strip()
    df = Prompt.ask("Date from (YYYY-MM-DD)", default="").strip()
    dt = Prompt.ask("Date to (YYYY-MM-DD)", default="").strip()
    return {
        "module_filter": m,
        "target_filter": t,
        "date_from": df,
        "date_to": dt,
    }


def menu() -> None:
    """Меню экспорта."""
    table = Table(title="[bold]Report Export Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "История → HTML (TOC, фильтры, timeline)"),
        ("2", "История → PDF (reportlab)"),
        ("3", "История → CSV"),
        ("4", "История → Markdown"),
        ("5", "История → JSON"),
        ("6", "Все форматы сразу (HTML+PDF+CSV+MD+JSON)"),
        ("7", "Конкретный скан → Markdown"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        limit = IntPrompt.ask("Сколько последних сканов", default=500)
        if Confirm.ask("Применить фильтры?", default=False):
            f = _ask_filters()
            p = export_html(limit=limit, **f)
        else:
            p = export_html(limit=limit)
        if p:
            _notify("HTML export", limit, [p])
    elif c == "2":
        limit = IntPrompt.ask("Сколько последних сканов", default=300)
        if Confirm.ask("Применить фильтры?", default=False):
            f = _ask_filters()
            p = export_pdf(limit=limit, **f)
        else:
            p = export_pdf(limit=limit)
        if p:
            _notify("PDF export", limit, [p])
    elif c == "3":
        limit = IntPrompt.ask("Сколько сканов", default=5000)
        export_csv(limit=limit)
    elif c == "4":
        limit = IntPrompt.ask("Сколько сканов", default=1000)
        export_markdown(limit=limit)
    elif c == "5":
        limit = IntPrompt.ask("Сколько сканов", default=5000)
        export_json(limit=limit)
    elif c == "6":
        limit = IntPrompt.ask("Сколько сканов", default=500)
        paths: list[Path] = []
        for fn in (export_html, export_pdf, export_csv,
                   export_markdown, export_json):
            try:
                p = fn(limit=limit)
                if p:
                    paths.append(p)
            except Exception:
                continue
        if paths:
            _notify("Full export", limit, paths)
    elif c == "7":
        export_scan_markdown(IntPrompt.ask("ID скана"))


# ===========================================================================
# CLI-обёртки
# ===========================================================================

def cli_html(limit: int = 500) -> None:
    export_html(limit=limit)


def cli_pdf(limit: int = 300) -> None:
    export_pdf(limit=limit)


def cli_csv(limit: int = 5000) -> None:
    export_csv(limit=limit)


def cli_md(limit: int = 1000) -> None:
    export_markdown(limit=limit)


def cli_json(limit: int = 5000) -> None:
    export_json(limit=limit)


def cli_scan_md(scan_id: int) -> None:
    export_scan_markdown(scan_id)