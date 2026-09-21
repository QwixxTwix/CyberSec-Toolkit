"""
Экспорт истории сканов и отчётов в PDF и HTML.
PDF генерируется через reportlab (pure-python, без системных зависимостей).
HTML — один самодостаточный файл с CSS-темой DedSec.
"""
import json
import html
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt, IntPrompt
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>CyberSec Toolkit — отчёт {ts}</title>
<style>
    * {{ box-sizing: border-box; }}
    body {{
        background: #0a0a0a;
        color: #c8c8c8;
        font-family: 'JetBrains Mono', 'Fira Code', Consolas, monospace;
        margin: 0;
        padding: 24px;
    }}
    h1 {{
        color: #00ff9c;
        border-bottom: 2px solid #00ff9c;
        padding-bottom: 8px;
    }}
    h2 {{ color: #00ff9c; margin-top: 32px; }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin-top: 12px;
        font-size: 13px;
    }}
    th {{
        background: #111;
        color: #00ff9c;
        text-align: left;
        padding: 8px;
        border: 1px solid #222;
    }}
    td {{
        padding: 6px 8px;
        border: 1px solid #222;
        vertical-align: top;
    }}
    tr:nth-child(even) {{ background: #0d0d0d; }}
    tr:hover {{ background: #141414; }}
    .module {{ color: #ff7ad9; }}
    .target {{ color: #7ad9ff; }}
    .ts {{ color: #888; }}
    pre {{
        background: #050505;
        border: 1px solid #222;
        padding: 10px;
        overflow-x: auto;
        color: #a0ffa0;
        font-size: 12px;
    }}
    .meta {{ color: #888; font-size: 12px; margin-bottom: 16px; }}
    .disclaimer {{
        border: 2px solid #ff4040;
        padding: 10px 14px;
        color: #ff9090;
        margin-bottom: 24px;
        background: #1a0000;
    }}
</style>
</head>
<body>
<h1>🛡️ CyberSec Toolkit — отчёт</h1>
<div class="meta">Сгенерирован: {ts}</div>
<div class="disclaimer">
    ⚠ Отчёт содержит результаты сканирования. Используй только в рамках
    этичного пентеста / CTF, с разрешения владельца цели.
</div>
<h2>Сканы ({count})</h2>
<table>
<tr><th>#</th><th>Модуль</th><th>Цель</th><th>Дата</th><th>Результат</th></tr>
{rows}
</table>
</body>
</html>
"""


def _row_html(r) -> str:
    """Одна строка таблицы."""
    result_str = str(r["result"])
    if len(result_str) > 500:
        result_str = result_str[:500] + " …"
    result = html.escape(result_str)
    module = html.escape(str(r["module"]))
    target = html.escape(str(r["target"]))
    ts = html.escape(str(r["created_at"]))
    return (
        f"<tr>"
        f"<td>{r['id']}</td>"
        f"<td class='module'>{module}</td>"
        f"<td class='target'>{target}</td>"
        f"<td class='ts'>{ts}</td>"
        f"<td><pre>{result}</pre></td>"
        f"</tr>"
    )


def export_html(limit: int = 500) -> None:
    """Экспорт истории сканов в HTML."""
    rows = db.history(limit)
    if not rows:
        console.print("[yellow]История пуста.[/yellow]")
        return
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    body = "\n".join(_row_html(r) for r in rows)
    html_str = HTML_TEMPLATE.format(ts=ts, count=len(rows), rows=body)

    ts_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = REPORT_DIR / f"report_{ts_file}.html"
    try:
        out.write_text(html_str, encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка записи: {exc}[/red]")
        return
    console.print(f"[green]✓ HTML: {out}[/green]")


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def _pdf_escape(text: str) -> str:
    """Экранирование для PDF (reportlab сам это делает, но подстрахуемся)."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def export_pdf(limit: int = 300) -> None:
    """Экспорт истории сканов в PDF через reportlab."""
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
        return

    rows = db.history(limit)
    if not rows:
        console.print("[yellow]История пуста.[/yellow]")
        return

    ts_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = REPORT_DIR / f"report_{ts_file}.pdf"

    try:
        doc = SimpleDocTemplate(
            str(out),
            pagesize=A4,
            leftMargin=15 * mm, rightMargin=15 * mm,
            topMargin=15 * mm, bottomMargin=15 * mm,
            title="CyberSec Toolkit Report",
            author="CyberSec Toolkit",
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка инициализации PDF: {exc}[/red]")
        return

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"],
                        textColor=colors.HexColor("#006633"))
    h2 = ParagraphStyle("H2", parent=styles["Heading2"],
                        textColor=colors.HexColor("#006633"))
    body = ParagraphStyle("Body", parent=styles["BodyText"], fontSize=8,
                          leading=10)
    warn = ParagraphStyle("Warn", parent=styles["BodyText"],
                          textColor=colors.red, fontSize=10, leading=13)

    story = []
    story.append(Paragraph("CyberSec Toolkit — Report", h1))
    story.append(Paragraph(
        f"Сгенерирован: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        body,
    ))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        "⚠ Только для этичного использования и CTF. "
        "Сканы выполнены с разрешения владельца.",
        warn,
    ))
    story.append(Spacer(1, 8 * mm))

    story.append(Paragraph(f"Сканы ({len(rows)})", h2))

    data = [["#", "Модуль", "Цель", "Дата", "Результат"]]
    for r in rows:
        result_str = str(r["result"])
        if len(result_str) > 200:
            result_str = result_str[:200] + " …"
        data.append([
            str(r["id"]),
            _pdf_escape(str(r["module"])),
            _pdf_escape(str(r["target"])),
            _pdf_escape(str(r["created_at"])[:19]),
            Paragraph(_pdf_escape(result_str), body),
        ])

    col_widths = [10 * mm, 22 * mm, 40 * mm, 30 * mm, 78 * mm]
    table = RLTable(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d0f0d8")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#004d26")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f5f5f5")]),
    ]))
    story.append(table)

    try:
        doc.build(story)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка сборки PDF: {exc}[/red]")
        log.exception("pdf build")
        return

    console.print(f"[green]✓ PDF: {out}[/green]")


# ---------------------------------------------------------------------------
# Одиночный отчёт из scan-записи в Markdown / JSON
# ---------------------------------------------------------------------------

def export_scan_markdown(scan_id: int) -> None:
    """Сохранить конкретный скан (по id) в Markdown."""
    rows = [r for r in db.history(1000) if r["id"] == scan_id]
    if not rows:
        console.print(f"[red]Скан #{scan_id} не найден.[/red]")
        return
    r = rows[0]
    ts_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = REPORT_DIR / f"scan_{scan_id}_{ts_file}.md"

    try:
        parsed = json.loads(r["result"])
    except Exception:  # noqa: BLE001
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
        out.write_text(md, encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return
    console.print(f"[green]✓ {out}[/green]")


def menu() -> None:
    """Меню экспорта."""
    table = Table(title="[bold]Report Export[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "История → HTML (тёмная тема)"),
        ("2", "История → PDF (reportlab)"),
        ("3", "Конкретный скан → Markdown"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        export_html(IntPrompt.ask("Сколько последних сканов", default=500))
    elif c == "2":
        export_pdf(IntPrompt.ask("Сколько последних сканов", default=300))
    elif c == "3":
        export_scan_markdown(IntPrompt.ask("ID скана"))