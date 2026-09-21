"""
Auto-Report Pro — единый отчёт CyberSec Toolkit.
Author: idqwixxa

Собирает из БД и файлов:
    - сканы (таблица scans)
    - находки и заметки (таблица notes)
    - графики (PNG из reports/, сгенерированные модулем stats)
    - скриншоты (PNG из reports/, сгенерированные модулем screenshot)

Генерирует:
    - HTML  (self-contained, картинки в base64)
    - PDF   (reportlab, с embedded-картинками)
    - JSON  (сырые данные для машинной обработки)

Шаблоны:
    default  — полный отчёт
    hackerone — секция findings с шаблоном H1
    bugcrowd  — секция findings с шаблоном Bugcrowd
"""
import base64
import html
import io
import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Сбор данных
# ---------------------------------------------------------------------------

def _collect_scans(limit: int = 500) -> list[dict]:
    rows = db.history(limit)
    out = []
    for r in rows:
        try:
            result = json.loads(r["result"]) if r["result"] else {}
        except Exception:  # noqa: BLE001
            result = {"raw": str(r["result"])[:500]}
        out.append({
            "id": r["id"],
            "module": r["module"],
            "target": r["target"],
            "created_at": str(r["created_at"]),
            "result": result,
        })
    return out


def _collect_notes() -> dict:
    """Вернуть {'findings': [...], 'notes': [...]}."""
    try:
        cur = db.conn.cursor()
        cur.execute("SELECT * FROM notes ORDER BY id DESC")
        rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001
        log.warning("notes read: %s", exc)
        return {"findings": [], "notes": []}

    findings, notes = [], []
    for r in rows:
        d = dict(r)
        try:
            d["tags"] = json.loads(d.get("tags") or "[]")
        except Exception:  # noqa: BLE001
            d["tags"] = []
        if d.get("kind") == "finding":
            findings.append(d)
        else:
            notes.append(d)
    return {"findings": findings, "notes": notes}


def _collect_images(prefixes: list[str]) -> list[dict]:
    """
    Вернуть список картинок из reports/ по префиксам имён.
    prefixes: например ['stats_', 'shot_', 'crawl_']
    """
    if not REPORT_DIR.exists():
        return []
    out = []
    for p in sorted(REPORT_DIR.glob("*.png")):
        if any(p.name.startswith(pre) for pre in prefixes):
            try:
                data = p.read_bytes()
                b64 = base64.b64encode(data).decode("ascii")
                out.append({
                    "path": str(p),
                    "name": p.name,
                    "size_kb": round(len(data) / 1024, 1),
                    "b64": b64,
                })
            except Exception as exc:  # noqa: BLE001
                log.warning("read image %s: %s", p, exc)
    return out


def _collect_all(scan_limit: int = 500) -> dict:
    """Собрать всё сразу."""
    scans = _collect_scans(scan_limit)
    notes = _collect_notes()
    stats_imgs = _collect_images(["stats_"])
    shots = _collect_images(["shot_"])

    # Сводка
    modules_count: dict[str, int] = {}
    targets_count: dict[str, int] = {}
    for s in scans:
        modules_count[s["module"]] = modules_count.get(s["module"], 0) + 1
        targets_count[s["target"]] = targets_count.get(s["target"], 0) + 1

    sev_count: dict[str, int] = {}
    status_count: dict[str, int] = {}
    for f in notes["findings"]:
        sev = (f.get("severity") or "info").lower()
        sev_count[sev] = sev_count.get(sev, 0) + 1
        st = f.get("status") or "open"
        status_count[st] = status_count.get(st, 0) + 1

    return {
        "scans": scans,
        "findings": notes["findings"],
        "notes": notes["notes"],
        "stats_images": stats_imgs,
        "screenshots": shots,
        "summary": {
            "total_scans": len(scans),
            "total_findings": len(notes["findings"]),
            "total_notes": len(notes["notes"]),
            "modules_count": modules_count,
            "targets_count": targets_count,
            "severity_count": sev_count,
            "status_count": status_count,
        },
    }


# ---------------------------------------------------------------------------
# HTML-шаблон
# ---------------------------------------------------------------------------

HTML_HEAD = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
    * {{ box-sizing: border-box; }}
    body {{
        background: #0a0a0a; color: #c8c8c8; margin: 0; padding: 32px;
        font-family: 'JetBrains Mono','Fira Code',Consolas,monospace;
        line-height: 1.5;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    h1 {{
        color: #00ff9c; border-bottom: 2px solid #00ff9c;
        padding-bottom: 8px; margin-top: 0;
    }}
    h2 {{
        color: #00ff9c; margin-top: 40px; border-left: 4px solid #00ff9c;
        padding-left: 12px;
    }}
    h3 {{ color: #7ad9ff; margin-top: 24px; }}
    .cover {{
        border: 2px solid #00ff9c; padding: 24px; margin-bottom: 24px;
        background: #080808;
    }}
    .cover .title {{ font-size: 28px; color: #00ff9c; font-weight: bold; }}
    .cover .meta {{ color: #888; margin-top: 8px; font-size: 13px; }}
    .disclaimer {{
        border: 2px solid #ff4040; background: #1a0000; color: #ff9090;
        padding: 12px 16px; margin: 20px 0; border-radius: 4px;
    }}
    .summary {{
        display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 12px; margin: 20px 0;
    }}
    .card {{
        background: #0d0d0d; border: 1px solid #222; padding: 14px;
        border-radius: 4px;
    }}
    .card .num {{ font-size: 26px; color: #00ff9c; font-weight: bold; }}
    .card .label {{ font-size: 12px; color: #888; margin-top: 4px; }}
    .sev-critical {{ color: #ff2020; font-weight: bold; }}
    .sev-high     {{ color: #ff7a40; font-weight: bold; }}
    .sev-medium   {{ color: #ffd23f; font-weight: bold; }}
    .sev-low      {{ color: #00ff9c; }}
    .sev-info     {{ color: #7ad9ff; }}
    table {{
        width: 100%; border-collapse: collapse; margin-top: 12px;
        font-size: 13px;
    }}
    th {{
        background: #111; color: #00ff9c; text-align: left;
        padding: 8px; border: 1px solid #222;
    }}
    td {{ padding: 6px 8px; border: 1px solid #222; vertical-align: top; }}
    tr:nth-child(even) {{ background: #0d0d0d; }}
    pre {{
        background: #050505; border: 1px solid #222; padding: 10px;
        overflow-x: auto; color: #a0ffa0; font-size: 12px;
        border-radius: 4px;
    }}
    img {{
        max-width: 100%; border: 1px solid #222; border-radius: 4px;
        margin: 8px 0; background: #0a0a0a;
    }}
    .finding {{
        border: 1px solid #222; border-left: 4px solid #ff7a40;
        padding: 14px; margin: 16px 0; background: #0d0d0d;
        border-radius: 4px;
    }}
    .finding.critical {{ border-left-color: #ff2020; }}
    .finding.high     {{ border-left-color: #ff7a40; }}
    .finding.medium   {{ border-left-color: #ffd23f; }}
    .finding.low      {{ border-left-color: #00ff9c; }}
    .finding.info     {{ border-left-color: #7ad9ff; }}
    .finding .head {{
        display: flex; justify-content: space-between; align-items: baseline;
        margin-bottom: 8px; flex-wrap: wrap; gap: 8px;
    }}
    .finding .id-title {{ font-size: 16px; color: #fff; font-weight: bold; }}
    .finding .badge {{
        background: #111; padding: 2px 8px; border-radius: 3px;
        font-size: 11px; color: #00ff9c;
    }}
    .tags {{ margin-top: 8px; }}
    .tag {{
        display: inline-block; background: #003322; color: #00ff9c;
        padding: 2px 8px; border-radius: 3px; font-size: 11px;
        margin-right: 4px;
    }}
    .footer {{
        margin-top: 40px; padding-top: 16px; border-top: 1px solid #222;
        color: #555; font-size: 12px; text-align: center;
    }}
    .scrollable-max {{ max-height: 600px; overflow-y: auto; }}
</style>
</head>
<body>
<div class="container">
"""

HTML_FOOT = """
<div class="footer">
    CyberSec Toolkit — Auto-Report Pro &nbsp;•&nbsp; by idqwixxa
    &nbsp;•&nbsp; {ts}
</div>
</div>
</body>
</html>
"""


def _esc(v) -> str:
    return html.escape(str(v if v is not None else ""))


def _html_cover(title: str, author: str, target_filter: str | None) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tf = target_filter or "все цели"
    return f"""
<div class="cover">
    <div class="title">🛡️ {_esc(title)}</div>
    <div class="meta">
        Сгенерирован: {ts}<br>
        Автор: {_esc(author)}<br>
        Фильтр по цели: {_esc(tf)}
    </div>
</div>
<div class="disclaimer">
    ⚠ Отчёт содержит результаты сканирования. Использование только в рамках
    этичного пентеста / CTF, с разрешения владельца цели.
</div>
"""


def _html_summary(summary: dict) -> str:
    s = summary
    cards = [
        ("Всего сканов", s["total_scans"]),
        ("Находок", s["total_findings"]),
        ("Заметок", s["total_notes"]),
        ("Уникальных целей", len(s["targets_count"])),
        ("Модулей использовано", len(s["modules_count"])),
    ]
    cards_html = "".join(
        f'<div class="card"><div class="num">{v}</div>'
        f'<div class="label">{_esc(k)}</div></div>'
        for k, v in cards
    )

    sev_html = ""
    if s["severity_count"]:
        sev_html = "<h3>Severity</h3><table><tr><th>Severity</th><th>Кол-во</th></tr>"
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in s["severity_count"]:
                sev_html += (f'<tr><td class="sev-{sev}">{sev.upper()}</td>'
                             f'<td>{s["severity_count"][sev]}</td></tr>')
        sev_html += "</table>"

    status_html = ""
    if s["status_count"]:
        status_html = "<h3>Status находок</h3><table><tr><th>Status</th><th>Кол-во</th></tr>"
        for st, c in s["status_count"].items():
            status_html += f"<tr><td>{_esc(st)}</td><td>{c}</td></tr>"
        status_html += "</table>"

    return f"""
<h2>📊 Сводка</h2>
<div class="summary">{cards_html}</div>
{sev_html}
{status_html}
"""


def _html_images(images: list[dict], title: str, max_images: int = 12) -> str:
    if not images:
        return ""
    html_out = f"<h2>{_esc(title)}</h2>"
    for img in images[:max_images]:
        html_out += (
            f'<div style="margin-bottom:16px;">'
            f'<div style="color:#888;font-size:12px;margin-bottom:4px;">'
            f'{_esc(img["name"])} ({img["size_kb"]} KB)</div>'
            f'<img src="data:image/png;base64,{img["b64"]}" alt="{_esc(img["name"])}">'
            f'</div>'
        )
    if len(images) > max_images:
        html_out += f'<div style="color:#888;">… и ещё {len(images)-max_images} изображений</div>'
    return html_out


def _html_findings(findings: list[dict]) -> str:
    if not findings:
        return "<h2>🔴 Findings</h2><p style='color:#888;'>Находок нет.</p>"

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_sorted = sorted(
        findings,
        key=lambda f: sev_order.get((f.get("severity") or "info").lower(), 5),
    )

    out = [f"<h2>🔴 Findings ({len(findings)})</h2>"]
    for f in findings_sorted:
        sev = (f.get("severity") or "info").lower()
        status = f.get("status") or "open"
        tags = f.get("tags") or []
        tags_html = "".join(f'<span class="tag">{_esc(t)}</span>' for t in tags)
        out.append(f"""
<div class="finding {sev}">
    <div class="head">
        <div class="id-title">#{f['id']} — {_esc(f['title'])}</div>
        <div>
            <span class="badge sev-{sev}">{_esc(sev.upper())}</span>
            <span class="badge">{_esc(status)}</span>
        </div>
    </div>
    <table>
        <tr><th>Target</th><td>{_esc(f.get('target') or '—')}</td></tr>
        <tr><th>Created</th><td>{_esc(f.get('created_at') or '—')}</td></tr>
        <tr><th>Updated</th><td>{_esc(f.get('updated_at') or '—')}</td></tr>
    </table>
    <div style="margin-top:10px;">{_esc(f.get('body') or '(пусто)').replace(chr(10), '<br>')}</div>
    <div class="tags">{tags_html}</div>
</div>
""")
    return "".join(out)


def _html_notes(notes: list[dict]) -> str:
    if not notes:
        return ""
    out = [f"<h2>📝 Notes ({len(notes)})</h2>"]
    for n in notes:
        tags = n.get("tags") or []
        tags_html = "".join(f'<span class="tag">{_esc(t)}</span>' for t in tags)
        target = f"<tr><th>Target</th><td>{_esc(n['target'])}</td></tr>" if n.get("target") else ""
        out.append(f"""
<div class="finding info">
    <div class="head">
        <div class="id-title">#{n['id']} — {_esc(n['title'])}</div>
    </div>
    <table>
        {target}
        <tr><th>Created</th><td>{_esc(n.get('created_at') or '—')}</td></tr>
    </table>
    <div style="margin-top:10px;">{_esc(n.get('body') or '(пусто)').replace(chr(10), '<br>')}</div>
    <div class="tags">{tags_html}</div>
</div>
""")


    return "".join(out)


def _html_scans(scans: list[dict], max_rows: int = 300) -> str:
    if not scans:
        return ""
    out = [f"<h2>🔍 Сканы ({len(scans)})</h2>"]
    out.append('<div class="scrollable-max"><table>')
    out.append("<tr><th>ID</th><th>Модуль</th><th>Цель</th><th>Дата</th><th>Результат</th></tr>")
    for s in scans[:max_rows]:
        result_str = json.dumps(s["result"], ensure_ascii=False)[:300]
        out.append(
            f"<tr>"
            f"<td>{s['id']}</td>"
            f"<td>{_esc(s['module'])}</td>"
            f"<td>{_esc(s['target'])}</td>"
            f"<td>{_esc(s['created_at'])}</td>"
            f"<td><pre>{_esc(result_str)}</pre></td>"
            f"</tr>"
        )
    out.append("</table></div>")
    if len(scans) > max_rows:
        out.append(f'<div style="color:#888;">… и ещё {len(scans)-max_rows} записей</div>')
    return "".join(out)


def _html_hackerone_template() -> str:
    return """
<h2>📋 HackerOne Template</h2>
<pre>
**Title:** [Vulnerability Type] in [Endpoint/Parameter]

**Summary:**
Краткое описание уязвимости.

**Steps To Reproduce:**
1. Перейти на URL ...
2. Внести payload ...
3. Наблюдать ...

**Impact:**
Что может сделать атакующий.

**Supporting Material/References:**
- Скриншоты
- Видео PoC
- CVE ссылки

**Suggested Fix:**
Конкретная рекомендация по исправлению.
</pre>
"""


def _html_bugcrowd_template() -> str:
    return """
<h2>📋 Bugcrowd Template</h2>
<pre>
**Vulnerability Title:**
[Type] at [URL]

**Bug Description:**
Описание.

**Steps to Reproduce:**
1. ...
2. ...

**Expected Result:**
Что ожидалось.

**Actual Result:**
Что получилось.

**Impact:**
Оценка влияния.
</pre>
"""


# ---------------------------------------------------------------------------
# Генерация HTML
# ---------------------------------------------------------------------------

def generate_html(title: str = "CyberSec Toolkit — Security Report",
                  author: str = "idqwixxa",
                  target_filter: str | None = None,
                  template: str = "default",
                  scan_limit: int = 500,
                  include_scans: bool = True,
                  include_stats_images: bool = True,
                  include_screenshots: bool = True,
                  out_path: str | None = None) -> Path | None:
    """Сгенерировать HTML-отчёт."""
    console.print("[cyan]📊 Auto-Report Pro — собираю данные…[/cyan]")
    data = _collect_all(scan_limit=scan_limit)

    # Фильтр по цели
    if target_filter:
        tf = target_filter.lower()
        data["scans"] = [s for s in data["scans"] if tf in s["target"].lower()]
        data["findings"] = [f for f in data["findings"]
                            if tf in (f.get("target") or "").lower()]
        data["notes"] = [n for n in data["notes"]
                         if tf in (n.get("target") or "").lower()]

    # Пересчёт сводки после фильтра
    summary = data["summary"]
    summary["total_scans"] = len(data["scans"])
    summary["total_findings"] = len(data["findings"])
    summary["total_notes"] = len(data["notes"])

    parts = [
        HTML_HEAD.format(title=_esc(title)),
        _html_cover(title, author, target_filter),
        _html_summary(summary),
    ]

    if include_stats_images:
        parts.append(_html_images(data["stats_images"],
                                  "📈 Графики статистики"))

    parts.append(_html_findings(data["findings"]))
    parts.append(_html_notes(data["notes"]))

    if include_screenshots:
        parts.append(_html_images(data["screenshots"],
                                  "📸 Скриншоты", max_images=20))

    if include_scans:
        parts.append(_html_scans(data["scans"]))

    if template == "hackerone":
        parts.append(_html_hackerone_template())
    elif template == "bugcrowd":
        parts.append(_html_bugcrowd_template())

    parts.append(HTML_FOOT.format(ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    html_str = "\n".join(parts)

    if not out_path:
        safe = (target_filter or "all").replace("/", "_").replace(":", "_")[:40]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(REPORT_DIR / f"autoreport_{safe}_{ts}.html")

    path = Path(out_path)
    try:
        path.write_text(html_str, encoding="utf-8")
        size_kb = path.stat().st_size / 1024
        console.print(f"[green]✓ HTML: {path} ({size_kb:.1f} KB)[/green]")
        db.save_scan("auto_report_html", target_filter or "all",
                     {"path": str(path), "size_kb": round(size_kb, 1)})
        return path
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка HTML: {exc}[/red]")
        return None


# ---------------------------------------------------------------------------
# Генерация PDF (reportlab)
# ---------------------------------------------------------------------------

def generate_pdf(title: str = "CyberSec Toolkit — Security Report",
                 author: str = "idqwixxa",
                 target_filter: str | None = None,
                 template: str = "default",
                 scan_limit: int = 300,
                 include_scans: bool = True,
                 include_stats_images: bool = True,
                 include_screenshots: bool = True,
                 out_path: str | None = None) -> Path | None:
    """Сгенерировать PDF через reportlab."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Image as RLImage,
            PageBreak, Table as RLTable, TableStyle,
        )
        from reportlab.lib.utils import ImageReader
    except ImportError:
        console.print("[red]reportlab не установлен.[/red]")
        console.print("[yellow]Установи: pip install reportlab[/yellow]")
        return None

    console.print("[cyan]📊 Auto-Report Pro — собираю данные (PDF)…[/cyan]")
    data = _collect_all(scan_limit=scan_limit)

    if target_filter:
        tf = target_filter.lower()
        data["scans"] = [s for s in data["scans"] if tf in s["target"].lower()]
        data["findings"] = [f for f in data["findings"]
                            if tf in (f.get("target") or "").lower()]
        data["notes"] = [n for n in data["notes"]
                         if tf in (n.get("target") or "").lower()]

    if not out_path:
        safe = (target_filter or "all").replace("/", "_").replace(":", "_")[:40]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(REPORT_DIR / f"autoreport_{safe}_{ts}.pdf")

    try:
        doc = SimpleDocTemplate(
            str(out_path), pagesize=A4,
            leftMargin=15 * mm, rightMargin=15 * mm,
            topMargin=15 * mm, bottomMargin=15 * mm,
            title=title, author=author,
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка PDF init: {exc}[/red]")
        return None

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"],
                        textColor=colors.HexColor("#006633"))
    h2 = ParagraphStyle("H2", parent=styles["Heading2"],
                        textColor=colors.HexColor("#006633"))
    h3 = ParagraphStyle("H3", parent=styles["Heading3"],
                        textColor=colors.HexColor("#006633"))
    body = ParagraphStyle("Body", parent=styles["BodyText"],
                          fontSize=9, leading=12)
    small = ParagraphStyle("Small", parent=styles["BodyText"],
                           fontSize=7, leading=9,
                           textColor=colors.HexColor("#444444"))
    warn = ParagraphStyle("Warn", parent=styles["BodyText"],
                          textColor=colors.red, fontSize=10, leading=13)
    pre = ParagraphStyle("Pre", parent=styles["BodyText"], fontSize=6,
                         leading=8, fontName="Courier")

    story = []

    # --- Cover ---
    story.append(Paragraph(f"🛡️ {_esc(title)}", h1))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(f"Автор: {_esc(author)}", body))
    story.append(Paragraph(
        f"Сгенерирован: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        body,
    ))
    story.append(Paragraph(
        f"Фильтр по цели: {_esc(target_filter or 'все цели')}", body,
    ))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        "⚠ Только для этичного использования и CTF. "
        "Сканы выполнены с разрешения владельца цели.",
        warn,
    ))
    story.append(Spacer(1, 8 * mm))

    # --- Summary ---
    story.append(Paragraph("📊 Сводка", h2))
    s = data["summary"]
    summary_rows = [
        ["Всего сканов", str(len(data["scans"]))],
        ["Находок", str(len(data["findings"]))],
        ["Заметок", str(len(data["notes"]))],
        ["Уникальных целей", str(len(s["targets_count"]))],
        ["Модулей использовано", str(len(s["modules_count"]))],
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in s["severity_count"]:
            summary_rows.append([f"Severity {sev}",
                                 str(s["severity_count"][sev])])
    if summary_rows:
        tbl = RLTable(summary_rows, colWidths=[80 * mm, 40 * mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.white),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        story.append(tbl)
    story.append(Spacer(1, 6 * mm))

    # --- Stats images ---
    if include_stats_images and data["stats_images"]:
        story.append(PageBreak())
        story.append(Paragraph("📈 Графики статистики", h2))
        for img in data["stats_images"][:6]:
            try:
                story.append(Paragraph(f"{_esc(img['name'])} "
                                       f"({img['size_kb']} KB)", small))
                story.append(RLImage(io.BytesIO(
                    base64.b64decode(img["b64"])
                ), width=170 * mm, height=100 * mm, kind="proportional"))
                story.append(Spacer(1, 4 * mm))
            except Exception as exc:  # noqa: BLE001
                log.warning("PDF img %s: %s", img["name"], exc)

    # --- Findings ---
    story.append(PageBreak())
    story.append(Paragraph(
        f"🔴 Findings ({len(data['findings'])})", h2
    ))
    if not data["findings"]:
        story.append(Paragraph("Находок нет.", body))
    else:
        sev_order = {"critical": 0, "high": 1, "medium": 2,
                     "low": 3, "info": 4}
        findings_sorted = sorted(
            data["findings"],
            key=lambda f: sev_order.get(
                (f.get("severity") or "info").lower(), 5),
        )
        for f in findings_sorted:
            sev = (f.get("severity") or "info").lower()
            color = {
                "critical": colors.red,
                "high": colors.orange,
                "medium": colors.yellow,
                "low": colors.green,
                "info": colors.blue,
            }.get(sev, colors.grey)
            title_style = ParagraphStyle(
                f"FT{sev}{f['id']}", parent=h3, textColor=color,
            )
            story.append(Paragraph(
                f"#{f['id']} — {_esc(f['title'])} [{sev.upper()} / "
                f"{_esc(f.get('status') or 'open')}]",
                title_style,
            ))
            story.append(Paragraph(
                f"<b>Target:</b> {_esc(f.get('target') or '—')}", body,
            ))
            story.append(Paragraph(
                f"<b>Created:</b> {_esc(f.get('created_at') or '—')}", body,
            ))
            if f.get("tags"):
                story.append(Paragraph(
                    f"<b>Tags:</b> {_esc(', '.join(f['tags']))}", body,
                ))
            story.append(Spacer(1, 2 * mm))
            body_text = (f.get("body") or "(пусто)").replace("\n", "<br/>")
            story.append(Paragraph(body_text, body))
            story.append(Spacer(1, 6 * mm))

    # --- Notes ---
    if data["notes"]:
        story.append(PageBreak())
        story.append(Paragraph(f"📝 Notes ({len(data['notes'])})", h2))
        for n in data["notes"]:
            story.append(Paragraph(f"#{n['id']} — {_esc(n['title'])}", h3))
            if n.get("target"):
                story.append(Paragraph(
                    f"<b>Target:</b> {_esc(n['target'])}", body))
            story.append(Paragraph(
                (n.get("body") or "(пусто)").replace("\n", "<br/>"), body,
            ))
            story.append(Spacer(1, 4 * mm))

    # --- Screenshots ---
    if include_screenshots and data["screenshots"]:
        story.append(PageBreak())
        story.append(Paragraph(
            f"📸 Скриншоты ({len(data['screenshots'])})", h2))
        for img in data["screenshots"][:20]:
            try:
                story.append(Paragraph(
                    f"{_esc(img['name'])} ({img['size_kb']} KB)", small))
                story.append(RLImage(
                    io.BytesIO(base64.b64decode(img["b64"])),
                    width=160 * mm, height=90 * mm, kind="proportional",
                ))
                story.append(Spacer(1, 4 * mm))
            except Exception as exc:  # noqa: BLE001
                log.warning("PDF shot %s: %s", img["name"], exc)

    # --- Scans ---
    if include_scans and data["scans"]:
        story.append(PageBreak())
        story.append(Paragraph(f"🔍 Сканы ({len(data['scans'])})", h2))
        for s in data["scans"][:150]:
            result_str = json.dumps(s["result"], ensure_ascii=False)[:600]
            story.append(Paragraph(
                f"#{s['id']} — {_esc(s['module'])} — "
                f"{_esc(s['target'])} — {_esc(s['created_at'])}",
                body,
            ))
            story.append(Paragraph(_esc(result_str), pre))
            story.append(Spacer(1, 2 * mm))

    # --- Templates ---
    if template == "hackerone":
        story.append(PageBreak())
        story.append(Paragraph("📋 HackerOne Template", h2))
        story.append(Paragraph(
            "Title: [Vulnerability Type] in [Endpoint/Parameter]<br/><br/>"
            "Summary: краткое описание.<br/><br/>"
            "Steps To Reproduce: 1) ... 2) ... 3) ...<br/><br/>"
            "Impact: что может сделать атакующий.<br/><br/>"
            "Suggested Fix: рекомендация.",
            body,
        ))
    elif template == "bugcrowd":
        story.append(PageBreak())
        story.append(Paragraph("📋 Bugcrowd Template", h2))
        story.append(Paragraph(
            "Vulnerability Title: [Type] at [URL]<br/><br/>"
            "Bug Description: описание.<br/><br/>"
            "Steps to Reproduce: 1) ... 2) ...<br/><br/>"
            "Expected Result / Actual Result / Impact.",
            body,
        ))

    try:
        doc.build(story)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка сборки PDF: {exc}[/red]")
        log.exception("pdf build")
        return None

    size_kb = Path(out_path).stat().st_size / 1024
    console.print(f"[green]✓ PDF: {out_path} ({size_kb:.1f} KB)[/green]")
    db.save_scan("auto_report_pdf", target_filter or "all",
                 {"path": str(out_path), "size_kb": round(size_kb, 1)})
    return Path(out_path)


# ---------------------------------------------------------------------------
# JSON-экспорт
# ---------------------------------------------------------------------------

def generate_json(target_filter: str | None = None,
                  scan_limit: int = 500,
                  out_path: str | None = None) -> Path | None:
    """Сырые данные в JSON."""
    data = _collect_all(scan_limit=scan_limit)
    if target_filter:
        tf = target_filter.lower()
        data["scans"] = [s for s in data["scans"] if tf in s["target"].lower()]
        data["findings"] = [f for f in data["findings"]
                            if tf in (f.get("target") or "").lower()]
        data["notes"] = [n for n in data["notes"]
                         if tf in (n.get("target") or "").lower()]

    # Не тащим base64 в JSON
    for key in ("stats_images", "screenshots"):
        for img in data[key]:
            img.pop("b64", None)

    if not out_path:
        safe = (target_filter or "all").replace("/", "_").replace(":", "_")[:40]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(REPORT_DIR / f"autoreport_{safe}_{ts}.json")

    try:
        Path(out_path).write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        console.print(f"[green]✓ JSON: {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка JSON: {exc}[/red]")
        return None


# ---------------------------------------------------------------------------
# Открытие файла в системе
# ---------------------------------------------------------------------------

def _open_file(path: Path) -> None:
    import os
    import sys
    try:
        if sys.platform == "win32":
            os.startfile(str(path))  # noqa: S606
        elif sys.platform == "darwin":
            os.system(f'open "{path}"')
        else:
            os.system(f'xdg-open "{path}" >/dev/null 2>&1 &')
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]Не удалось открыть: {exc}[/yellow]")


# ---------------------------------------------------------------------------
# Меню
# ---------------------------------------------------------------------------

def menu() -> None:
    table = Table(title="[bold]📊 Auto-Report Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Полный HTML-отчёт (все данные)"),
        ("2", "Полный PDF-отчёт (все данные)"),
        ("3", "JSON (сырые данные)"),
        ("4", "HTML с шаблоном HackerOne"),
        ("5", "HTML с шаблоном Bugcrowd"),
        ("6", "HTML по конкретной цели"),
        ("7", "PDF по конкретной цели"),
        ("8", "Все три формата сразу (HTML+PDF+JSON)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        p = generate_html()
        if p and Confirm.ask("Открыть в браузере?", default=True):
            _open_file(p)
    elif c == "2":
        p = generate_pdf()
        if p and Confirm.ask("Открыть?", default=True):
            _open_file(p)
    elif c == "3":
        generate_json()
    elif c == "4":
        p = generate_html(template="hackerone")
        if p and Confirm.ask("Открыть?", default=True):
            _open_file(p)
    elif c == "5":
        p = generate_html(template="bugcrowd")
        if p and Confirm.ask("Открыть?", default=True):
            _open_file(p)
    elif c == "6":
        target = Prompt.ask("Target (фильтр)")
        p = generate_html(target_filter=target)
        if p and Confirm.ask("Открыть?", default=True):
            _open_file(p)
    elif c == "7":
        target = Prompt.ask("Target (фильтр)")
        p = generate_pdf(target_filter=target)
        if p and Confirm.ask("Открыть?", default=True):
            _open_file(p)
    elif c == "8":
        target = Prompt.ask("Target (фильтр, пусто = все)", default="").strip() or None
        h = generate_html(target_filter=target)
        p = generate_pdf(target_filter=target)
        j = generate_json(target_filter=target)
        if h and Confirm.ask("Открыть HTML?", default=False):
            _open_file(h)
        if p and Confirm.ask("Открыть PDF?", default=True):
            _open_file(p)


# ---------------------------------------------------------------------------
# Публичные функции для TUI/CLI (без интерактива)
# ---------------------------------------------------------------------------

def quick_html() -> None:
    """Для TUI: сгенерировать HTML по всем данным."""
    generate_html()


def quick_pdf() -> None:
    """Для TUI: сгенерировать PDF по всем данным."""
    generate_pdf()


def quick_json() -> None:
    """Для TUI: сгенерировать JSON."""
    generate_json()