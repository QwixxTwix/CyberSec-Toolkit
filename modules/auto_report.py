"""
Auto-Report Pro — расширенный.
Author: idqwixxa

⚠ Только для этичного использования.

Возможности:
    - Сбор данных: scans, notes, findings, CVEs, takeover, KEV, screenshots
    - Executive summary (автогенерируемый текст)
    - Timeline сканов
    - Methodology секция
    - TOC + якоря
    - Инкрементальный diff с предыдущим отчётом
    - Форматы: HTML / PDF / JSON / Markdown
    - 4 шаблона: default / hackerone / bugcrowd / pentest
"""
import base64
import html as html_mod
import io
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

AR_DIR = REPORT_DIR / "auto_report"
AR_DIR.mkdir(parents=True, exist_ok=True)

TEMPLATES = ["default", "hackerone", "bugcrowd", "pentest"]


# ===========================================================================
# Сбор данных
# ===========================================================================

def _collect_scans(limit: int = 500) -> list[dict]:
    rows = db.history(limit)
    out = []
    for r in rows:
        try:
            result = json.loads(r["result"]) if r["result"] else {}
        except Exception:
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
    try:
        cur = db.conn.cursor()
        cur.execute("SELECT * FROM notes ORDER BY id DESC")
        rows = cur.fetchall()
    except Exception as exc:
        log.warning("notes: %s", exc)
        return {"findings": [], "notes": []}

    findings, notes = [], []
    for r in rows:
        d = dict(r)
        try:
            d["tags"] = json.loads(d.get("tags") or "[]")
        except Exception:
            d["tags"] = []
        if d.get("kind") == "finding":
            findings.append(d)
        else:
            notes.append(d)
    return {"findings": findings, "notes": notes}


def _collect_cves(limit: int = 100) -> list[dict]:
    """Последние CVE из таблицы cves, если существует."""
    try:
        cur = db.conn.cursor()
        cur.execute(
            "SELECT cve_id, cvss_score, cvss_severity, kev, published "
            "FROM cves ORDER BY COALESCE(cvss_score,0) DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []


def _collect_takeovers(limit: int = 100) -> list[dict]:
    """dangling_subdomains, если таблица существует."""
    try:
        cur = db.conn.cursor()
        cur.execute(
            "SELECT subdomain, service, severity, first_seen, last_seen, status "
            "FROM dangling_subdomains ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []


def _collect_images(prefixes: list[str]) -> list[dict]:
    if not REPORT_DIR.exists():
        return []
    out: list[dict] = []
    for p in sorted(REPORT_DIR.glob("*.png")):
        if any(p.name.startswith(pre) for pre in prefixes):
            try:
                data = p.read_bytes()
                out.append({
                    "path": str(p),
                    "name": p.name,
                    "size_kb": round(len(data) / 1024, 1),
                    "b64": base64.b64encode(data).decode("ascii"),
                })
            except Exception as exc:
                log.warning("img %s: %s", p, exc)
    return out


def _collect_all(scan_limit: int = 500) -> dict:
    scans = _collect_scans(scan_limit)
    notes = _collect_notes()
    cves = _collect_cves(100)
    takeovers = _collect_takeovers(100)
    stats_imgs = _collect_images(["stats_"])
    shots = _collect_images(["shot_"])

    modules_count: Counter = Counter(s["module"] for s in scans)
    targets_count: Counter = Counter(s["target"] for s in scans)
    sev_count: Counter = Counter()
    status_count: Counter = Counter()
    for f in notes["findings"]:
        sev = (f.get("severity") or "info").lower()
        sev_count[sev] += 1
        st = f.get("status") or "open"
        status_count[st] += 1

    # Timeline: количество сканов по дням
    timeline: dict[str, int] = defaultdict(int)
    for s in scans:
        try:
            d = datetime.fromisoformat(
                s["created_at"].replace(" ", "T")
            ).strftime("%Y-%m-%d")
            timeline[d] += 1
        except Exception:
            pass

    return {
        "scans": scans,
        "findings": notes["findings"],
        "notes": notes["notes"],
        "cves": cves,
        "takeovers": takeovers,
        "stats_images": stats_imgs,
        "screenshots": shots,
        "timeline": dict(sorted(timeline.items())),
        "summary": {
            "total_scans": len(scans),
            "total_findings": len(notes["findings"]),
            "total_notes": len(notes["notes"]),
            "total_cves": len(cves),
            "total_takeovers": len(takeovers),
            "modules_count": dict(modules_count),
            "targets_count": dict(targets_count),
            "severity_count": dict(sev_count),
            "status_count": dict(status_count),
        },
    }


# ===========================================================================
# Executive summary (автогенерация)
# ===========================================================================

def _exec_summary_text(data: dict, target_filter: str = "") -> str:
    s = data["summary"]
    scope = f"цели `{target_filter}`" if target_filter else "всех протестированных целей"
    if s["total_scans"] == 0:
        return "Сканы не найдены — отчёт пуст."

    critical = s["severity_count"].get("critical", 0)
    high = s["severity_count"].get("high", 0)
    medium = s["severity_count"].get("medium", 0)

    parts = []
    parts.append(
        f"В ходе тестирования {scope} было выполнено "
        f"{s['total_scans']} сканов с использованием "
        f"{len(s['modules_count'])} модулей. "
        f"Обработано {len(s['targets_count'])} уникальных целей."
    )
    if s["total_findings"] > 0:
        parts.append(
            f"Идентифицировано **{s['total_findings']} находок**, "
            f"из них: critical={critical}, high={high}, medium={medium}."
        )
        if critical > 0:
            parts.append(
                f"[!] Обнаружены уязвимости критического уровня — "
                f"требуется немедленное реагирование."
            )
        elif high > 0:
            parts.append(
                f"Обнаружены уязвимости высокого уровня — "
                f"рекомендуется приоритезировать исправление."
            )
    else:
        parts.append("Существенных находок не зафиксировано.")

    if s["total_takeovers"] > 0:
        parts.append(
            f"Обнаружено {s['total_takeovers']} потенциальных "
            f"subdomain-takeover."
        )

    return "\n\n".join(parts)


# ===========================================================================
# HTML
# ===========================================================================

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
        line-height: 1.55;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    h1 {{ color: #00ff9c; border-bottom: 2px solid #00ff9c;
          padding-bottom: 8px; margin-top: 0; }}
    h2 {{ color: #00ff9c; margin-top: 40px; border-left: 4px solid #00ff9c;
          padding-left: 12px; }}
    h3 {{ color: #7ad9ff; margin-top: 24px; }}
    a {{ color: #7ad9ff; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .toc {{ background: #0d0d0d; border: 1px solid #222;
            padding: 16px 24px; border-radius: 4px; margin-bottom: 24px; }}
    .toc ul {{ list-style: none; padding-left: 0; }}
    .toc li {{ padding: 3px 0; }}
    .cover {{ border: 2px solid #00ff9c; padding: 24px;
              margin-bottom: 24px; background: #080808; }}
    .cover .title {{ font-size: 28px; color: #00ff9c; font-weight: bold; }}
    .cover .meta {{ color: #888; margin-top: 8px; font-size: 13px; }}
    .disclaimer {{ border: 2px solid #ff4040; background: #1a0000;
                    color: #ff9090; padding: 12px 16px;
                    margin: 20px 0; border-radius: 4px; }}
    .exec {{ background: #0d0d0d; border: 1px solid #222;
             border-left: 4px solid #00ff9c; padding: 16px;
             border-radius: 4px; }}
    .summary {{ display: grid;
                grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
                gap: 12px; margin: 20px 0; }}
    .card {{ background: #0d0d0d; border: 1px solid #222;
             padding: 14px; border-radius: 4px; }}
    .card .num {{ font-size: 26px; color: #00ff9c; font-weight: bold; }}
    .card .label {{ font-size: 12px; color: #888; margin-top: 4px; }}
    .sev-critical {{ color: #ff2020; font-weight: bold; }}
    .sev-high     {{ color: #ff7a40; font-weight: bold; }}
    .sev-medium   {{ color: #ffd23f; font-weight: bold; }}
    .sev-low      {{ color: #00ff9c; }}
    .sev-info     {{ color: #7ad9ff; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px;
             font-size: 13px; }}
    th {{ background: #111; color: #00ff9c; text-align: left;
          padding: 8px; border: 1px solid #222; }}
    td {{ padding: 6px 8px; border: 1px solid #222; vertical-align: top; }}
    tr:nth-child(even) {{ background: #0d0d0d; }}
    pre {{ background: #050505; border: 1px solid #222; padding: 10px;
           overflow-x: auto; color: #a0ffa0; font-size: 12px;
           border-radius: 4px; }}
    img {{ max-width: 100%; border: 1px solid #222; border-radius: 4px;
           margin: 8px 0; background: #0a0a0a; }}
    .finding {{ border: 1px solid #222; border-left: 4px solid #ff7a40;
                padding: 14px; margin: 16px 0; background: #0d0d0d;
                border-radius: 4px; }}
    .finding.critical {{ border-left-color: #ff2020; }}
    .finding.high     {{ border-left-color: #ff7a40; }}
    .finding.medium   {{ border-left-color: #ffd23f; }}
    .finding.low      {{ border-left-color: #00ff9c; }}
    .finding.info     {{ border-left-color: #7ad9ff; }}
    .finding .head {{ display: flex; justify-content: space-between;
                      align-items: baseline; margin-bottom: 8px;
                      flex-wrap: wrap; gap: 8px; }}
    .finding .id-title {{ font-size: 16px; color: #fff; font-weight: bold; }}
    .finding .badge {{ background: #111; padding: 2px 8px; border-radius: 3px;
                       font-size: 11px; color: #00ff9c; }}
    .tag {{ display: inline-block; background: #003322; color: #00ff9c;
            padding: 2px 8px; border-radius: 3px; font-size: 11px;
            margin-right: 4px; }}
    .footer {{ margin-top: 40px; padding-top: 16px;
               border-top: 1px solid #222; color: #555;
               font-size: 12px; text-align: center; }}
    .scrollable-max {{ max-height: 600px; overflow-y: auto; }}
    .timeline {{ background: #0d0d0d; border: 1px solid #222;
                 border-radius: 4px; padding: 12px;
                 font-family: monospace; font-size: 11px;
                 overflow-x: auto; white-space: pre; color: #00ff9c; }}
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


def _esc(v: Any) -> str:
    return html_mod.escape(str(v if v is not None else ""))


def _html_toc() -> str:
    entries = [
        ("summary", "Сводка"),
        ("exec", "Executive Summary"),
        ("timeline", "Timeline"),
        ("findings", "Findings"),
        ("notes", "Notes"),
        ("cves", "CVEs"),
        ("takeovers", "Takeover-кандидаты"),
        ("stats", "Графики"),
        ("screens", "Скриншоты"),
        ("scans", "Сканы"),
        ("methodology", "Methodology"),
        ("appendix", "Appendix"),
    ]
    items = "".join(
        f'<li>• <a href="#{anchor}">{title}</a></li>'
        for anchor, title in entries
    )
    return f'<div class="toc"><b>Содержание:</b><ul>{items}</ul></div>'


def _html_cover(title: str, author: str, tf: str | None) -> str:
    return f"""
<div class="cover">
    <div class="title">🛡️ {_esc(title)}</div>
    <div class="meta">
        Сгенерирован: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
        Автор: {_esc(author)}<br>
        Фильтр: {_esc(tf or 'все цели')}
    </div>
</div>
<div class="disclaimer">
    ⚠ Отчёт содержит результаты сканирования. Только для этичного
    использования и CTF, с разрешения владельца цели.
</div>
"""


def _html_exec_summary(text: str) -> str:
    safe = _esc(text).replace("\n", "<br>").replace("**", "")
    safe = safe.replace("[!]", "<span class='sev-critical'>[!]</span>")
    return f'<h2 id="exec">📌 Executive Summary</h2><div class="exec">{safe}</div>'


def _html_summary(s: dict) -> str:
    cards = [
        ("Всего сканов", s["total_scans"]),
        ("Находок", s["total_findings"]),
        ("Заметок", s["total_notes"]),
        ("CVEs в БД", s["total_cves"]),
        ("Takeovers", s["total_takeovers"]),
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
        status_html = ("<h3>Status находок</h3>"
                       "<table><tr><th>Status</th><th>Кол-во</th></tr>")
        for st, c in s["status_count"].items():
            status_html += f"<tr><td>{_esc(st)}</td><td>{c}</td></tr>"
        status_html += "</table>"

    top_mods = sorted(s["modules_count"].items(), key=lambda x: -x[1])[:5]
    mods_html = ""
    if top_mods:
        mods_html = ("<h3>Топ модулей</h3>"
                     "<table><tr><th>Module</th><th>Сканов</th></tr>")
        for m, c in top_mods:
            mods_html += f"<tr><td>{_esc(m)}</td><td>{c}</td></tr>"
        mods_html += "</table>"

    return f"""
<h2 id="summary">📊 Сводка</h2>
<div class="summary">{cards_html}</div>
{sev_html}
{status_html}
{mods_html}
"""


def _html_timeline(timeline: dict) -> str:
    if not timeline:
        return ""
    # ASCII-график
    max_v = max(timeline.values())
    lines = []
    for day, cnt in sorted(timeline.items()):
        bar = "█" * int(cnt / max(max_v, 1) * 40)
        lines.append(f"{day}  {bar}  {cnt}")
    return (f'<h2 id="timeline">📅 Timeline</h2>'
            f'<div class="timeline">{_esc(chr(10).join(lines))}</div>')


def _html_images(images: list[dict], title: str, anchor: str,
                 max_images: int = 12) -> str:
    if not images:
        return ""
    out = [f'<h2 id="{anchor}">{_esc(title)}</h2>']
    for img in images[:max_images]:
        out.append(
            f'<div style="margin-bottom:16px;">'
            f'<div style="color:#888;font-size:12px;margin-bottom:4px;">'
            f'{_esc(img["name"])} ({img["size_kb"]} KB)</div>'
            f'<img src="data:image/png;base64,{img["b64"]}" alt="{_esc(img["name"])}">'
            f'</div>'
        )
    if len(images) > max_images:
        out.append(f'<div style="color:#888;">… ещё '
                    f'{len(images)-max_images} изображений</div>')
    return "".join(out)


def _html_findings(findings: list[dict]) -> str:
    if not findings:
        return ('<h2 id="findings">🔴 Findings</h2>'
                '<p style="color:#888;">Находок нет.</p>')
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_sorted = sorted(
        findings,
        key=lambda f: sev_order.get((f.get("severity") or "info").lower(), 5),
    )
    out = [f'<h2 id="findings">🔴 Findings ({len(findings)})</h2>']
    for f in findings_sorted:
        sev = (f.get("severity") or "info").lower()
        status = f.get("status") or "open"
        tags = f.get("tags") or []
        tags_html = "".join(f'<span class="tag">{_esc(t)}</span>' for t in tags)
        body = (f.get("body") or "(пусто)").replace("\n", "<br>")
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
    </table>
    <div style="margin-top:10px;">{body}</div>
    <div class="tags">{tags_html}</div>
</div>
""")
    return "".join(out)


def _html_notes(notes: list[dict]) -> str:
    if not notes:
        return ""
    out = [f'<h2 id="notes">📝 Notes ({len(notes)})</h2>']
    for n in notes:
        tags = n.get("tags") or []
        tags_html = "".join(f'<span class="tag">{_esc(t)}</span>' for t in tags)
        target = (f"<tr><th>Target</th><td>{_esc(n['target'])}</td></tr>"
                  if n.get("target") else "")
        body = (n.get("body") or "(пусто)").replace("\n", "<br>")
        out.append(f"""
<div class="finding info">
    <div class="head">
        <div class="id-title">#{n['id']} — {_esc(n['title'])}</div>
    </div>
    <table>
        {target}
        <tr><th>Created</th><td>{_esc(n.get('created_at') or '—')}</td></tr>
    </table>
    <div style="margin-top:10px;">{body}</div>
    <div class="tags">{tags_html}</div>
</div>
""")
    return "".join(out)


def _html_cves(cves: list[dict]) -> str:
    if not cves:
        return ""
    out = [f'<h2 id="cves">📡 CVEs ({len(cves)})</h2>']
    out.append("<table><tr><th>CVE</th><th>Score</th><th>Severity</th>"
               "<th>KEV</th><th>Published</th></tr>")
    for c in cves:
        score = c.get("cvss_score")
        score_str = f"{score:.1f}" if isinstance(score, (int, float)) else "—"
        sev = (c.get("cvss_severity") or "").lower()
        sev_class = f"sev-{sev}" if sev in ("critical", "high", "medium",
                                             "low", "info") else ""
        kev = "🔴" if c.get("kev") else ""
        out.append(
            f"<tr><td>{_esc(c.get('cve_id'))}</td>"
            f"<td>{score_str}</td>"
            f"<td class='{sev_class}'>{_esc(sev.upper())}</td>"
            f"<td>{kev}</td>"
            f"<td>{_esc(str(c.get('published') or '')[:10])}</td></tr>"
        )
    out.append("</table>")
    return "".join(out)


def _html_takeovers(takeovers: list[dict]) -> str:
    if not takeovers:
        return ""
    out = [f'<h2 id="takeovers">🎯 Takeover-кандидаты ({len(takeovers)})</h2>']
    out.append("<table><tr><th>Subdomain</th><th>Service</th>"
               "<th>Severity</th><th>Status</th></tr>")
    for t in takeovers:
        sev = (t.get("severity") or "info").lower()
        out.append(
            f"<tr><td>{_esc(t.get('subdomain'))}</td>"
            f"<td>{_esc(t.get('service'))}</td>"
            f"<td class='sev-{sev}'>{_esc(sev.upper())}</td>"
            f"<td>{_esc(t.get('status'))}</td></tr>"
        )
    out.append("</table>")
    return "".join(out)


def _html_scans(scans: list[dict], max_rows: int = 300) -> str:
    if not scans:
        return ""
    out = [f'<h2 id="scans">🔍 Сканы ({len(scans)})</h2>']
    out.append('<div class="scrollable-max"><table>')
    out.append("<tr><th>ID</th><th>Модуль</th><th>Цель</th>"
               "<th>Дата</th><th>Результат</th></tr>")
    for s in scans[:max_rows]:
        result_str = json.dumps(s["result"], ensure_ascii=False)[:300]
        out.append(
            f"<tr><td>{s['id']}</td>"
            f"<td>{_esc(s['module'])}</td>"
            f"<td>{_esc(s['target'])}</td>"
            f"<td>{_esc(s['created_at'])}</td>"
            f"<td><pre>{_esc(result_str)}</pre></td></tr>"
        )
    out.append("</table></div>")
    if len(scans) > max_rows:
        out.append(f'<div style="color:#888;">… ещё '
                    f'{len(scans)-max_rows} записей</div>')
    return "".join(out)


def _html_methodology() -> str:
    return """
<h2 id="methodology">🔬 Methodology</h2>
<p>Отчёт сгенерирован автоматически на основе данных, собранных модулями
CyberSec Toolkit. Методология:</p>
<ul>
<li>Активная разведка: DNS, WHOIS, subdomain enumeration, port scanning</li>
<li>Пассивная разведка: OSINT, Wayback Machine, certificate transparency</li>
<li>Web-анализ: HTTP-заголовки, SSL/TLS, SQLi/XSS/LFI/SSRF checks</li>
<li>Cloud-анализ: S3/GCS/Azure bucket enumeration, metadata SSRF</li>
<li>AD-анализ: LDAP, SMB signing, Kerberoasting, AS-REP, DCSync</li>
<li>Автоматизация findings через Notes &amp; Findings DB</li>
</ul>
<p>Severity-классификация основана на CVSS v3.1 Base Score.</p>
"""


def _html_appendix(data: dict) -> str:
    """Сырые данные в приложении."""
    s = json.dumps({
        "modules": data["summary"]["modules_count"],
        "targets": data["summary"]["targets_count"],
    }, indent=2, ensure_ascii=False)
    return (f'<h2 id="appendix">📎 Appendix</h2>'
            f'<pre>{_esc(s)}</pre>')


def _html_hackerone_template() -> str:
    return """
<h2>📋 HackerOne Template</h2>
<pre>**Title:** [Vulnerability Type] in [Endpoint/Parameter]

**Summary:** краткое описание.

**Steps To Reproduce:** 1) ... 2) ... 3) ...

**Impact:** что может сделать атакующий.

**Suggested Fix:** рекомендация.</pre>
"""


def _html_bugcrowd_template() -> str:
    return """
<h2>📋 Bugcrowd Template</h2>
<pre>**Vulnerability Title:** [Type] at [URL]

**Bug Description:** описание.

**Steps to Reproduce:** 1) ... 2) ...

**Expected Result** / **Actual Result** / **Impact**.</pre>
"""


def _html_pentest_template() -> str:
    return """
<h2>🔍 Pentest Report Template</h2>
<pre>**Executive Summary**
Высокоуровневое описание рисков.

**Scope**
Список IP / доменов / сервисов.

**Findings**
Каждая находка — severity + CVSS + PoC + remediation.

**Recommendations**
Приоритезированный план исправления.

**Appendix**
Логи, скриншоты, raw output.</pre>
"""


# ===========================================================================
# HTML Generator
# ===========================================================================

def generate_html(title: str = "CyberSec Toolkit — Security Report",
                  author: str = "idqwixxa",
                  target_filter: str | None = None,
                  template: str = "default",
                  scan_limit: int = 500,
                  include_scans: bool = True,
                  include_stats_images: bool = True,
                  include_screenshots: bool = True,
                  include_cves: bool = True,
                  include_takeovers: bool = True,
                  out_path: str | None = None) -> Path | None:
    console.print("[cyan]📊 Auto-Report Pro — собираю данные…[/cyan]")
    data = _collect_all(scan_limit=scan_limit)

    if target_filter:
        tf = target_filter.lower()
        data["scans"] = [s for s in data["scans"] if tf in s["target"].lower()]
        data["findings"] = [f for f in data["findings"]
                             if tf in (f.get("target") or "").lower()]
        data["notes"] = [n for n in data["notes"]
                          if tf in (n.get("target") or "").lower()]

    summary = data["summary"]
    summary["total_scans"] = len(data["scans"])
    summary["total_findings"] = len(data["findings"])
    summary["total_notes"] = len(data["notes"])

    exec_text = _exec_summary_text(data, target_filter or "")

    parts = [
        HTML_HEAD.format(title=_esc(title)),
        _html_cover(title, author, target_filter),
        _html_toc(),
        _html_summary(summary),
        _html_exec_summary(exec_text),
    ]
    if data["timeline"]:
        parts.append(_html_timeline(data["timeline"]))
    parts.append(_html_findings(data["findings"]))
    parts.append(_html_notes(data["notes"]))
    if include_cves:
        parts.append(_html_cves(data["cves"]))
    if include_takeovers:
        parts.append(_html_takeovers(data["takeovers"]))
    if include_stats_images:
        parts.append(_html_images(data["stats_images"], "📈 Графики",
                                   "stats"))
    if include_screenshots:
        parts.append(_html_images(data["screenshots"], "📸 Скриншоты",
                                   "screens", max_images=20))
    if include_scans:
        parts.append(_html_scans(data["scans"]))
    parts.append(_html_methodology())
    if template == "hackerone":
        parts.append(_html_hackerone_template())
    elif template == "bugcrowd":
        parts.append(_html_bugcrowd_template())
    elif template == "pentest":
        parts.append(_html_pentest_template())
    parts.append(_html_appendix(data))
    parts.append(HTML_FOOT.format(
        ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    html_str = "\n".join(parts)

    if not out_path:
        safe = (target_filter or "all").replace("/", "_").replace(":", "_")[:40]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(AR_DIR / f"autoreport_{safe}_{ts}.html")

    path = Path(out_path)
    try:
        path.write_text(html_str, encoding="utf-8")
        size_kb = path.stat().st_size / 1024
        console.print(f"[green]✓ HTML: {path} ({size_kb:.1f} KB)[/green]")
        db.save_scan("auto_report_html", target_filter or "all",
                     {"path": str(path), "size_kb": round(size_kb, 1)})
        return path
    except Exception as exc:
        console.print(f"[red]HTML: {exc}[/red]")
        return None


# ===========================================================================
# PDF
# ===========================================================================

def generate_pdf(title: str = "CyberSec Toolkit — Security Report",
                 author: str = "idqwixxa",
                 target_filter: str | None = None,
                 template: str = "default",
                 scan_limit: int = 300,
                 include_scans: bool = True,
                 include_stats_images: bool = True,
                 include_screenshots: bool = True,
                 include_cves: bool = True,
                 out_path: str | None = None) -> Path | None:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Image as RLImage,
            PageBreak, Table as RLTable, TableStyle,
        )
    except ImportError:
        console.print("[red]reportlab не установлен.[/red]")
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
        out_path = str(AR_DIR / f"autoreport_{safe}_{ts}.pdf")

    try:
        doc = SimpleDocTemplate(
            str(out_path), pagesize=A4,
            leftMargin=15 * mm, rightMargin=15 * mm,
            topMargin=15 * mm, bottomMargin=15 * mm,
            title=title, author=author,
        )
    except Exception as exc:
        console.print(f"[red]PDF init: {exc}[/red]")
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
    story.append(Paragraph(f"🛡️ {_esc(title)}", h1))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(f"Автор: {_esc(author)}", body))
    story.append(Paragraph(
        f"Сгенерирован: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body))
    story.append(Paragraph(
        f"Фильтр: {_esc(target_filter or 'все цели')}", body))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        "⚠ Только для этичного использования и CTF.", warn))
    story.append(Spacer(1, 8 * mm))

    # Executive Summary
    story.append(Paragraph("📌 Executive Summary", h2))
    exec_text = _exec_summary_text(data, target_filter or "")
    for line in exec_text.split("\n\n"):
        safe = _esc(line).replace("**", "")
        story.append(Paragraph(safe, body))
        story.append(Spacer(1, 2 * mm))
    story.append(Spacer(1, 4 * mm))

    # Summary
    story.append(Paragraph("📊 Сводка", h2))
    s = data["summary"]
    summary_rows = [
        ["Сканов", str(len(data["scans"]))],
        ["Находок", str(len(data["findings"]))],
        ["Заметок", str(len(data["notes"]))],
        ["CVEs", str(len(data["cves"]))],
        ["Takeovers", str(len(data["takeovers"]))],
        ["Целей", str(len(s["targets_count"]))],
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in s["severity_count"]:
            summary_rows.append([f"Severity {sev}",
                                 str(s["severity_count"][sev])])
    tbl = RLTable(summary_rows, colWidths=[80 * mm, 40 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(tbl)

    # Stats images
    if include_stats_images and data["stats_images"]:
        story.append(PageBreak())
        story.append(Paragraph("📈 Графики статистики", h2))
        for img in data["stats_images"][:6]:
            try:
                story.append(Paragraph(
                    f"{_esc(img['name'])} ({img['size_kb']} KB)", small))
                story.append(RLImage(
                    io.BytesIO(base64.b64decode(img["b64"])),
                    width=170 * mm, height=100 * mm, kind="proportional"))
                story.append(Spacer(1, 4 * mm))
            except Exception as exc:
                log.warning("PDF img %s: %s", img["name"], exc)

    # Findings
    story.append(PageBreak())
    story.append(Paragraph(
        f"🔴 Findings ({len(data['findings'])})", h2))
    if not data["findings"]:
        story.append(Paragraph("Находок нет.", body))
    else:
        sev_order = {"critical": 0, "high": 1, "medium": 2,
                     "low": 3, "info": 4}
        for f in sorted(
            data["findings"],
            key=lambda x: sev_order.get(
                (x.get("severity") or "info").lower(), 5),
        ):
            sev = (f.get("severity") or "info").lower()
            color = {"critical": colors.red, "high": colors.orange,
                     "medium": colors.yellow, "low": colors.green,
                     "info": colors.blue}.get(sev, colors.grey)
            title_style = ParagraphStyle(
                f"FT{sev}{f['id']}", parent=h3, textColor=color)
            story.append(Paragraph(
                f"#{f['id']} — {_esc(f['title'])} "
                f"[{sev.upper()} / {_esc(f.get('status') or 'open')}]",
                title_style))
            story.append(Paragraph(
                f"<b>Target:</b> {_esc(f.get('target') or '—')}", body))
            if f.get("tags"):
                story.append(Paragraph(
                    f"<b>Tags:</b> {_esc(', '.join(f['tags']))}", body))
            body_text = (f.get("body") or "(пусто)").replace("\n", "<br/>")
            story.append(Paragraph(body_text, body))
            story.append(Spacer(1, 4 * mm))

    # Notes
    if data["notes"]:
        story.append(PageBreak())
        story.append(Paragraph(f"📝 Notes ({len(data['notes'])})", h2))
        for n in data["notes"][:100]:
            story.append(Paragraph(f"#{n['id']} — {_esc(n['title'])}", h3))
            if n.get("target"):
                story.append(Paragraph(
                    f"<b>Target:</b> {_esc(n['target'])}", body))
            story.append(Paragraph(
                (n.get("body") or "(пусто)").replace("\n", "<br/>"), body))
            story.append(Spacer(1, 3 * mm))

    # CVEs
    if include_cves and data["cves"]:
        story.append(PageBreak())
        story.append(Paragraph(
            f"📡 CVEs ({len(data['cves'])})", h2))
        cve_rows = [["CVE", "Score", "Severity", "KEV"]]
        for c in data["cves"][:80]:
            score = c.get("cvss_score")
            cve_rows.append([
                str(c.get("cve_id", "")),
                f"{score:.1f}" if isinstance(score, (int, float)) else "—",
                (c.get("cvss_severity") or "").upper(),
                "YES" if c.get("kev") else "",
            ])
        t = RLTable(cve_rows, colWidths=[50 * mm, 20 * mm, 30 * mm, 20 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
        ]))
        story.append(t)

    # Screenshots
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
                    width=160 * mm, height=90 * mm, kind="proportional"))
                story.append(Spacer(1, 3 * mm))
            except Exception as exc:
                log.warning("PDF shot %s: %s", img["name"], exc)

    # Scans
    if include_scans and data["scans"]:
        story.append(PageBreak())
        story.append(Paragraph(
            f"🔍 Сканы ({len(data['scans'])})", h2))
        for s in data["scans"][:100]:
            result_str = json.dumps(s["result"], ensure_ascii=False)[:500]
            story.append(Paragraph(
                f"#{s['id']} — {_esc(s['module'])} — "
                f"{_esc(s['target'])} — {_esc(s['created_at'])}", body))
            story.append(Paragraph(_esc(result_str), pre))
            story.append(Spacer(1, 1.5 * mm))

    # Templates
    if template == "hackerone":
        story.append(PageBreak())
        story.append(Paragraph("📋 HackerOne Template", h2))
        story.append(Paragraph(
            "Title / Summary / Steps To Reproduce / Impact / Suggested Fix.",
            body))
    elif template == "bugcrowd":
        story.append(PageBreak())
        story.append(Paragraph("📋 Bugcrowd Template", h2))
        story.append(Paragraph(
            "Vulnerability Title / Bug Description / Steps to Reproduce / "
            "Expected Result / Actual Result / Impact.", body))
    elif template == "pentest":
        story.append(PageBreak())
        story.append(Paragraph("🔍 Pentest Report Template", h2))
        story.append(Paragraph(
            "Executive Summary / Scope / Findings / Recommendations / "
            "Appendix.", body))

    try:
        doc.build(story)
    except Exception as exc:
        console.print(f"[red]PDF build: {exc}[/red]")
        log.exception("pdf build")
        return None

    size_kb = Path(out_path).stat().st_size / 1024
    console.print(f"[green]✓ PDF: {out_path} ({size_kb:.1f} KB)[/green]")
    db.save_scan("auto_report_pdf", target_filter or "all",
                 {"path": str(out_path), "size_kb": round(size_kb, 1)})
    return Path(out_path)


# ===========================================================================
# JSON
# ===========================================================================

def generate_json(target_filter: str | None = None,
                  scan_limit: int = 500,
                  out_path: str | None = None) -> Path | None:
    data = _collect_all(scan_limit=scan_limit)
    if target_filter:
        tf = target_filter.lower()
        data["scans"] = [s for s in data["scans"] if tf in s["target"].lower()]
        data["findings"] = [f for f in data["findings"]
                             if tf in (f.get("target") or "").lower()]
        data["notes"] = [n for n in data["notes"]
                          if tf in (n.get("target") or "").lower()]

    for key in ("stats_images", "screenshots"):
        for img in data[key]:
            img.pop("b64", None)

    if not out_path:
        safe = (target_filter or "all").replace("/", "_").replace(":", "_")[:40]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(AR_DIR / f"autoreport_{safe}_{ts}.json")

    try:
        Path(out_path).write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
        console.print(f"[green]✓ JSON: {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:
        console.print(f"[red]JSON: {exc}[/red]")
        return None


# ===========================================================================
# Markdown
# ===========================================================================

def generate_markdown(title: str = "CyberSec Toolkit — Security Report",
                      author: str = "idqwixxa",
                      target_filter: str | None = None,
                      scan_limit: int = 500,
                      out_path: str | None = None) -> Path | None:
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
        out_path = str(AR_DIR / f"autoreport_{safe}_{ts}.md")

    lines: list[str] = [
        f"# {title}\n",
        f"**Author:** {author}  ",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Filter:** {target_filter or 'все цели'}\n",
        "---\n",
    ]

    # Exec summary
    lines.append("## 📌 Executive Summary\n")
    lines.append(_exec_summary_text(data, target_filter or ""))
    lines.append("\n")

    # Summary
    s = data["summary"]
    lines.append("## 📊 Сводка\n")
    lines.append(f"- Сканов: **{len(data['scans'])}**")
    lines.append(f"- Находок: **{len(data['findings'])}**")
    lines.append(f"- Заметок: **{len(data['notes'])}**")
    lines.append(f"- CVEs: **{len(data['cves'])}**")
    lines.append(f"- Takeovers: **{len(data['takeovers'])}**")
    lines.append(f"- Целей: **{len(s['targets_count'])}**\n")

    # Timeline
    if data["timeline"]:
        lines.append("## 📅 Timeline\n")
        lines.append("```")
        max_v = max(data["timeline"].values())
        for day, cnt in sorted(data["timeline"].items()):
            bar = "█" * int(cnt / max(max_v, 1) * 40)
            lines.append(f"{day}  {bar}  {cnt}")
        lines.append("```\n")

    # Findings
    lines.append(f"## 🔴 Findings ({len(data['findings'])})\n")
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(data["findings"],
                    key=lambda x: sev_order.get(
                        (x.get("severity") or "info").lower(), 5)):
        sev = (f.get("severity") or "info").upper()
        lines.append(f"### #{f['id']} — {f['title']} [{sev}]\n")
        lines.append(f"- **Target:** `{f.get('target') or '—'}`")
        lines.append(f"- **Status:** {f.get('status') or 'open'}")
        if f.get("tags"):
            lines.append(f"- **Tags:** {', '.join(f['tags'])}")
        lines.append(f"\n{f.get('body') or ''}\n")

    # Notes
    if data["notes"]:
        lines.append(f"## 📝 Notes ({len(data['notes'])})\n")
        for n in data["notes"][:50]:
            lines.append(f"### #{n['id']} — {n['title']}\n")
            if n.get("target"):
                lines.append(f"- **Target:** `{n['target']}`")
            lines.append(f"\n{n.get('body') or ''}\n")

    # CVEs
    if data["cves"]:
        lines.append(f"## 📡 CVEs ({len(data['cves'])})\n")
        lines.append("| CVE | Score | Severity | KEV |")
        lines.append("|-----|-------|----------|-----|")
        for c in data["cves"][:50]:
            score = c.get("cvss_score")
            score_str = f"{score:.1f}" if isinstance(score, (int, float)) else "—"
            lines.append(f"| {c.get('cve_id')} | {score_str} | "
                         f"{(c.get('cvss_severity') or '').upper()} | "
                         f"{'🔴' if c.get('kev') else ''} |")
        lines.append("")

    # Scans
    if data["scans"]:
        lines.append(f"## 🔍 Сканы ({len(data['scans'])})\n")
        lines.append("| ID | Module | Target | Date |")
        lines.append("|----|--------|--------|------|")
        for s_ in data["scans"][:200]:
            lines.append(f"| {s_['id']} | {s_['module']} | "
                         f"{s_['target']} | {s_['created_at']} |")
        lines.append("")

    try:
        Path(out_path).write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green]✓ Markdown: {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:
        console.print(f"[red]Markdown: {exc}[/red]")
        return None


# ===========================================================================
# Открытие
# ===========================================================================

def _open_file(path: Path) -> None:
    import os
    import sys
    try:
        if sys.platform == "win32":
            os.startfile(str(path))
        elif sys.platform == "darwin":
            os.system(f'open "{path}"')
        else:
            os.system(f'xdg-open "{path}" >/dev/null 2>&1 &')
    except Exception as exc:
        console.print(f"[yellow]Не открыть: {exc}[/yellow]")


# ===========================================================================
# Инкрементальный diff
# ===========================================================================

def incremental_diff(out_dir: str | None = None) -> None:
    """
    Сравнить текущее состояние с последним auto-report JSON.
    Показать новые findings / новые сканы / изменения.
    """
    previous: dict | None = None
    for p in sorted(AR_DIR.glob("autoreport_*.json"),
                    key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            previous = json.loads(p.read_text(encoding="utf-8"))
            console.print(f"[dim]Сравниваю с: {p.name}[/dim]")
            break
        except Exception:
            continue
    if not previous:
        console.print("[yellow]Нет предыдущего отчёта для diff.[/yellow]")
        return

    current = _collect_all()
    for key in ("stats_images", "screenshots"):
        for img in current[key]:
            img.pop("b64", None)

    prev_findings = {f.get("id") for f in previous.get("findings", [])}
    curr_findings = {f.get("id") for f in current.get("findings", [])}
    new_ids = curr_findings - prev_findings

    prev_scans = {s.get("id") for s in previous.get("scans", [])}
    curr_scans = {s.get("id") for s in current.get("scans", [])}
    new_scan_ids = curr_scans - prev_scans

    console.print(f"\n[bold cyan]═══ Incremental diff ═══[/bold cyan]")
    console.print(f"Новых сканов: [green]{len(new_scan_ids)}[/green]")
    console.print(f"Новых находок: [red]{len(new_ids)}[/red]")

    if new_ids:
        t = Table(title=f"Новые находки ({len(new_ids)})")
        t.add_column("ID", style="cyan", width=6)
        t.add_column("Severity", width=10)
        t.add_column("Target", style="green")
        t.add_column("Title", style="white")
        for f in current.get("findings", []):
            if f.get("id") in new_ids:
                t.add_row(str(f["id"]),
                          (f.get("severity") or "").upper(),
                          (f.get("target") or "—")[:40],
                          f.get("title") or "")
        console.print(t)


# ===========================================================================
# Публичные функции
# ===========================================================================

def quick_html() -> None:
    generate_html()


def quick_pdf() -> None:
    generate_pdf()


def quick_json() -> None:
    generate_json()


def quick_markdown() -> None:
    generate_markdown()


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]📊 Auto-Report Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "HTML (все данные + exec summary + timeline)"),
        ("2", "PDF (все данные)"),
        ("3", "JSON (сырые данные)"),
        ("4", "Markdown"),
        ("5", "HTML шаблон HackerOne"),
        ("6", "HTML шаблон Bugcrowd"),
        ("7", "HTML шаблон Pentest"),
        ("8", "HTML по конкретной цели"),
        ("9", "PDF по конкретной цели"),
        ("10", "Все 4 формата сразу"),
        ("11", "Incremental diff с предыдущим"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        p = generate_html()
        if p and Confirm.ask("Открыть?", default=True):
            _open_file(p)
    elif c == "2":
        p = generate_pdf()
        if p and Confirm.ask("Открыть?", default=True):
            _open_file(p)
    elif c == "3":
        generate_json()
    elif c == "4":
        generate_markdown()
    elif c == "5":
        p = generate_html(template="hackerone")
        if p and Confirm.ask("Открыть?", default=True):
            _open_file(p)
    elif c == "6":
        p = generate_html(template="bugcrowd")
        if p and Confirm.ask("Открыть?", default=True):
            _open_file(p)
    elif c == "7":
        p = generate_html(template="pentest")
        if p and Confirm.ask("Открыть?", default=True):
            _open_file(p)
    elif c == "8":
        target = Prompt.ask("Target (фильтр)")
        p = generate_html(target_filter=target)
        if p and Confirm.ask("Открыть?", default=True):
            _open_file(p)
    elif c == "9":
        target = Prompt.ask("Target (фильтр)")
        p = generate_pdf(target_filter=target)
        if p and Confirm.ask("Открыть?", default=True):
            _open_file(p)
    elif c == "10":
        target = Prompt.ask("Target (пусто = все)",
                            default="").strip() or None
        generate_html(target_filter=target)
        generate_pdf(target_filter=target)
        generate_json(target_filter=target)
        generate_markdown(target_filter=target)
    elif c == "11":
        incremental_diff()


# ===========================================================================
# CLI-обёртки (совместимы со старыми)
# ===========================================================================

def cli_html(target: str | None = None, template: str = "default",
             out: str | None = None) -> None:
    generate_html(target_filter=target, template=template, out_path=out)


def cli_pdf(target: str | None = None, template: str = "default",
            out: str | None = None) -> None:
    generate_pdf(target_filter=target, template=template, out_path=out)


def cli_json(target: str | None = None, out: str | None = None) -> None:
    generate_json(target_filter=target, out_path=out)


def cli_markdown(target: str | None = None, out: str | None = None) -> None:
    generate_markdown(target_filter=target, out_path=out)


def cli_diff() -> None:
    incremental_diff()