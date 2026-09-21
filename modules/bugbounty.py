"""Модуль Bug Bounty: CVSS 3.1, генератор отчётов, экспорт истории,
отправка уведомлений после генерации отчёта."""
import json
import csv
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


CVSS_VECTORS = [
    ("AV", "Attack Vector", {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}),
    ("AC", "Attack Complexity", {"L": 0.77, "H": 0.44}),
    ("PR", "Privileges Required", {"N": 0.85, "L": 0.62, "H": 0.27}),
    ("UI", "User Interaction", {"N": 0.85, "R": 0.62}),
    ("S", "Scope", {"U": 1.0, "C": 1.08}),
    ("C", "Confidentiality", {"H": 0.56, "L": 0.22, "N": 0.0}),
    ("I", "Integrity", {"H": 0.56, "L": 0.22, "N": 0.0}),
    ("A", "Availability", {"H": 0.56, "L": 0.22, "N": 0.0}),
]


def _notify_report(report: dict, md_path: Path, json_path: Path) -> None:
    """Отправить уведомление о новом отчёте."""
    try:
        from modules import notifier
    except Exception:  # noqa: BLE001
        return
    title = f"Bug Bounty отчёт: {report['severity']} — {report['target']}"
    message = (
        f"Заголовок: {report['title']}\n"
        f"Цель:      {report['target']}\n"
        f"Severity:  {report['severity']} (CVSS {report['cvss']})\n"
        f"Файлы:\n"
        f"  {md_path}\n"
        f"  {json_path}\n\n"
        f"Описание:\n{report['description'][:800]}"
    )
    notifier.notify_all(title, message)


def cvss_calculator() -> None:
    """Интерактивный CVSS v3.1 Base Score."""
    console.print("[cyan]CVSS v3.1 Base Score Calculator[/cyan]")

    table = Table()
    table.add_column("Метрика", style="cyan")
    table.add_column("Значения", style="green")
    for code, name, values in CVSS_VECTORS:
        table.add_row(f"{code} — {name}", ", ".join(values.keys()))
    console.print(table)

    chosen: dict[str, str] = {}
    for code, name, values in CVSS_VECTORS:
        chosen[code] = Prompt.ask(f"{code} ({name})",
                                  choices=list(values.keys()))

    av = CVSS_VECTORS[0][2][chosen["AV"]]
    ac = CVSS_VECTORS[1][2][chosen["AC"]]
    pr = CVSS_VECTORS[2][2][chosen["PR"]]
    ui = CVSS_VECTORS[3][2][chosen["UI"]]
    scope_changed = chosen["S"] == "C"
    c = CVSS_VECTORS[5][2][chosen["C"]]
    i = CVSS_VECTORS[6][2][chosen["I"]]
    a = CVSS_VECTORS[7][2][chosen["A"]]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    else:
        if scope_changed:
            score = min(1.08 * (impact + exploitability), 10)
        else:
            score = min(impact + exploitability, 10)
    score = round(score, 1)

    vector = (
        f"CVSS:3.1/AV:{chosen['AV']}/AC:{chosen['AC']}/PR:{chosen['PR']}"
        f"/UI:{chosen['UI']}/S:{chosen['S']}/C:{chosen['C']}"
        f"/I:{chosen['I']}/A:{chosen['A']}"
    )
    if score == 0:
        severity = "None"
    elif score < 4:
        severity = "Low"
    elif score < 7:
        severity = "Medium"
    elif score < 9:
        severity = "High"
    else:
        severity = "Critical"

    console.print(f"[bold green]Score: {score} ({severity})[/bold green]")
    console.print(f"[cyan]Vector:[/cyan] {vector}")

    db.save_scan("cvss", vector, {"score": score, "severity": severity})


def _write_markdown(report: dict, path: Path) -> None:
    """Сохранить отчёт в Markdown."""
    md = (
        f"# {report['title']}\n\n"
        f"**Target:** {report['target']}  \n"
        f"**Severity:** {report['severity']} (CVSS: {report['cvss']})  \n"
        f"**Date:** {report['date']}  \n"
        f"**Author:** {report['author']}  \n\n"
        f"## Description\n\n{report['description']}\n\n"
        f"## Impact\n\n{report['impact']}\n\n"
        f"## Steps to Reproduce (PoC)\n\n```\n{report['poc']}\n```\n\n"
        f"## Remediation\n\n{report['remediation']}\n\n"
        f"## References\n\n{report['references']}\n"
    )
    path.write_text(md, encoding="utf-8")


def generate_report() -> None:
    """Интерактивный генератор отчёта (MD + JSON + уведомление)."""
    title = Prompt.ask("Заголовок отчёта", default="Vulnerability Report")
    target = Prompt.ask("Цель (URL/IP)")
    severity = Prompt.ask(
        "Severity",
        choices=["low", "medium", "high", "critical"],
        default="medium",
    )
    cvss = Prompt.ask("CVSS score (например 7.5)", default="0.0")
    author = Prompt.ask("Автор", default="anon")
    description = Prompt.ask("Описание")
    impact = Prompt.ask("Impact")
    poc = Prompt.ask("PoC / шаги воспроизведения")
    remediation = Prompt.ask("Рекомендации по исправлению")
    references = Prompt.ask("Ссылки (references)", default="—")

    report = {
        "title": title,
        "target": target,
        "severity": severity.upper(),
        "cvss": cvss,
        "author": author,
        "date": datetime.utcnow().isoformat(),
        "description": description,
        "impact": impact,
        "poc": poc,
        "remediation": remediation,
        "references": references,
    }

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    md_path = REPORT_DIR / f"report_{ts}.md"
    json_path = REPORT_DIR / f"report_{ts}.json"

    try:
        _write_markdown(report, md_path)
        json_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка сохранения: {exc}[/red]")
        log.exception("report save")
        return

    console.print(f"[green]✓ Markdown: {md_path}[/green]")
    console.print(f"[green]✓ JSON: {json_path}[/green]")
    db.save_scan("report", target, report)

    # --- Уведомление ---
    _notify_report(report, md_path, json_path)
    console.print("[cyan]Уведомление отправлено (если NOTIFY_ENABLED=true).[/cyan]")


def export_history_csv() -> None:
    """Экспорт всей истории сканов в CSV."""
    rows = db.history(1000)
    if not rows:
        console.print("[yellow]История пуста.[/yellow]")
        return
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORT_DIR / f"history_{ts}.csv"
    try:
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["id", "module", "target", "created_at", "result"])
            for r in rows:
                w.writerow([r["id"], r["module"], r["target"],
                            r["created_at"], r["result"]])
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка экспорта: {exc}[/red]")
        return
    console.print(f"[green]✓ {path}[/green]")


def export_history_json() -> None:
    """Экспорт истории в JSON."""
    rows = db.history(1000)
    if not rows:
        console.print("[yellow]История пуста.[/yellow]")
        return
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORT_DIR / f"history_{ts}.json"
    data = [
        {
            "id": r["id"],
            "module": r["module"],
            "target": r["target"],
            "created_at": str(r["created_at"]),
            "result": r["result"],
        }
        for r in rows
    ]
    try:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return
    console.print(f"[green]✓ {path}[/green]")


def hackerone_template() -> None:
    """Шаблон отчёта для HackerOne."""
    tmpl = """
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
"""
    console.print(f"[cyan]{tmpl}[/cyan]")


def bugcrowd_template() -> None:
    """Шаблон для Bugcrowd."""
    tmpl = """
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
"""
    console.print(f"[cyan]{tmpl}[/cyan]")


def menu() -> None:
    """Меню Bug Bounty."""
    table = Table(title="[bold]Bug Bounty[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "CVSS v3.1 calculator"),
        ("2", "Generate report (MD + JSON + notify)"),
        ("3", "Export scan history to CSV"),
        ("4", "Export scan history to JSON"),
        ("5", "HackerOne report template"),
        ("6", "Bugcrowd report template"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])
    {
        "1": cvss_calculator,
        "2": generate_report,
        "3": export_history_csv,
        "4": export_history_json,
        "5": hackerone_template,
        "6": bugcrowd_template,
    }[c]()