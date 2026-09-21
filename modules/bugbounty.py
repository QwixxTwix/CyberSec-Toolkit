"""
Bug Bounty Toolkit — расширенный.
Author: idqwixxa

⚠ Только для авторизованных bug bounty программ.

Возможности:
    ─── CVSS ───
    - Base v3.1 (интерактивный + из вектора)
    - Temporal (E, RL, RC)
    - Environmental (CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA)
    - Пресеты уязвимостей (13 типов: XSS/SQLi/SSRF/RCE/IDOR/CSRF/XXE/...)
    - Сохранение/загрузка кастомных пресетов
    - Таблица severity + vector + score

    ─── Отчёты ───
    - Многострочный интерактивный ввод
    - Автоподстановка из notes (kind="finding") по ID
    - 6 шаблонов платформ (H1/Bugcrowd/Intigriti/YesWeHack/Immunefi/CVE)
    - 4 формата экспорта (MD/HTML/PDF/JSON)
    - Quality-checker перед публикацией
    - Сохранение в notes как finding
    - Уведомление через notifier

    ─── Экспорт истории ───
    - CSV / JSON / HTML / Markdown
    - Фильтры по модулю / цели / дате
    - Статистика и распределения
"""
import csv
import html as html_mod
import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.markdown import Markdown as RichMarkdown

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

BB_DIR = REPORT_DIR / "bug_bounty"
BB_DIR.mkdir(parents=True, exist_ok=True)

PRESETS_FILE = BB_DIR / "cvss_presets.json"


# ===========================================================================
# CVSS v3.1 — метрики
# ===========================================================================

CVSS_BASE = {
    "AV": ("Attack Vector", {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}),
    "AC": ("Attack Complexity", {"L": 0.77, "H": 0.44}),
    "PR": ("Privileges Required", {"N": 0.85, "L": 0.62, "H": 0.27}),
    "UI": ("User Interaction", {"N": 0.85, "R": 0.62}),
    "S":  ("Scope", {"U": 1.0, "C": 1.08}),
    "C":  ("Confidentiality", {"H": 0.56, "L": 0.22, "N": 0.0}),
    "I":  ("Integrity", {"H": 0.56, "L": 0.22, "N": 0.0}),
    "A":  ("Availability", {"H": 0.56, "L": 0.22, "N": 0.0}),
}

CVSS_TEMPORAL = {
    "E":  ("Exploit Code Maturity",
            {"X": 1.0, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.0}),
    "RL": ("Remediation Level",
            {"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95}),
    "RC": ("Report Confidence",
            {"X": 1.0, "U": 0.92, "R": 0.96, "C": 1.0}),
}

CVSS_ENV = {
    "CR": ("Confidentiality Requirement", {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}),
    "IR": ("Integrity Requirement", {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}),
    "AR": ("Availability Requirement", {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}),
    "MAV": ("Modified AV", CVSS_BASE["AV"][1]),
    "MAC": ("Modified AC", CVSS_BASE["AC"][1]),
    "MPR": ("Modified PR", CVSS_BASE["PR"][1]),
    "MUI": ("Modified UI", CVSS_BASE["UI"][1]),
    "MS":  ("Modified Scope", CVSS_BASE["S"][1]),
    "MC":  ("Modified C", CVSS_BASE["C"][1]),
    "MI":  ("Modified I", CVSS_BASE["I"][1]),
    "MA":  ("Modified A", CVSS_BASE["A"][1]),
}


# ===========================================================================
# Пресеты уязвимостей
# ===========================================================================

VULN_PRESETS = {
    "xss-reflected": {
        "name": "Reflected XSS",
        "severity": "medium",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe": "CWE-79",
        "description": "Reflected XSS — payload отражается в HTML без "
                       "экранирования.",
        "impact": "Кража cookie / сессии, действия от имени жертвы.",
        "remediation": "Контекстное экранирование, CSP, X-XSS-Protection.",
    },
    "xss-stored": {
        "name": "Stored XSS",
        "severity": "high",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
        "cwe": "CWE-79",
        "description": "Stored XSS — payload сохраняется и выполняется "
                       "у всех пользователей.",
        "impact": "Полная компрометация сессий всех пользователей.",
        "remediation": "Экранирование вывода + sanitization ввода.",
    },
    "sqli": {
        "name": "SQL Injection",
        "severity": "critical",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-89",
        "description": "SQL-инъекция через пользовательский ввод.",
        "impact": "Чтение/изменение БД, возможен RCE.",
        "remediation": "Параметризованные запросы, ORM, WAF.",
    },
    "ssrf": {
        "name": "SSRF",
        "severity": "high",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "cwe": "CWE-918",
        "description": "Server-Side Request Forgery.",
        "impact": "Доступ к internal-сервисам, чтение cloud-metadata.",
        "remediation": "Allowlist URL, блокировка 169.254.*/127.*.",
    },
    "idor": {
        "name": "IDOR",
        "severity": "high",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-639",
        "description": "Insecure Direct Object Reference.",
        "impact": "Доступ к чужим объектам, утечка PII.",
        "remediation": "Ownership-check на каждый запрос.",
    },
    "rce": {
        "name": "Remote Code Execution",
        "severity": "critical",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-94",
        "description": "Remote Code Execution.",
        "impact": "Полная компрометация сервера.",
        "remediation": "Никогда не передавать user-input в eval/exec.",
    },
    "auth-bypass": {
        "name": "Authentication Bypass",
        "severity": "critical",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-287",
        "description": "Обход аутентификации.",
        "impact": "Доступ ко всем защищённым функциям.",
        "remediation": "Единая точка auth, deny-by-default.",
    },
    "subdomain-takeover": {
        "name": "Subdomain Takeover",
        "severity": "high",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe": "CWE-350",
        "description": "Dangling CNAME → takeover.",
        "impact": "Фишинг, кража cookie, обход CSP.",
        "remediation": "Удалять неиспользуемые DNS-записи.",
    },
    "open-redirect": {
        "name": "Open Redirect",
        "severity": "medium",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
        "cwe": "CWE-601",
        "description": "Открытый редирект.",
        "impact": "Фишинг через доверенный домен.",
        "remediation": "Allowlist домена-назначения.",
    },
    "csrf": {
        "name": "CSRF",
        "severity": "medium",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cwe": "CWE-352",
        "description": "Cross-Site Request Forgery.",
        "impact": "State-changing действия от имени жертвы.",
        "remediation": "CSRF-токен, SameSite cookies.",
    },
    "xxe": {
        "name": "XXE",
        "severity": "high",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "cwe": "CWE-611",
        "description": "XML External Entity Injection.",
        "impact": "Чтение файлов, SSRF, при некоторых конфигах — RCE.",
        "remediation": "Отключить DTD и внешние entity.",
    },
    "race-condition": {
        "name": "Race Condition",
        "severity": "high",
        "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "cwe": "CWE-362",
        "description": "Race Condition (TOCTOU).",
        "impact": "Многократное использование купона, обход лимитов.",
        "remediation": "Атомарные операции, distributed locks.",
    },
    "info-disclosure": {
        "name": "Information Disclosure",
        "severity": "low",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200",
        "description": "Утечка информации.",
        "impact": "Помощь атакующему, утечка PII.",
        "remediation": "Отключить debug-инфо в production.",
    },
}


# ===========================================================================
# CVSS v3.1 — вычисления
# ===========================================================================

def _round_up(x: float) -> float:
    """CVSS Roundup (спецификация FIRST)."""
    return round(x + 0.0000000001, 1)


def cvss_score_from_vector(vector: str) -> dict:
    """
    Вычислить Base + Temporal + Environmental score из вектора.
    Возвращает dict с base/temporal/environmental score и severity.
    """
    out: dict[str, Any] = {"vector": vector, "valid": False,
                            "base_score": 0.0, "base_severity": "None",
                            "temporal_score": 0.0, "temporal_severity": "None",
                            "env_score": 0.0, "env_severity": "None"}
    try:
        parts = dict(p.split(":") for p in vector.split("/") if ":" in p)
        # убираем "CVSS" из первого элемента
        if "CVSS" in parts:
            del parts["CVSS"]
    except Exception:
        return out

    def get(k: str, default: str) -> str:
        return parts.get(k, default)

    av = CVSS_BASE["AV"][1].get(get("AV", "N"), 0.85)
    ac = CVSS_BASE["AC"][1].get(get("AC", "L"), 0.77)
    pr_scope_changed = get("S", "U") == "C"
    if pr_scope_changed:
        pr_table = {"N": 0.85, "L": 0.68, "H": 0.5}
    else:
        pr_table = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr = pr_table.get(get("PR", "N"), 0.85)
    ui = CVSS_BASE["UI"][1].get(get("UI", "N"), 0.85)
    scope_changed = pr_scope_changed
    c = CVSS_BASE["C"][1].get(get("C", "N"), 0.0)
    i = CVSS_BASE["I"][1].get(get("I", "N"), 0.0)
    a = CVSS_BASE["A"][1].get(get("A", "N"), 0.0)

    # Impact
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base_score = 0.0
    else:
        if scope_changed:
            base_score = min(1.08 * (impact + exploitability), 10)
        else:
            base_score = min(impact + exploitability, 10)
    base_score = _round_up(base_score)

    # Temporal
    e = CVSS_TEMPORAL["E"][1].get(get("E", "X"), 1.0)
    rl = CVSS_TEMPORAL["RL"][1].get(get("RL", "X"), 1.0)
    rc = CVSS_TEMPORAL["RC"][1].get(get("RC", "X"), 1.0)
    if base_score > 0:
        temporal_score = _round_up(base_score * e * rl * rc)
    else:
        temporal_score = 0.0

    # Environmental — упрощённо
    cr = CVSS_ENV["CR"][1].get(get("CR", "X"), 1.0)
    ir = CVSS_ENV["IR"][1].get(get("IR", "X"), 1.0)
    ar = CVSS_ENV["AR"][1].get(get("AR", "X"), 1.0)
    mc = CVSS_ENV["MC"][1].get(get("MC", "X") or get("C", "N"), 0.0) * cr
    mi = CVSS_ENV["MI"][1].get(get("MI", "X") or get("I", "N"), 0.0) * ir
    ma = CVSS_ENV["MA"][1].get(get("MA", "X") or get("A", "N"), 0.0) * ar
    mc = min(mc, 0.56)
    mi = min(mi, 0.56)
    ma = min(ma, 0.56)
    miss = 1 - ((1 - mc) * (1 - mi) * (1 - ma))
    if scope_changed:
        m_impact = 7.52 * (miss - 0.029) - 3.25 * (miss - 0.02) ** 15
    else:
        m_impact = 6.42 * miss
    if m_impact <= 0:
        env_score = 0.0
    else:
        if scope_changed:
            env_score = min(1.08 * (m_impact + exploitability), 10)
        else:
            env_score = min(m_impact + exploitability, 10)
    env_score = _round_up(env_score)

    out.update({
        "valid": True,
        "base_score": base_score,
        "base_severity": _severity(base_score),
        "temporal_score": temporal_score,
        "temporal_severity": _severity(temporal_score),
        "env_score": env_score,
        "env_severity": _severity(env_score),
    })
    return out


def _severity(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"


def cvss_calculator() -> None:
    """Интерактивный CVSS v3.1 Base Score (сохранён как old API)."""
    _cvss_interactive()


def _cvss_interactive() -> None:
    """Расширенный интерактивный CVSS."""
    console.print("[cyan]CVSS v3.1 Calculator (base + temporal + env)[/cyan]")

    # Base
    console.print("\n[bold cyan]── Base metrics ──[/bold cyan]")
    table = Table()
    table.add_column("Метрика", style="cyan")
    table.add_column("Значения", style="green")
    for code, (name, values) in CVSS_BASE.items():
        table.add_row(f"{code} — {name}", ", ".join(values.keys()))
    console.print(table)

    chosen: dict[str, str] = {}
    for code, (name, _values) in CVSS_BASE.items():
        vals = list(CVSS_BASE[code][1].keys())
        chosen[code] = Prompt.ask(f"{code} ({name})", choices=vals)

    # Вектор base
    base_vector = (
        f"CVSS:3.1/AV:{chosen['AV']}/AC:{chosen['AC']}/PR:{chosen['PR']}"
        f"/UI:{chosen['UI']}/S:{chosen['S']}/C:{chosen['C']}"
        f"/I:{chosen['I']}/A:{chosen['A']}"
    )

    # Temporal (опционально)
    temp_vector = ""
    if Confirm.ask("Добавить Temporal метрики?", default=False):
        temp_parts = []
        for code, (name, values) in CVSS_TEMPORAL.items():
            v = Prompt.ask(f"{code} ({name})",
                           choices=list(values.keys()), default="X")
            temp_parts.append(f"{code}:{v}")
        if temp_parts:
            temp_vector = "/" + "/".join(temp_parts)

    # Environmental (опционально)
    env_vector = ""
    if Confirm.ask("Добавить Environmental метрики?", default=False):
        env_parts = []
        for code, (name, values) in CVSS_ENV.items():
            default = "X"
            v = Prompt.ask(f"{code} ({name})",
                           choices=list(values.keys()), default=default)
            env_parts.append(f"{code}:{v}")
        if env_parts:
            env_vector = "/" + "/".join(env_parts)

    full_vector = base_vector + temp_vector + env_vector

    result = cvss_score_from_vector(full_vector)

    t = Table(title="Результат")
    t.add_column("Тип", style="cyan")
    t.add_column("Score", style="green")
    t.add_column("Severity", style="yellow")
    t.add_row("Base", f"{result['base_score']}",
              result["base_severity"])
    if result["temporal_score"]:
        t.add_row("Temporal", f"{result['temporal_score']}",
                  result["temporal_severity"])
    if result["env_score"]:
        t.add_row("Environmental", f"{result['env_score']}",
                  result["env_severity"])
    console.print(t)
    console.print(f"[cyan]Vector:[/cyan] {full_vector}")

    db.save_scan("cvss", full_vector, result)


def cvss_from_vector_cli() -> None:
    """CLI: рассчитать из готового вектора."""
    vector = Prompt.ask("CVSS vector")
    result = cvss_score_from_vector(vector)
    if not result["valid"]:
        console.print("[red]Невалидный вектор.[/red]")
        return
    t = Table(title="CVSS result")
    t.add_column("Тип", style="cyan")
    t.add_column("Score", style="green")
    t.add_column("Severity", style="yellow")
    t.add_row("Base", str(result["base_score"]), result["base_severity"])
    t.add_row("Temporal", str(result["temporal_score"]),
              result["temporal_severity"])
    t.add_row("Environmental", str(result["env_score"]),
              result["env_severity"])
    console.print(t)


def cvss_from_preset_cli() -> None:
    """CLI: выбрать пресет уязвимости."""
    t = Table(title=f"Пресеты ({len(VULN_PRESETS)})")
    t.add_column("#", style="yellow", width=4)
    t.add_column("Slug", style="cyan")
    t.add_column("Name", style="white")
    t.add_column("Severity", style="red", width=10)
    t.add_column("CWE", style="magenta", width=10)
    for i, (slug, data) in enumerate(VULN_PRESETS.items(), 1):
        t.add_row(str(i), slug, data["name"],
                  data["severity"].upper(), data["cwe"])
    console.print(t)

    slug = Prompt.ask("Slug", choices=list(VULN_PRESETS.keys()),
                       default="xss-reflected")
    preset = VULN_PRESETS[slug]
    result = cvss_score_from_vector(preset["vector"])
    console.print(f"\n[cyan]{preset['name']}[/cyan]")
    console.print(f"Vector: {preset['vector']}")
    console.print(f"Base score: {result['base_score']} "
                  f"({result['base_severity']})")


# ===========================================================================
# Многострочный ввод
# ===========================================================================

def _multiline(label: str, default: str = "") -> str:
    """Многострочный ввод. Пустая строка = конец."""
    console.print(f"[cyan]{label}[/cyan] [dim](пустая строка — конец; "
                  f"'.' → принять текущее)[/dim]")
    if default:
        short = default.splitlines()[0][:80]
        console.print(f"[dim]  Текущее: {short}"
                      f"{'…' if len(default) > 80 else ''}[/dim]")
    lines: list[str] = []
    while True:
        try:
            line = input("  > ")
        except (EOFError, KeyboardInterrupt):
            break
        if line == "":
            break
        if line == "." and default:
            return default
        lines.append(line)
    return "\n".join(lines) if lines else default


# ===========================================================================
# Report model
# ===========================================================================

@dataclass
class BugReport:
    platform: str = "hackerone"
    title: str = ""
    target: str = ""
    severity: str = ""
    cvss_vector: str = ""
    cvss_score: float = 0.0
    cwe: str = ""
    author: str = "anon"
    date: str = ""
    description: str = ""
    impact: str = ""
    steps: str = ""
    poc: str = ""
    remediation: str = ""
    references: str = ""
    expected: str = ""
    actual: str = ""
    finding_id: int = 0


PLATFORM_TEMPLATES = {
    "hackerone": {
        "name": "HackerOne",
        "sections": [
            ("description", "Summary"),
            ("steps", "Steps To Reproduce"),
            ("impact", "Impact"),
            ("poc", "Supporting Material/References"),
            ("remediation", "Suggested Fix"),
        ],
    },
    "bugcrowd": {
        "name": "Bugcrowd",
        "sections": [
            ("description", "Bug Description"),
            ("steps", "Steps to Reproduce"),
            ("expected", "Expected Result"),
            ("actual", "Actual Result"),
            ("impact", "Impact"),
            ("remediation", "Suggested Fix"),
        ],
    },
    "intigriti": {
        "name": "Intigriti",
        "sections": [
            ("description", "Detailed Description"),
            ("steps", "Steps to Reproduce"),
            ("impact", "Impact"),
            ("remediation", "Remediation"),
        ],
    },
    "yeswehack": {
        "name": "YesWeHack",
        "sections": [
            ("description", "Description"),
            ("poc", "Proof of Concept"),
            ("impact", "Impact"),
            ("remediation", "Remediation"),
        ],
    },
    "immunefi": {
        "name": "Immunefi",
        "sections": [
            ("description", "Vulnerability Details"),
            ("impact", "Impact"),
            ("poc", "Proof of Concept"),
            ("remediation", "Recommended Mitigation"),
        ],
    },
    "cve": {
        "name": "CVE / MITRE",
        "sections": [
            ("description", "Description"),
            ("impact", "Impact"),
            ("poc", "References"),
            ("remediation", "Solution"),
        ],
    },
}


# ===========================================================================
# Quality checker
# ===========================================================================

def quality_check(report: BugReport) -> list[tuple[str, str, str]]:
    """Проверить качество отчёта. Возвращает [(field, level, msg)]."""
    out: list[tuple[str, str, str]] = []
    if len(report.title) < 10:
        out.append(("title", "error", "Заголовок < 10 символов"))
    elif len(report.title) > 120:
        out.append(("title", "warn", "Заголовок > 120 символов"))
    else:
        out.append(("title", "ok", f"OK ({len(report.title)})"))
    if len(report.description) < 50:
        out.append(("description", "error", "Description < 50 символов"))
    else:
        out.append(("description", "ok", f"OK ({len(report.description)})"))
    n_steps = len([l for l in report.steps.splitlines() if l.strip()])
    if n_steps < 3:
        out.append(("steps", "error", f"Шагов < 3 ({n_steps})"))
    else:
        out.append(("steps", "ok", f"{n_steps} шагов"))
    if len(report.impact) < 80:
        out.append(("impact", "warn", "Impact < 80 символов"))
    else:
        out.append(("impact", "ok", f"OK ({len(report.impact)})"))
    if not report.poc:
        out.append(("poc", "warn", "Нет PoC"))
    elif not re.search(r"(curl|wget|POST|GET|http|python)", report.poc,
                        re.IGNORECASE):
        out.append(("poc", "warn", "PoC без команд/URL"))
    else:
        out.append(("poc", "ok", "OK"))
    if len(report.remediation) < 40:
        out.append(("remediation", "warn", "Remediation < 40 символов"))
    else:
        out.append(("remediation", "ok", f"OK ({len(report.remediation)})"))
    if report.cvss_vector:
        r = cvss_score_from_vector(report.cvss_vector)
        if r["valid"]:
            if report.cvss_score and abs(r["base_score"] - report.cvss_score) > 0.2:
                out.append(("cvss", "warn",
                            f"Вектор даёт {r['base_score']}, "
                            f"заявлено {report.cvss_score}"))
            else:
                out.append(("cvss", "ok",
                            f"Base {r['base_score']} ({r['base_severity']})"))
    else:
        out.append(("cvss", "warn", "CVSS-вектор не указан"))
    if not report.cwe:
        out.append(("cwe", "warn", "CWE не указан"))
    else:
        out.append(("cwe", "ok", report.cwe))
    return out


# ===========================================================================
# Report renderers
# ===========================================================================

def _render_markdown(r: BugReport) -> str:
    tpl = PLATFORM_TEMPLATES.get(r.platform, PLATFORM_TEMPLATES["hackerone"])
    out: list[str] = [f"# {r.title}\n"]
    out.append(f"**Target:** `{r.target or '—'}`  ")
    if r.cvss_vector:
        out.append(f"**CVSS:** `{r.cvss_vector}` — "
                   f"{r.cvss_score or cvss_score_from_vector(r.cvss_vector)['base_score']}  ")
    if r.severity:
        out.append(f"**Severity:** {r.severity.upper()}  ")
    if r.cwe:
        out.append(f"**CWE:** {r.cwe}  ")
    out.append(f"**Author:** {r.author}  ")
    out.append(f"**Date:** {r.date or datetime.utcnow().isoformat()}  ")
    out.append("")

    for key, title in tpl["sections"]:
        val = getattr(r, key, "") or ""
        if not val:
            continue
        out.append(f"## {title}\n")
        out.append(val)
        out.append("")
    if r.references:
        out.append("## References\n")
        out.append(r.references)
    return "\n".join(out)


def _render_html(r: BugReport) -> str:
    tpl = PLATFORM_TEMPLATES.get(r.platform, PLATFORM_TEMPLATES["hackerone"])
    calc = cvss_score_from_vector(r.cvss_vector) if r.cvss_vector else {}
    sev = (r.severity or calc.get("base_severity", "info")).lower()

    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>{html_mod.escape(r.title)}</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:32px;max-width:1000px;margin:0 auto;line-height:1.6;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;padding-bottom:8px;}",
        "h2{color:#00ff9c;margin-top:32px;border-left:4px solid #00ff9c;"
        "padding-left:12px;}",
        ".meta{background:#0d0d0d;border:1px solid #222;padding:12px;"
        "border-radius:4px;margin-bottom:24px;font-size:13px;}",
        ".meta b{color:#7ad9ff;}",
        "pre{background:#050505;border:1px solid #222;padding:12px;"
        "overflow-x:auto;color:#a0ffa0;border-radius:4px;}",
        ".badge{display:inline-block;padding:3px 10px;border-radius:3px;"
        "font-size:11px;font-weight:bold;margin-left:8px;}",
        ".critical{background:#3a0000;color:#ff4040;}",
        ".high{background:#3a1a00;color:#ff7a40;}",
        ".medium{background:#3a2a00;color:#ffd23f;}",
        ".low{background:#003322;color:#00ff9c;}",
        ".none{background:#111;color:#888;}",
        "</style></head><body>",
        f"<h1>{html_mod.escape(r.title)}"
        f"<span class='badge {sev}'>{sev.upper()}</span></h1>",
        "<div class='meta'>",
        f"<b>Platform:</b> {html_mod.escape(tpl['name'])}<br>",
        f"<b>Target:</b> {html_mod.escape(r.target)}<br>",
    ]
    if r.cvss_vector:
        parts.append(f"<b>CVSS:</b> "
                     f"{r.cvss_score or calc.get('base_score', '?')} — "
                     f"<code>{html_mod.escape(r.cvss_vector)}</code><br>")
    if r.cwe:
        parts.append(f"<b>CWE:</b> {html_mod.escape(r.cwe)}<br>")
    parts.append(f"<b>Author:</b> {html_mod.escape(r.author)}<br>")
    parts.append(f"<b>Date:</b> {html_mod.escape(r.date)}")
    parts.append("</div>")

    for key, title in tpl["sections"]:
        val = getattr(r, key, "") or ""
        if not val:
            continue
        safe = html_mod.escape(val).replace("\n", "<br>")
        parts.append(f"<h2>{html_mod.escape(title)}</h2>")
        parts.append(f"<div>{safe}</div>")
    if r.references:
        parts.append("<h2>References</h2>")
        parts.append(f"<div>{html_mod.escape(r.references).replace(chr(10), '<br>')}</div>")
    parts.append("</body></html>")
    return "\n".join(parts)


def _render_pdf(r: BugReport, path: Path) -> Path | None:
    """PDF через reportlab."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer,
        )
    except ImportError:
        console.print("[red]reportlab не установлен.[/red]")
        return None

    try:
        doc = SimpleDocTemplate(
            str(path), pagesize=A4,
            leftMargin=15 * mm, rightMargin=15 * mm,
            topMargin=15 * mm, bottomMargin=15 * mm,
            title=r.title, author=r.author,
        )
    except Exception as exc:
        console.print(f"[red]PDF init: {exc}[/red]")
        return None

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"],
                        textColor=colors.HexColor("#006633"))
    h2 = ParagraphStyle("H2", parent=styles["Heading2"],
                        textColor=colors.HexColor("#006633"))
    body = ParagraphStyle("Body", parent=styles["BodyText"],
                          fontSize=10, leading=13)
    pre = ParagraphStyle("Pre", parent=styles["BodyText"], fontSize=8,
                          leading=11, fontName="Courier")

    story = []
    story.append(Paragraph(html_mod.escape(r.title), h1))
    story.append(Spacer(1, 4 * mm))
    meta_lines = [
        f"<b>Target:</b> {html_mod.escape(r.target)}",
        f"<b>Severity:</b> {r.severity.upper() if r.severity else '—'}",
    ]
    if r.cvss_vector:
        meta_lines.append(
            f"<b>CVSS:</b> {r.cvss_score or '?'} — "
            f"<font face='Courier' size=8>{html_mod.escape(r.cvss_vector)}</font>"
        )
    if r.cwe:
        meta_lines.append(f"<b>CWE:</b> {html_mod.escape(r.cwe)}")
    meta_lines.append(f"<b>Author:</b> {html_mod.escape(r.author)}")
    meta_lines.append(f"<b>Date:</b> {html_mod.escape(r.date)}")
    for line in meta_lines:
        story.append(Paragraph(line, body))
    story.append(Spacer(1, 8 * mm))

    tpl = PLATFORM_TEMPLATES.get(r.platform, PLATFORM_TEMPLATES["hackerone"])
    for key, title in tpl["sections"]:
        val = getattr(r, key, "") or ""
        if not val:
            continue
        story.append(Paragraph(html_mod.escape(title), h2))
        safe = html_mod.escape(val).replace("\n", "<br/>")
        story.append(Paragraph(safe, body))
        story.append(Spacer(1, 4 * mm))
    if r.references:
        story.append(Paragraph("References", h2))
        story.append(Paragraph(
            html_mod.escape(r.references).replace("\n", "<br/>"), body))

    try:
        doc.build(story)
    except Exception as exc:
        console.print(f"[red]PDF build: {exc}[/red]")
        return None
    return path


# ===========================================================================
# Report generator
# ===========================================================================

def _autofill_from_finding(finding_id: int) -> BugReport | None:
    """Префилл из notes.finding."""
    try:
        from modules import notes
        n = notes.get_note(finding_id)
    except Exception as exc:
        console.print(f"[yellow]notes error: {exc}[/yellow]")
        return None
    if not n:
        console.print(f"[red]Finding #{finding_id} не найден.[/red]")
        return None
    if n.get("kind") != "finding":
        console.print(f"[yellow]#{finding_id} — kind={n.get('kind')}, "
                      f"не finding.[/yellow]")
    r = BugReport(
        title=n.get("title") or "",
        target=n.get("target") or "",
        severity=(n.get("severity") or "").lower(),
        description=n.get("body") or "",
        author="anon",
        date=datetime.utcnow().isoformat(),
        finding_id=finding_id,
    )
    # Автопресет по тегам/title
    tags = [t.lower() for t in (n.get("tags") or [])]
    title_low = r.title.lower()
    for slug, data in VULN_PRESETS.items():
        if slug.replace("-", "") in "".join(tags).replace("-", "") or \
           data["name"].lower() in title_low or \
           slug.split("-")[0] in title_low:
            r.cvss_vector = data["vector"]
            r.cvss_score = cvss_score_from_vector(data["vector"])["base_score"]
            r.cwe = data["cwe"]
            if not r.severity:
                r.severity = data["severity"]
            if not r.impact:
                r.impact = data["impact"]
            if not r.remediation:
                r.remediation = data["remediation"]
            console.print(f"[cyan]Применён пресет: {data['name']}[/cyan]")
            break
    return r


def generate_report() -> None:
    """Интерактивный генератор отчёта (совместим со старым API)."""
    # Платформа
    t = Table(title="Platform")
    t.add_column("Slug", style="cyan")
    t.add_column("Name", style="white")
    for slug, data in PLATFORM_TEMPLATES.items():
        t.add_row(slug, data["name"])
    console.print(t)
    platform = Prompt.ask("Платформа",
                          choices=list(PLATFORM_TEMPLATES.keys()),
                          default="hackerone")

    # Автопресет?
    preset_slug = ""
    if Confirm.ask("Использовать пресет уязвимости?", default=False):
        preset_slug = Prompt.ask("Slug", choices=list(VULN_PRESETS.keys()),
                                  default="xss-reflected")

    # Префилл из finding?
    finding_id = 0
    if Confirm.ask("Префилл из notes (finding ID)?", default=False):
        finding_id = IntPrompt.ask("Finding ID")

    r = BugReport(platform=platform, author="anon",
                  date=datetime.utcnow().isoformat())

    if finding_id:
        filled = _autofill_from_finding(finding_id)
        if filled:
            r = filled
            r.platform = platform
            r.finding_id = finding_id

    # Пресет
    if preset_slug and preset_slug in VULN_PRESETS:
        p = VULN_PRESETS[preset_slug]
        if not r.title:
            r.title = p["name"]
        if not r.description:
            r.description = p["description"]
        if not r.impact:
            r.impact = p["impact"]
        if not r.remediation:
            r.remediation = p["remediation"]
        if not r.severity:
            r.severity = p["severity"]
        if not r.cvss_vector:
            r.cvss_vector = p["vector"]
            r.cvss_score = cvss_score_from_vector(p["vector"])["base_score"]
        if not r.cwe:
            r.cwe = p["cwe"]

    # Заполнение
    r.title = Prompt.ask("Title", default=r.title) or r.title
    r.target = Prompt.ask("Target", default=r.target) or r.target
    if not r.description:
        r.description = _multiline("Description")
    if not r.steps:
        r.steps = _multiline("Steps to Reproduce (один шаг = одна строка)")
    if not r.impact:
        r.impact = _multiline("Impact")
    if not r.poc:
        r.poc = _multiline("PoC / Supporting Material")
    if not r.remediation:
        r.remediation = _multiline("Remediation")

    if platform == "bugcrowd":
        if not r.expected:
            r.expected = _multiline("Expected Result")
        if not r.actual:
            r.actual = _multiline("Actual Result")

    if not r.cvss_vector:
        if Confirm.ask("Задать CVSS вектор?", default=False):
            r.cvss_vector = Prompt.ask("Vector")
            res = cvss_score_from_vector(r.cvss_vector)
            r.cvss_score = res["base_score"]
            if not r.severity:
                r.severity = res["base_severity"].lower()
    if not r.severity and r.cvss_vector:
        r.severity = cvss_score_from_vector(
            r.cvss_vector)["base_severity"].lower()

    r.references = Prompt.ask("References", default="") or r.references
    r.author = Prompt.ask("Author", default="anon")

    # Quality check
    console.print("\n[bold cyan]🔍 Quality check:[/bold cyan]")
    qc = quality_check(r)
    t2 = Table(show_header=False, border_style="dim")
    t2.add_column("Field", style="cyan", width=14)
    t2.add_column("Status", width=8)
    t2.add_column("Message", style="white")
    errors = 0
    for field_, level, msg in qc:
        icon = {"ok": "[green]✓[/green]",
                "warn": "[yellow]⚠[/yellow]",
                "error": "[red]✗[/red]"}[level]
        if level == "error":
            errors += 1
        t2.add_row(field_, icon, msg)
    console.print(t2)
    if errors:
        console.print(f"[red]⚠ {errors} критичных проблем — "
                      f"триаж может отклонить.[/red]")

    # Preview
    if Confirm.ask("Preview Markdown?", default=True):
        console.print(RichMarkdown(_render_markdown(r)))

    # Формат
    fmt = Prompt.ask("Формат", choices=["md", "html", "pdf", "json", "all"],
                     default="md")
    paths: list[Path] = []
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", r.title)[:40]
    base = BB_DIR / f"{r.platform}_{safe}_{ts}"

    if fmt in ("md", "all"):
        p = base.with_suffix(".md")
        try:
            p.write_text(_render_markdown(r), encoding="utf-8")
            paths.append(p)
        except Exception as exc:
            console.print(f"[red]MD: {exc}[/red]")
    if fmt in ("html", "all"):
        p = base.with_suffix(".html")
        try:
            p.write_text(_render_html(r), encoding="utf-8")
            paths.append(p)
        except Exception as exc:
            console.print(f"[red]HTML: {exc}[/red]")
    if fmt in ("pdf", "all"):
        p = base.with_suffix(".pdf")
        res = _render_pdf(r, p)
        if res:
            paths.append(res)
    if fmt in ("json", "all"):
        p = base.with_suffix(".json")
        try:
            p.write_text(json.dumps(asdict(r), indent=2, ensure_ascii=False),
                         encoding="utf-8")
            paths.append(p)
        except Exception as exc:
            console.print(f"[red]JSON: {exc}[/red]")

    for p in paths:
        console.print(f"[green]✓ {p}[/green]")

    db.save_scan("bugbounty_report", r.target or "unknown",
                 {"title": r.title, "platform": r.platform,
                  "severity": r.severity, "paths": [str(p) for p in paths]})

    # Notify
    try:
        from modules import notifier
        notifier.notify_all(
            f"📝 Bug Bounty отчёт: {r.severity.upper()} — {r.target}",
            f"Title: {r.title}\nPlatform: {r.platform}\n"
            f"Files: {len(paths)}",
        )
    except Exception:
        pass

    # Сохранить как finding?
    if Confirm.ask("Сохранить в notes как finding?", default=False):
        try:
            from modules import notes
            nid = notes.add_note(
                kind="finding",
                title=r.title or "Bug Bounty Report",
                target=r.target or "unknown",
                severity=(r.severity or "info").lower(),
                status="open",
                tags=["bugbounty", r.platform],
                body=_render_markdown(r)[:8000],
            )
            if nid > 0:
                console.print(f"[green]✓ Finding #{nid} добавлен.[/green]")
        except Exception as exc:
            console.print(f"[red]notes: {exc}[/red]")


def report_from_finding_cli(finding_id: int,
                            platform: str = "hackerone",
                            fmt: str = "md") -> None:
    """CLI: из finding → отчёт."""
    r = _autofill_from_finding(finding_id)
    if not r:
        return
    r.platform = platform
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", r.title or "report")[:40]
    path = BB_DIR / f"{platform}_{safe}_{ts}"
    if fmt == "md":
        p = path.with_suffix(".md")
        p.write_text(_render_markdown(r), encoding="utf-8")
    elif fmt == "html":
        p = path.with_suffix(".html")
        p.write_text(_render_html(r), encoding="utf-8")
    elif fmt == "pdf":
        p = path.with_suffix(".pdf")
        p = _render_pdf(r, p) or path
    elif fmt == "json":
        p = path.with_suffix(".json")
        p.write_text(json.dumps(asdict(r), indent=2, ensure_ascii=False),
                     encoding="utf-8")
    else:
        console.print(f"[red]Неизвестный формат: {fmt}[/red]")
        return
    console.print(f"[green]✓ {p}[/green]")


# ===========================================================================
# Export history
# ===========================================================================

def _filter_history(rows: list, module: str = "", target: str = "",
                    days: int = 0) -> list:
    out = []
    cutoff = datetime.utcnow() - timedelta(days=days) if days > 0 else None
    for r in rows:
        if module and module.lower() not in str(r["module"]).lower():
            continue
        if target and target.lower() not in str(r["target"]).lower():
            continue
        if cutoff:
            try:
                ts = datetime.fromisoformat(str(r["created_at"]).replace(" ", "T"))
                if ts < cutoff:
                    continue
            except Exception:
                pass
        out.append(r)
    return out


def export_history_csv(module: str = "", target: str = "",
                       days: int = 0, limit: int = 1000) -> Path | None:
    """CSV-экспорт истории."""
    rows = _filter_history(db.history(limit), module, target, days)
    if not rows:
        console.print("[yellow]Нечего экспортировать.[/yellow]")
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = BB_DIR / f"history_{ts}.csv"
    try:
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["id", "module", "target", "created_at", "result"])
            for r in rows:
                w.writerow([r["id"], r["module"], r["target"],
                            str(r["created_at"]), r["result"]])
        console.print(f"[green]✓ CSV: {path} ({len(rows)} записей)[/green]")
        return path
    except Exception as exc:
        console.print(f"[red]CSV: {exc}[/red]")
        return None


def export_history_json(module: str = "", target: str = "",
                        days: int = 0, limit: int = 1000) -> Path | None:
    """JSON-экспорт истории."""
    rows = _filter_history(db.history(limit), module, target, days)
    if not rows:
        console.print("[yellow]Нечего экспортировать.[/yellow]")
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = BB_DIR / f"history_{ts}.json"
    data = [{"id": r["id"], "module": r["module"], "target": r["target"],
             "created_at": str(r["created_at"]), "result": r["result"]}
            for r in rows]
    try:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False,
                                    default=str), encoding="utf-8")
        console.print(f"[green]✓ JSON: {path} ({len(rows)} записей)[/green]")
        return path
    except Exception as exc:
        console.print(f"[red]JSON: {exc}[/red]")
        return None


def export_history_html(module: str = "", target: str = "",
                        days: int = 0, limit: int = 500) -> Path | None:
    """HTML-экспорт истории."""
    rows = _filter_history(db.history(limit), module, target, days)
    if not rows:
        console.print("[yellow]Нечего экспортировать.[/yellow]")
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = BB_DIR / f"history_{ts}.html"

    html = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        "<title>Scan History</title>",
        "<style>body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:24px;}h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}"
        "table{width:100%;border-collapse:collapse;margin-top:16px;font-size:13px;}"
        "th{background:#111;color:#00ff9c;padding:8px;border:1px solid #222;text-align:left;}"
        "td{padding:6px 8px;border:1px solid #222;word-break:break-all;}"
        "tr:nth-child(even){background:#0d0d0d;}"
        "pre{color:#a0ffa0;max-height:200px;overflow:auto;font-size:11px;}"
        "</style></head><body>",
        f"<h1>📜 Scan History ({len(rows)})</h1>",
        f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "<table><tr><th>ID</th><th>Module</th><th>Target</th>"
        "<th>Date</th><th>Result</th></tr>",
    ]
    for r in rows:
        result = str(r["result"])[:500]
        html.append(
            f"<tr><td>{r['id']}</td>"
            f"<td>{html_mod.escape(str(r['module']))}</td>"
            f"<td>{html_mod.escape(str(r['target']))}</td>"
            f"<td>{html_mod.escape(str(r['created_at']))}</td>"
            f"<td><pre>{html_mod.escape(result)}</pre></td></tr>"
        )
    html.append("</table></body></html>")
    try:
        path.write_text("\n".join(html), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return path
    except Exception as exc:
        console.print(f"[red]HTML: {exc}[/red]")
        return None


def export_history_markdown(module: str = "", target: str = "",
                            days: int = 0, limit: int = 500) -> Path | None:
    """Markdown-экспорт истории."""
    rows = _filter_history(db.history(limit), module, target, days)
    if not rows:
        console.print("[yellow]Нечего экспортировать.[/yellow]")
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = BB_DIR / f"history_{ts}.md"
    lines = [
        "# Scan History",
        f"_Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_",
        f"_Total: {len(rows)}_", "",
        "| ID | Module | Target | Date |",
        "|----|--------|--------|------|",
    ]
    for r in rows:
        lines.append(f"| {r['id']} | {r['module']} | {r['target']} | "
                     f"{r['created_at']} |")
    try:
        path.write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green]✓ Markdown: {path}[/green]")
        return path
    except Exception as exc:
        console.print(f"[red]Markdown: {exc}[/red]")
        return None


def show_history_stats() -> None:
    """Статистика по истории."""
    rows = db.history(1000)
    if not rows:
        console.print("[yellow]История пуста.[/yellow]")
        return
    from collections import Counter
    mods = Counter(r["module"] for r in rows)
    targets = Counter(r["target"] for r in rows)
    t = Table(title=f"📊 История ({len(rows)} сканов)")
    t.add_column("Метрика", style="cyan")
    t.add_column("Значение", style="green")
    t.add_row("Всего", str(len(rows)))
    t.add_row("Уникальных модулей", str(len(mods)))
    t.add_row("Уникальных целей", str(len(targets)))
    top_mod = mods.most_common(3)
    t.add_row("Топ модулей",
              ", ".join(f"{m}({c})" for m, c in top_mod))
    top_t = targets.most_common(3)
    t.add_row("Топ целей",
              ", ".join(f"{x[:20]}({c})" for x, c in top_t))
    console.print(t)


# ===========================================================================
# Templates (сохраняю старые функции)
# ===========================================================================

def hackerone_template() -> None:
    console.print(RichMarkdown("""
**Title:** [Vulnerability Type] in [Endpoint/Parameter]

**Summary:**
Краткое описание.

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
Конкретная рекомендация.
"""))


def bugcrowd_template() -> None:
    console.print(RichMarkdown("""
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
"""))


def intigriti_template() -> None:
    console.print(RichMarkdown("""
**Vulnerability Description:**
Краткое название.

**Detailed Description:**
Полное описание с контекстом.

**Steps to Reproduce:**
1. ...
2. ...

**Impact:**
Влияние на безопасность.

**Remediation:**
Как исправить.
"""))


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🎯 Bug Bounty Toolkit[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "CVSS v3.1 calculator (интерактивный)"),
        ("2", "CVSS из вектора"),
        ("3", "CVSS из пресета уязвимости"),
        ("4", "Generate report (MD/HTML/PDF/JSON)"),
        ("5", "Report из notes.finding (по ID)"),
        ("6", "Export history → CSV"),
        ("7", "Export history → JSON"),
        ("8", "Export history → HTML"),
        ("9", "Export history → Markdown"),
        ("10", "История — статистика"),
        ("11", "HackerOne template"),
        ("12", "Bugcrowd template"),
        ("13", "Intigriti template"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        _cvss_interactive()
    elif c == "2":
        cvss_from_vector_cli()
    elif c == "3":
        cvss_from_preset_cli()
    elif c == "4":
        generate_report()
    elif c == "5":
        fid = IntPrompt.ask("Finding ID")
        plat = Prompt.ask("Platform",
                          choices=list(PLATFORM_TEMPLATES.keys()),
                          default="hackerone")
        fmt = Prompt.ask("Format",
                         choices=["md", "html", "pdf", "json"], default="md")
        report_from_finding_cli(fid, plat, fmt)
    elif c == "6":
        m = Prompt.ask("Filter module (пусто = все)", default="")
        t_ = Prompt.ask("Filter target (пусто = все)", default="")
        d = IntPrompt.ask("Days back (0 = все)", default=0)
        export_history_csv(m, t_, d)
    elif c == "7":
        m = Prompt.ask("Filter module (пусто = все)", default="")
        t_ = Prompt.ask("Filter target (пусто = все)", default="")
        d = IntPrompt.ask("Days back (0 = все)", default=0)
        export_history_json(m, t_, d)
    elif c == "8":
        export_history_html()
    elif c == "9":
        export_history_markdown()
    elif c == "10":
        show_history_stats()
    elif c == "11":
        hackerone_template()
    elif c == "12":
        bugcrowd_template()
    elif c == "13":
        intigriti_template()


# ===========================================================================
# Совместимость с CLI
# ===========================================================================

def cli_cvss() -> None:
    """CLI: интерактивный CVSS."""
    _cvss_interactive()


def cli_report() -> None:
    """CLI: интерактивный отчёт."""
    generate_report()


def cli_cvss_from_vector(vector: str) -> None:
    """CLI: CVSS из вектора."""
    r = cvss_score_from_vector(vector)
    console.print(f"[green]Base: {r['base_score']} ({r['base_severity']})[/green]")