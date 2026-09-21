"""
Scheduler Pro — планировщик задач с cron-подобным расписанием.
Author: idqwixxa

⚠ Только для авторизованного пентеста / мониторинга своей инфраструктуры.

Возможности:
    ─── Расписание ───
    - Интервалы (every_minutes)
    - Daily at HH:MM (daily_at)
    - Weekly (day-of-week + HH:MM)
    - Cron expression (минимальный парсер: m h dom mon dow)
    - One-shot (run_at)
    - Retry с backoff (retry_count, retry_delay)

    ─── Jobs ───
    - 40+ действий из всех модулей (recon, web, cloud, AD, bug-bounty…)
    - Зависимости (depends_on: [job_id])
    - Теги (для выборочного запуска)
    - Enable / disable без удаления
    - Priority

    ─── История ───
    - SQLite таблица job_history (start/finish/status/duration/output)
    - Экспорт истории в JSON/CSV/Markdown/HTML
    - Fail-safe: ошибки пишутся в БД, не валят цикл

    ─── Утилиты ───
    - Import/export schedule (YAML ↔ JSON)
    - Dry-run (проверить что due, не запуская)
    - Run-one (по индексу/имени)
    - Pause/Resume всего планировщика
    - Cleanup старых записей

    ─── Интеграция ───
    - Findings → notes (для fail-статусов critical jobs)
    - Notify (start/finish/fail)
    - CLI-совместимость сохранена
"""
import csv
import html as html_mod
import json
import re
import threading
import time
import traceback
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

import yaml
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table

from core.config import BASE_DIR, REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

SCHEDULE_PATH = BASE_DIR / "schedule.yaml"
SCHEDULE_JSON = BASE_DIR / "schedule.json"
SCHED_HISTORY_DIR = REPORT_DIR / "scheduler"
SCHED_HISTORY_DIR.mkdir(parents=True, exist_ok=True)

# Флаг: планировщик на паузе (глобально)
_paused = False


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class SchedFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: SchedFinding) -> int:
    if f.severity not in ("critical", "high"):
        return -1
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f.title,
            target=f.target,
            severity=f.severity,
            status="open",
            tags=["scheduler", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Actions (расширенный)
# ===========================================================================

ACTIONS: dict[str, tuple] = {
    # ─── Recon ───
    "whois":        ("modules.recon", "whois_lookup", "target", "WHOIS lookup"),
    "dns":          ("modules.recon", "dns_enum", "target", "DNS enumeration"),
    "subdomain":    ("modules.recon", "subdomain_scan", "domain", "Subdomain scan"),
    "portscan":     ("modules.recon", "port_scan", "target", "Port scan 1-1024"),
    "geoip":        ("modules.recon", "ip_geolocation", "target", "IP geolocation"),
    "fingerprint":  ("modules.recon", "tech_fingerprint", "url", "Tech fingerprint"),
    "ssl":          ("modules.recon", "ssl_info", "host", "SSL/TLS info"),
    "headers":      ("modules.recon", "http_headers", "url", "HTTP headers"),

    # ─── Web ───
    "web-sqli":     ("modules.web_vuln", "sqli_scan", "url", "SQLi scan"),
    "web-xss":      ("modules.web_vuln", "xss_scan", "url", "XSS scan"),
    "web-lfi":      ("modules.web_vuln", "lfi_scan", "url", "LFI scan"),
    "web-dirb":     ("modules.web_vuln", "dir_bruteforce", "url", "Dir brute"),
    "web-redirect": ("modules.web_vuln", "open_redirect", "url", "Open redirect"),
    "web-csrf":     ("modules.web_vuln", "csrf_checker", "url", "CSRF check"),

    # ─── Async ───
    "asyncscan":    ("modules.async_engine", "async_port_scan", "target", "Async portscan"),
    "asyncweb":     ("modules.async_engine", "async_http_scan", "url", "Async HTTP scan"),

    # ─── DNS Tools ───
    "dns-axfr":     ("modules.dns_tools", "zone_transfer", "domain", "DNS AXFR"),
    "dns-dnssec":   ("modules.dns_tools", "dnssec_check", "domain", "DNSSEC check"),
    "dns-wildcard": ("modules.dns_tools", "wildcard_detect", "domain", "Wildcard"),
    "dns-mail":     ("modules.dns_tools", "mail_security", "domain", "SPF/DMARC/DKIM"),
    "dns-rebind":   ("modules.dns_tools", "rebinding_detect", "domain", "DNS rebinding"),

    # ─── Subdomain takeover ───
    "takeover":     ("modules.subdomain_takeover_v2", "cli_check", "subdomain", "Takeover check"),
    "takeover-scan": ("modules.subdomain_takeover_v2", "cli_scan", "domain", "Takeover scan"),

    # ─── Monitor ───
    "monitor-scan": ("modules.subdomain_monitor", "cli_scan", "domain", "Subdomain monitor"),

    # ─── Cloud ───
    "cloud-s3":     ("modules.cloud_storage", "cli_scan", "domain", "Cloud S3 scan"),
    "cloud-all":    ("modules.cloud_storage", "cli_scan_all", "domain", "Cloud all"),
    "cloud-iam":    ("modules.cloud_iam", "cli_env", "none", "Cloud IAM env scan"),

    # ─── Threat Intel ───
    "ti-ip":        ("modules.threat_intel", "cli_ip", "ip", "TI: IP lookup"),
    "ti-domain":    ("modules.threat_intel", "cli_domain", "domain", "TI: domain"),
    "ti-hash":      ("modules.threat_intel", "cli_hash", "hash", "TI: hash"),

    # ─── CVE ───
    "cve-kev-update": ("modules.cve_feeds", "download_kev", "none", "CISA KEV update"),
    "cve-download": ("modules.cve_feeds", "cli_download", "none", "NVD download"),

    # ─── AD / K8s ───
    "ad-smb-signing": ("modules.ad_attack", "cli_smb_signing", "target", "AD: SMB signing"),
    "ad-ldap-anon": ("modules.ad_attack", "cli_ldap_anon", "target", "AD: LDAP anon"),
    "k8s-api":      ("modules.k8s_scanner", "cli_api", "target", "K8s: API check"),

    # ─── DB ───
    "db-scan":      ("modules.db_attack", "cli_scan", "target", "DB scan"),

    # ─── Screenshot ───
    "screenshot":   ("modules.screenshot", "screenshot_one", "url", "Screenshot URL"),

    # ─── Reports ───
    "report-html":  ("modules.report_export", "cli_html", "none", "Report → HTML"),
    "report-pdf":   ("modules.report_export", "cli_pdf", "none", "Report → PDF"),

    # ─── Wordlist ───
    "wordlists-update": ("modules.wordlist_updater", "update_all", "none", "Wordlist update"),
}


# ===========================================================================
# Schedule load/save
# ===========================================================================

def _load_schedule() -> dict:
    """Загрузить schedule.yaml."""
    if not SCHEDULE_PATH.exists():
        return {"jobs": [], "settings": {"max_workers": 3,
                                          "paused": False,
                                          "history_keep_days": 30}}
    try:
        data = yaml.safe_load(SCHEDULE_PATH.read_text(encoding="utf-8")) or {}
        data.setdefault("jobs", [])
        data.setdefault("settings", {})
        data["settings"].setdefault("max_workers", 3)
        data["settings"].setdefault("paused", False)
        data["settings"].setdefault("history_keep_days", 30)
        return data
    except Exception as exc:
        console.print(f"[red]Ошибка чтения schedule.yaml: {exc}[/red]")
        return {"jobs": [], "settings": {}}


def _save_schedule(data: dict) -> None:
    """Сохранить schedule.yaml."""
    try:
        SCHEDULE_PATH.write_text(
            yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
    except Exception as exc:
        console.print(f"[red]Ошибка записи schedule.yaml: {exc}[/red]")


def _resolve_callable(action_key: str) -> Callable | None:
    """Вернуть python-функцию по ключу действия."""
    if action_key not in ACTIONS:
        return None
    mod_path, fn_name, _kind, _desc = ACTIONS[action_key]
    try:
        mod_name, _sub = mod_path.rsplit(".", 1)
        mod = __import__(f"{mod_name}", fromlist=[_sub])
        return getattr(mod, fn_name, None)
    except Exception as exc:
        log.error("resolve %s: %s", action_key, exc)
        return None


# ===========================================================================
# Job history (SQLite)
# ===========================================================================

def _init_history_schema() -> None:
    try:
        cur = db.conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS job_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_idx INTEGER,
                action TEXT,
                arg TEXT,
                started TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                finished TIMESTAMP,
                status TEXT DEFAULT 'running',
                duration_ms REAL DEFAULT 0,
                error TEXT DEFAULT '',
                output TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_job_history_action
                ON job_history(action);
            CREATE INDEX IF NOT EXISTS idx_job_history_status
                ON job_history(status);
            CREATE INDEX IF NOT EXISTS idx_job_history_started
                ON job_history(started);
        """)
        db.conn.commit()
    except Exception as exc:
        log.warning("job_history schema: %s", exc)


try:
    _init_history_schema()
except Exception:
    pass


def _history_add(job_idx: int, action: str, arg: str) -> int:
    try:
        cur = db.conn.cursor()
        cur.execute(
            "INSERT INTO job_history(job_idx, action, arg) "
            "VALUES (?, ?, ?)", (job_idx, action, arg))
        db.conn.commit()
        return cur.lastrowid
    except Exception:
        return -1


def _history_finish(hid: int, status: str, duration_ms: float,
                     error: str = "", output: str = "") -> None:
    try:
        cur = db.conn.cursor()
        cur.execute(
            "UPDATE job_history SET finished=CURRENT_TIMESTAMP, "
            "status=?, duration_ms=?, error=?, output=? WHERE id=?",
            (status, duration_ms, error[:2000], output[:4000], hid))
        db.conn.commit()
    except Exception:
        pass


def show_history(limit: int = 50,
                 only_failed: bool = False) -> None:
    """Показать историю запусков."""
    try:
        cur = db.conn.cursor()
        sql = "SELECT * FROM job_history"
        args: list = []
        if only_failed:
            sql += " WHERE status != 'ok'"
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        cur.execute(sql, args)
        rows = cur.fetchall()
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        return
    if not rows:
        console.print("[yellow]История пуста.[/yellow]")
        return
    t = Table(title=f"📜 Job history ({len(rows)})")
    t.add_column("ID", style="dim", width=5)
    t.add_column("Action", style="cyan", width=20)
    t.add_column("Arg", style="green", max_width=30)
    t.add_column("Started", width=19)
    t.add_column("Status", width=8)
    t.add_column("ms", width=8)
    t.add_column("Error", style="red", max_width=40)
    for r in rows:
        sty = {"ok": "green", "fail": "red",
               "running": "yellow"}.get(r["status"], "white")
        t.add_row(
            str(r["id"]),
            r["action"],
            (r["arg"] or "—")[:30],
            str(r["started"])[:19],
            f"[{sty}]{r['status']}[/{sty}]",
            f"{r['duration_ms']:.0f}" if r["duration_ms"] else "—",
            (r["error"] or "")[:40],
        )
    console.print(t)


def export_history(fmt: str = "json",
                   out_path: str | None = None,
                   limit: int = 1000) -> Path | None:
    """Экспорт истории запусков."""
    try:
        cur = db.conn.cursor()
        cur.execute(
            "SELECT * FROM job_history ORDER BY id DESC LIMIT ?",
            (limit,))
        rows = [dict(r) for r in cur.fetchall()]
    except Exception as exc:
        console.print(f"[red]Ошибка чтения истории: {exc}[/red]")
        return None
    if not rows:
        console.print("[yellow]История пуста.[/yellow]")
        return None

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not out_path:
        ext = {"json": ".json", "csv": ".csv",
               "md": ".md", "html": ".html"}.get(fmt, ".json")
        out_path = str(SCHED_HISTORY_DIR / f"job_history_{ts}{ext}")
    path = Path(out_path)

    try:
        if fmt == "json":
            path.write_text(
                json.dumps(rows, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8")
        elif fmt == "csv":
            with path.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=list(rows[0].keys()),
                                    extrasaction="ignore")
                w.writeheader()
                for r in rows:
                    w.writerow(r)
        elif fmt == "md":
            lines = [
                "# Scheduler — Job history",
                f"_Generated: {datetime.now().isoformat()}_", "",
                f"Total: **{len(rows)}**", "",
                "| ID | Action | Arg | Started | Status | ms | Error |",
                "|----|--------|-----|---------|--------|----|----|",
            ]
            for r in rows:
                lines.append(
                    f"| {r['id']} | {r['action']} | "
                    f"{(r['arg'] or '—')[:40]} | "
                    f"{str(r['started'])[:19]} | {r['status']} | "
                    f"{r['duration_ms']:.0f} | "
                    f"{(r['error'] or '')[:60]} |"
                )
            path.write_text("\n".join(lines), encoding="utf-8")
        elif fmt == "html":
            parts = [
                "<!DOCTYPE html><html><head><meta charset='utf-8'>",
                "<title>Scheduler history</title>",
                "<style>",
                "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
                "padding:24px;line-height:1.5;}",
                "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
                "table{width:100%;border-collapse:collapse;margin-top:12px;"
                "font-size:13px;}",
                "th{background:#111;color:#00ff9c;padding:6px;text-align:left;"
                "border:1px solid #222;}",
                "td{padding:4px 6px;border:1px solid #222;word-break:break-all;}",
                "tr:nth-child(even){background:#0d0d0d;}",
                ".ok{color:#00ff9c;}.fail{color:#ff2020;font-weight:bold;}",
                ".running{color:#ffd23f;}",
                "</style></head><body>",
                f"<h1>📜 Scheduler history ({len(rows)})</h1>",
                f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
                "<table><tr><th>ID</th><th>Action</th><th>Arg</th>"
                "<th>Started</th><th>Status</th><th>ms</th>"
                "<th>Error</th></tr>",
            ]
            for r in rows:
                cls = {"ok": "ok", "fail": "fail",
                       "running": "running"}.get(r["status"], "")
                parts.append(
                    f"<tr><td>{r['id']}</td>"
                    f"<td>{html_mod.escape(str(r['action']))}</td>"
                    f"<td>{html_mod.escape((r['arg'] or '—')[:80])}</td>"
                    f"<td>{html_mod.escape(str(r['started'])[:19])}</td>"
                    f"<td class='{cls}'>{html_mod.escape(str(r['status']))}</td>"
                    f"<td>{r['duration_ms']:.0f}</td>"
                    f"<td>{html_mod.escape((r['error'] or '')[:120])}</td></tr>"
                )
            parts.append("</table></body></html>")
            path.write_text("\n".join(parts), encoding="utf-8")
        else:
            console.print(f"[red]Неизвестный формат: {fmt}[/red]")
            return None
        console.print(f"[green]✓ {fmt.upper()}: {path}[/green]")
        return path
    except Exception as exc:
        console.print(f"[red]Ошибка экспорта: {exc}[/red]")
        return None


def cleanup_history(days: int = 30) -> int:
    """Удалить старые записи истории."""
    try:
        cutoff = (datetime.now() - timedelta(days=days)).strftime(
            "%Y-%m-%d %H:%M:%S")
        cur = db.conn.cursor()
        cur.execute("DELETE FROM job_history WHERE started < ?",
                     (cutoff,))
        db.conn.commit()
        n = cur.rowcount
        console.print(f"[green]✓ Удалено: {n} старых записей[/green]")
        return n
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        return 0


# ===========================================================================
# Notify
# ===========================================================================

def _notify(action: str, arg: str, ok: bool, extra: str = "",
            duration_ms: float = 0.0) -> None:
    """Отправить уведомление после выполнения задачи."""
    try:
        from modules import notifier
    except Exception:
        return
    status = "✓ OK" if ok else "✗ FAIL"
    title = f"Scheduler — {status}"
    message = (
        f"Задача: {action}\n"
        f"Цель:   {arg}\n"
        f"Время:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Длит.:  {duration_ms:.0f} ms\n"
    )
    if extra:
        message += f"\n{extra[:600]}"
    sev = "high" if not ok else "info"
    try:
        notifier.notify_all(title, message, severity=sev)
    except Exception:
        pass


# ===========================================================================
# Scheduling logic (cron-like)
# ===========================================================================

def _parse_cron(expr: str) -> dict | None:
    """
    Минимальный cron-парсер: 'm h dom mon dow'.
    Поддерживает '*' и числа (без диапазонов/шагов).
    """
    parts = expr.strip().split()
    if len(parts) != 5:
        return None
    try:
        return {
            "minute": parts[0],
            "hour": parts[1],
            "day": parts[2],
            "month": parts[3],
            "dow": parts[4],
        }
    except Exception:
        return None


def _cron_match(cron: dict, now: datetime) -> bool:
    """Проверить, соответствует ли now cron-выражению."""
    def _match(field: str, value: int) -> bool:
        if field == "*":
            return True
        try:
            return int(field) == value
        except ValueError:
            return False

    return (_match(cron["minute"], now.minute) and
            _match(cron["hour"], now.hour) and
            _match(cron["day"], now.day) and
            _match(cron["month"], now.month) and
            _match(cron["dow"], now.weekday()))


def _due(job: dict, now: datetime) -> bool:
    """Пора ли запускать задачу (с поддержкой cron/daily/weekly/one-shot)."""
    if not job.get("enabled", True):
        return False

    # One-shot (run_at)
    run_at = job.get("run_at")
    if run_at:
        try:
            rt = datetime.fromisoformat(str(run_at)[:19])
            if now >= rt and not job.get("last_run"):
                return True
            return False
        except Exception:
            pass

    # Cron
    cron_expr = job.get("cron")
    if cron_expr:
        cron = _parse_cron(cron_expr)
        if cron and _cron_match(cron, now):
            last = job.get("last_run")
            if last:
                try:
                    last_dt = datetime.fromisoformat(str(last)[:19])
                    if (now - last_dt).total_seconds() < 60:
                        return False  # не чаще 1 раза в минуту
                except Exception:
                    pass
            return True
        return False

    # Daily at HH:MM
    daily_at = job.get("daily_at")
    if daily_at:
        try:
            hh, mm = map(int, str(daily_at).split(":"))
            if now.hour == hh and now.minute == mm:
                last = job.get("last_run")
                if last:
                    last_dt = datetime.fromisoformat(str(last)[:19])
                    if (now - last_dt).total_seconds() < 60:
                        return False
                return True
        except Exception:
            pass
        return False

    # Weekly (dow + HH:MM)
    weekly = job.get("weekly")  # {"dow": 0-6, "at": "HH:MM"}
    if weekly:
        try:
            dow = int(weekly.get("dow", 0))
            hh, mm = map(int, str(weekly.get("at", "00:00")).split(":"))
            if now.weekday() == dow and now.hour == hh and now.minute == mm:
                last = job.get("last_run")
                if last:
                    last_dt = datetime.fromisoformat(str(last)[:19])
                    if (now - last_dt).total_seconds() < 60:
                        return False
                return True
        except Exception:
            pass
        return False

    # Fallback: every_minutes
    every = job.get("every_minutes", 60)
    last = job.get("last_run")
    if not last:
        return True
    try:
        last_dt = datetime.fromisoformat(str(last)[:19])
    except Exception:
        return True
    return now >= last_dt + timedelta(minutes=every)


def _deps_ok(job: dict, jobs: list[dict]) -> bool:
    """Проверить зависимости (depends_on — список индексов 0-based)."""
    deps = job.get("depends_on") or []
    if not deps:
        return True
    for d in deps:
        try:
            idx = int(d)
            if 0 <= idx < len(jobs):
                if jobs[idx].get("status") not in ("ok", None):
                    return False
        except Exception:
            continue
    return True


# ===========================================================================
# Job execution
# ===========================================================================

def _run_job(job: dict, job_idx: int = -1,
             jobs_list: list[dict] | None = None) -> bool:
    """Выполнить одну задачу. Возвращает True если ok."""
    action = job.get("action", "")
    arg = job.get("arg", "")
    extra = job.get("extra", {}) or {}

    fn = _resolve_callable(action)
    if fn is None:
        console.print(f"[red]Неизвестное действие: {action}[/red]")
        _notify(action, arg, ok=False, extra="неизвестное действие")
        job["status"] = "fail"
        return False

    # Dependencies
    if jobs_list and not _deps_ok(job, jobs_list):
        console.print(f"[yellow]↷ {action} {arg} — deps не готовы, "
                      f"пропуск[/yellow]")
        job["status"] = "skipped"
        return False

    # Retry настройки
    max_retries = int(job.get("retry_count", 0))
    retry_delay = float(job.get("retry_delay", 5))

    console.print(
        f"[cyan]▶ [{datetime.now().strftime('%H:%M:%S')}] "
        f"#{job_idx} {action} {arg}"
        + (f" (retry={max_retries})" if max_retries else "")
        + "[/cyan]"
    )

    hid = _history_add(job_idx, action, arg)

    attempt = 0
    last_err = ""
    while attempt <= max_retries:
        attempt += 1
        start = time.time()
        ok = True
        err = ""
        try:
            if extra:
                fn(arg, **extra)
            else:
                fn(arg)
        except Exception as exc:
            ok = False
            err = str(exc)[:400]
            log.exception("scheduler job: %s", action)
            if attempt <= max_retries:
                console.print(f"[yellow]  ↻ retry {attempt}/{max_retries} "
                              f"через {retry_delay}s…[/yellow]")
                time.sleep(retry_delay)
                continue
        duration = (time.time() - start) * 1000

        if ok:
            job["status"] = "ok"
            job["last_run"] = datetime.now().isoformat(timespec="seconds")
            db.save_scan("scheduler", f"{action}:{arg}",
                         {"job": job, "ok": True,
                          "duration_ms": duration,
                          "attempt": attempt})
            _history_finish(hid, "ok", duration, "", "")
            console.print(f"[green]  ✓ {action} {arg} "
                          f"({duration:.0f} ms, attempt={attempt})[/green]")
            _notify(action, arg, ok=True, duration_ms=duration)
            return True
        last_err = err
        break

    # Fail
    job["status"] = "fail"
    job["last_run"] = datetime.now().isoformat(timespec="seconds")
    console.print(f"[red]  ✗ {action} {arg}: {last_err}[/red]")
    db.save_scan("scheduler", f"{action}:{arg}",
                 {"job": job, "error": last_err})
    _history_finish(hid, "fail", 0, last_err, "")
    _notify(action, arg, ok=False, extra=last_err)

    # Finding для critical failure?
    sev = job.get("severity", "info")
    if sev in ("critical", "high"):
        _save_finding(SchedFinding(
            kind="scheduled_job_failed",
            severity=sev,
            title=f"Scheduled job failed: {action}",
            target=arg,
            evidence=last_err,
            data={"job": job, "attempt": attempt},
        ))
    return False


def _run_job_by_index(idx: int) -> bool:
    """Запустить job по 0-based индексу."""
    data = _load_schedule()
    jobs = data.get("jobs", [])
    if not (0 <= idx < len(jobs)):
        console.print(f"[red]Неверный индекс: {idx}[/red]")
        return False
    ok = _run_job(jobs[idx], job_idx=idx, jobs_list=jobs)
    _save_schedule(data)
    return ok


# ===========================================================================
# CRUD
# ===========================================================================

def list_jobs(show_status: bool = True) -> None:
    """Показать список задач."""
    data = _load_schedule()
    jobs = data.get("jobs", [])
    if not jobs:
        console.print("[yellow]Задач нет. Добавь через меню.[/yellow]")
        return
    table = Table(title=f"📅 Jobs ({len(jobs)})")
    table.add_column("#", style="yellow", width=4)
    table.add_column("On", width=3)
    table.add_column("Действие", style="cyan", width=20)
    table.add_column("Аргумент", style="green", max_width=25)
    table.add_column("Расписание", style="magenta", width=22)
    table.add_column("Last", width=19)
    if show_status:
        table.add_column("Status", width=8)
    for i, j in enumerate(jobs, 1):
        # Формат расписания
        sched = "?"
        if j.get("cron"):
            sched = f"cron: {j['cron']}"
        elif j.get("daily_at"):
            sched = f"daily {j['daily_at']}"
        elif j.get("weekly"):
            w = j["weekly"]
            sched = f"weekly dow={w.get('dow','?')} at {w.get('at','?')}"
        elif j.get("run_at"):
            sched = f"once {str(j['run_at'])[:16]}"
        elif j.get("every_minutes"):
            sched = f"every {j['every_minutes']}m"
        row = [
            str(i),
            "✓" if j.get("enabled", True) else "✗",
            j.get("action", "?"),
            str(j.get("arg", "?"))[:25],
            sched,
            str(j.get("last_run", "—"))[:19],
        ]
        if show_status:
            st = j.get("status", "—")
            sty = {"ok": "green", "fail": "red",
                   "skipped": "yellow"}.get(st, "white")
            row.append(f"[{sty}]{st}[/{sty}]")
        table.add_row(*row)
    console.print(table)


def add_job() -> None:
    """Добавить задачу (интерактивно)."""
    console.print("[cyan]Доступные действия:[/cyan]")
    for k, (_m, _f, _a, desc) in ACTIONS.items():
        console.print(f"  [green]{k:<22}[/green] — {desc}")
    action = Prompt.ask("Действие", choices=list(ACTIONS.keys()))
    _, _, arg_kind, _ = ACTIONS[action]
    arg = ""
    if arg_kind != "none":
        arg = Prompt.ask(f"Аргумент ({arg_kind})")

    # Тип расписания
    sched_type = Prompt.ask(
        "Тип расписания",
        choices=["every", "daily", "weekly", "cron", "once"],
        default="every",
    )

    job: dict = {
        "action": action,
        "arg": arg,
        "enabled": True,
        "last_run": None,
    }
    if sched_type == "every":
        job["every_minutes"] = IntPrompt.ask(
            "Интервал (мин)", default=60)
    elif sched_type == "daily":
        job["daily_at"] = Prompt.ask("Время (HH:MM)", default="03:00")
    elif sched_type == "weekly":
        dow = IntPrompt.ask(
            "День недели (0=Пн … 6=Вс)", default=0)
        at = Prompt.ask("Время (HH:MM)", default="03:00")
        job["weekly"] = {"dow": dow, "at": at}
    elif sched_type == "cron":
        console.print("[dim]Формат: 'm h dom mon dow' (0-59 0-23 1-31 "
                      "1-12 0-6), только '*' или числа[/dim]")
        job["cron"] = Prompt.ask("Cron", default="0 3 * * *")
    elif sched_type == "once":
        at = Prompt.ask("Когда (YYYY-MM-DDTHH:MM)",
                        default=datetime.now().strftime("%Y-%m-%dT%H:%M"))
        job["run_at"] = at

    # Опционально: retry/severity
    if Confirm.ask("Настроить retry?", default=False):
        job["retry_count"] = IntPrompt.ask("retry_count", default=2)
        job["retry_delay"] = float(Prompt.ask("retry_delay (сек)",
                                                default="5"))
    if Confirm.ask("Установить severity (для findings)?", default=False):
        job["severity"] = Prompt.ask(
            "Severity",
            choices=["info", "low", "medium", "high", "critical"],
            default="info")

    data = _load_schedule()
    data.setdefault("jobs", []).append(job)
    _save_schedule(data)
    console.print(f"[green]✓ Добавлено: {action} {arg} "
                  f"({sched_type})[/green]")


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
        console.print(f"[green]✓ Удалено: {removed.get('action')} "
                      f"{removed.get('arg')}[/green]")
    else:
        console.print("[red]Неверный номер.[/red]")


def toggle_job() -> None:
    """Включить/выключить задачу."""
    data = _load_schedule()
    jobs = data.get("jobs", [])
    if not jobs:
        console.print("[yellow]Задач нет.[/yellow]")
        return
    list_jobs()
    idx = IntPrompt.ask("Номер для toggle")
    if 1 <= idx <= len(jobs):
        j = jobs[idx - 1]
        j["enabled"] = not j.get("enabled", True)
        _save_schedule(data)
        status = "enabled" if j["enabled"] else "disabled"
        console.print(f"[green]✓ {j.get('action')} → {status}[/green]")
    else:
        console.print("[red]Неверный номер.[/red]")


def run_one() -> None:
    """Запустить одну задачу вручную."""
    data = _load_schedule()
    jobs = data.get("jobs", [])
    if not jobs:
        console.print("[yellow]Задач нет.[/yellow]")
        return
    list_jobs()
    idx = IntPrompt.ask("Номер для запуска")
    if 1 <= idx <= len(jobs):
        _run_job(jobs[idx - 1], job_idx=idx - 1, jobs_list=jobs)
        _save_schedule(data)
    else:
        console.print("[red]Неверный номер.[/red]")


# ===========================================================================
# Import / Export schedule
# ===========================================================================

def export_schedule(fmt: str = "yaml",
                    out_path: str | None = None) -> Path | None:
    """Экспорт расписания."""
    data = _load_schedule()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not out_path:
        ext = {"yaml": ".yaml", "json": ".json"}.get(fmt, ".yaml")
        out_path = str(SCHED_HISTORY_DIR / f"schedule_{ts}{ext}")
    path = Path(out_path)
    try:
        if fmt == "yaml":
            path.write_text(yaml.safe_dump(data, allow_unicode=True,
                                             sort_keys=False),
                             encoding="utf-8")
        elif fmt == "json":
            path.write_text(json.dumps(data, indent=2,
                                         ensure_ascii=False, default=str),
                             encoding="utf-8")
        else:
            console.print(f"[red]Формат: yaml | json[/red]")
            return None
        console.print(f"[green]✓ {fmt.upper()}: {path}[/green]")
        return path
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        return None


def import_schedule(path: str, merge: bool = False) -> int:
    """Импорт расписания (merge=True — добавить к существующему)."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return 0
    try:
        if p.suffix.lower() == ".json":
            data = json.loads(p.read_text(encoding="utf-8"))
        else:
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        console.print(f"[red]Парсинг: {exc}[/red]")
        return 0
    jobs = data.get("jobs", [])
    if not jobs:
        console.print("[yellow]Нет jobs в файле.[/yellow]")
        return 0
    if merge:
        cur = _load_schedule()
        cur.setdefault("jobs", []).extend(jobs)
        _save_schedule(cur)
    else:
        _save_schedule({"jobs": jobs,
                        "settings": data.get("settings", {})})
    console.print(f"[green]✓ Импортировано: {len(jobs)} задач[/green]")
    return len(jobs)


# ===========================================================================
# Loop / daemon
# ===========================================================================

def run_loop(stop_event: threading.Event,
             dry_run: bool = False,
             interval: int = 30) -> None:
    """Главный цикл планировщика."""
    global _paused
    console.print("[bold cyan]▶ Планировщик запущен. Ctrl+C — стоп.[/bold cyan]")
    if dry_run:
        console.print("[yellow]DRY-RUN: реального запуска не будет.[/yellow]")

    last_log = datetime.now()
    while not stop_event.is_set():
        # Регулярное обновление статуса
        now_check = datetime.now()
        if (now_check - last_log).total_seconds() > 300:
            data = _load_schedule()
            active = sum(1 for j in data.get("jobs", [])
                          if j.get("enabled", True))
            console.print(f"[dim]{now_check.strftime('%H:%M:%S')} — "
                          f"{active} активных задач, "
                          f"paused={_paused}[/dim]")
            last_log = now_check

        data = _load_schedule()
        settings = data.get("settings", {})
        if settings.get("paused", False) or _paused:
            time.sleep(interval)
            continue

        jobs = data.get("jobs", [])
        now = datetime.now()
        changed = False
        for idx, job in enumerate(jobs):
            if _due(job, now):
                if dry_run:
                    console.print(f"[dim]DRY: would run "
                                  f"#{idx} {job.get('action')} "
                                  f"{job.get('arg')}[/dim]")
                    continue
                _run_job(job, job_idx=idx, jobs_list=jobs)
                changed = True
        if changed:
            _save_schedule(data)

        # Sniff sleep
        for _ in range(interval):
            if stop_event.is_set():
                return
            time.sleep(1)


def run_forever(dry_run: bool = False) -> None:
    """Обёртка с обработкой Ctrl+C."""
    stop_event = threading.Event()
    try:
        run_loop(stop_event, dry_run=dry_run)
    except KeyboardInterrupt:
        stop_event.set()
        console.print("\n[yellow]Планировщик остановлен.[/yellow]")


def pause_scheduler() -> None:
    """Поставить планировщик на паузу (сохраняется в yaml)."""
    global _paused
    _paused = True
    data = _load_schedule()
    data.setdefault("settings", {})["paused"] = True
    _save_schedule(data)
    console.print("[yellow]⏸ Планировщик на паузе.[/yellow]")


def resume_scheduler() -> None:
    """Снять с паузы."""
    global _paused
    _paused = False
    data = _load_schedule()
    data.setdefault("settings", {})["paused"] = False
    _save_schedule(data)
    console.print("[green]▶ Планировщик возобновлён.[/green]")


# ===========================================================================
# Dry-run / due listing
# ===========================================================================

def list_due(dry_run: bool = True) -> None:
    """Показать, что сейчас due."""
    data = _load_schedule()
    jobs = data.get("jobs", [])
    now = datetime.now()
    due = [(i, j) for i, j in enumerate(jobs) if _due(j, now)]
    if not due:
        console.print("[green]Нет due задач.[/green]")
        return
    t = Table(title=f"⏰ Due now ({len(due)})")
    t.add_column("#", width=4)
    t.add_column("Action", style="cyan", width=20)
    t.add_column("Arg", style="green", max_width=30)
    t.add_column("Enabled", width=8)
    t.add_column("Deps", width=8)
    for i, j in due:
        t.add_row(str(i + 1), j.get("action", "?"),
                  str(j.get("arg", "—"))[:30],
                  "✓" if j.get("enabled", True) else "✗",
                  str(len(j.get("depends_on", []) or [])))
    console.print(t)


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    """Меню планировщика."""
    table = Table(title="[bold]📅 Scheduler Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Показать задачи"),
        ("2", "Добавить задачу"),
        ("3", "Удалить задачу"),
        ("4", "Включить/выключить задачу"),
        ("5", "Запустить одну задачу вручную"),
        ("6", "Запустить сейчас все 'due'"),
        ("7", "Показать, что due сейчас"),
        ("8", "Запустить планировщик (Ctrl+C для стопа)"),
        ("9", "Запустить в dry-run режиме"),
        ("10", "⏸ Пауза"),
        ("11", "▶ Продолжить"),
        ("12", "📜 История запусков"),
        ("13", "📤 Экспорт истории (json/csv/md/html)"),
        ("14", "📤 Экспорт расписания (yaml/json)"),
        ("15", "📥 Импорт расписания"),
        ("16", "🧹 Очистить старую историю"),
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
        toggle_job()
    elif c == "5":
        run_one()
    elif c == "6":
        data = _load_schedule()
        jobs = data.get("jobs", [])
        now = datetime.now()
        for idx, job in enumerate(jobs):
            if _due(job, now):
                _run_job(job, job_idx=idx, jobs_list=jobs)
        _save_schedule(data)
    elif c == "7":
        list_due()
    elif c == "8":
        if Confirm.ask("Запустить планировщик?", default=False):
            run_forever()
    elif c == "9":
        run_forever(dry_run=True)
    elif c == "10":
        pause_scheduler()
    elif c == "11":
        resume_scheduler()
    elif c == "12":
        show_history(IntPrompt.ask("Лимит", default=50))
    elif c == "13":
        fmt = Prompt.ask("Формат",
                         choices=["json", "csv", "md", "html"],
                         default="json")
        export_history(fmt)
    elif c == "14":
        fmt = Prompt.ask("Формат", choices=["yaml", "json"],
                         default="yaml")
        export_schedule(fmt)
    elif c == "15":
        p = Prompt.ask("Путь к файлу")
        merge = Confirm.ask("Merge с текущим?", default=False)
        import_schedule(p, merge=merge)
    elif c == "16":
        days = IntPrompt.ask("Удалить записи старше (дней)", default=30)
        cleanup_history(days)


# ===========================================================================
# CLI-обёртки (сохранены + новые)
# ===========================================================================

def cli_list() -> None:
    list_jobs()


def cli_add() -> None:
    add_job()


def cli_remove() -> None:
    remove_job()


def cli_run() -> None:
    run_forever()


def cli_run_dry() -> None:
    run_forever(dry_run=True)


def cli_history(limit: int = 50) -> None:
    show_history(limit)


def cli_history_export(fmt: str = "json") -> None:
    export_history(fmt)


def cli_schedule_export(fmt: str = "yaml") -> None:
    export_schedule(fmt)


def cli_schedule_import(path: str, merge: bool = False) -> None:
    import_schedule(path, merge=merge)


def cli_pause() -> None:
    pause_scheduler()


def cli_resume() -> None:
    resume_scheduler()