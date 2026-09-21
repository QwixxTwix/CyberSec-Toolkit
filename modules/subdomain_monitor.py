"""
Subdomain Monitoring Suite (Pro).
Author: idqwixxa

⚠ Только для этичного использования / bug bounty.

Возможности:
    ─── Watch-list ───
    - SQLite watch-list с интервалами, тегами, enabled/paused
    - Bulk-import из файла
    - Статистика по домену (change frequency, stability score)

    ─── Scanning (много источников) ───
    - Wordlist brute (custom + builtin)
    - crt.sh (Certificate Transparency)
    - Wayback Machine (CDX API)
    - AXFR (zone transfer на NS)
    - DNS resolver tricks (NSEC walking — если удастся)
    - Permutations (dev-www, www-dev, etc.)

    ─── Diff (расширенный) ───
    - new / disappeared / unchanged
    - Changed IP (тот же FQDN → другой IP)
    - Changed CNAME
    - Takeover-кандидаты (dangling CNAME)

    ─── Интеграция ───
    - Findings → notes (new subs / takeover candidates)
    - Notify (Telegram/Discord/Email)
    - Экспорт: JSON / CSV / Markdown / HTML (с diff-таблицами)

    ─── Daemon / Scheduler ───
    - Простой daemon-режим
    - Интеграция с core.scheduler (если доступен)
"""
import csv
import html as html_mod
import json
import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from core.config import config, WORDLIST_DIR, REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, extract_host

console = Console()
log = get_logger(__name__)

MON_DIR = REPORT_DIR / "monitor"
MON_DIR.mkdir(parents=True, exist_ok=True)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

UA = "Mozilla/5.0 (compatible; CyberSecToolkit/1.0)"


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class MonFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: MonFinding) -> int:
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
            tags=["monitor", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Схема
# ===========================================================================

def _init_schema() -> None:
    try:
        cur = db.conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS monitor_targets (
                domain TEXT PRIMARY KEY,
                enabled INTEGER DEFAULT 1,
                interval_min INTEGER DEFAULT 360,
                last_scan TIMESTAMP,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT DEFAULT '',
                tags TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS monitor_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                sub_count INTEGER,
                subdomains TEXT,
                source TEXT DEFAULT 'scan',
                meta TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_snap_domain_ts
                ON monitor_snapshots(domain, ts);
        """)
        db.conn.commit()
        # add columns if missing (migration)
        try:
            cur.execute("PRAGMA table_info(monitor_targets)")
            cols = {r[1] for r in cur.fetchall()}
            if "tags" not in cols:
                cur.execute("ALTER TABLE monitor_targets "
                            "ADD COLUMN tags TEXT DEFAULT ''")
            cur.execute("PRAGMA table_info(monitor_snapshots)")
            cols = {r[1] for r in cur.fetchall()}
            if "meta" not in cols:
                cur.execute("ALTER TABLE monitor_snapshots "
                            "ADD COLUMN meta TEXT DEFAULT ''")
            db.conn.commit()
        except Exception:
            pass
    except Exception as exc:  # noqa: BLE001
        log.warning("monitor schema: %s", exc)


try:
    _init_schema()
except Exception:
    pass


# ===========================================================================
# Модель
# ===========================================================================

@dataclass
class DiffResult:
    domain: str
    ts: str
    prev_ts: str = ""
    new: list[str] = field(default_factory=list)
    disappeared: list[str] = field(default_factory=list)
    changed_ip: list[dict] = field(default_factory=list)
    unchanged_count: int = 0
    total: int = 0
    takeover: list[str] = field(default_factory=list)
    sources: dict = field(default_factory=dict)


# ===========================================================================
# Резолв
# ===========================================================================

def _resolve(fqdn: str, timeout: float = 3.0) -> str | None:
    """Резолв fqdn → IP."""
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(fqdn)
    except Exception:
        return None


def _resolve_cname(fqdn: str, timeout: float = 3.0) -> str:
    """Попытаться получить CNAME."""
    try:
        import dns.resolver
        try:
            ans = dns.resolver.resolve(fqdn, "CNAME", lifetime=timeout)
            return str(ans[0].target).rstrip(".")
        except Exception:
            return ""
    except ImportError:
        return ""


def _resolve_many(fqdns: list[str], threads: int = 30) -> dict[str, str]:
    """Резолв списка FQDN → {fqdn: ip}."""
    out: dict[str, str] = {}
    if not fqdns:
        return out

    def _one(f: str) -> tuple[str, str | None]:
        return f, _resolve(f)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_one, f): f for f in fqdns}
        for fut in as_completed(futs):
            try:
                f, ip = fut.result()
                if ip:
                    out[f] = ip
            except Exception:
                continue
    return out


# ===========================================================================
# Источники
# ===========================================================================

def _source_wordlist(domain: str, wordlist: str,
                     threads: int) -> set[str]:
    """Wordlist brute."""
    wl_path = WORDLIST_DIR / wordlist
    if wl_path.exists():
        try:
            words = [w.strip() for w in wl_path.read_text(
                encoding="utf-8", errors="ignore").splitlines()
                if w.strip() and not w.startswith("#")]
        except Exception:
            words = []
    else:
        words = []
    if not words:
        words = [
            "www", "mail", "ftp", "webmail", "smtp", "pop", "imap",
            "ns1", "ns2", "dns", "admin", "api", "app", "dev", "test",
            "stage", "staging", "prod", "beta", "demo", "portal",
            "login", "auth", "sso", "shop", "store", "blog", "news",
            "support", "help", "docs", "wiki", "static", "assets",
            "cdn", "media", "img", "images", "video", "m", "mobile",
            "old", "backup", "temp", "monitor", "status", "health",
            "metrics", "grafana", "jenkins", "ci", "cd", "git",
            "gitlab", "jira", "vpn", "remote", "rdp", "s3", "storage",
            "files", "gateway", "proxy", "internal", "intranet",
        ]
    subs = [f"{w}.{domain}" for w in words]
    subs.append(domain)
    resolved = _resolve_many(subs, threads)
    return set(resolved.keys())


def _source_crtsh(domain: str) -> set[str]:
    """crt.sh Certificate Transparency."""
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=20, headers={"User-Agent": UA})
        if r.status_code != 200:
            return set()
        try:
            data = r.json()
        except Exception:
            return set()
        out: set[str] = set()
        for entry in data:
            name = entry.get("name_value", "")
            for n in str(name).split("\n"):
                n = n.strip().lower()
                if n and "*" not in n and n.endswith(domain):
                    out.add(n)
        return out
    except Exception as exc:
        log.debug("crtsh: %s", exc)
        return set()


def _source_wayback(domain: str) -> set[str]:
    """Wayback Machine CDX API."""
    try:
        r = requests.get(
            "http://web.archive.org/cdx/search/cdx",
            params={"url": f"*.{domain}/*", "output": "json",
                    "fl": "original", "collapse": "urlkey",
                    "limit": "5000"},
            timeout=30, headers={"User-Agent": UA})
        if r.status_code != 200:
            return set()
        try:
            rows = r.json()
        except Exception:
            return set()
        out: set[str] = set()
        for row in rows[1:]:
            if not row:
                continue
            url = row[0]
            try:
                from urllib.parse import urlparse
                host = urlparse(url).hostname or ""
                host = host.lower()
                if host.endswith(domain) and "*" not in host:
                    out.add(host)
            except Exception:
                continue
        return out
    except Exception as exc:
        log.debug("wayback: %s", exc)
        return set()


def _source_axfr(domain: str) -> set[str]:
    """AXFR через NS — если разрешён."""
    try:
        import dns.resolver
        import dns.query
        import dns.zone
        try:
            ns_ans = dns.resolver.resolve(domain, "NS", lifetime=5)
            ns_list = [str(r.target).rstrip(".") for r in ns_ans]
        except Exception:
            return set()
        found: set[str] = set()
        for ns in ns_list[:3]:
            try:
                ns_ip = socket.gethostbyname(ns)
            except Exception:
                continue
            try:
                z = dns.zone.from_xfr(
                    dns.query.xfr(ns_ip, domain, timeout=10))
                for name in z.nodes.keys():
                    fqdn = str(name).rstrip(".")
                    if fqdn == "@":
                        fqdn = domain
                    if fqdn.endswith(domain):
                        found.add(fqdn)
            except Exception:
                continue
        return found
    except ImportError:
        return set()


def _source_permutations(known: set[str], domain: str) -> set[str]:
    """Генерация permutations из уже известных."""
    out: set[str] = set()
    prefixes = ["dev-", "stg-", "test-", "prod-", "old-", "new-",
                "beta-", "v2-", "internal-", "ext-"]
    suffixes = ["-dev", "-stg", "-test", "-prod", "-old", "-new",
                "-v2", "-internal"]
    for fqdn in list(known)[:200]:
        if not fqdn.endswith("." + domain):
            continue
        base = fqdn[:-(len(domain) + 1)]
        for p in prefixes:
            out.add(f"{p}{base}.{domain}")
        for s in suffixes:
            out.add(f"{base}{s}.{domain}")
    out.discard(domain)
    return out


# ===========================================================================
# Сканирование
# ===========================================================================

def _quick_scan(domain: str, wordlist: str = "subdomains.txt",
                threads: int = 30,
                sources: list[str] | None = None,
                extra_permutations: bool = False) -> set[str]:
    """
    Быстрый скан поддоменов из нескольких источников.
    """
    if sources is None:
        sources = ["wordlist", "crtsh", "wayback"]

    console.print(f"[cyan]  → источники: {', '.join(sources)}[/cyan]")
    found: set[str] = set()

    if "wordlist" in sources:
        try:
            wl_found = _source_wordlist(domain, wordlist, threads)
            console.print(f"    [dim]wordlist: {len(wl_found)}[/dim]")
            found |= wl_found
        except Exception as exc:
            log.debug("wordlist: %s", exc)

    if "crtsh" in sources:
        try:
            crt = _source_crtsh(domain)
            console.print(f"    [dim]crtsh: {len(crt)}[/dim]")
            found |= crt
        except Exception as exc:
            log.debug("crtsh: %s", exc)

    if "wayback" in sources:
        try:
            wb = _source_wayback(domain)
            console.print(f"    [dim]wayback: {len(wb)}[/dim]")
            found |= wb
        except Exception as exc:
            log.debug("wayback: %s", exc)

    if "axfr" in sources:
        try:
            ax = _source_axfr(domain)
            console.print(f"    [dim]axfr: {len(ax)}[/dim]")
            found |= ax
        except Exception as exc:
            log.debug("axfr: %s", exc)

    if extra_permutations and found:
        try:
            perm = _source_permutations(found, domain)
            # Резолвим только те, что ещё не проверены
            to_check = [p for p in perm if p not in found]
            resolved = _resolve_many(to_check[:500], threads)
            console.print(f"    [dim]permutations: {len(resolved)}[/dim]")
            found |= set(resolved.keys())
        except Exception as exc:
            log.debug("permutations: %s", exc)

    found = {f.lower().strip(".") for f in found if f}
    return found


# ===========================================================================
# Snapshots
# ===========================================================================

def _save_snapshot(domain: str, subs: set[str],
                   source: str = "scan",
                   meta: dict | None = None) -> int:
    try:
        cur = db.conn.cursor()
        cur.execute(
            "INSERT INTO monitor_snapshots(domain, sub_count, subdomains, "
            "source, meta) VALUES (?, ?, ?, ?, ?)",
            (domain, len(subs),
             json.dumps(sorted(subs), ensure_ascii=False),
             source,
             json.dumps(meta or {}, ensure_ascii=False)),
        )
        db.conn.commit()
        return cur.lastrowid
    except Exception as exc:  # noqa: BLE001
        log.warning("snapshot save: %s", exc)
        return -1


def _get_last_snapshot(domain: str) -> tuple[str, set[str]] | None:
    """Вернуть (ts, subs) предыдущего снапшота."""
    try:
        cur = db.conn.cursor()
        cur.execute(
            "SELECT ts, subdomains FROM monitor_snapshots "
            "WHERE domain=? ORDER BY id DESC LIMIT 2",
            (domain,),
        )
        rows = cur.fetchall()
        if len(rows) < 2:
            return None
        prev = rows[1]
        return (str(prev["ts"]),
                set(json.loads(prev["subdomains"])))
    except Exception as exc:  # noqa: BLE001
        log.warning("get_last: %s", exc)
        return None


# ===========================================================================
# Diff
# ===========================================================================

def _diff(domain: str, current: set[str],
          prev: set[str] | None, prev_ts: str = "",
          prev_ips: dict[str, str] | None = None,
          cur_ips: dict[str, str] | None = None) -> DiffResult:
    r = DiffResult(
        domain=domain,
        ts=datetime.now().isoformat(timespec="seconds"),
        prev_ts=prev_ts,
        total=len(current),
    )
    if prev is None:
        r.new = sorted(current)
        return r
    r.new = sorted(current - prev)
    r.disappeared = sorted(prev - current)
    r.unchanged_count = len(current & prev)

    # Changed IP
    if prev_ips and cur_ips:
        changed: list[dict] = []
        for fqdn in (current & prev):
            old_ip = prev_ips.get(fqdn)
            new_ip = cur_ips.get(fqdn)
            if old_ip and new_ip and old_ip != new_ip:
                changed.append({
                    "fqdn": fqdn, "old_ip": old_ip, "new_ip": new_ip,
                })
        r.changed_ip = changed
    return r


def _print_diff(d: DiffResult) -> None:
    if not d.prev_ts:
        console.print(f"[cyan]Первый скан для {d.domain} — "
                      f"{len(d.new)} поддоменов[/cyan]")
        return

    console.print(f"\n[bold cyan]═══ DIFF: {d.domain} ═══[/bold cyan]")
    console.print(f"[dim]prev: {d.prev_ts}[/dim]")
    console.print(f"[dim]now:  {d.ts}[/dim]\n")

    if d.new:
        table = Table(title=f"🆕 НОВЫЕ ({len(d.new)})",
                      border_style="green")
        table.add_column("#", width=4)
        table.add_column("Subdomain", style="green")
        for i, s in enumerate(d.new, 1):
            table.add_row(str(i), s)
        console.print(table)
    else:
        console.print("[dim]Новых нет.[/dim]")

    if d.disappeared:
        table = Table(title=f"💨 ИСЧЕЗЛИ ({len(d.disappeared)})",
                      border_style="red")
        table.add_column("#", width=4)
        table.add_column("Subdomain", style="red")
        for i, s in enumerate(d.disappeared, 1):
            table.add_row(str(i), s)
        console.print(table)

    if d.changed_ip:
        table = Table(title=f"🔀 СМЕНИЛИ IP ({len(d.changed_ip)})",
                      border_style="yellow")
        table.add_column("Subdomain", style="cyan")
        table.add_column("Было", style="dim")
        table.add_column("Стало", style="yellow")
        for c in d.changed_ip:
            table.add_row(c["fqdn"], c["old_ip"], c["new_ip"])
        console.print(table)

    console.print(f"[dim]Без изменений: {d.unchanged_count} | "
                  f"Всего сейчас: {d.total}[/dim]")


# ===========================================================================
# Alerts
# ===========================================================================

def _send_alert(d: DiffResult, takeover: list[str] | None = None) -> None:
    """Отправить алерт если есть новые поддомены."""
    if not d.new and not takeover and not d.changed_ip:
        return
    try:
        from modules import notifier
    except Exception:
        return

    title = f"🔔 {d.domain}: {len(d.new)} new subdomains"
    parts = []
    if d.new:
        parts.append(f"🆕 Новые ({len(d.new)}):\n" +
                     "\n".join(f"  • {s}" for s in d.new[:30]))
    if d.disappeared:
        parts.append(f"💨 Исчезли ({len(d.disappeared)}):\n" +
                     "\n".join(f"  • {s}" for s in d.disappeared[:15]))
    if d.changed_ip:
        parts.append(f"🔀 Сменили IP ({len(d.changed_ip)}):\n" +
                     "\n".join(
                         f"  • {c['fqdn']}: {c['old_ip']} → {c['new_ip']}"
                         for c in d.changed_ip[:15]))
    if takeover:
        parts.append(f"⚠ Takeover-кандидаты ({len(takeover)}):\n" +
                     "\n".join(f"  🔴 {s}" for s in takeover[:15]))
    msg = "\n\n".join(parts)
    try:
        notifier.notify_all(title, msg)
        console.print("[cyan]→ Алерт отправлен (если NOTIFY_ENABLED=true)"
                      "[/cyan]")
    except Exception as exc:  # noqa: BLE001
        log.warning("notify: %s", exc)


# ===========================================================================
# Watch-list CRUD
# ===========================================================================

def add_target(domain: str, interval_min: int = 360,
               notes: str = "", tags: str = "") -> bool:
    domain = extract_host(domain).lower()
    if not domain:
        return False
    try:
        cur = db.conn.cursor()
        cur.execute(
            "INSERT INTO monitor_targets(domain, interval_min, notes, tags) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(domain) DO UPDATE SET "
            "interval_min=excluded.interval_min, "
            "notes=excluded.notes, "
            "tags=excluded.tags",
            (domain, interval_min, notes, tags),
        )
        db.conn.commit()
        console.print(f"[green]✓ Добавлено: {domain} (каждые "
                      f"{interval_min} мин)[/green]")
        return True
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return False


def remove_target(domain: str) -> bool:
    try:
        cur = db.conn.cursor()
        cur.execute("DELETE FROM monitor_targets WHERE domain=?",
                    (domain,))
        db.conn.commit()
        return cur.rowcount > 0
    except Exception:
        return False


def pause_target(domain: str, paused: bool = True) -> bool:
    try:
        cur = db.conn.cursor()
        cur.execute("UPDATE monitor_targets SET enabled=? WHERE domain=?",
                    (0 if paused else 1, domain))
        db.conn.commit()
        return cur.rowcount > 0
    except Exception:
        return False


def list_targets() -> None:
    try:
        cur = db.conn.cursor()
        cur.execute(
            "SELECT domain, enabled, interval_min, last_scan, "
            "created, notes, tags FROM monitor_targets ORDER BY domain",
        )
        rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{exc}[/red]")
        return
    if not rows:
        console.print("[yellow]Watch-list пуст. "
                      "Добавь: monitor-add <domain>[/yellow]")
        return
    table = Table(title=f"👁  Monitored domains ({len(rows)})")
    table.add_column("#", width=4)
    table.add_column("Domain", style="cyan")
    table.add_column("Enabled", width=8)
    table.add_column("Interval", width=10)
    table.add_column("Last scan", width=20)
    table.add_column("Tags", style="magenta", max_width=18)
    table.add_column("Notes", style="dim", max_width=24)
    for i, r in enumerate(rows, 1):
        table.add_row(
            str(i), r["domain"],
            "✓" if r["enabled"] else "⏸",
            f"{r['interval_min']} мин",
            str(r["last_scan"])[:19] if r["last_scan"] else "—",
            (r["tags"] or "")[:18],
            (r["notes"] or "")[:24],
        )
    console.print(table)


def bulk_import_targets(path: str, interval_min: int = 360) -> int:
    """Импорт доменов из файла (по одному на строку)."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red]Файл не найден: {path}[/red]")
        return 0
    count = 0
    try:
        for line in p.read_text(encoding="utf-8",
                                  errors="ignore").splitlines():
            d = line.strip()
            if not d or d.startswith("#"):
                continue
            d = extract_host(d).lower()
            if d:
                try:
                    cur = db.conn.cursor()
                    cur.execute(
                        "INSERT INTO monitor_targets(domain, interval_min) "
                        "VALUES (?, ?) "
                        "ON CONFLICT(domain) DO NOTHING",
                        (d, interval_min),
                    )
                    count += cur.rowcount
                except Exception:
                    continue
        db.conn.commit()
        console.print(f"[green]✓ Импортировано: {count} доменов[/green]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
    return count


# ===========================================================================
# Сканирование
# ===========================================================================

def scan_one(domain: str, wordlist: str = "subdomains.txt",
             threads: int = 30,
             takeover_check: bool = False,
             sources: list[str] | None = None,
             extra_permutations: bool = False,
             save_findings: bool = True) -> DiffResult:
    """Скан одного домена + diff + алерт."""
    domain = extract_host(domain).lower()
    if not confirm_external(domain):
        return DiffResult(domain=domain, ts="")

    console.print(f"\n[bold cyan]🔍 Scan: {domain}[/bold cyan]")

    # 1. Сканируем
    subs = _quick_scan(domain, wordlist, threads,
                        sources=sources,
                        extra_permutations=extra_permutations)
    console.print(f"[green]✓ Найдено: {len(subs)}[/green]")

    # 2. Резолвим IP для всех текущих
    cur_ips = _resolve_many(sorted(subs), threads)

    # 3. Diff с предыдущим
    prev = _get_last_snapshot(domain)
    prev_subs = prev[1] if prev else None
    prev_ts = prev[0] if prev else ""
    diff = _diff(domain, subs, prev_subs, prev_ts, cur_ips=cur_ips)
    _print_diff(diff)

    # 4. Takeover (опц.)
    takeover_found: list[str] = []
    if takeover_check and diff.new:
        try:
            from modules import subdomain_takeover_v2 as t2
            console.print("[cyan]→ Проверка takeover…[/cyan]")
            tf = t2.scan_list(",".join(list(diff.new)[:30]), threads=15)
            takeover_found = [f.subdomain for f in tf if f.dangling]
            if takeover_found:
                console.print(f"[red]⚠ Dangling: {len(takeover_found)}"
                              f"[/red]")
                # Finding для takeover
                if save_findings:
                    _save_finding(MonFinding(
                        kind="monitor_takeover",
                        severity="critical",
                        title=f"Takeover-кандидат в {domain}",
                        target=domain,
                        evidence="\n".join(takeover_found[:20]),
                        data={"count": len(takeover_found),
                              "candidates": takeover_found[:20]},
                    ))
        except Exception as exc:  # noqa: BLE001
            log.debug("takeover: %s", exc)

    diff.takeover = takeover_found

    # 5. Сохраняем snapshot
    _save_snapshot(domain, subs, source="scan",
                    meta={"ips": cur_ips})

    # 6. Обновляем last_scan
    try:
        cur = db.conn.cursor()
        cur.execute(
            "UPDATE monitor_targets SET last_scan=CURRENT_TIMESTAMP "
            "WHERE domain=?", (domain,),
        )
        db.conn.commit()
    except Exception:
        pass

    # 7. Findings для новых поддоменов
    if save_findings and diff.new and prev_subs is not None:
        _save_finding(MonFinding(
            kind="monitor_new_subdomains",
            severity="high" if len(diff.new) >= 5 else "medium",
            title=f"Новые поддомены в {domain} ({len(diff.new)})",
            target=domain,
            evidence="\n".join(diff.new[:50]),
            data={"count": len(diff.new), "subs": diff.new[:50]},
        ))

    # 8. Алерт
    if prev_subs is not None:
        _send_alert(diff, takeover_found)

    # 9. Сохраняем diff в JSON
    _save_diff_json(diff, takeover_found)

    db.save_scan("monitor_scan", domain, {
        "total": diff.total,
        "new": len(diff.new),
        "disappeared": len(diff.disappeared),
        "changed_ip": len(diff.changed_ip),
        "takeover": len(takeover_found),
    })
    return diff


def _save_diff_json(d: DiffResult, takeover: list[str]) -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = d.domain.replace(".", "_")
    path = MON_DIR / f"diff_{safe}_{ts}.json"
    try:
        path.write_text(json.dumps({
            **asdict(d),
            "takeover_candidates": takeover,
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        return path
    except Exception:
        return None


def scan_all(wordlist: str = "subdomains.txt", threads: int = 30,
             takeover_check: bool = False,
             sources: list[str] | None = None,
             extra_permutations: bool = False) -> None:
    """Сканировать все домены из watch-list."""
    try:
        cur = db.conn.cursor()
        cur.execute(
            "SELECT domain FROM monitor_targets WHERE enabled=1",
        )
        domains = [r["domain"] for r in cur.fetchall()]
    except Exception:
        domains = []
    if not domains:
        console.print("[yellow]Watch-list пуст.[/yellow]")
        return
    console.print(f"[cyan]👁  Сканирую {len(domains)} доменов…[/cyan]\n")
    for d in domains:
        try:
            scan_one(d, wordlist, threads, takeover_check,
                     sources=sources,
                     extra_permutations=extra_permutations)
        except KeyboardInterrupt:
            console.print("\n[yellow]Прервано.[/yellow]")
            break
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]{d}: {exc}[/red]")


def show_history(domain: str) -> None:
    """История снапшотов."""
    try:
        cur = db.conn.cursor()
        cur.execute(
            "SELECT ts, sub_count, source FROM monitor_snapshots "
            "WHERE domain=? ORDER BY id DESC LIMIT 50",
            (domain,),
        )
        rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{exc}[/red]")
        return
    if not rows:
        console.print(f"[yellow]Нет истории для {domain}.[/yellow]")
        return
    table = Table(title=f"📊 History: {domain}")
    table.add_column("Timestamp", width=20)
    table.add_column("Subs", width=6)
    table.add_column("Source", style="dim")
    for r in rows:
        table.add_row(str(r["ts"])[:19], str(r["sub_count"]),
                      r["source"])
    console.print(table)


def show_stats(domain: str) -> None:
    """Статистика по домену: change frequency, stability."""
    try:
        cur = db.conn.cursor()
        cur.execute(
            "SELECT ts, sub_count FROM monitor_snapshots "
            "WHERE domain=? ORDER BY id ASC",
            (domain,),
        )
        rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{exc}[/red]")
        return
    if len(rows) < 2:
        console.print("[yellow]Недостаточно снапшотов для статистики."
                      "[/yellow]")
        return

    counts = [r["sub_count"] for r in rows]
    first_ts = str(rows[0]["ts"])
    last_ts = str(rows[-1]["ts"])
    total_change = counts[-1] - counts[0]
    max_count = max(counts)
    min_count = min(counts)

    # Stability: % снапшотов без изменений
    unchanged = sum(1 for i in range(1, len(counts))
                    if counts[i] == counts[i - 1])
    stability = unchanged / (len(counts) - 1) * 100 if len(counts) > 1 else 0

    table = Table(title=f"📊 Stats: {domain}")
    table.add_column("Метрика", style="cyan")
    table.add_column("Значение", style="green")
    table.add_row("Снапшотов", str(len(rows)))
    table.add_row("Первый", first_ts[:19])
    table.add_row("Последний", last_ts[:19])
    table.add_row("Subs сейчас", str(counts[-1]))
    table.add_row("Subs было", str(counts[0]))
    table.add_row("Изменение", f"{total_change:+d}")
    table.add_row("Максимум", str(max_count))
    table.add_row("Минимум", str(min_count))
    table.add_row("Stability", f"{stability:.1f}%")
    console.print(table)


def run_daemon(interval_min: int = 60,
               wordlist: str = "subdomains.txt",
               takeover_check: bool = False,
               sources: list[str] | None = None) -> None:
    """Простой демон — запускать scan_all каждые N минут."""
    console.print(f"[bold cyan]👁  Monitor daemon (каждые {interval_min} мин)"
                  f"[/bold cyan]")
    console.print("[yellow]Ctrl+C для остановки.[/yellow]")
    try:
        while True:
            console.print(f"\n[cyan]{datetime.now().strftime('%H:%M:%S')} "
                          f"— запуск сканирования…[/cyan]")
            scan_all(wordlist=wordlist, takeover_check=takeover_check,
                     sources=sources)
            console.print(f"[dim]Следующий запуск через "
                          f"{interval_min} мин. Ctrl+C — стоп.[/dim]")
            time.sleep(interval_min * 60)
    except KeyboardInterrupt:
        console.print("\n[yellow]Daemon остановлен.[/yellow]")


# ===========================================================================
# Экспорт
# ===========================================================================

def export_diff(d: DiffResult, fmt: str = "html",
                out_path: str | None = None) -> Path | None:
    """Экспорт diff-отчёта."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = d.domain.replace(".", "_")
    ext = {"json": ".json", "html": ".html", "md": ".md",
           "csv": ".csv"}.get(fmt, ".json")
    if not out_path:
        out_path = str(MON_DIR / f"report_{safe}_{ts}{ext}")
    p = Path(out_path)

    try:
        if fmt == "json":
            p.write_text(json.dumps(asdict(d), indent=2,
                                      ensure_ascii=False, default=str),
                          encoding="utf-8")
        elif fmt == "md":
            lines = [
                f"# Subdomain diff: {d.domain}",
                f"_Generated: {datetime.now().isoformat()}_",
                "",
                f"- prev: `{d.prev_ts or '—'}`",
                f"- now:  `{d.ts}`",
                f"- total subdomains: **{d.total}**",
                f"- new: **{len(d.new)}**",
                f"- disappeared: **{len(d.disappeared)}**",
                f"- changed_ip: **{len(d.changed_ip)}**",
                f"- unchanged: {d.unchanged_count}",
                "",
            ]
            if d.new:
                lines.append(f"## 🆕 New ({len(d.new)})")
                for s in d.new:
                    lines.append(f"- `{s}`")
                lines.append("")
            if d.disappeared:
                lines.append(f"## 💨 Disappeared ({len(d.disappeared)})")
                for s in d.disappeared:
                    lines.append(f"- `{s}`")
                lines.append("")
            if d.changed_ip:
                lines.append(f"## 🔀 Changed IP ({len(d.changed_ip)})")
                lines.append("| FQDN | Old | New |")
                lines.append("|------|-----|-----|")
                for c in d.changed_ip:
                    lines.append(f"| `{c['fqdn']}` | `{c['old_ip']}` "
                                 f"| `{c['new_ip']}` |")
                lines.append("")
            if d.takeover:
                lines.append(f"## ⚠ Takeover ({len(d.takeover)})")
                for s in d.takeover:
                    lines.append(f"- 🔴 `{s}`")
            p.write_text("\n".join(lines), encoding="utf-8")
        elif fmt == "csv":
            with p.open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["kind", "fqdn", "old_ip", "new_ip"])
                for s in d.new:
                    w.writerow(["new", s, "", ""])
                for s in d.disappeared:
                    w.writerow(["disappeared", s, "", ""])
                for c in d.changed_ip:
                    w.writerow(["changed_ip", c["fqdn"],
                                c["old_ip"], c["new_ip"]])
                for s in d.takeover:
                    w.writerow(["takeover", s, "", ""])
        elif fmt == "html":
            parts = [
                "<!DOCTYPE html><html lang='ru'><head>"
                "<meta charset='utf-8'>",
                f"<title>Subdomain diff — {html_mod.escape(d.domain)}</title>",
                "<style>",
                "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
                "padding:24px;max-width:1200px;margin:0 auto;line-height:1.5;}",
                "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
                "h2{color:#00ff9c;margin-top:28px;}",
                ".kpi-grid{display:grid;"
                "grid-template-columns:repeat(auto-fit,minmax(140px,1fr));"
                "gap:12px;margin:16px 0;}",
                ".kpi{background:#111;border:1px solid #222;border-radius:6px;"
                "padding:12px;text-align:center;}",
                ".kpi .v{font-size:22px;font-weight:bold;}",
                ".kpi .l{font-size:11px;color:#888;text-transform:uppercase;}",
                ".new .v{color:#00ff9c;}.gone .v{color:#ff7a40;}"
                ".chg .v{color:#ffd23f;}.to .v{color:#ff2020;}",
                "table{width:100%;border-collapse:collapse;margin-top:12px;"
                "font-size:13px;}",
                "th{background:#111;color:#00ff9c;padding:6px;"
                "text-align:left;border:1px solid #222;}",
                "td{padding:5px 8px;border:1px solid #222;"
                "word-break:break-all;}",
                "tr:nth-child(even){background:#0d0d0d;}",
                "</style></head><body>",
                f"<h1>👁  Subdomain diff — {html_mod.escape(d.domain)}</h1>",
                f"<p>prev: <code>{html_mod.escape(d.prev_ts or '—')}</code> "
                f"| now: <code>{html_mod.escape(d.ts)}</code></p>",
                "<div class='kpi-grid'>",
                f"<div class='kpi'><div class='v'>{d.total}</div>"
                f"<div class='l'>Total</div></div>",
                f"<div class='kpi new'><div class='v'>{len(d.new)}</div>"
                f"<div class='l'>New</div></div>",
                f"<div class='kpi gone'><div class='v'>{len(d.disappeared)}</div>"
                f"<div class='l'>Gone</div></div>",
                f"<div class='kpi chg'><div class='v'>{len(d.changed_ip)}</div>"
                f"<div class='l'>IP changed</div></div>",
                f"<div class='kpi to'><div class='v'>{len(d.takeover)}</div>"
                f"<div class='l'>Takeover</div></div>",
                "</div>",
            ]
            if d.new:
                parts.append(f"<h2>🆕 New ({len(d.new)})</h2><ul>")
                for s in d.new:
                    parts.append(f"<li><code>{html_mod.escape(s)}</code></li>")
                parts.append("</ul>")
            if d.disappeared:
                parts.append(f"<h2>💨 Disappeared ({len(d.disappeared)})</h2><ul>")
                for s in d.disappeared:
                    parts.append(f"<li><code>{html_mod.escape(s)}</code></li>")
                parts.append("</ul>")
            if d.changed_ip:
                parts.append(
                    f"<h2>🔀 Changed IP ({len(d.changed_ip)})</h2>"
                    "<table><tr><th>FQDN</th><th>Old</th><th>New</th></tr>")
                for c in d.changed_ip:
                    parts.append(
                        f"<tr><td>{html_mod.escape(c['fqdn'])}</td>"
                        f"<td>{html_mod.escape(c['old_ip'])}</td>"
                        f"<td>{html_mod.escape(c['new_ip'])}</td></tr>")
                parts.append("</table>")
            if d.takeover:
                parts.append(f"<h2>⚠ Takeover ({len(d.takeover)})</h2><ul>")
                for s in d.takeover:
                    parts.append(f"<li style='color:#ff2020;'>🔴 "
                                 f"<code>{html_mod.escape(s)}</code></li>")
                parts.append("</ul>")
            parts.append("</body></html>")
            p.write_text("\n".join(parts), encoding="utf-8")

        console.print(f"[green]✓ {fmt.upper()}: {p}[/green]")
        return p
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка экспорта: {exc}[/red]")
        return None


# ===========================================================================
# CLI-обёртки
# ===========================================================================

def cli_add(domain: str, interval_min: int = 360) -> None:
    add_target(domain, interval_min)


def cli_remove(domain: str) -> None:
    if remove_target(domain):
        console.print(f"[green]✓ Удалено: {domain}[/green]")
    else:
        console.print(f"[red]Не найдено.[/red]")


def cli_list() -> None:
    list_targets()


def cli_scan(domain: str, takeover_check: bool = False) -> None:
    d = scan_one(domain, takeover_check=takeover_check)
    if Confirm.ask("Экспорт diff?", default=False):
        fmt = Prompt.ask("Формат",
                         choices=["html", "json", "md", "csv"],
                         default="html")
        export_diff(d, fmt=fmt)


def cli_scan_all(takeover_check: bool = False) -> None:
    scan_all(takeover_check=takeover_check)


def cli_history(domain: str) -> None:
    show_history(domain)


def cli_stats(domain: str) -> None:
    show_stats(domain)


def cli_daemon(interval_min: int = 60,
               takeover_check: bool = False) -> None:
    run_daemon(interval_min, takeover_check=takeover_check)


def cli_bulk_import(path: str, interval_min: int = 360) -> None:
    bulk_import_targets(path, interval_min)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]👁  Subdomain Monitoring Suite Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Показать watch-list"),
        ("2", "Добавить домен в watch-list"),
        ("3", "Удалить домен"),
        ("4", "Pause/Resume домен"),
        ("5", "Bulk-import из файла"),
        ("6", "Сканировать один домен (diff + alert)"),
        ("7", "Сканировать ВСЕ из watch-list"),
        ("8", "История снапшотов"),
        ("9", "Статистика домена (stability)"),
        ("10", "Запустить daemon (периодически)"),
        ("11", "Экспорт diff последнего скана"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для этичного использования / bug bounty."
                  "[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        list_targets()
    elif c == "2":
        d = Prompt.ask("Домен")
        i = IntPrompt.ask("Интервал (мин)", default=360)
        tags = Prompt.ask("Теги (через запятую)", default="")
        add_target(d, i, tags=tags)
    elif c == "3":
        cli_remove(Prompt.ask("Домен"))
    elif c == "4":
        d = Prompt.ask("Домен")
        paused = Confirm.ask("Pause? (нет = Resume)", default=True)
        if pause_target(d, paused):
            console.print(f"[green]✓ {'Paused' if paused else 'Resumed'}: "
                          f"{d}[/green]")
    elif c == "5":
        path = Prompt.ask("Путь к файлу")
        i = IntPrompt.ask("Интервал (мин)", default=360)
        bulk_import_targets(path, i)
    elif c == "6":
        d = Prompt.ask("Домен")
        t = Confirm.ask("Проверять takeover?", default=True)
        ext = Confirm.ask("Доп. источники (wayback/crtsh/permutations)?",
                           default=True)
        sources = None
        if ext:
            sources = ["wordlist", "crtsh", "wayback"]
        diff = scan_one(d, takeover_check=t,
                         sources=sources,
                         extra_permutations=ext)
        if Confirm.ask("Экспорт diff?", default=False):
            fmt = Prompt.ask("Формат",
                             choices=["html", "json", "md", "csv"],
                             default="html")
            export_diff(diff, fmt=fmt)
    elif c == "7":
        t = Confirm.ask("Проверять takeover?", default=True)
        ext = Confirm.ask("Доп. источники?", default=True)
        sources = ["wordlist", "crtsh", "wayback"] if ext else None
        scan_all(takeover_check=t, sources=sources,
                 extra_permutations=ext)
    elif c == "8":
        show_history(Prompt.ask("Домен"))
    elif c == "9":
        show_stats(Prompt.ask("Домен"))
    elif c == "10":
        i = IntPrompt.ask("Интервал (мин)", default=60)
        t = Confirm.ask("Проверять takeover?", default=True)
        run_daemon(i, takeover_check=t)
    elif c == "11":
        # Экспорт последнего diff — читаем из БД
        d = Prompt.ask("Домен")
        cur = db.conn.cursor()
        cur.execute(
            "SELECT ts, subdomains FROM monitor_snapshots "
            "WHERE domain=? ORDER BY id DESC LIMIT 2",
            (d,),
        )
        rows = cur.fetchall()
        if len(rows) < 2:
            console.print("[yellow]Недостаточно снапшотов.[/yellow]")
            return
        cur_subs = set(json.loads(rows[0]["subdomains"]))
        prev_subs = set(json.loads(rows[1]["subdomains"]))
        diff = _diff(d, cur_subs, prev_subs, str(rows[1]["ts"]))
        fmt = Prompt.ask("Формат",
                         choices=["html", "json", "md", "csv"],
                         default="html")
        export_diff(diff, fmt=fmt)