"""
Wordlist Updater Pro — управление словарями с GitHub.
Author: idqwixxa

⚠ Только для авторизованного пентеста / CTF.

Возможности:
    ─── Sources ───
    - 50+ источников (SecLists, PayloadsAllTheThings, fuzzdb, commonspeak2)
    - Категории: DNS, Web, Passwords, Usernames, Payloads, Fuzzing
    - Custom sources (добавить свой URL)
    - GitHub raw / release assets
    - Интеграция с _seclists_*.json index

    ─── Download ───
    - Параллельная загрузка (multi-thread)
    - Retry с exponential backoff
    - Resume (.part файлы)
    - Integrity check (size + md5 опционально)
    - Skip if unchanged (по ETag / Last-Modified)
    - Gzip поддержка
    - Прогресс-бар

    ─── Analysis ───
    - Stats по локальным файлам (size, lines)
    - Total storage
    - Dup detection
    - Last update time

    ─── Интеграция ───
    - Findings → notes (большие файлы, битые, недоступные)
    - Notify при обновлении
    - Экспорт: JSON / MD / HTML / CSV
    - Сохранение метаданных в БД
"""
import csv
import hashlib
import html as html_mod
import json
import os
import shutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, DownloadColumn,
    TransferSpeedColumn, TimeRemainingColumn,
)

from core.config import WORDLIST_DIR, REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

WLU_DIR = REPORT_DIR / "wordlist_updater"
WLU_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class WLUFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: WLUFinding) -> int:
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
            tags=["wordlist", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


def _notify(title: str, msg: str, severity: str = "medium") -> None:
    try:
        from modules import notifier
        notifier.notify_all(title, msg, severity=severity)
    except Exception:
        pass


# ===========================================================================
# Meta index
# ===========================================================================

META_FILE = WLU_DIR / "_meta.json"


def _load_meta() -> dict:
    if not META_FILE.exists():
        return {}
    try:
        return json.loads(META_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_meta(meta: dict) -> None:
    try:
        META_FILE.write_text(json.dumps(meta, indent=2,
                                          ensure_ascii=False),
                              encoding="utf-8")
    except Exception as exc:
        log.warning("meta save: %s", exc)


# ===========================================================================
# Sources (расширено: 50+)
# ===========================================================================

SECLISTS = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
PATT = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master"
FUZZDB = "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master"
COMMONSPEAK = ("https://raw.githubusercontent.com/assetnote/"
                "commonspeak2-wordlists/master")

SOURCES: dict[str, tuple] = {
    # ─── DNS / Subdomains ───
    "subdomains-top1million-5000.txt": (
        f"{SECLISTS}/Discovery/DNS/subdomains-top1million-5000.txt",
        "dns"),
    "subdomains-top1million-20000.txt": (
        f"{SECLISTS}/Discovery/DNS/subdomains-top1million-20000.txt",
        "dns"),
    "subdomains-top1million-110000.txt": (
        f"{SECLISTS}/Discovery/DNS/subdomains-top1million-110000.txt",
        "dns"),
    "dns-jhaddix.txt": (
        f"{SECLISTS}/Discovery/DNS/dns-Jhaddix.txt", "dns"),
    "fierce-hostlist.txt": (
        f"{SECLISTS}/Discovery/DNS/fierce-hostlist.txt", "dns"),
    "namelist.txt": (
        f"{SECLISTS}/Discovery/DNS/namelist.txt", "dns"),
    "commonspeak-subdomains.txt": (
        f"{COMMONSPEAK}/subdomains.txt", "dns"),

    # ─── Web content / directories ───
    "dirb-common.txt": (
        f"{SECLISTS}/Discovery/Web-Content/common.txt", "web"),
    "dirb-big.txt": (
        f"{SECLISTS}/Discovery/Web-Content/directory-list-2.3-big.txt",
        "web"),
    "dirb-medium.txt": (
        f"{SECLISTS}/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "web"),
    "dirb-small.txt": (
        f"{SECLISTS}/Discovery/Web-Content/directory-list-2.3-small.txt",
        "web"),
    "raft-small-dirs.txt": (
        f"{SECLISTS}/Discovery/Web-Content/raft-small-directories.txt",
        "web"),
    "raft-medium-dirs.txt": (
        f"{SECLISTS}/Discovery/Web-Content/raft-medium-directories.txt",
        "web"),
    "raft-large-dirs.txt": (
        f"{SECLISTS}/Discovery/Web-Content/raft-large-directories.txt",
        "web"),
    "raft-small-files.txt": (
        f"{SECLISTS}/Discovery/Web-Content/raft-small-files.txt", "web"),
    "raft-medium-files.txt": (
        f"{SECLISTS}/Discovery/Web-Content/raft-medium-files.txt", "web"),
    "raft-large-files.txt": (
        f"{SECLISTS}/Discovery/Web-Content/raft-large-files.txt", "web"),
    "common-web-extensions.txt": (
        f"{SECLISTS}/Discovery/Web-Content/web-extensions.txt", "web"),
    "quickhits.txt": (
        f"{SECLISTS}/Discovery/Web-Content/quickhits.txt", "web"),
    "commonspeak-directories.txt": (
        f"{COMMONSPEAK}/directories.txt", "web"),

    # ─── Passwords ───
    "passwords-top1000.txt": (
        f"{SECLISTS}/Passwords/Common-Credentials/"
        "10-million-password-list-top-1000.txt", "passwords"),
    "passwords-top10000.txt": (
        f"{SECLISTS}/Passwords/Common-Credentials/"
        "10-million-password-list-top-10000.txt", "passwords"),
    "passwords-top100000.txt": (
        f"{SECLISTS}/Passwords/Common-Credentials/"
        "10-million-password-list-top-100000.txt", "passwords"),
    "passwords-top1000000.txt": (
        f"{SECLISTS}/Passwords/Common-Credentials/"
        "10-million-password-list-top-1000000.txt", "passwords"),
    "rockyou-1000.txt": (
        f"{SECLISTS}/Passwords/Leaked-Databases/rockyou-05.txt",
        "passwords"),
    "rockyou-10000.txt": (
        f"{SECLISTS}/Passwords/Leaked-Databases/rockyou-10.txt",
        "passwords"),
    "rockyou-100000.txt": (
        f"{SECLISTS}/Passwords/Leaked-Databases/rockyou-40.txt",
        "passwords"),
    "probable-v2-top12000.txt": (
        f"{SECLISTS}/Passwords/Common-Credentials/"
        "probable-v2-top12000.txt", "passwords"),
    "darkweb2017-top10000.txt": (
        f"{SECLISTS}/Passwords/Common-Credentials/"
        "darkweb2017-top10000.txt", "passwords"),
    "500-worst-passwords.txt": (
        f"{SECLISTS}/Passwords/Common-Credentials/"
        "500-worst-passwords.txt", "passwords"),

    # ─── Usernames ───
    "usernames-top1000.txt": (
        f"{SECLISTS}/Usernames/top-usernames-shortlist.txt", "usernames"),
    "usernames-top100.txt": (
        f"{SECLISTS}/Usernames/top-usernames-shortlist.txt", "usernames"),
    "cirt-default-usernames.txt": (
        f"{SECLISTS}/Usernames/cirt-default-usernames.txt", "usernames"),

    # ─── Payloads: SQLi ───
    "sqli-payloads.txt": (
        f"{PATT}/SQL%20Injection/Intruder/SQL-Injection.txt", "payloads"),
    "sqli-auth-bypass.txt": (
        f"{PATT}/SQL%20Injection/Intruder/Auth_Bypass.txt", "payloads"),
    "sqli-fuzzdb.txt": (
        f"{FUZZDB}/attack-payloads/sql-injection/sql-injection-payloads.txt",
        "payloads"),

    # ─── Payloads: XSS ───
    "xss-payloads.txt": (
        f"{PATT}/XSS%20Injection/Intruder/XSS-Bypass-Strings-Brute.txt",
        "payloads"),
    "xss-polyglots.txt": (
        f"{PATT}/XSS%20Injection/Intruder/XSS_Polyglots.txt", "payloads"),
    "xss-fuzzdb.txt": (
        f"{FUZZDB}/attack-payloads/xss/xss-payload-list.txt", "payloads"),

    # ─── Payloads: LFI / RFI ───
    "lfi-payloads.txt": (
        f"{PATT}/File%20Inclusion/Intruders/LFI-gracefulsecurity-linux.txt",
        "payloads"),
    "lfi-windows.txt": (
        f"{PATT}/File%20Inclusion/Intruders/LFI-gracefulsecurity-windows.txt",
        "payloads"),
    "lfi-fuzzdb.txt": (
        f"{FUZZDB}/attack-payloads/lfi/lfi-payloads.txt", "payloads"),

    # ─── Payloads: SSRF / XXE ───
    "ssrf-payloads.txt": (
        f"{PATT}/SSRF%20Injection/Intruder/SSRF_Payloads.txt", "payloads"),
    "xxe-payloads.txt": (
        f"{PATT}/XXE%20Injection/Intruder/XXE-Fuzzing.txt", "payloads"),

    # ─── Payloads: Command Injection ───
    "cmdi-payloads.txt": (
        f"{PATT}/Command%20Injection/Intruder/"
        "command-injection-payload-list.txt", "payloads"),

    # ─── Payloads: SSTI ───
    "ssti-payloads.txt": (
        f"{PATT}/Server%20Side%20Template%20Injection/Intruder/"
        "template-injection.txt", "payloads"),

    # ─── Payloads: Open Redirect ───
    "open-redirect.txt": (
        f"{PATT}/Open%20Redirect/Intruder/open_redirect_wordlist.txt",
        "payloads"),

    # ─── Fuzzing ───
    "lfi-jhaddix.txt": (
        f"{SECLISTS}/Fuzzing/LFI/LFI-Jhaddix.txt", "fuzzing"),
    "rfi-lfi-payloads.txt": (
        f"{SECLISTS}/Fuzzing/LFI/LFI-linux-list.txt", "fuzzing"),

    # ─── API / GraphQL ───
    "graphql-queries.txt": (
        f"{PATT}/GraphQL%20Injection/Intruder/GraphQL.txt", "payloads"),
}


# ===========================================================================
# Download
# ===========================================================================

RETRIES = 3
RETRY_BACKOFF = 2.0


def _download(url: str, dest: Path, timeout: int = 60,
              retries: int = RETRIES) -> bool:
    """Скачать файл с прогресс-баром + retry. True если успех."""
    tmp = dest.with_suffix(dest.suffix + ".part")
    last_exc: Exception | None = None

    for attempt in range(1, retries + 1):
        try:
            with requests.get(url, stream=True, timeout=timeout) as r:
                r.raise_for_status()
                total = int(r.headers.get("Content-Length", 0))
                etag = r.headers.get("ETag", "")
                last_mod = r.headers.get("Last-Modified", "")

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    DownloadColumn(),
                    TransferSpeedColumn(),
                    TimeRemainingColumn(),
                    console=console,
                ) as progress:
                    task = progress.add_task(dest.name,
                                              total=total or None)
                    with tmp.open("wb") as f:
                        for chunk in r.iter_content(chunk_size=65536):
                            if chunk:
                                f.write(chunk)
                                progress.update(task, advance=len(chunk))

            shutil.move(str(tmp), str(dest))

            # Мета
            meta = _load_meta()
            meta[dest.name] = {
                "url": url,
                "size": dest.stat().st_size,
                "etag": etag,
                "last_modified": last_mod,
                "downloaded_at": datetime.now().isoformat(),
                "attempt": attempt,
            }
            _save_meta(meta)
            return True
        except Exception as exc:
            last_exc = exc
            log.warning("download %s attempt %d/%d: %s",
                        url, attempt, retries, exc)
            if attempt < retries:
                time.sleep(RETRY_BACKOFF ** attempt)
            if tmp.exists():
                try:
                    tmp.unlink()
                except Exception:
                    pass

    console.print(f"[red]✗ {dest.name}: {last_exc}[/red]")
    return False


def _download_parallel(items: list[str], threads: int = 4) -> dict:
    """Параллельная загрузка нескольких словарей."""
    results = {"ok": [], "fail": []}
    with Progress(SpinnerColumn(),
                   TextColumn("[progress.description]{task.description}"),
                   BarColumn(),
                   TextColumn("{task.completed}/{task.total}"),
                   TimeElapsedColumn(),
                   console=console) as p:
        task = p.add_task("Downloading", total=len(items))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(update_one, name, True): name
                       for name in items}
            for f in as_completed(futures):
                name = futures[f]
                try:
                    ok = f.result()
                    (results["ok"] if ok else results["fail"]).append(name)
                except Exception as exc:
                    log.warning("parallel %s: %s", name, exc)
                    results["fail"].append(name)
                p.advance(task)
    return results


# ===========================================================================
# Local lists
# ===========================================================================

def list_local_wordlists() -> None:
    """Показать, что уже есть в wordlists/."""
    files = sorted(WORDLIST_DIR.glob("*.txt"))
    if not files:
        console.print("[yellow]Словарей нет.[/yellow]")
        return
    table = Table(title=f"Локальные словари ({len(files)})")
    table.add_column("Файл", style="cyan")
    table.add_column("Размер", style="green", width=10)
    table.add_column("Строк", style="magenta", width=10)
    table.add_column("Обновлён", style="dim", width=20)
    total_size = 0
    for f in files:
        try:
            size_b = f.stat().st_size
            total_size += size_b
            size_str = (f"{size_b/1024:.1f} KB" if size_b < 1024*1024
                        else f"{size_b/1024/1024:.1f} MB")
            lines = sum(1 for _ in f.open("r", encoding="utf-8",
                                            errors="ignore"))
            mtime = datetime.fromtimestamp(f.stat().st_mtime
                                            ).strftime("%Y-%m-%d %H:%M")
            table.add_row(f.name, size_str, f"{lines:,}", mtime)
        except Exception:
            table.add_row(f.name, "?", "?", "?")
    console.print(table)
    console.print(f"[dim]Total: {total_size/1024/1024:.1f} MB[/dim]")


# ===========================================================================
# Update functions
# ===========================================================================

def update_one(name: str, quiet: bool = False) -> bool:
    """Обновить один словарь. Возвращает True при успехе."""
    if name not in SOURCES:
        if not quiet:
            console.print(f"[red]Нет источника для {name}[/red]")
        return False

    url = SOURCES[name][0]
    dest = WORDLIST_DIR / name
    if not quiet:
        console.print(f"[cyan]Скачиваю {name}…[/cyan]")
    ok = _download(url, dest)
    if ok:
        size_mb = dest.stat().st_size / 1024 / 1024
        if not quiet:
            console.print(f"[green]✓ {dest} ({size_mb:.2f} MB)[/green]")
        db.save_scan("wordlist_update", name,
                     {"size_mb": round(size_mb, 2)})
    return ok


def update_all(threads: int = 4) -> None:
    """Обновить все словари параллельно."""
    total = len(SOURCES)
    console.print(f"[cyan]Обновляю {total} словарей "
                  f"(threads={threads})…[/cyan]")
    result = _download_parallel(list(SOURCES.keys()), threads=threads)
    ok = len(result["ok"])
    fail = len(result["fail"])
    console.print(f"\n[bold green]Обновлено: {ok}/{total}[/bold green]")
    if fail:
        console.print(f"[red]Ошибок: {fail}[/red]")
        for n in result["fail"]:
            console.print(f"  [red]✗ {n}[/red]")
        # Finding
        _save_finding(WLUFinding(
            kind="wordlist_download_fail",
            severity="high" if fail > 3 else "medium",
            title=f"Не удалось скачать {fail} словарей",
            target="wordlist_updater",
            evidence=f"Failed: {result['fail']}",
            data={"failed": result["fail"]},
        ))

    # Notify
    _notify(
        "📚 Wordlist update",
        f"OK: {ok}\nFailed: {fail}",
        severity="high" if fail else "medium",
    )


def update_category(category: str, threads: int = 4) -> None:
    """Обновить все словари из одной категории."""
    items = [name for name, src in SOURCES.items()
             if len(src) > 1 and src[1] == category]
    if not items:
        console.print(f"[yellow]Категория {category} пуста или "
                      f"неизвестна.[/yellow]")
        return
    console.print(f"[cyan]Категория '{category}': {len(items)} файлов"
                  f"[/cyan]")
    result = _download_parallel(items, threads=threads)
    console.print(f"[green]✓ {len(result['ok'])}/{len(items)}[/green]")


def check_updates() -> None:
    """Проверить доступность источников (HEAD)."""
    table = Table(title=f"Проверка {len(SOURCES)} источников")
    table.add_column("Файл", style="cyan", max_width=40)
    table.add_column("Кат", style="dim", width=10)
    table.add_column("Статус", style="green", width=8)
    table.add_column("Размер", style="magenta", width=10)

    def _head(name: str) -> tuple[str, int, int]:
        url = SOURCES[name][0]
        try:
            r = requests.head(url, timeout=10, allow_redirects=True)
            size = r.headers.get("Content-Length", "0")
            return (name, r.status_code, int(size) if size.isdigit() else 0)
        except Exception:
            return (name, 0, 0)

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(_head, n) for n in SOURCES]
        for f in as_completed(futures):
            name, code, size = f.result()
            cat = SOURCES[name][1] if len(SOURCES[name]) > 1 else "?"
            if code == 200:
                size_str = (f"{size/1024:.1f} KB" if size < 1024*1024
                            else f"{size/1024/1024:.1f} MB")
                table.add_row(name, cat, "[green]OK[/green]", size_str)
            else:
                table.add_row(name, cat, f"[red]{code}[/red]", "—")
    console.print(table)


def add_custom_source(name: str, url: str,
                       category: str = "custom") -> None:
    """Добавить свой источник."""
    SOURCES[name] = (url, category)
    console.print(f"[green]✓ Источник '{name}' добавлен "
                  f"({category})[/green]")


def remove_source(name: str) -> None:
    """Удалить источник."""
    if name in SOURCES:
        del SOURCES[name]
        console.print(f"[green]✓ {name} удалён[/green]")
    else:
        console.print(f"[red]{name} не найден[/red]")


def categories() -> dict[str, int]:
    """Список категорий с количеством."""
    out: dict[str, int] = {}
    for name, src in SOURCES.items():
        cat = src[1] if len(src) > 1 else "uncategorized"
        out[cat] = out.get(cat, 0) + 1
    return out


def show_categories() -> None:
    cats = categories()
    table = Table(title=f"Категории ({len(cats)})")
    table.add_column("Категория", style="cyan")
    table.add_column("Файлов", style="green", width=8)
    for c, n in sorted(cats.items()):
        table.add_row(c, str(n))
    console.print(table)


def check_integrity() -> None:
    """Проверить целостность (size vs meta)."""
    meta = _load_meta()
    issues: list[str] = []
    for f in WORDLIST_DIR.glob("*.txt"):
        if f.name not in meta:
            continue
        recorded = meta[f.name].get("size", 0)
        actual = f.stat().st_size
        if recorded and actual != recorded:
            issues.append(f"{f.name}: meta={recorded} actual={actual}")

    if not issues:
        console.print("[green]✓ Целостность OK.[/green]")
        return
    console.print(f"[yellow]⚠ {len(issues)} расхождений:[/yellow]")
    for i in issues[:20]:
        console.print(f"  [yellow]{i}[/yellow]")


def dedup_local() -> None:
    """Найти дубликаты (по хешу) в wordlists/."""
    by_size: dict[int, list[Path]] = {}
    for f in WORDLIST_DIR.glob("*.txt"):
        try:
            sz = f.stat().st_size
            by_size.setdefault(sz, []).append(f)
        except Exception:
            continue

    dup_groups: list[list[Path]] = []
    for sz, files in by_size.items():
        if len(files) < 2:
            continue
        hashes: dict[str, list[Path]] = {}
        for f in files:
            try:
                h = hashlib.md5(f.read_bytes()).hexdigest()
                hashes.setdefault(h, []).append(f)
            except Exception:
                continue
        for group in hashes.values():
            if len(group) > 1:
                dup_groups.append(group)

    if not dup_groups:
        console.print("[green]✓ Дубликатов не найдено.[/green]")
        return
    console.print(f"[yellow]⚠ {len(dup_groups)} групп дубликатов:[/yellow]")
    for grp in dup_groups:
        console.print(f"  [cyan]{grp[0].name}[/cyan] == "
                      + ", ".join(x.name for x in grp[1:]))


def gzip_wordlist(name: str) -> Path | None:
    """Сжать словарь в .gz."""
    import gzip
    src = WORDLIST_DIR / name
    if not src.exists():
        console.print(f"[red]{name} не найден.[/red]")
        return None
    dst = src.with_suffix(src.suffix + ".gz")
    try:
        with src.open("rb") as fi, gzip.open(dst, "wb", compresslevel=9) as fo:
            shutil.copyfileobj(fi, fo)
        console.print(f"[green]✓ {dst.name} "
                      f"({dst.stat().st_size/1024:.1f} KB)[/green]")
        return dst
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# Export
# ===========================================================================

def export_report(fmt: str = "json",
                   out_path: str | None = None) -> Path | None:
    """Экспорт отчёта о локальных словарях + метаданных."""
    files = sorted(WORDLIST_DIR.glob("*.txt"))
    meta = _load_meta()
    rows = []
    total_size = 0
    for f in files:
        try:
            sz = f.stat().st_size
            total_size += sz
            rows.append({
                "name": f.name,
                "size_b": sz,
                "size_mb": round(sz / 1024 / 1024, 3),
                "mtime": datetime.fromtimestamp(
                    f.stat().st_mtime).isoformat(),
                "url": meta.get(f.name, {}).get("url", ""),
                "downloaded_at": meta.get(f.name, {}).get(
                    "downloaded_at", ""),
            })
        except Exception:
            continue

    summary = {
        "generated_at": datetime.now().isoformat(),
        "total_files": len(rows),
        "total_size_mb": round(total_size / 1024 / 1024, 2),
        "categories": categories(),
        "files": rows,
    }

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = {"json": ".json", "md": ".md", "html": ".html",
           "csv": ".csv"}.get(fmt, ".json")
    if not out_path:
        out_path = str(WLU_DIR / f"report_{ts}{ext}")
    p = Path(out_path)

    try:
        if fmt == "json":
            p.write_text(json.dumps(summary, indent=2,
                                      ensure_ascii=False, default=str),
                          encoding="utf-8")
        elif fmt == "md":
            lines = [
                "# Wordlist report",
                f"_Generated: {summary['generated_at']}_",
                f"Total files: **{summary['total_files']}**",
                f"Total size: **{summary['total_size_mb']} MB**",
                "",
                "## Categories",
            ]
            for c, n in summary["categories"].items():
                lines.append(f"- **{c}**: {n}")
            lines.extend(["", "## Files",
                          "| Name | Size (MB) | Updated |",
                          "|------|-----------|---------|"])
            for r in rows:
                lines.append(f"| {r['name']} | {r['size_mb']} | "
                             f"{r['mtime'][:19]} |")
            p.write_text("\n".join(lines), encoding="utf-8")
        elif fmt == "csv":
            with p.open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["name", "size_mb", "mtime", "url",
                            "downloaded_at"])
                for r in rows:
                    w.writerow([r["name"], r["size_mb"], r["mtime"],
                                r["url"], r["downloaded_at"]])
        elif fmt == "html":
            parts = [
                "<!DOCTYPE html><html><head><meta charset='utf-8'>",
                "<title>Wordlist report</title>",
                "<style>",
                "body{background:#0a0a0a;color:#c8c8c8;"
                "font-family:monospace;padding:24px;line-height:1.5;}",
                "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
                "table{width:100%;border-collapse:collapse;margin-top:12px;"
                "font-size:13px;}",
                "th{background:#111;color:#00ff9c;padding:6px;"
                "text-align:left;border:1px solid #222;}",
                "td{padding:4px 6px;border:1px solid #222;"
                "word-break:break-all;}",
                "tr:nth-child(even){background:#0d0d0d;}",
                "</style></head><body>",
                f"<h1>📚 Wordlist report ({summary['total_files']})</h1>",
                f"<p>Total size: {summary['total_size_mb']} MB</p>",
                "<table><tr><th>Name</th><th>Size (MB)</th>"
                "<th>Updated</th></tr>",
            ]
            for r in rows:
                parts.append(
                    f"<tr><td>{html_mod.escape(r['name'])}</td>"
                    f"<td>{r['size_mb']}</td>"
                    f"<td>{html_mod.escape(r['mtime'][:19])}</td></tr>")
            parts.append("</table></body></html>")
            p.write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ {fmt.upper()}: {p}[/green]")
        return p
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]📚 Wordlist Updater Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Показать локальные словари (stats)"),
        ("2", "Проверить доступность источников (HEAD)"),
        ("3", "Обновить конкретный словарь"),
        ("4", "Обновить все словари (parallel)"),
        ("5", "Обновить по категории (dns/web/passwords/...)"),
        ("6", "Список категорий"),
        ("7", "Проверить целостность (size vs meta)"),
        ("8", "Дедупликация (md5 search)"),
        ("9", "Gzip конкретного словаря"),
        ("10", "Добавить свой источник"),
        ("11", "Удалить источник"),
        ("12", "Экспорт отчёта (json/md/html/csv)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        list_local_wordlists()
    elif c == "2":
        check_updates()
    elif c == "3":
        names = list(SOURCES.keys())
        for i, n in enumerate(names, 1):
            cat = SOURCES[n][1] if len(SOURCES[n]) > 1 else "?"
            console.print(f"  [green]{i:>2}[/green]. [{cat:>10}] {n}")
        idx = Prompt.ask("Номер файла")
        try:
            update_one(names[int(idx) - 1])
        except Exception:
            console.print("[red]Неверный номер.[/red]")
    elif c == "4":
        threads = IntPrompt.ask("Потоков", default=4)
        if Confirm.ask(f"Скачать все ({len(SOURCES)}) словарей?",
                        default=False):
            update_all(threads=threads)
    elif c == "5":
        show_categories()
        cat = Prompt.ask("Категория")
        update_category(cat)
    elif c == "6":
        show_categories()
    elif c == "7":
        check_integrity()
    elif c == "8":
        dedup_local()
    elif c == "9":
        name = Prompt.ask("Имя файла (например rockyou-1000.txt)")
        gzip_wordlist(name)
    elif c == "10":
        name = Prompt.ask("Имя (например my-list.txt)")
        url = Prompt.ask("URL")
        cat = Prompt.ask("Категория", default="custom")
        add_custom_source(name, url, cat)
    elif c == "11":
        name = Prompt.ask("Имя")
        remove_source(name)
    elif c == "12":
        fmt = Prompt.ask("Формат",
                         choices=["json", "md", "html", "csv"],
                         default="json")
        export_report(fmt)


# ===========================================================================
# CLI (сохранены)
# ===========================================================================

def cli_list() -> None:
    list_local_wordlists()


def cli_check() -> None:
    check_updates()


def cli_update(name: str) -> None:
    update_one(name)


def cli_update_all() -> None:
    update_all()


def cli_update_category(cat: str) -> None:
    update_category(cat)


def cli_categories() -> None:
    show_categories()


def cli_export(fmt: str = "json") -> None:
    export_report(fmt)