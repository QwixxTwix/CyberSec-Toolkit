"""
Автоматическое обновление словарей с GitHub (SecLists и др.).
Качает файлы по прямым ссылкам, сохраняет в wordlists/.
"""
import os
import shutil
import time
from pathlib import Path

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, DownloadColumn,
    TransferSpeedColumn, TimeRemainingColumn,
)

from core.config import WORDLIST_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

# Источники: удобные и короткие словари из SecLists + PayloadsAllTheThings.
SOURCES = {
    "subdomains-top1million-5000.txt": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/DNS/subdomains-top1million-5000.txt",
    ),
    "subdomains-top1million-20000.txt": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/DNS/subdomains-top1million-20000.txt",
    ),
    "dirb-common.txt": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/Web-Content/common.txt",
    ),
    "dirb-big.txt": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/Web-Content/directory-list-2.3-big.txt",
    ),
    "raft-small-dirs.txt": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/Web-Content/raft-small-directories.txt",
    ),
    "passwords-top1000.txt": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    ),
    "passwords-top10000.txt": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
    ),
    "usernames-top1000.txt": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Usernames/top-usernames-shortlist.txt",
    ),
    "sqli-payloads.txt": (
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/"
        "master/SQL%20Injection/Intruder/SQL-Injection.txt",
    ),
    "xss-payloads.txt": (
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/"
        "master/XSS%20Injection/Intruder/XSS-Bypass-Strings-Brute.txt",
    ),
}


def _download(url: str, dest: Path, timeout: int = 60) -> bool:
    """Скачать файл с прогресс-баром. True если успех."""
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        with requests.get(url, stream=True, timeout=timeout) as r:
            r.raise_for_status()
            total = int(r.headers.get("Content-Length", 0))

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(dest.name, total=total or None)
                with tmp.open("wb") as f:
                    for chunk in r.iter_content(chunk_size=65536):
                        if chunk:
                            f.write(chunk)
                            progress.update(task, advance=len(chunk))

        # Атомарно переименовать
        shutil.move(str(tmp), str(dest))
        return True
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка загрузки {dest.name}: {exc}[/red]")
        log.error("download %s: %s", url, exc)
        if tmp.exists():
            try:
                tmp.unlink()
            except Exception:  # noqa: BLE001
                pass
        return False


def list_local_wordlists() -> None:
    """Показать, что уже есть в wordlists/."""
    files = sorted(WORDLIST_DIR.glob("*.txt"))
    if not files:
        console.print("[yellow]Словарей нет.[/yellow]")
        return
    table = Table(title="Локальные словари")
    table.add_column("Файл", style="cyan")
    table.add_column("Размер", style="green")
    table.add_column("Строк", style="magenta")
    for f in files:
        try:
            size_kb = f.stat().st_size / 1024
            lines = sum(1 for _ in f.open("r", encoding="utf-8", errors="ignore"))
            table.add_row(f.name, f"{size_kb:.1f} KB", str(lines))
        except Exception:  # noqa: BLE001
            table.add_row(f.name, "?", "?")
    console.print(table)


def update_one(name: str) -> None:
    """Обновить один словарь из списка SOURCES."""
    if name not in SOURCES:
        console.print(f"[red]Нет источника для {name}[/red]")
        return
    url = SOURCES[name][0]
    dest = WORDLIST_DIR / name
    console.print(f"[cyan]Скачиваю {name}…[/cyan]")
    if _download(url, dest):
        size_mb = dest.stat().st_size / 1024 / 1024
        console.print(f"[green]✓ {dest} ({size_mb:.2f} MB)[/green]")
        db.save_scan("wordlist_update", name, {"size_mb": round(size_mb, 2)})


def update_all() -> None:
    """Обновить все словари из списка SOURCES."""
    total = len(SOURCES)
    ok = 0
    for i, name in enumerate(SOURCES.keys(), 1):
        console.print(f"\n[bold cyan]({i}/{total}) {name}[/bold cyan]")
        url = SOURCES[name][0]
        dest = WORDLIST_DIR / name
        if _download(url, dest):
            size_mb = dest.stat().st_size / 1024 / 1024
            console.print(f"[green]  ✓ {dest.name} ({size_mb:.2f} MB)[/green]")
            db.save_scan("wordlist_update", name, {"size_mb": round(size_mb, 2)})
            ok += 1
        time.sleep(0.3)  # вежливая пауза

    console.print(f"\n[bold green]Обновлено: {ok}/{total}[/bold green]")


def check_updates() -> None:
    """Проверить доступность источников (HEAD-запрос)."""
    table = Table(title="Проверка источников")
    table.add_column("Файл", style="cyan")
    table.add_column("Статус", style="green")
    table.add_column("Размер", style="magenta")
    for name, (url,) in SOURCES.items():
        try:
            r = requests.head(url, timeout=10, allow_redirects=True)
            if r.status_code == 200:
                size = r.headers.get("Content-Length", "?")
                try:
                    size_kb = f"{int(size) / 1024:.1f} KB"
                except Exception:  # noqa: BLE001
                    size_kb = str(size)
                table.add_row(name, "[green]OK[/green]", size_kb)
            else:
                table.add_row(name, f"[red]{r.status_code}[/red]", "—")
        except Exception as exc:  # noqa: BLE001
            table.add_row(name, f"[red]{str(exc)[:30]}[/red]", "—")
    console.print(table)


def menu() -> None:
    """Меню обновления словарей."""
    table = Table(title="[bold]Wordlist Updater[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Показать локальные словари"),
        ("2", "Проверить доступность источников"),
        ("3", "Обновить конкретный словарь"),
        ("4", "Обновить все словари"),
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
            console.print(f"  [green]{i}[/green]. {n}")
        idx = Prompt.ask("Номер файла")
        try:
            update_one(names[int(idx) - 1])
        except Exception:  # noqa: BLE001
            console.print("[red]Неверный номер.[/red]")
    elif c == "4":
        if Confirm.ask("Скачать все словари (~50 MB)?", default=False):
            update_all()