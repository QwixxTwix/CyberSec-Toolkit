"""
Автоматизация скриншотов веб-страниц через playwright.
Требует: pip install playwright && playwright install chromium
"""
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import normalize_url, confirm_external

console = Console()
log = get_logger(__name__)


def _playwright_available() -> bool:
    """Проверить, установлен ли playwright и браузеры."""
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except ImportError:
        return False


def _take_screenshot_sync(url: str, out_path: Path, full_page: bool = True) -> bool:
    """Синхронный скриншот одного URL. True если успех."""
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(
                viewport={"width": 1440, "height": 900},
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0 Safari/537.36"
                ),
                ignore_https_errors=True,
            )
            page = context.new_page()
            page.goto(url, timeout=30000, wait_until="networkidle")
            page.screenshot(path=str(out_path), full_page=full_page)
            context.close()
            browser.close()
        return True
    except PWTimeout:
        console.print(f"[red]Таймаут загрузки {url}[/red]")
        return False
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка скриншота {url}: {exc}[/red]")
        log.error("screenshot %s: %s", url, exc)
        return False


def screenshot_one(url: str, full_page: bool = True) -> None:
    """Скриншот одного URL."""
    if not _playwright_available():
        console.print("[red]playwright не установлен.[/red]")
        console.print("[yellow]Установка:[/yellow]")
        console.print("  pip install playwright")
        console.print("  playwright install chromium")
        return

    if not confirm_external(url):
        return

    url = normalize_url(url)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = url.replace("://", "_").replace("/", "_").replace(":", "_")[:60]
    out = REPORT_DIR / f"shot_{safe}_{ts}.png"

    console.print(f"[cyan]Скриншот {url}…[/cyan]")
    if _take_screenshot_sync(url, out, full_page):
        console.print(f"[green]✓ {out}[/green]")
        db.save_scan("screenshot", url, {"path": str(out)})


def screenshot_many(urls: list[str], full_page: bool = False) -> None:
    """Скриншоты пачки URL."""
    if not _playwright_available():
        console.print("[red]playwright не установлен.[/red]")
        return

    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    results: list[tuple[str, str]] = []

    console.print(f"[cyan]Скриншоты {len(urls)} URL…[/cyan]")
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(
                viewport={"width": 1440, "height": 900},
                ignore_https_errors=True,
            )
            for i, url in enumerate(urls, 1):
                url = normalize_url(url)
                safe = url.replace("://", "_").replace("/", "_").replace(":", "_")[:60]
                out = REPORT_DIR / f"shot_{ts}_{i:03d}_{safe}.png"
                try:
                    page = context.new_page()
                    page.goto(url, timeout=20000, wait_until="domcontentloaded")
                    page.screenshot(path=str(out), full_page=full_page)
                    page.close()
                    results.append((url, str(out)))
                    console.print(f"[green]✓[/green] {url}")
                except PWTimeout:
                    console.print(f"[yellow]timeout[/yellow] {url}")
                except Exception as exc:  # noqa: BLE001
                    console.print(f"[red]err[/red] {url}: {str(exc)[:50]}")
            context.close()
            browser.close()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка playwright: {exc}[/red]")
        return

    db.save_scan("screenshot_batch", f"{len(urls)} urls",
                 [{"url": u, "path": p} for u, p in results])


def menu() -> None:
    """Меню скриншотов."""
    table = Table(title="[bold]Screenshot[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Скриншот одного URL"),
        ("2", "Скриншоты списка URL"),
        ("3", "Проверить установку playwright"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        url = Prompt.ask("URL")
        full = Confirm.ask("Full page?", default=True)
        screenshot_one(url, full)
    elif c == "2":
        raw = Prompt.ask("URLs через запятую")
        urls = [u.strip() for u in raw.split(",") if u.strip()]
        if urls:
            screenshot_many(urls)
    elif c == "3":
        if _playwright_available():
            console.print("[green]playwright установлен.[/green]")
        else:
            console.print("[red]playwright НЕ установлен.[/red]")
            console.print("  pip install playwright")
            console.print("  playwright install chromium")