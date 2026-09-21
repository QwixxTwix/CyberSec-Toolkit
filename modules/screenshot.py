"""
Screenshot Pro — расширенный скриншотер веб-страниц через Playwright.
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty / CTF.

Возможности:
    ─── Браузеры ───
    - Chromium / Firefox / WebKit
    - Headless / headful
    - Кастомный User-Agent
    - Stealth-опции (обход headless-детекта)

    ─── Viewports ───
    - Desktop (1440×900) / Tablet (768×1024) / Mobile (390×844) / 4K
    - Custom viewport
    - Все viewports за один прогон (для responsive-аудита)

    ─── Screenshots ───
    - Full page / viewport / element (по CSS-селектору)
    - PDF (page.pdf — Chromium)
    - Multiple formats (PNG, JPEG)
    - Quality (для JPEG)

    ─── Wait strategies ───
    - load / domcontentloaded / networkidle
    - Кастомный селектор (wait_for_selector)
    - Extra delay (мс)

    ─── Advanced ───
    - Basic auth (login/password)
    - Custom headers
    - Cookies (name=value)
    - Proxy (HTTP/SOCKS)
    - Console log capture (errors/warnings)
    - Network capture (запросы, статусы, размеры)
    - Element screenshots (по CSS)
    - Сравнение (hash diff между двумя URL)

    ─── Batch ───
    - Список URL (файл / через запятую)
    - Параллельно (threads)
    - Один браузер на все (efficiency)

    ─── Интеграция ───
    - Findings → notes (для больших выгрузок)
    - Notify
    - HTML-отчёт со встроенными скриншотами (base64)
    - JSON / CSV экспорт
"""
import base64
import csv
import hashlib
import html as html_mod
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn,
)

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import normalize_url, confirm_external

console = Console()
log = get_logger(__name__)

SHOT_DIR = REPORT_DIR / "screenshots"
SHOT_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class ShotFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: ShotFinding) -> int:
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
            tags=["screenshot", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Viewports / presets
# ===========================================================================

VIEWPORTS = {
    "desktop":      {"width": 1440, "height": 900},
    "desktop-hd":   {"width": 1920, "height": 1080},
    "4k":           {"width": 3840, "height": 2160},
    "tablet":       {"width": 768,  "height": 1024},
    "mobile":       {"width": 390,  "height": 844},
    "iphone-14":    {"width": 390,  "height": 844},
    "ipad-pro":     {"width": 1024, "height": 1366},
    "small":        {"width": 320,  "height": 568},
}


# ===========================================================================
# Shot result
# ===========================================================================

@dataclass
class ShotResult:
    url: str
    out_path: str = ""
    status: str = "ok"       # ok | timeout | error
    http_status: int = 0
    title: str = ""
    viewport: str = "desktop"
    browser: str = "chromium"
    width: int = 0
    height: int = 0
    size_bytes: int = 0
    sha256: str = ""
    error: str = ""
    duration_ms: float = 0.0
    console_errors: list[str] = field(default_factory=list)
    network_requests: int = 0
    network_bytes: int = 0


# ===========================================================================
# Playwright check
# ===========================================================================

def _playwright_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except ImportError:
        return False


def _ensure_playwright() -> bool:
    if not _playwright_available():
        console.print("[red]playwright не установлен.[/red]")
        console.print("[yellow]Установка:[/yellow]")
        console.print("  pip install playwright")
        console.print("  playwright install chromium firefox webkit")
        return False
    return True


# ===========================================================================
# Screenshot core
# ===========================================================================

def _take_screenshot_sync(
    url: str,
    out_path: Path,
    full_page: bool = True,
    browser: str = "chromium",
    viewport: str = "desktop",
    viewport_size: dict | None = None,
    wait_until: str = "networkidle",
    extra_delay_ms: int = 0,
    selector: str = "",
    user_agent: str | None = None,
    headers: dict | None = None,
    cookies: str = "",
    basic_auth: tuple | None = None,
    proxy: str | None = None,
    format_: str = "png",
    quality: int = 90,
    capture_console: bool = False,
    capture_network: bool = False,
    time: int = 30,
) -> ShotResult:
    """Синхронный скриншот одного URL. Возвращает ShotResult."""
    from playwright.sync_api import sync_playwright
    from playwright.sync_api import TimeoutError as PWTimeout
    from playwright.sync_api import Error as PWError

    result = ShotResult(url=url, out_path=str(out_path),
                        browser=browser, viewport=viewport)

    vp = viewport_size or VIEWPORTS.get(viewport, VIEWPORTS["desktop"])
    result.width = vp.get("width", 0)
    result.height = vp.get("height", 0)

    start = datetime.now()

    try:
        with sync_playwright() as pw:
            # Браузер
            launcher = getattr(pw, browser, pw.chromium)
            launch_args = {}
            if proxy:
                launch_args["proxy"] = {"server": proxy}
            b = launcher.launch(headless=True, args=[
                "--disable-blink-features=AutomationControlled",
            ]) if browser == "chromium" else launcher.launch(headless=True)

            ctx_kwargs: dict = {
                "viewport": vp,
                "user_agent": (user_agent or
                               "Mozilla/5.0 (X11; Linux x86_64) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/120.0 Safari/537.36"),
                "ignore_https_errors": True,
                "extra_http_headers": headers or {},
            }
            if basic_auth:
                ctx_kwargs["http_credentials"] = {
                    "username": basic_auth[0],
                    "password": basic_auth[1],
                }
            context = b.new_context(**ctx_kwargs)

            # Cookies
            if cookies:
                cookie_list = []
                for c in cookies.split(";"):
                    c = c.strip()
                    if "=" in c:
                        k, _, v = c.partition("=")
                        cookie_list.append({
                            "name": k.strip(),
                            "value": v.strip(),
                            "url": url if "://" in url else f"https://{url}",
                        })
                if cookie_list:
                    try:
                        context.add_cookies(cookie_list)
                    except Exception:
                        pass

            page = context.new_page()

            # Console capture
            if capture_console:
                def _on_console(msg):
                    if msg.type in ("error", "warning"):
                        result.console_errors.append(
                            f"[{msg.type}] {msg.text[:200]}")
                page.on("console", _on_console)

            # Network capture
            if capture_network:
                def _on_response(resp):
                    try:
                        result.network_requests += 1
                        cl = resp.headers.get("content-length")
                        if cl and cl.isdigit():
                            result.network_bytes += int(cl)
                    except Exception:
                        pass
                page.on("response", _on_response)

            # Navigate
            response = page.goto(url, timeout=time * 1000,
                                 wait_until=wait_until)
            if response:
                try:
                    result.http_status = response.status
                except Exception:
                    pass

            # Title
            try:
                result.title = (page.title() or "")[:200]
            except Exception:
                pass

            # Extra delay / selector
            if selector:
                try:
                    page.wait_for_selector(selector, timeout=time * 1000)
                except Exception:
                    pass
            if extra_delay_ms > 0:
                page.wait_for_timeout(extra_delay_ms)

            # Screenshot
            shot_kwargs = {"path": str(out_path), "full_page": full_page}
            if format_ == "jpeg" and out_path.suffix.lower() in (".jpg",
                                                                  ".jpeg"):
                shot_kwargs["type"] = "jpeg"
                shot_kwargs["quality"] = quality

            if selector:
                element = page.query_selector(selector)
                if element:
                    element.screenshot(path=str(out_path))
                else:
                    page.screenshot(**shot_kwargs)
            else:
                page.screenshot(**shot_kwargs)

            context.close()
            b.close()

            # Stats
            if out_path.exists():
                result.size_bytes = out_path.stat().st_size
                try:
                    h = hashlib.sha256()
                    with out_path.open("rb") as fp:
                        for chunk in iter(lambda: fp.read(8192), b""):
                            h.update(chunk)
                    result.sha256 = h.hexdigest()[:16]
                except Exception:
                    pass

    except PWTimeout:
        result.status = "timeout"
        result.error = f"timeout after {time}s"
    except PWError as exc:
        result.status = "error"
        result.error = str(exc)[:200]
    except Exception as exc:
        result.status = "error"
        result.error = str(exc)[:200]

    duration = (datetime.now() - start).total_seconds() * 1000
    result.duration_ms = duration
    return result


# ===========================================================================
# Public API
# ===========================================================================

def screenshot_one(url: str, full_page: bool = True,
                   browser: str = "chromium",
                   viewport: str = "desktop",
                   wait_until: str = "networkidle",
                   selector: str = "",
                   out_path: str | None = None,
                   basic_auth: tuple | None = None,
                   headers: dict | None = None,
                   cookies: str = "",
                   proxy: str | None = None,
                   format_: str = "png",
                   extra_delay_ms: int = 0,
                   capture_console: bool = False,
                   capture_network: bool = False) -> ShotResult | None:
    """Скриншот одного URL."""
    if not _ensure_playwright():
        return None
    if not confirm_external(url):
        return None

    url = normalize_url(url)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", url)[:60]
    ext = ".jpg" if format_ == "jpeg" else ".png"
    if not out_path:
        out_path = str(SHOT_DIR / f"shot_{safe}_{viewport}_{ts}{ext}")

    console.print(f"[cyan]📸 {url} ({browser}/{viewport})…[/cyan]")
    result = _take_screenshot_sync(
        url=url, out_path=Path(out_path), full_page=full_page,
        browser=browser, viewport=viewport, wait_until=wait_until,
        selector=selector, basic_auth=basic_auth, headers=headers,
        cookies=cookies, proxy=proxy, format_=format_,
        extra_delay_ms=extra_delay_ms,
        capture_console=capture_console, capture_network=capture_network,
    )

    if result.status == "ok":
        console.print(f"[green]✓ {out_path} "
                      f"({result.size_bytes / 1024:.1f} KB, "
                      f"{result.duration_ms:.0f} ms)[/green]")
    else:
        console.print(f"[red]✗ {result.status}: {result.error}[/red]")

    db.save_scan("screenshot", url, asdict(result))
    _save_screenshot_finding(result)
    return result


def _save_screenshot_finding(r: ShotResult) -> None:
    """Findings для интересных случаев (error/console errors)."""
    if r.console_errors:
        critical = [e for e in r.console_errors
                    if any(k in e.lower() for k in
                           ("unauthorized", "forbidden", "api", "token",
                            "secret", "password"))]
        if critical:
            _save_finding(ShotFinding(
                kind="console_errors",
                severity="high",
                title=f"JS console errors на {r.url[:60]}",
                target=r.url,
                evidence="\n".join(critical[:10]),
                data={"errors": r.console_errors[:20]},
            ))


def screenshot_many(urls: list[str], full_page: bool = False,
                    browser: str = "chromium",
                    viewport: str = "desktop",
                    threads: int = 4,
                    out_dir: str | None = None,
                    wait_until: str = "domcontentloaded",
                    save_report: bool = True,
                    notify: bool = True) -> list[ShotResult]:
    """Batch скриншотов (параллельно через ThreadPoolExecutor)."""
    if not _ensure_playwright():
        return []
    if not urls:
        return []

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = Path(out_dir) if out_dir else SHOT_DIR / f"batch_{ts}"
    base_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[cyan]📸 Batch: {len(urls)} URLs → {base_dir.name} "
                  f"(threads={threads})[/cyan]")

    results: list[ShotResult] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as p:
        task = p.add_task("shots", total=len(urls))

        def _one(i_url: tuple[int, str]) -> ShotResult | None:
            i, u = i_url
            u = normalize_url(u)
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", u)[:50]
            out = base_dir / f"{i:03d}_{safe}.png"
            try:
                return _take_screenshot_sync(
                    url=u, out_path=out, full_page=full_page,
                    browser=browser, viewport=viewport,
                    wait_until=wait_until, capture_console=True,
                    capture_network=True,
                )
            except Exception as exc:
                r = ShotResult(url=u, status="error", error=str(exc)[:200])
                return r

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = [ex.submit(_one, (i, u))
                    for i, u in enumerate(urls, 1)]
            for f in as_completed(futs):
                p.advance(task)
                r = f.result()
                if r:
                    results.append(r)
                    if r.status == "ok":
                        console.print(f"  [green]✓[/green] "
                                      f"{r.url[:70]}")
                    else:
                        console.print(f"  [red]✗[/red] {r.url[:70]} — "
                                      f"{r.error[:40]}")

    console.print(f"[green]✓ Готово: "
                  f"{sum(1 for r in results if r.status == 'ok')}"
                  f"/{len(results)}[/green]")

    db.save_scan("screenshot_batch", f"{len(urls)} urls",
                 [asdict(r) for r in results])

    if save_report:
        export_html(results, base_dir / "report.html")
        export_json(results, base_dir / "report.json")

    if notify:
        _notify_batch(results)

    return results


def screenshot_multi_viewport(url: str,
                               viewports: list[str] | None = None,
                               out_dir: str | None = None
                               ) -> list[ShotResult]:
    """Скриншот одного URL в нескольких viewports (responsive-аудит)."""
    if not _ensure_playwright():
        return []
    if not confirm_external(url):
        return []
    viewports = viewports or ["desktop", "tablet", "mobile"]

    url = normalize_url(url)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", url)[:50]
    base_dir = Path(out_dir) if out_dir else SHOT_DIR / f"multi_{safe}_{ts}"
    base_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[cyan]📸 Multi-viewport: {url} → "
                  f"{', '.join(viewports)}[/cyan]")

    results: list[ShotResult] = []
    for vp in viewports:
        out = base_dir / f"{vp}.png"
        console.print(f"  → {vp}…")
        r = _take_screenshot_sync(
            url=url, out_path=out, full_page=True,
            viewport=vp, wait_until="networkidle",
        )
        results.append(r)

    # HTML-отчёт со всеми viewports
    try:
        export_html(results, base_dir / "report.html",
                    title=f"Responsive: {url}")
    except Exception:
        pass

    return results


def screenshot_pdf(url: str, out_path: str | None = None,
                   format_: str = "A4") -> Path | None:
    """PDF страницы (только Chromium)."""
    if not _ensure_playwright():
        return None
    if not confirm_external(url):
        return None

    from playwright.sync_api import sync_playwright
    from playwright.sync_api import TimeoutError as PWTimeout

    url = normalize_url(url)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", url)[:50]
    if not out_path:
        out_path = str(SHOT_DIR / f"page_{safe}_{ts}.pdf")
    path = Path(out_path)

    try:
        with sync_playwright() as pw:
            b = pw.chromium.launch(headless=True)
            ctx = b.new_context(ignore_https_errors=True)
            page = ctx.new_page()
            page.goto(url, timeout=30000, wait_until="networkidle")
            page.pdf(path=str(path), format=format_,
                     print_background=True)
            ctx.close()
            b.close()
        size = path.stat().st_size / 1024
        console.print(f"[green]✓ PDF: {path} ({size:.1f} KB)[/green]")
        db.save_scan("screenshot_pdf", url,
                     {"path": str(path), "size_kb": size})
        return path
    except PWTimeout:
        console.print(f"[red]Таймаут PDF {url}[/red]")
        return None
    except Exception as exc:
        console.print(f"[red]PDF {url}: {exc}[/red]")
        return None


# ===========================================================================
# Compare (hash diff)
# ===========================================================================

def compare_urls(url_a: str, url_b: str,
                  full_page: bool = True) -> dict:
    """Сравнить два URL (hash-based diff)."""
    if not _ensure_playwright():
        return {}
    if not confirm_external(url_a) or not confirm_external(url_b):
        return {}

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    a_out = SHOT_DIR / f"cmp_a_{ts}.png"
    b_out = SHOT_DIR / f"cmp_b_{ts}.png"

    ra = _take_screenshot_sync(url_a, a_out, full_page=full_page)
    rb = _take_screenshot_sync(url_b, b_out, full_page=full_page)

    same = (ra.sha256 == rb.sha256) if (ra.sha256 and rb.sha256) else None
    diff = {
        "url_a": url_a, "url_b": url_b,
        "hash_a": ra.sha256, "hash_b": rb.sha256,
        "size_a": ra.size_bytes, "size_b": rb.size_bytes,
        "same": same,
        "delta_bytes": rb.size_bytes - ra.size_bytes,
        "screenshots": [str(a_out), str(b_out)],
    }
    console.print(f"[cyan]Compare:[/cyan] A={ra.sha256} "
                  f"({ra.size_bytes}B) B={rb.sha256} "
                  f"({rb.size_bytes}B) "
                  f"[{'green' if same else 'yellow'}]"
                  f"{'SAME' if same else 'DIFF'}[/]")
    db.save_scan("screenshot_compare", f"{url_a}|{url_b}", diff)
    return diff


# ===========================================================================
# Notify
# ===========================================================================

def _notify_batch(results: list[ShotResult]) -> None:
    if not results:
        return
    try:
        from modules import notifier
        ok = sum(1 for r in results if r.status == "ok")
        err = len(results) - ok
        notifier.notify_all(
            f"📸 Screenshot batch: {ok}/{len(results)}",
            f"OK: {ok}\nErrors: {err}\n"
            f"Total: {len(results)}",
            severity="info",
        )
    except Exception:
        pass


# ===========================================================================
# Export
# ===========================================================================

def export_json(results: list[ShotResult],
                path: str | Path | None = None) -> Path | None:
    if not results:
        return None
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = SHOT_DIR / f"screenshots_{ts}.json"
    p = Path(path)
    try:
        p.write_text(
            json.dumps([asdict(r) for r in results],
                        indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
        console.print(f"[green]✓ JSON: {p}[/green]")
        return p
    except Exception as exc:
        console.print(f"[red]JSON: {exc}[/red]")
        return None


def export_csv(results: list[ShotResult],
               path: str | Path | None = None) -> Path | None:
    if not results:
        return None
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = SHOT_DIR / f"screenshots_{ts}.csv"
    p = Path(path)
    cols = ["url", "status", "http_status", "title", "viewport",
            "browser", "width", "height", "size_bytes", "sha256",
            "duration_ms", "error", "out_path"]
    try:
        with p.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for r in results:
                w.writerow(asdict(r))
        console.print(f"[green]✓ CSV: {p}[/green]")
        return p
    except Exception as exc:
        console.print(f"[red]CSV: {exc}[/red]")
        return None


def export_html(results: list[ShotResult],
                path: str | Path | None = None,
                title: str = "Screenshots") -> Path | None:
    """HTML-отчёт со встроенными скриншотами (base64)."""
    if not results:
        return None
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = SHOT_DIR / f"screenshots_{ts}.html"
    p = Path(path)

    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>{html_mod.escape(title)}</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:24px;line-height:1.5;max-width:1400px;margin:0 auto;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
        "h2{color:#00ff9c;margin-top:36px;}",
        ".card{background:#0d0d0d;border:1px solid #222;padding:14px;"
        "border-radius:4px;margin-bottom:16px;}",
        ".meta{font-size:12px;color:#888;margin-bottom:10px;}",
        ".meta b{color:#7ad9ff;}",
        "img{max-width:100%;border:1px solid #222;border-radius:4px;"
        "background:#fff;}",
        ".ok{color:#00ff9c;}.err{color:#ff4040;font-weight:bold;}",
        ".to{color:#ffd23f;}",
        ".grid{display:grid;grid-template-columns:repeat(auto-fit,"
        "minmax(400px,1fr));gap:16px;}",
        "</style></head><body>",
        f"<h1>📸 {html_mod.escape(title)} ({len(results)})</h1>",
        f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        f"OK: {sum(1 for r in results if r.status == 'ok')}/"
        f"{len(results)}</p>",
        "<div class='grid'>",
    ]

    for r in results:
        cls = {"ok": "ok", "timeout": "to",
               "error": "err"}.get(r.status, "")
        parts.append("<div class='card'>")
        parts.append(
            f"<div class='meta'>"
            f"<b>URL:</b> {html_mod.escape(r.url)}<br>"
            f"<b>Status:</b> <span class='{cls}'>{r.status}</span> "
            f"(HTTP {r.http_status}) | "
            f"<b>Viewport:</b> {r.viewport} ({r.width}×{r.height}) | "
            f"<b>Size:</b> {r.size_bytes / 1024:.1f} KB | "
            f"<b>Time:</b> {r.duration_ms:.0f} ms"
            f"</div>"
        )
        if r.title:
            parts.append(f"<div class='meta'>"
                          f"<b>Title:</b> {html_mod.escape(r.title)}"
                          f"</div>")
        if r.status == "ok" and r.out_path and Path(r.out_path).exists():
            try:
                b64 = base64.b64encode(
                    Path(r.out_path).read_bytes()).decode()
                mime = "image/jpeg" if r.out_path.lower().endswith(
                    (".jpg", ".jpeg")) else "image/png"
                parts.append(
                    f"<img src='data:{mime};base64,{b64}'>"
                )
            except Exception:
                parts.append(f"<div>[image error]</div>")
        elif r.error:
            parts.append(f"<div class='err'>{html_mod.escape(r.error)}"
                          f"</div>")
        if r.console_errors:
            parts.append("<details><summary>Console errors "
                          f"({len(r.console_errors)})</summary><pre>")
            for e in r.console_errors[:20]:
                parts.append(html_mod.escape(e))
            parts.append("</pre></details>")
        parts.append("</div>")

    parts.append("</div></body></html>")
    try:
        p.write_text("\n".join(parts), encoding="utf-8")
        size = p.stat().st_size / 1024
        console.print(f"[green]✓ HTML: {p} ({size:.1f} KB)[/green]")
        return p
    except Exception as exc:
        console.print(f"[red]HTML: {exc}[/red]")
        return None


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    """Меню скриншотов."""
    table = Table(title="[bold]📸 Screenshot Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Скриншот одного URL (default)"),
        ("2", "Скриншот одного URL (кастомные параметры)"),
        ("3", "Batch (список URL через запятую)"),
        ("4", "Batch из файла"),
        ("5", "Multi-viewport (desktop/tablet/mobile)"),
        ("6", "PDF страницы (Chromium)"),
        ("7", "Сравнить два URL (hash diff)"),
        ("8", "Проверить playwright"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        url = Prompt.ask("URL")
        full = Confirm.ask("Full page?", default=True)
        screenshot_one(url, full_page=full)

    elif c == "2":
        url = Prompt.ask("URL")
        full = Confirm.ask("Full page?", default=True)
        browser = Prompt.ask("Browser",
                             choices=["chromium", "firefox", "webkit"],
                             default="chromium")
        vp = Prompt.ask("Viewport",
                        choices=list(VIEWPORTS.keys()),
                        default="desktop")
        wait = Prompt.ask("Wait",
                          choices=["load", "domcontentloaded", "networkidle"],
                          default="networkidle")
        selector = Prompt.ask("CSS selector (опц.)", default="").strip()
        extra_ms = IntPrompt.ask("Extra delay (ms)", default=0)
        fmt = Prompt.ask("Format", choices=["png", "jpeg"], default="png")
        cap_console = Confirm.ask("Capture console errors?", default=False)
        cap_network = Confirm.ask("Capture network?", default=False)
        screenshot_one(
            url, full_page=full, browser=browser, viewport=vp,
            wait_until=wait, selector=selector,
            extra_delay_ms=extra_ms, format_=fmt,
            capture_console=cap_console, capture_network=cap_network,
        )

    elif c == "3":
        raw = Prompt.ask("URLs через запятую")
        urls = [u.strip() for u in raw.split(",") if u.strip()]
        if urls:
            threads = IntPrompt.ask("Threads", default=4)
            full = Confirm.ask("Full page?", default=False)
            screenshot_many(urls, full_page=full, threads=threads)

    elif c == "4":
        p = Prompt.ask("Путь к файлу (по одному URL на строку)")
        try:
            urls = [l.strip() for l in open(p, encoding="utf-8",
                                              errors="ignore")
                    if l.strip() and not l.startswith("#")]
        except Exception as exc:
            console.print(f"[red]{exc}[/red]")
            return
        if urls:
            threads = IntPrompt.ask("Threads", default=4)
            full = Confirm.ask("Full page?", default=False)
            screenshot_many(urls, full_page=full, threads=threads)

    elif c == "5":
        url = Prompt.ask("URL")
        vps_raw = Prompt.ask("Viewports через запятую",
                              default="desktop,tablet,mobile")
        vps = [v.strip() for v in vps_raw.split(",") if v.strip()]
        screenshot_multi_viewport(url, viewports=vps)

    elif c == "6":
        url = Prompt.ask("URL")
        screenshot_pdf(url)

    elif c == "7":
        a = Prompt.ask("URL A")
        b = Prompt.ask("URL B")
        compare_urls(a, b)

    elif c == "8":
        if _playwright_available():
            console.print("[green]playwright установлен.[/green]")
            try:
                from playwright.sync_api import sync_playwright
                with sync_playwright() as pw:
                    for name in ("chromium", "firefox", "webkit"):
                        try:
                            getattr(pw, name).launch(headless=True)
                            console.print(f"  [green]✓ {name}[/green]")
                        except Exception as exc:
                            console.print(f"  [red]✗ {name}: "
                                          f"{str(exc)[:60]}[/red]")
            except Exception as exc:
                console.print(f"[red]{exc}[/red]")
        else:
            console.print("[red]playwright НЕ установлен.[/red]")
            console.print("  pip install playwright")
            console.print("  playwright install chromium firefox webkit")


# ===========================================================================
# CLI-обёртки (сохранены)
# ===========================================================================

def cli_one(url: str) -> None:
    screenshot_one(url)


def cli_many(source: str, threads: int = 4) -> None:
    p = Path(source)
    if p.exists():
        urls = [l.strip() for l in p.read_text(encoding="utf-8",
                                                 errors="ignore").splitlines()
                if l.strip() and not l.startswith("#")]
    else:
        urls = [u.strip() for u in source.split(",") if u.strip()]
    screenshot_many(urls, threads=threads)


def cli_pdf(url: str) -> None:
    screenshot_pdf(url)


def cli_compare(a: str, b: str) -> None:
    compare_urls(a, b)


def cli_multi(url: str) -> None:
    screenshot_multi_viewport(url)