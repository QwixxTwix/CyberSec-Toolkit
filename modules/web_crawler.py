"""
Web Crawler: обход сайта, сбор URL, форм, параметров, cookies, JS-эндпоинтов.
Результаты:
  - вывод в консоль (таблицы)
  - JSON в reports/crawl_<host>_<ts>.json
  - готовые targets для sqlmap/ffuf
"""
import json
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, normalize_url

console = Console()
log = get_logger(__name__)

# Расширения, которые не считаем «страницами»
SKIP_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv",
    ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    ".exe", ".dll", ".iso", ".dmg", ".apk",
}

# Регулярка для поиска URL в JS/HTML
URL_RE = re.compile(
    r"""(?:"|')((?:https?://|/)[^"'\s<>]+)(?:"|')""",
    re.IGNORECASE,
)


class Crawler:
    """Простой краулер в ширину."""

    def __init__(self, start_url: str, depth: int = 1, max_pages: int = 50,
                 timeout: int = 10, same_host: bool = True) -> None:
        self.start_url = normalize_url(start_url).rstrip("/")
        self.depth = depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.same_host = same_host
        self.start_host = urlparse(self.start_url).hostname

        self.visited: set[str] = set()
        self.urls: set[str] = set()
        self.forms: list[dict] = []
        self.params: set[str] = set()
        self.cookies: set[str] = set()
        self.js_endpoints: set[str] = set()
        self.errors: list[tuple[str, str]] = []

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "CyberSecToolkit-Crawler/1.0"
            )
        })

    def _same_domain(self, url: str) -> bool:
        if not self.same_host:
            return True
        try:
            return urlparse(url).hostname == self.start_host
        except Exception:  # noqa: BLE001
            return False

    def _is_page(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        for ext in SKIP_EXT:
            if path.endswith(ext):
                return False
        return True

    def _extract_from_html(self, html: str, base_url: str) -> None:
        soup = BeautifulSoup(html, "html.parser")

        # --- ссылки ---
        for a in soup.find_all("a", href=True):
            full = urljoin(base_url, a["href"])
            full = full.split("#")[0]
            if full and self._is_page(full):
                self.urls.add(full)

        # --- формы ---
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = (form.get("method") or "GET").upper()
            full_action = urljoin(base_url, action)
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                inputs.append({
                    "name": name,
                    "type": (inp.get("type") or inp.name).lower(),
                    "value": inp.get("value", ""),
                })
                self.params.add(name)
            if inputs:
                self.forms.append({
                    "page": base_url,
                    "action": full_action,
                    "method": method,
                    "inputs": inputs,
                })

        # --- URL с параметрами в тексте ---
        for match in URL_RE.finditer(html):
            candidate = match.group(1)
            full = urljoin(base_url, candidate)
            if self._is_page(full):
                self.urls.add(full)
                if "?" in full:
                    qs = parse_qs(urlparse(full).query)
                    for k in qs:
                        self.params.add(k)

        # --- JS эндпоинты (fetch/axios/ajax) ---
        for js_url_re in [
            re.compile(r"""fetch\(\s*["']([^"']+)["']"""),
            re.compile(r"""axios\.[a-z]+\(\s*["']([^"']+)["']"""),
            re.compile(r"""\.open\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)["']"""),
        ]:
            for m in js_url_re.finditer(html):
                ep = m.group(1)
                full = urljoin(base_url, ep)
                self.js_endpoints.add(full)

    def crawl(self) -> None:
        """Запустить обход."""
        frontier = [(self.start_url, 0)]

        while frontier and len(self.visited) < self.max_pages:
            url, level = frontier.pop(0)
            if url in self.visited:
                continue
            if not self._same_domain(url):
                continue

            self.visited.add(url)
            try:
                r = self.session.get(url, timeout=self.timeout,
                                     allow_redirects=True, verify=False)
            except Exception as exc:  # noqa: BLE001
                self.errors.append((url, str(exc)[:80]))
                continue

            # cookies
            for c in r.cookies:
                self.cookies.add(f"{c.name}={c.value}")

            ctype = r.headers.get("Content-Type", "")
            if "html" not in ctype.lower():
                continue

            self._extract_from_html(r.text, r.url)

            if level < self.depth:
                # Достаём ссылки того же хоста и добавляем во фронтир
                for u in list(self.urls):
                    if u not in self.visited:
                        frontier.append((u, level + 1))

        # --- финальная сводка ---
        self._print_summary()
        self._save_json()

    def _print_summary(self) -> None:
        console.print(f"\n[bold green]✓ Обход завершён[/bold green]")
        console.print(f"  Страниц посещено: {len(self.visited)}")
        console.print(f"  URL найдено:      {len(self.urls)}")
        console.print(f"  Форм найдено:     {len(self.forms)}")
        console.print(f"  Параметров:       {len(self.params)}")
        console.print(f"  JS-эндпоинтов:    {len(self.js_endpoints)}")
        console.print(f"  Cookies:          {len(self.cookies)}")
        console.print(f"  Ошибок:           {len(self.errors)}")

        if self.forms:
            table = Table(title="Формы")
            table.add_column("#", style="yellow")
            table.add_column("Action", style="cyan")
            table.add_column("Method", style="green")
            table.add_column("Поля", style="magenta")
            for i, f in enumerate(self.forms[:20], 1):
                fields = ", ".join(inp["name"] for inp in f["inputs"])
                table.add_row(str(i), f["action"], f["method"], fields)
            console.print(table)

        if self.params:
            console.print("\n[cyan]Параметры:[/cyan] " +
                          ", ".join(sorted(self.params)))

        if self.js_endpoints:
            table = Table(title="JS endpoints (первые 20)")
            table.add_column("#", style="yellow")
            table.add_column("URL", style="green")
            for i, ep in enumerate(sorted(self.js_endpoints)[:20], 1):
                table.add_row(str(i), ep)
            console.print(table)

    def _save_json(self) -> None:
        host = (self.start_host or "unknown").replace(".", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = REPORT_DIR / f"crawl_{host}_{ts}.json"

        data = {
            "start_url": self.start_url,
            "timestamp": ts,
            "stats": {
                "visited": len(self.visited),
                "urls": len(self.urls),
                "forms": len(self.forms),
                "params": len(self.params),
                "js_endpoints": len(self.js_endpoints),
                "cookies": len(self.cookies),
            },
            "visited": sorted(self.visited),
            "urls": sorted(self.urls),
            "forms": self.forms,
            "params": sorted(self.params),
            "cookies": sorted(self.cookies),
            "js_endpoints": sorted(self.js_endpoints),
            "errors": self.errors,
        }
        try:
            out.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                           encoding="utf-8")
            console.print(f"[green]✓ Сохранено: {out}[/green]")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Ошибка сохранения: {exc}[/red]")
            return

        db.save_scan("web_crawl", self.start_url, data["stats"])


def crawl(url: str, depth: int = 1, max_pages: int = 50) -> None:
    """Публичная точка входа."""
    if not confirm_external(url):
        return
    console.print(f"[cyan]Краулю {url} (depth={depth}, max={max_pages})…[/cyan]")
    try:
        c = Crawler(url, depth=depth, max_pages=max_pages)
        c.crawl()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка краулера: {exc}[/red]")
        log.exception("crawl error")


def menu() -> None:
    """Меню Web Crawler."""
    table = Table(title="[bold]Web Crawler[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Обход страницы (глубина + лимит)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])
    if c == "1":
        url = Prompt.ask("URL")
        depth = IntPrompt.ask("Глубина", default=1)
        max_pages = IntPrompt.ask("Максимум страниц", default=50)
        crawl(url, depth, max_pages)