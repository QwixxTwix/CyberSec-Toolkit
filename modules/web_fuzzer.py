"""
Auto Web Fuzzer (ffuf-подобный): фаззинг параметров, путей, заголовков.
Работает на asyncio + aiohttp. Author: idqwixxa
"""
import asyncio
import json
import re
from dataclasses import dataclass, asdict, field
from datetime import datetime
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
from pathlib import Path

import aiohttp
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table

from core.config import config, WORDLIST_DIR, REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, normalize_url

console = Console()
log = get_logger(__name__)

DEFAULT_WORDLIST = "dirs.txt"
DEFAULT_MATCH_STATUS = "200,204,301,302,307,401,403"
FUZZ_KEYWORD = "FUZZ"


# ---------------------------------------------------------------------------
# Модель результата
# ---------------------------------------------------------------------------

@dataclass
class FuzzHit:
    url: str
    status: int = 0
    length: int = 0
    words: int = 0
    lines: int = 0
    word: str = ""
    error: str = ""


# ---------------------------------------------------------------------------
# Ядро
# ---------------------------------------------------------------------------

class Fuzzer:
    """Асинхронный фаззер."""

    def __init__(
        self,
        base_url: str,
        words: list[str],
        threads: int = 20,
        match_status: set[int] | None = None,
        filter_status: set[int] | None = None,
        filter_size: set[int] | None = None,
        filter_words: set[int] | None = None,
        match_regex: str | None = None,
        filter_regex: str | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
        follow_redirects: bool = False,
        method: str = "GET",
    ) -> None:
        self.base_url = base_url
        self.words = words
        self.threads = threads
        self.match_status = match_status or {200, 204, 301, 302, 307, 401, 403}
        self.filter_status = filter_status or set()
        self.filter_size = filter_size or set()
        self.filter_words = filter_words or set()
        self.match_re = re.compile(match_regex) if match_regex else None
        self.filter_re = re.compile(filter_regex) if filter_regex else None
        self.headers = headers or {}
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.method = method
        self.hits: list[FuzzHit] = []

    def _build_url(self, word: str) -> str:
        """Подставить слово вместо FUZZ (urlencoded)."""
        from urllib.parse import quote
        return self.base_url.replace(FUZZ_KEYWORD, quote(word, safe=""))

    def _build_headers(self, word: str) -> dict[str, str]:
        out = {}
        for k, v in self.headers.items():
            out[k] = v.replace(FUZZ_KEYWORD, word)
        return out

    def _match(self, hit: FuzzHit, body: str) -> bool:
        """Проверить результат на соответствие фильтрам."""
        if hit.status not in self.match_status:
            return False
        if hit.status in self.filter_status:
            return False
        if hit.length in self.filter_size:
            return False
        if hit.words in self.filter_words:
            return False
        if self.match_re and not self.match_re.search(body):
            return False
        if self.filter_re and self.filter_re.search(body):
            return False
        return True

    async def _check_one(
        self,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        word: str,
    ) -> FuzzHit | None:
        url = self._build_url(word)
        headers = self._build_headers(word)
        async with sem:
            try:
                async with session.request(
                    self.method, url, headers=headers,
                    allow_redirects=self.follow_redirects,
                    timeout=self.timeout,
                ) as r:
                    body = await r.text(errors="ignore")
                    hit = FuzzHit(
                        url=url,
                        status=r.status,
                        length=len(body),
                        words=len(body.split()),
                        lines=body.count("\n") + 1,
                        word=word,
                    )
                    if self._match(hit, body):
                        return hit
                    return None
            except asyncio.TimeoutError:
                return FuzzHit(url=url, word=word, error="timeout")
            except Exception as exc:  # noqa: BLE001
                return FuzzHit(url=url, word=word, error=str(exc)[:60])

    async def run_async(self) -> list[FuzzHit]:
        """Запустить фаззинг."""
        sem = asyncio.Semaphore(self.threads)
        connector = aiohttp.TCPConnector(ssl=False, limit=self.threads)
        base_headers = {"User-Agent": config.USER_AGENT}
        base_headers.update(self.headers)
        async with aiohttp.ClientSession(
            headers=base_headers, connector=connector,
        ) as session:
            tasks = [self._check_one(session, sem, w) for w in self.words]
            total = len(tasks)
            done = 0
            hits: list[FuzzHit] = []
            for coro in asyncio.as_completed(tasks):
                res = await coro
                done += 1
                if res and not res.error:
                    hits.append(res)
                    console.print(
                        f"[green]{res.status:<4}[/green] "
                        f"[cyan]{res.length:>7}B[/cyan] "
                        f"[magenta]{res.words:>5}w[/magenta] "
                        f"{res.url}"
                    )
                if done % 100 == 0:
                    console.print(f"[dim]  {done}/{total}…[/dim]")
            return hits

    def run(self) -> list[FuzzHit]:
        """Синхронная обёртка."""
        try:
            self.hits = asyncio.run(self.run_async())
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Ошибка фаззера: {exc}[/red]")
            log.exception("fuzzer run")
            return []
        return self.hits


# ---------------------------------------------------------------------------
# Вспомогательные
# ---------------------------------------------------------------------------

def _load_wordlist(name: str | None) -> list[str]:
    """Загрузить словарь из wordlists/ или из абсолютного пути."""
    if not name:
        name = DEFAULT_WORDLIST
    p = Path(name)
    if not p.is_absolute() and not p.exists():
        p = WORDLIST_DIR / name
    if not p.exists():
        console.print(f"[red]Словарь не найден: {p}[/red]")
        return []
    try:
        return [w.strip() for w in p.read_text(
            encoding="utf-8", errors="ignore").splitlines()
            if w.strip() and not w.startswith("#")]
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка чтения {p}: {exc}[/red]")
        return []


def _save_results(base_url: str, hits: list[FuzzHit],
                  meta: dict) -> None:
    """Сохранить результаты в reports/fuzz_<host>_<ts>.json."""
    host = (urlparse(base_url).hostname or "unknown").replace(".", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = REPORT_DIR / f"fuzz_{host}_{ts}.json"
    data = {
        "base_url": base_url,
        "timestamp": ts,
        "meta": meta,
        "hits": [asdict(h) for h in hits],
    }
    try:
        out.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                       encoding="utf-8")
        console.print(f"[green]✓ Сохранено: {out}[/green]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка сохранения: {exc}[/red]")
        return
    db.save_scan("web_fuzz", base_url,
                 {"mode": meta.get("mode"), "hits": len(hits)})


def _print_hits(hits: list[FuzzHit], title: str = "Результаты") -> None:
    if not hits:
        console.print("[yellow]Ничего не найдено.[/yellow]")
        return
    table = Table(title=f"{title} ({len(hits)})")
    table.add_column("#", style="yellow", width=4)
    table.add_column("Status", style="green")
    table.add_column("Size", style="cyan")
    table.add_column("Words", style="magenta")
    table.add_column("URL")
    for i, h in enumerate(sorted(hits, key=lambda x: x.status), 1):
        if h.error:
            table.add_row(str(i), "[red]err[/red]", "—", "—",
                          f"{h.url} ({h.error})")
        else:
            table.add_row(str(i), str(h.status), str(h.length),
                          str(h.words), h.url)
    console.print(table)


def _collect_filters() -> dict:
    """Собрать фильтры интерактивно."""
    match_status = Prompt.ask(
        "Match статусы (через запятую)",
        default=DEFAULT_MATCH_STATUS,
    )
    filter_status = Prompt.ask(
        "Filter статусы (через запятую)", default="",
    )
    filter_size = Prompt.ask("Filter размеров (байты)", default="")
    threads = IntPrompt.ask("Потоков", default=20)
    timeout = float(Prompt.ask("Timeout (сек)", default="10"))
    follow = Confirm.ask("Follow redirects?", default=False)

    def _parse_ints(s: str) -> set[int]:
        return {int(x.strip()) for x in s.split(",") if x.strip().isdigit()}

    return {
        "match_status": _parse_ints(match_status),
        "filter_status": _parse_ints(filter_status),
        "filter_size": _parse_ints(filter_size),
        "threads": threads,
        "timeout": timeout,
        "follow": follow,
    }


# ---------------------------------------------------------------------------
# Публичные режимы
# ---------------------------------------------------------------------------

def fuzz_paths(target: str, wordlist: str | None = None,
               threads: int = 20) -> None:
    """
    Fuzz директорий: http://target/FUZZ
    """
    if not confirm_external(target):
        return
    base = normalize_url(target).rstrip("/") + "/" + FUZZ_KEYWORD
    words = _load_wordlist(wordlist)
    if not words:
        return
    console.print(f"[cyan]Fuzz директорий: {base}[/cyan]")
    console.print(f"[dim]Слов: {len(words)}, потоков: {threads}[/dim]\n")

    f = Fuzzer(base, words, threads=threads)
    hits = f.run()
    _print_hits(hits, title=f"Найдено в {target}")
    _save_results(target, hits, {"mode": "paths", "wordlist":
                                  wordlist or DEFAULT_WORDLIST,
                                  "words": len(words)})


def fuzz_params(target: str, param: str | None = None,
                wordlist: str | None = None,
                threads: int = 20) -> None:
    """
    Fuzz параметров URL.
    Если URL содержит FUZZ — использовать его как есть.
    Если указан param — заменить значение этого параметра на FUZZ.
    Иначе fuzz'ить первый параметр.
    """
    if not confirm_external(target):
        return
    url = normalize_url(target)
    if FUZZ_KEYWORD not in url:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if param and param in qs:
            qs[param] = [FUZZ_KEYWORD]
        elif qs:
            first = list(qs.keys())[0]
            qs[first] = [FUZZ_KEYWORD]
        else:
            console.print("[yellow]URL без параметров — добавь FUZZ вручную.[/yellow]")
            return
        new_query = urlencode({k: v[0] for k, v in qs.items()})
        url = urlunparse(parsed._replace(query=new_query))

    words = _load_wordlist(wordlist or "sqli-payloads.txt")
    if not words:
        words = ["'", "\"", "' OR 1=1--", "<script>alert(1)</script>",
                 "test", "admin", "1", "../../etc/passwd"]

    console.print(f"[cyan]Fuzz параметров: {url}[/cyan]")
    console.print(f"[dim]Payload'ов: {len(words)}, потоков: {threads}[/dim]\n")

    f = Fuzzer(url, words, threads=threads)
    hits = f.run()
    _print_hits(hits, title=f"Параметры {target}")
    _save_results(target, hits, {"mode": "params", "words": len(words)})


def fuzz_headers(target: str, header: str, wordlist: str | None = None,
                 threads: int = 20) -> None:
    """
    Fuzz одного заголовка: -H "X-Header: FUZZ"
    """
    if not confirm_external(target):
        return
    url = normalize_url(target)
    words = _load_wordlist(wordlist)
    if not words:
        return
    console.print(f"[cyan]Fuzz заголовка '{header}' на {url}[/cyan]\n")
    f = Fuzzer(url, words, threads=threads, headers={header: FUZZ_KEYWORD})
    hits = f.run()
    _print_hits(hits, title=f"Заголовок {header}")
    _save_results(target, hits, {"mode": "headers", "header": header})


# ---------------------------------------------------------------------------
# Меню
# ---------------------------------------------------------------------------

def menu() -> None:
    """Интерактивное меню фаззера."""
    table = Table(title="[bold]Web Fuzzer (ffuf-like)[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Режим")
    opts = [
        ("1", "Fuzz директорий (URL/FUZZ)"),
        ("2", "Fuzz параметров (URL?param=FUZZ)"),
        ("3", "Fuzz заголовка (X-Header: FUZZ)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        url = Prompt.ask("URL (без /FUZZ — добавится)")
        wl = Prompt.ask("Словарь (в wordlists/)", default="dirs.txt")
        threads = IntPrompt.ask("Потоков", default=20)
        fuzz_paths(url, wl, threads)
    elif c == "2":
        url = Prompt.ask("URL (можно с FUZZ)")
        param = Prompt.ask("Параметр (пусто = первый)", default="")
        wl = Prompt.ask("Словарь", default="sqli-payloads.txt")
        threads = IntPrompt.ask("Потоков", default=20)
        fuzz_params(url, param or None, wl, threads)
    elif c == "3":
        url = Prompt.ask("URL")
        hdr = Prompt.ask("Заголовок", default="User-Agent")
        wl = Prompt.ask("Словарь", default="dirs.txt")
        threads = IntPrompt.ask("Потоков", default=20)
        fuzz_headers(url, hdr, wl, threads)