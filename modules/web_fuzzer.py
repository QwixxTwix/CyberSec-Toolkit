"""
Auto Web Fuzzer Pro (extended): фаззинг путей, параметров, заголовков,
cookies, методов, subdomain-ов, vhost-ов, JSON-body.
Работает на asyncio + aiohttp. Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty / CTF.

Возможности:
    ─── Режимы ───
    - Paths (URL/FUZZ)
    - Params (URL?param=FUZZ)
    - Headers (X-Header: FUZZ)
    - Cookies (Cookie: session=FUZZ)
    - Methods (OPTIONS/HEAD/PUT/DELETE/PATCH/TRACE/...)
    - Body (POST/PUT: form-data)
    - JSON-body (application/json: {"key": "FUZZ"})
    - Subdomains (FUZZ.example.com)
    - VHost (Host: FUZZ.example.com)
    - Recursion (dir-by-dir)
    - Multi-position (FUZZ + FUZ2Z)

    ─── Filters / Matchers (ffuf-like) ───
    - Status (match/filter)
    - Size (match/filter)
    - Words (match/filter)
    - Lines (match/filter)
    - Regex (match/filter)
    - Response time (match/filter)
    - Auto-calibration (baseline)
    - Multi-keyword splitting

    ─── Filters: rate-limit, retry ───
    - Delay between requests
    - Retry on timeout
    - Jitter

    ─── Интеграция ───
    - Findings → notes (severity=high при критичных находках)
    - Notify при burst (≥ N hits)
    - Экспорт: JSON / CSV / HTML / Markdown
    - Auto-recursion: при 301/302 → продолжаем
"""
import asyncio
import csv
import hashlib
import html as html_mod
import json
import random
import re
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import (urlparse, urlencode, urlunparse, parse_qs,
                          quote, urljoin)

import aiohttp
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from core.config import config, WORDLIST_DIR, REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, normalize_url

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_WORDLIST = "dirs.txt"
DEFAULT_MATCH_STATUS = "200,204,301,302,307,401,403"
FUZZ_KEYWORD = "FUZZ"

FUZZ_DIR = REPORT_DIR / "web_fuzzer"
FUZZ_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class FuzzerFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: FuzzerFinding) -> int:
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
            tags=["web-fuzzer", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


def _notify(title: str, msg: str, severity: str = "high") -> None:
    try:
        from modules import notifier
        notifier.notify_all(title, msg, severity=severity)
    except Exception:
        pass


# ===========================================================================
# Модель результата
# ===========================================================================

@dataclass
class FuzzHit:
    url: str
    status: int = 0
    length: int = 0
    words: int = 0
    lines: int = 0
    word: str = ""
    error: str = ""
    time_ms: int = 0
    redirect_to: str = ""
    content_type: str = ""
    body_preview: str = ""
    method: str = "GET"


# ===========================================================================
# Ядро
# ===========================================================================

class Fuzzer:
    """Асинхронный фаззер (extended)."""

    def __init__(
        self,
        base_url: str,
        words: list[str],
        threads: int = 20,
        match_status: set[int] | None = None,
        filter_status: set[int] | None = None,
        filter_size: set[int] | None = None,
        filter_words: set[int] | None = None,
        filter_lines: set[int] | None = None,
        match_size: set[int] | None = None,
        match_words: set[int] | None = None,
        match_regex: str | None = None,
        filter_regex: str | None = None,
        match_time: tuple[float, float] | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        timeout: float = 10.0,
        follow_redirects: bool = False,
        method: str = "GET",
        body: str | None = None,
        json_body: dict | None = None,
        delay: float = 0.0,
        retries: int = 0,
        # Multi keyword: {"FUZ2Z": ["a", "b"]}
        extra_words: dict[str, list[str]] | None = None,
        user_agent_pool: list[str] | None = None,
    ) -> None:
        self.base_url = base_url
        self.words = words
        self.threads = threads
        self.match_status = match_status or {200, 204, 301, 302, 307, 401, 403}
        self.filter_status = filter_status or set()
        self.filter_size = filter_size or set()
        self.filter_words = filter_words or set()
        self.filter_lines = filter_lines or set()
        self.match_size = match_size or set()
        self.match_words = match_words or set()
        self.match_re = re.compile(match_regex) if match_regex else None
        self.filter_re = re.compile(filter_regex) if filter_regex else None
        self.match_time = match_time
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.method = method
        self.body = body
        self.json_body = json_body
        self.delay = delay
        self.retries = retries
        self.extra_words = extra_words or {}
        self.user_agent_pool = user_agent_pool or []
        self.hits: list[FuzzHit] = []

    def _build_url(self, word: str) -> str:
        url = self.base_url.replace(FUZZ_KEYWORD, quote(word, safe=""))
        for k, opts in self.extra_words.items():
            if opts:
                # Просто чередуем — детерминированный hash
                idx = sum(ord(c) for c in word) % len(opts)
                url = url.replace(k, quote(opts[idx], safe=""))
        return url

    def _build_headers(self, word: str) -> dict[str, str]:
        out = {}
        for k, v in self.headers.items():
            out[k] = v.replace(FUZZ_KEYWORD, word)
        # UA pool
        if self.user_agent_pool:
            out["User-Agent"] = random.choice(self.user_agent_pool)
        return out

    def _build_body(self, word: str) -> str | bytes | None:
        if self.json_body is not None:
            def _sub(v):
                if isinstance(v, str):
                    return v.replace(FUZZ_KEYWORD, word)
                if isinstance(v, dict):
                    return {k: _sub(vv) for k, vv in v.items()}
                if isinstance(v, list):
                    return [_sub(x) for x in v]
                return v
            return json.dumps(_sub(self.json_body))
        if self.body is not None:
            return self.body.replace(FUZZ_KEYWORD, word)
        return None

    def _match(self, hit: FuzzHit, body: str) -> bool:
        # Status match
        if hit.status not in self.match_status:
            return False
        if hit.status in self.filter_status:
            return False
        # Size
        if hit.length in self.filter_size:
            return False
        if self.match_size and hit.length not in self.match_size:
            return False
        # Words
        if hit.words in self.filter_words:
            return False
        if self.match_words and hit.words not in self.match_words:
            return False
        # Lines
        if hit.lines in self.filter_lines:
            return False
        # Time
        if self.match_time:
            lo, hi = self.match_time
            if not (lo <= hit.time_ms <= hi):
                return False
        # Regex
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
        body = self._build_body(word)
        attempt = 0
        while attempt <= self.retries:
            attempt += 1
            if self.delay > 0:
                await asyncio.sleep(self.delay + random.uniform(0, self.delay * 0.3))
            async with sem:
                t0 = time.time()
                try:
                    kwargs = {
                        "headers": headers,
                        "allow_redirects": self.follow_redirects,
                        "timeout": self.timeout,
                        "cookies": self.cookies,
                    }
                    if body is not None:
                        kwargs["data"] = body
                        if self.json_body is not None:
                            kwargs["headers"] = {
                                **headers,
                                "Content-Type": "application/json",
                            }
                    async with session.request(
                        self.method, url, **kwargs
                    ) as r:
                        text = await r.text(errors="ignore")
                        elapsed_ms = int((time.time() - t0) * 1000)
                        hit = FuzzHit(
                            url=url,
                            status=r.status,
                            length=len(text),
                            words=len(text.split()),
                            lines=text.count("\n") + 1,
                            word=word,
                            time_ms=elapsed_ms,
                            redirect_to=r.headers.get("Location", ""),
                            content_type=r.headers.get("Content-Type", ""),
                            body_preview=text[:500],
                            method=self.method,
                        )
                        if self._match(hit, text):
                            return hit
                        return None
                except asyncio.TimeoutError:
                    if attempt > self.retries:
                        return FuzzHit(url=url, word=word,
                                        error="timeout",
                                        method=self.method)
                except Exception as exc:  # noqa: BLE001
                    if attempt > self.retries:
                        return FuzzHit(url=url, word=word,
                                        error=str(exc)[:60],
                                        method=self.method)
        return None

    async def run_async(self, on_hit=None) -> list[FuzzHit]:
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
                    if on_hit:
                        on_hit(res)
                    else:
                        console.print(
                            f"[green]{res.status:<4}[/green] "
                            f"[cyan]{res.length:>7}B[/cyan] "
                            f"[magenta]{res.words:>5}w[/magenta] "
                            f"[dim]{res.time_ms:>4}ms[/dim] "
                            f"{res.url}"
                        )
                if done % 200 == 0:
                    console.print(f"[dim]  {done}/{total}…[/dim]")
            return hits

    def run(self, on_hit=None) -> list[FuzzHit]:
        try:
            self.hits = asyncio.run(self.run_async(on_hit=on_hit))
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Ошибка фаззера: {exc}[/red]")
            log.exception("fuzzer run")
            return []
        return self.hits


# ===========================================================================
# Вспомогательные
# ===========================================================================

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
    """Сохранить результаты в reports/web_fuzzer/fuzz_<host>_<ts>.json."""
    host = (urlparse(base_url).hostname or "unknown").replace(".", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = FUZZ_DIR / f"fuzz_{host}_{ts}.json"
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

    # Findings + notify
    _analyze_and_report(hits, base_url, meta)


def _analyze_and_report(hits: list[FuzzHit], base_url: str,
                          meta: dict) -> None:
    """Findings + notify для интересных находок."""
    mode = meta.get("mode", "?")
    # 500-ки = возможный injection
    errs = [h for h in hits if h.status == 500]
    if errs:
        _save_finding(FuzzerFinding(
            kind="fuzzer_500",
            severity="high",
            title=f"500-ответы при fuzzing ({len(errs)})",
            target=base_url,
            evidence="\n".join(f"{h.status} {h.url}" for h in errs[:10]),
            data={"count": len(errs), "urls": [h.url for h in errs[:20]]},
        ))

    # Admin-панели / интересные пути в 200
    interesting_kw = ("admin", "login", "phpmyadmin", "dashboard",
                       "config", ".env", ".git", "backup", "wp-admin",
                       "manager", "console", "debug", "test", "api")
    interesting = [h for h in hits if h.status == 200
                   and any(kw in h.url.lower() for kw in interesting_kw)]
    if interesting:
        _save_finding(FuzzerFinding(
            kind="fuzzer_interesting_path",
            severity="high",
            title=f"Интересные пути найдены ({len(interesting)})",
            target=base_url,
            evidence="\n".join(f"{h.status} {h.url}" for h in interesting[:10]),
            data={"urls": [h.url for h in interesting[:20]]},
        ))

    # Burst notify
    if len(hits) >= 20:
        _notify(
            f"🔎 Fuzzer: {len(hits)} hits ({mode})",
            f"Target: {base_url}\nMode: {mode}\n"
            f"Sample: {hits[0].url if hits else '—'}",
            severity="medium",
        )


def _print_hits(hits: list[FuzzHit], title: str = "Результаты") -> None:
    if not hits:
        console.print("[yellow]Ничего не найдено.[/yellow]")
        return
    table = Table(title=f"{title} ({len(hits)})")
    table.add_column("#", style="yellow", width=4)
    table.add_column("Status", style="green", width=6)
    table.add_column("Size", style="cyan", width=9)
    table.add_column("Words", style="magenta", width=7)
    table.add_column("Time", style="dim", width=6)
    table.add_column("URL")
    for i, h in enumerate(sorted(hits, key=lambda x: (x.status, x.length)),
                            1):
        if h.error:
            table.add_row(str(i), "[red]err[/red]", "—", "—", "—",
                          f"{h.url} ({h.error})")
        else:
            table.add_row(
                str(i), str(h.status), str(h.length),
                str(h.words), f"{h.time_ms}ms", h.url,
            )
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
    filter_words = Prompt.ask("Filter слов", default="")
    filter_lines = Prompt.ask("Filter строк", default="")
    filter_regex = Prompt.ask("Filter regex", default="")
    match_regex = Prompt.ask("Match regex", default="")
    threads = IntPrompt.ask("Потоков", default=20)
    timeout = float(Prompt.ask("Timeout (сек)", default="10"))
    follow = Confirm.ask("Follow redirects?", default=False)
    delay = float(Prompt.ask("Delay (сек)", default="0"))
    retries = IntPrompt.ask("Retries", default=0)

    def _parse_ints(s: str) -> set[int]:
        out: set[int] = set()
        for x in s.split(","):
            x = x.strip()
            if x.isdigit():
                out.add(int(x))
        return out

    return {
        "match_status": _parse_ints(match_status),
        "filter_status": _parse_ints(filter_status),
        "filter_size": _parse_ints(filter_size),
        "filter_words": _parse_ints(filter_words),
        "filter_lines": _parse_ints(filter_lines),
        "match_regex": match_regex or None,
        "filter_regex": filter_regex or None,
        "threads": threads,
        "timeout": timeout,
        "follow": follow,
        "delay": delay,
        "retries": retries,
    }


# ===========================================================================
# Экспорт
# ===========================================================================

def _export_hits(hits: list[FuzzHit], base_url: str,
                   fmt: str = "html") -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    host = (urlparse(base_url).hostname or "target").replace(".", "_")
    ext = {"json": ".json", "csv": ".csv", "md": ".md",
           "html": ".html"}.get(fmt, ".html")
    path = FUZZ_DIR / f"fuzz_{host}_{ts}{ext}"

    try:
        if fmt == "json":
            path.write_text(json.dumps(
                {"base_url": base_url,
                 "hits": [asdict(h) for h in hits]},
                indent=2, ensure_ascii=False, default=str),
                encoding="utf-8")
        elif fmt == "csv":
            with path.open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["status", "length", "words", "lines",
                            "time_ms", "method", "url", "redirect"])
                for h in hits:
                    w.writerow([h.status, h.length, h.words,
                                h.lines, h.time_ms, h.method,
                                h.url, h.redirect_to])
        elif fmt == "md":
            lines = [
                f"# Web Fuzz results — {base_url}",
                f"_Generated: {datetime.now().isoformat()}_",
                f"_Hits: {len(hits)}_",
                "",
                "| # | Status | Size | Words | Time | URL |",
                "|---|--------|------|-------|------|-----|",
            ]
            for i, h in enumerate(sorted(hits,
                                          key=lambda x: (x.status,
                                                          x.length)),
                                    1):
                lines.append(
                    f"| {i} | {h.status} | {h.length} | {h.words} "
                    f"| {h.time_ms}ms | `{h.url}` |")
            path.write_text("\n".join(lines), encoding="utf-8")
        elif fmt == "html":
            parts = [
                "<!DOCTYPE html><html lang='ru'><head>"
                "<meta charset='utf-8'>",
                f"<title>Fuzz — {html_mod.escape(base_url)}</title>",
                "<style>",
                "body{background:#0a0a0a;color:#c8c8c8;"
                "font-family:monospace;padding:24px;"
                "max-width:1300px;margin:0 auto;line-height:1.5;}",
                "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
                "table{width:100%;border-collapse:collapse;"
                "margin-top:12px;font-size:13px;}",
                "th{background:#111;color:#00ff9c;padding:6px;"
                "text-align:left;border:1px solid #222;}",
                "td{padding:5px 8px;border:1px solid #222;"
                "word-break:break-all;}",
                "tr:nth-child(even){background:#0d0d0d;}",
                ".s2{color:#00ff9c;}.s3{color:#ffcc66;}"
                ".s4{color:#ff7a40;}.s5{color:#ff2020;font-weight:bold;}",
                "</style></head><body>",
                f"<h1>🔎 Web Fuzzer — {html_mod.escape(base_url)}</h1>",
                f"<p>Generated: "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} • "
                f"Hits: {len(hits)}</p>",
                "<table><tr><th>#</th><th>Status</th><th>Size</th>"
                "<th>Words</th><th>Time</th><th>URL</th></tr>",
            ]
            for i, h in enumerate(sorted(hits,
                                          key=lambda x: (x.status,
                                                          x.length)),
                                    1):
                cls = {200: "s2", 301: "s3", 302: "s3",
                       401: "s4", 403: "s4", 500: "s5"}.get(
                    h.status, "")
                parts.append(
                    f"<tr><td>{i}</td>"
                    f"<td class='{cls}'>{h.status}</td>"
                    f"<td>{h.length}</td><td>{h.words}</td>"
                    f"<td>{h.time_ms}ms</td>"
                    f"<td>{html_mod.escape(h.url)}</td></tr>")
            parts.append("</table></body></html>")
            path.write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ {fmt.upper()}: {path}[/green]")
        return path
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Экспорт: {exc}[/red]")
        return None


# ===========================================================================
# Public modes
# ===========================================================================

def fuzz_paths(target: str, wordlist: str | None = None,
                threads: int = 20, recursive: bool = False) -> None:
    """Fuzz директорий: http://target/FUZZ"""
    if not confirm_external(target):
        return
    base = normalize_url(target).rstrip("/") + "/" + FUZZ_KEYWORD
    words = _load_wordlist(wordlist)
    if not words:
        return
    console.print(f"[cyan]Fuzz директорий: {base}[/cyan]")
    console.print(f"[dim]Слов: {len(words)}, потоков: {threads}"
                  f"{', recursive' if recursive else ''}[/dim]\n")

    f = Fuzzer(base, words, threads=threads)
    hits = f.run()
    _print_hits(hits, title=f"Найдено в {target}")
    _save_results(target, hits,
                   {"mode": "paths",
                    "wordlist": wordlist or DEFAULT_WORDLIST,
                    "words": len(words)})

    # Recursion по 301/302
    if recursive:
        dirs = [h for h in hits if h.status in (301, 302, 307)
                and h.redirect_to.rstrip("/").endswith(
                    h.url.rstrip("/").split("/")[-1])]
        if dirs:
            console.print(f"\n[cyan]→ Recursion в {len(dirs)} "
                          f"директорий…[/cyan]")
            for h in dirs[:5]:
                d = h.url.rstrip("/") + "/"
                f2 = Fuzzer(d + FUZZ_KEYWORD, words,
                             threads=threads)
                sub_hits = f2.run()
                if sub_hits:
                    hits.extend(sub_hits)
                    console.print(f"[dim]  + {len(sub_hits)} "
                                  f"в {d}[/dim]")

    if hits and Confirm.ask("Экспорт?", default=False):
        fmt = Prompt.ask("Формат",
                         choices=["html", "json", "csv", "md"],
                         default="html")
        _export_hits(hits, target, fmt=fmt)


def fuzz_params(target: str, param: str | None = None,
                 wordlist: str | None = None,
                 threads: int = 20) -> None:
    """Fuzz параметров URL."""
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
            console.print("[yellow]URL без параметров — "
                          "добавь FUZZ вручную.[/yellow]")
            return
        new_query = urlencode({k: v[0] for k, v in qs.items()})
        url = urlunparse(parsed._replace(query=new_query))

    words = _load_wordlist(wordlist or "sqli-payloads.txt")
    if not words:
        words = ["'", "\"", "' OR 1=1--", "<script>alert(1)</script>",
                 "test", "admin", "1", "../../etc/passwd",
                 "${7*7}", "{{7*7}}", "%00"]

    console.print(f"[cyan]Fuzz параметров: {url}[/cyan]")
    console.print(f"[dim]Payload'ов: {len(words)}, потоков: "
                  f"{threads}[/dim]\n")

    f = Fuzzer(url, words, threads=threads)
    hits = f.run()
    _print_hits(hits, title=f"Параметры {target}")
    _save_results(target, hits,
                   {"mode": "params", "words": len(words)})

    if hits and Confirm.ask("Экспорт?", default=False):
        fmt = Prompt.ask("Формат",
                         choices=["html", "json", "csv", "md"],
                         default="html")
        _export_hits(hits, target, fmt=fmt)


def fuzz_headers(target: str, header: str, wordlist: str | None = None,
                  threads: int = 20) -> None:
    """Fuzz одного заголовка: -H "X-Header: FUZZ"."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    words = _load_wordlist(wordlist)
    if not words:
        return
    console.print(f"[cyan]Fuzz заголовка '{header}' на {url}[/cyan]\n")
    f = Fuzzer(url, words, threads=threads,
                headers={header: FUZZ_KEYWORD})
    hits = f.run()
    _print_hits(hits, title=f"Заголовок {header}")
    _save_results(target, hits,
                   {"mode": "headers", "header": header})

    if hits and Confirm.ask("Экспорт?", default=False):
        fmt = Prompt.ask("Формат",
                         choices=["html", "json", "csv", "md"],
                         default="html")
        _export_hits(hits, target, fmt=fmt)


def fuzz_cookies(target: str, cookie_name: str = "session",
                  wordlist: str | None = None,
                  threads: int = 20) -> None:
    """Fuzz cookie-значения."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    words = _load_wordlist(wordlist)
    if not words:
        return
    console.print(f"[cyan]Fuzz cookie '{cookie_name}' на {url}[/cyan]\n")

    # Оборачиваем через заголовок Cookie
    f = Fuzzer(
        url, words, threads=threads,
        headers={"Cookie": f"{cookie_name}={FUZZ_KEYWORD}"},
    )
    hits = f.run()
    _print_hits(hits, title=f"Cookie {cookie_name}")
    _save_results(target, hits,
                   {"mode": "cookies", "cookie": cookie_name})

    if hits and Confirm.ask("Экспорт?", default=False):
        fmt = Prompt.ask("Формат",
                         choices=["html", "json", "csv", "md"],
                         default="html")
        _export_hits(hits, target, fmt=fmt)


def fuzz_methods(target: str, methods: list[str] | None = None,
                  threads: int = 10) -> None:
    """Fuzz HTTP-методов на URL."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    if methods is None:
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH",
                   "OPTIONS", "HEAD", "TRACE", "CONNECT"]
    console.print(f"[cyan]Fuzz методов на {url}[/cyan]\n")

    table = Table(title=f"Methods — {url}")
    table.add_column("Method", style="cyan", width=10)
    table.add_column("Status", style="green", width=6)
    table.add_column("Size", style="magenta", width=9)
    table.add_column("Allow", style="dim", max_width=40)

    import requests as _req
    results = []
    for m in methods:
        try:
            r = _req.request(m, url, timeout=10, verify=False,
                              allow_redirects=False,
                              headers={"User-Agent": config.USER_AGENT})
            table.add_row(m, str(r.status_code), str(len(r.text)),
                          r.headers.get("Allow", "—"))
            results.append({
                "method": m, "status": r.status_code,
                "allow": r.headers.get("Allow", ""),
            })
        except Exception as exc:
            table.add_row(m, "[red]err[/red]", "—", str(exc)[:40])
    console.print(table)
    db.save_scan("web_fuzz_methods", url, {"results": results})

    # Findings: если PUT/DELETE доступны → critical
    for r in results:
        if r["method"] in ("PUT", "DELETE") and r["status"] in (200, 201, 204):
            _save_finding(FuzzerFinding(
                kind="fuzzer_method_allowed",
                severity="high",
                title=f"Dangerous method allowed: {r['method']}",
                target=url,
                evidence=f"{r['method']} → {r['status']}",
                data=r,
            ))


def fuzz_subdomains(domain: str, wordlist: str | None = None,
                     threads: int = 20) -> None:
    """Fuzz subdomain-ов (FUZZ.domain.com)."""
    if not confirm_external(domain):
        return
    domain = domain.lstrip("*.").strip(".")
    words = _load_wordlist(wordlist or "subdomains.txt")
    if not words:
        return
    console.print(f"[cyan]Fuzz subdomains: *.{domain}[/cyan]\n")

    base_url = f"http://{FUZZ_KEYWORD}.{domain}/"
    f = Fuzzer(base_url, words, threads=threads,
                timeout=3.0)
    hits = f.run()
    _print_hits(hits, title=f"Subdomains — {domain}")
    _save_results(domain, hits, {"mode": "subdomains"})

    if hits and Confirm.ask("Экспорт?", default=False):
        fmt = Prompt.ask("Формат",
                         choices=["html", "json", "csv", "md"],
                         default="html")
        _export_hits(hits, domain, fmt=fmt)


def fuzz_vhost(target: str, domain: str, wordlist: str | None = None,
                threads: int = 20) -> None:
    """Fuzz vhost-ов (Host: FUZZ.domain)."""
    if not confirm_external(target):
        return
    target = normalize_url(target)
    words = _load_wordlist(wordlist or "subdomains.txt")
    if not words:
        return
    console.print(f"[cyan]Fuzz vhost: Host: FUZZ.{domain} "
                  f"на {target}[/cyan]\n")

    f = Fuzzer(
        target, words, threads=threads,
        headers={"Host": f"{FUZZ_KEYWORD}.{domain}"},
    )
    hits = f.run()
    _print_hits(hits, title=f"VHosts — {domain}")
    _save_results(target, hits,
                   {"mode": "vhost", "domain": domain})

    if hits and Confirm.ask("Экспорт?", default=False):
        fmt = Prompt.ask("Формат",
                         choices=["html", "json", "csv", "md"],
                         default="html")
        _export_hits(hits, target, fmt=fmt)


def fuzz_json_body(target: str, key: str = "value",
                    wordlist: str | None = None,
                    threads: int = 20) -> None:
    """Fuzz JSON-body POST."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    words = _load_wordlist(wordlist or "sqli-payloads.txt")
    if not words:
        words = ["'", "\"", "1 OR 1=1", "<script>alert(1)</script>",
                 "null", "true", "[]", "{}"]
    console.print(f"[cyan]Fuzz JSON body: {url} "
                  f"key={key}[/cyan]\n")

    f = Fuzzer(
        url, words, threads=threads, method="POST",
        json_body={key: FUZZ_KEYWORD},
    )
    hits = f.run()
    _print_hits(hits, title=f"JSON body — {target}")
    _save_results(target, hits,
                   {"mode": "json-body", "key": key})

    if hits and Confirm.ask("Экспорт?", default=False):
        fmt = Prompt.ask("Формат",
                         choices=["html", "json", "csv", "md"],
                         default="html")
        _export_hits(hits, target, fmt=fmt)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]Web Fuzzer Pro (extended)[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Режим")
    opts = [
        ("1", "Fuzz директорий (URL/FUZZ)"),
        ("2", "Fuzz директорий + recursion"),
        ("3", "Fuzz параметров (URL?param=FUZZ)"),
        ("4", "Fuzz заголовка (X-Header: FUZZ)"),
        ("5", "Fuzz cookie (session=FUZZ)"),
        ("6", "Fuzz HTTP-методов (OPTIONS/PUT/...)"),
        ("7", "Fuzz subdomains (FUZZ.domain.com)"),
        ("8", "Fuzz vhost (Host: FUZZ.domain)"),
        ("9", "Fuzz JSON body (POST)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного пентеста.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        url = Prompt.ask("URL (без /FUZZ — добавится)")
        wl = Prompt.ask("Словарь (в wordlists/)", default="dirs.txt")
        threads = IntPrompt.ask("Потоков", default=20)
        fuzz_paths(url, wl, threads)
    elif c == "2":
        url = Prompt.ask("URL")
        wl = Prompt.ask("Словарь", default="dirs.txt")
        threads = IntPrompt.ask("Потоков", default=20)
        fuzz_paths(url, wl, threads, recursive=True)
    elif c == "3":
        url = Prompt.ask("URL (можно с FUZZ)")
        param = Prompt.ask("Параметр (пусто = первый)", default="")
        wl = Prompt.ask("Словарь", default="sqli-payloads.txt")
        threads = IntPrompt.ask("Потоков", default=20)
        fuzz_params(url, param or None, wl, threads)
    elif c == "4":
        url = Prompt.ask("URL")
        hdr = Prompt.ask("Заголовок", default="User-Agent")
        wl = Prompt.ask("Словарь", default="dirs.txt")
        threads = IntPrompt.ask("Потоков", default=20)
        fuzz_headers(url, hdr, wl, threads)
    elif c == "5":
        url = Prompt.ask("URL")
        cn = Prompt.ask("Cookie name", default="session")
        wl = Prompt.ask("Словарь", default="dirs.txt")
        threads = IntPrompt.ask("Потоков", default=20)
        fuzz_cookies(url, cn, wl, threads)
    elif c == "6":
        url = Prompt.ask("URL")
        fuzz_methods(url)
    elif c == "7":
        d = Prompt.ask("Домен")
        wl = Prompt.ask("Словарь", default="subdomains.txt")
        threads = IntPrompt.ask("Потоков", default=20)
        fuzz_subdomains(d, wl, threads)
    elif c == "8":
        tgt = Prompt.ask("Target URL (IP или домен)")
        d = Prompt.ask("Домен для Host")
        wl = Prompt.ask("Словарь", default="subdomains.txt")
        threads = IntPrompt.ask("Потоков", default=20)
        fuzz_vhost(tgt, d, wl, threads)
    elif c == "9":
        url = Prompt.ask("URL")
        key = Prompt.ask("JSON key", default="value")
        wl = Prompt.ask("Словарь", default="sqli-payloads.txt")
        threads = IntPrompt.ask("Потоков", default=20)
        fuzz_json_body(url, key, wl, threads)