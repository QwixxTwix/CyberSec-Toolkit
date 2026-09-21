"""
Асинхронный движок: быстрый портскан и HTTP-скан на asyncio + aiohttp.
Работает в разы быстрее ThreadPoolExecutor, особенно для больших диапазонов.
"""
import asyncio
from dataclasses import dataclass

import aiohttp
from rich.console import Console
from rich.prompt import Prompt, IntPrompt
from rich.table import Table

from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, extract_host, normalize_url

console = Console()
log = get_logger(__name__)

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432: "Postgres", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


# ---------------------------------------------------------------------------
# Портскан
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    port: int
    open: bool
    service: str = ""
    banner: str = ""


async def _try_banner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    timeout: float = 1.5,
) -> str:
    """Попытаться прочитать баннер после установки соединения."""
    try:
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        return data.decode(errors="ignore").strip().splitlines()[0][:120]
    except Exception:  # noqa: BLE001
        return ""


async def _scan_one_port(
    host: str,
    port: int,
    sem: asyncio.Semaphore,
    timeout: float,
) -> PortResult:
    """Скан одного порта."""
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            banner = await _try_banner(reader, writer)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            return PortResult(
                port=port,
                open=True,
                service=COMMON_SERVICES.get(port, "unknown"),
                banner=banner,
            )
        except Exception:  # noqa: BLE001
            return PortResult(port=port, open=False)


def _parse_ports(spec: str) -> list[int]:
    """'1-1024' или '22,80,443' → список int."""
    ports: list[int] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        elif chunk.isdigit():
            ports.append(int(chunk))
    return sorted(set(ports))


async def _port_scan_async(
    host: str,
    ports: list[int],
    concurrency: int,
    timeout: float,
) -> list[PortResult]:
    """Асинхронный скан всех портов."""
    sem = asyncio.Semaphore(concurrency)
    tasks = [_scan_one_port(host, p, sem, timeout) for p in ports]

    results: list[PortResult] = []
    total = len(tasks)
    done = 0
    for coro in asyncio.as_completed(tasks):
        r = await coro
        done += 1
        if done % 100 == 0 or done == total:
            console.print(f"[dim]  Прогресс: {done}/{total}[/dim]")
        if r.open:
            results.append(r)
    return results


def async_port_scan(
    target: str,
    ports_spec: str = "1-1024",
    concurrency: int = 500,
    timeout: float = 1.0,
) -> None:
    """Публичный вход: синхронная обёртка над asyncio-сканом."""
    if not confirm_external(target):
        return
    host = extract_host(target)
    ports = _parse_ports(ports_spec)
    console.print(
        f"[cyan]Async портскан {host}, портов: {len(ports)}, "
        f"параллельно: {concurrency}, timeout: {timeout}s[/cyan]"
    )

    try:
        results = asyncio.run(
            _port_scan_async(host, ports, concurrency, timeout)
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка async-скана: {exc}[/red]")
        return

    table = Table(title=f"Открытые порты {host}")
    table.add_column("Порт", style="green")
    table.add_column("Сервис", style="magenta")
    table.add_column("Баннер")
    for r in sorted(results, key=lambda x: x.port):
        table.add_row(str(r.port), r.service, r.banner)
    console.print(table)

    if not results:
        console.print("[yellow]Открытых портов не найдено.[/yellow]")

    db.save_scan(
        "async_portscan",
        host,
        [
            {"port": r.port, "service": r.service, "banner": r.banner}
            for r in results
        ],
    )


# ---------------------------------------------------------------------------
# HTTP-скан
# ---------------------------------------------------------------------------

@dataclass
class HttpResult:
    url: str
    status: int = 0
    title: str = ""
    server: str = ""
    length: int = 0
    error: str = ""


async def _http_check(
    session: aiohttp.ClientSession,
    url: str,
    timeout: float,
    sem: asyncio.Semaphore,
) -> HttpResult:
    """Проверка одного URL."""
    async with sem:
        try:
            async with session.get(url, timeout=timeout,
                                   allow_redirects=True) as resp:
                body = await resp.text(errors="ignore")
                title = ""
                low = body.lower()
                if "<title>" in low:
                    start = low.index("<title>") + 7
                    end = low.find("</title>", start)
                    if end > start:
                        title = body[start:end].strip()[:80]
                return HttpResult(
                    url=url,
                    status=resp.status,
                    title=title,
                    server=resp.headers.get("Server", ""),
                    length=len(body),
                )
        except asyncio.TimeoutError:
            return HttpResult(url=url, error="timeout")
        except Exception as exc:  # noqa: BLE001
            return HttpResult(url=url, error=str(exc)[:60])


async def _http_scan_async(
    urls: list[str],
    concurrency: int,
    timeout: float,
) -> list[HttpResult]:
    """Параллельный HTTP-скан."""
    sem = asyncio.Semaphore(concurrency)
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CyberSecToolkit/1.0"
    }
    connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)
    async with aiohttp.ClientSession(headers=headers,
                                     connector=connector) as session:
        tasks = [_http_check(session, u, timeout, sem) for u in urls]
        return await asyncio.gather(*tasks)


def async_http_scan(
    target: str,
    paths_spec: str,
    concurrency: int = 50,
    timeout: float = 5.0,
) -> None:
    """Асинхронный HTTP-скан набора путей."""
    if not confirm_external(target):
        return

    base = normalize_url(target).rstrip("/")
    paths = [p.strip().lstrip("/") for p in paths_spec.split(",") if p.strip()]
    if not paths:
        console.print("[red]Пустой список путей.[/red]")
        return

    urls = [f"{base}/{p}" for p in paths]
    console.print(
        f"[cyan]Async HTTP-скан {len(urls)} URL, параллельно: {concurrency}[/cyan]"
    )

    try:
        results = asyncio.run(_http_scan_async(urls, concurrency, timeout))
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return

    table = Table(title=f"HTTP-скан {base}")
    table.add_column("URL", style="cyan")
    table.add_column("Статус", style="green")
    table.add_column("Title", style="magenta")
    table.add_column("Len", style="white")

    for r in sorted(results, key=lambda x: x.status):
        if r.error:
            table.add_row(r.url, f"[red]{r.error}[/red]", "—", "—")
        else:
            if 200 <= r.status < 300:
                color = "green"
            elif 300 <= r.status < 400:
                color = "yellow"
            elif r.status >= 400:
                color = "red"
            else:
                color = "white"
            table.add_row(
                r.url,
                f"[{color}]{r.status}[/{color}]",
                r.title or "—",
                str(r.length),
            )
    console.print(table)

    db.save_scan(
        "async_http_scan",
        base,
        [
            {"url": r.url, "status": r.status, "title": r.title,
             "server": r.server, "len": r.length, "err": r.error}
            for r in results
        ],
    )


# ---------------------------------------------------------------------------
# Меню
# ---------------------------------------------------------------------------

def menu() -> None:
    """Меню async-движка."""
    table = Table(title="[bold]Async Engine[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Быстрый портскан (asyncio)"),
        ("2", "Пакетный HTTP-скан URL"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])
    if c == "1":
        host = Prompt.ask("Хост")
        ports = Prompt.ask("Порты", default="1-1024")
        conc = IntPrompt.ask("Параллельно", default=500)
        to = float(Prompt.ask("Timeout (сек)", default="1.0"))
        async_port_scan(host, ports, conc, to)
    elif c == "2":
        target = Prompt.ask("Базовый URL")
        paths = Prompt.ask("Пути через запятую",
                           default="admin,login,api,robots.txt,.env")
        conc = IntPrompt.ask("Параллельно", default=50)
        async_http_scan(target, paths, conc)