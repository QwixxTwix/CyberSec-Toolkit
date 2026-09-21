"""
Асинхронный движок: быстрый портскан и HTTP-скан на asyncio + aiohttp.
Author: idqwixxa

Возможности:
    - Резолв host (домен → список IP, IPv4 + IPv6)
    - TCP-скан с баннер-граббингом
    - UDP-скан (DNS/NTP/SNMP/SSDP)
    - Определение версии сервиса по баннеру
    - Rate-limit + retry + timeout
    - Прогресс с ETA и скоростью
    - Batch-хосты (несколько целей)
    - HTTP-скан с методами (GET/HEAD/POST), follow-redirect
    - Сохранение в JSON / CSV / Markdown
"""
import asyncio
import csv
import ipaddress
import json
import socket
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

import aiohttp
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn,
    TimeElapsedColumn, TimeRemainingColumn,
)

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, extract_host, normalize_url

console = Console()
log = get_logger(__name__)

ASYNC_DIR = REPORT_DIR / "async_engine"
ASYNC_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) CyberSecToolkit/1.0"

# Расширенный список сервисов
COMMON_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp-server", 68: "dhcp-client", 69: "tftp",
    80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap",
    179: "bgp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 500: "isakmp", 514: "syslog", 515: "lpd",
    548: "afp", 554: "rtsp", 587: "submission", 631: "ipp",
    636: "ldaps", 873: "rsync", 990: "ftps", 993: "imaps",
    995: "pop3s", 1025: "rpc", 1080: "socks", 1111: "lmsocial",
    1433: "mssql", 1434: "mssql-browser", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2086: "whm", 2087: "whm-ssl", 2095: "webmail", 2096: "webmail-ssl",
    2181: "zookeeper", 2222: "ssh-alt", 2375: "docker",
    2376: "docker-ssl", 2379: "etcd", 2380: "etcd-peer",
    2480: "couchdb", 3000: "grafana", 3128: "squid",
    3306: "mysql", 3389: "rdp", 4000: "icq",
    4443: "https-alt", 4505: "salt-master", 4506: "salt-minion",
    5000: "http-alt", 5001: "sotware", 5432: "postgres",
    5555: "adb", 5601: "kibana", 5672: "amqp", 5900: "vnc",
    5901: "vnc-1", 5984: "couchdb", 5985: "winrm-http",
    5986: "winrm-https", 6000: "x11", 6379: "redis",
    6443: "kube-api", 7001: "weblogic", 7077: "spark",
    7443: "https-alt", 7474: "neo4j", 8000: "http-alt",
    8008: "http-alt", 8009: "ajp", 8010: "http-alt",
    8043: "https-alt", 8069: "odoo", 8080: "http-alt",
    8081: "http-alt", 8082: "http-alt", 8088: "http-alt",
    8090: "http-alt", 8099: "http-alt", 8161: "activemq",
    8180: "http-alt", 8200: "vault", 8300: "consul-ssl",
    8333: "bitcoin", 8443: "https-alt", 8500: "consul",
    8529: "arangodb", 8834: "nessus", 8888: "http-alt",
    9000: "http-alt", 9001: "tor", 9042: "cassandra",
    9060: "http-alt", 9090: "http-alt", 9092: "kafka",
    9100: "jetdirect", 9200: "elasticsearch",
    9300: "elasticsearch-cluster", 9443: "https-alt",
    9500: "http-alt", 9800: "http-alt", 9981: "http-alt",
    9999: "http-alt", 10000: "webmin", 10250: "kubelet",
    11211: "memcached", 15672: "rabbitmq-mgmt",
    16379: "redis-cluster", 27017: "mongodb",
    27018: "mongodb-shard", 28017: "mongodb-web",
    50000: "sap", 50030: "hadoop-nn", 50060: "hadoop-dn",
    50070: "hadoop-web", 50075: "hadoop-dn-web",
    50090: "hadoop-sn", 61616: "activemq-openwire",
}


TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110,
    111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444,
    445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873,
    990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720,
    1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128,
    3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190,
    5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000,
    32768, 49152, 49153, 49154, 49155, 49156, 49157,
]


# ===========================================================================
# Модели
# ===========================================================================

@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"     # tcp | udp
    open: bool = False
    service: str = ""
    version: str = ""
    banner: str = ""
    latency_ms: float = 0.0


@dataclass
class HttpResult:
    url: str
    method: str = "GET"
    status: int = 0
    title: str = ""
    server: str = ""
    length: int = 0
    content_type: str = ""
    redirect_to: str = ""
    latency_ms: float = 0.0
    error: str = ""


# ===========================================================================
# Утилиты
# ===========================================================================

def _parse_ports(spec: str) -> list[int]:
    """'1-1024' или '22,80,443' → список int."""
    ports: list[int] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            try:
                a, b = chunk.split("-", 1)
                a_i, b_i = int(a), int(b)
                if a_i <= b_i:
                    ports.extend(range(a_i, b_i + 1))
            except ValueError:
                continue
        elif chunk.isdigit():
            ports.append(int(chunk))
    return sorted(set(p for p in ports if 1 <= p <= 65535))


def _resolve_target(target: str) -> list[str]:
    """Резолв hostname → список IP (v4 + v6)."""
    host = extract_host(target)
    # Проверяем: уже IP?
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass

    ips: set[str] = set()
    try:
        infos = socket.getaddrinfo(host, None)
        for fam, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            ips.add(ip)
    except socket.gaierror as exc:
        log.warning("resolve %s: %s", host, exc)
    return sorted(ips)


def _detect_version(banner: str) -> str:
    """Извлечь версию сервиса из баннера (эвристика)."""
    if not banner:
        return ""
    import re
    # SSH: SSH-2.0-OpenSSH_8.2p1
    m = re.search(r"SSH-2\.0-([\w._-]+)", banner)
    if m:
        return m.group(1)
    # HTTP Server: nginx/1.18.0
    m = re.search(r"Server:\s*([\w./\-() ]+)", banner, re.IGNORECASE)
    if m:
        return m.group(1).strip()[:60]
    # FTP: 220 ProFTPD 1.3.5
    m = re.search(r"(?:FTP|220)[\s\-]*([\w./\-]+\s[\d.]+)", banner)
    if m:
        return m.group(1).strip()[:60]
    # Generic version
    m = re.search(r"([A-Za-z][\w.\-]+\s+v?[\d.]+)", banner)
    if m:
        return m.group(1).strip()[:60]
    return ""


def _save_results_json(name: str, data: Any) -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(c if c.isalnum() or c in "._-" else "_"
                   for c in name)[:40]
    path = ASYNC_DIR / f"{safe}_{ts}.json"
    try:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False,
                                    default=str),
                        encoding="utf-8")
        console.print(f"[green]✓ JSON: {path}[/green]")
        return path
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка JSON: {exc}[/red]")
        return None


def _save_results_csv(name: str, rows: list[dict]) -> Path | None:
    if not rows:
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(c if c.isalnum() or c in "._-" else "_"
                   for c in name)[:40]
    path = ASYNC_DIR / f"{safe}_{ts}.csv"
    try:
        keys = sorted({k for r in rows for k in r.keys()})
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(r)
        console.print(f"[green]✓ CSV: {path}[/green]")
        return path
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка CSV: {exc}[/red]")
        return None


# ===========================================================================
# TCP-портскан
# ===========================================================================

async def _try_banner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    probe: bytes = b"",
    timeout: float = 1.5,
) -> str:
    """Попытаться прочитать баннер. Если probe непустой — сначала шлём его."""
    try:
        if probe:
            writer.write(probe)
            await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        text = data.decode("utf-8", errors="ignore")
        # Берём первые непустые строки
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        return " | ".join(lines[:2])[:200]
    except Exception:  # noqa: BLE001
        return ""


# HTTP-probe для портов без баннера (80/8080/443)
_HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"


async def _scan_one_port(
    host: str, port: int, sem: asyncio.Semaphore,
    timeout: float, retry: int = 0,
) -> PortResult:
    async with sem:
        last_err = ""
        for attempt in range(retry + 1):
            start = time.time()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=timeout,
                )
                latency = round((time.time() - start) * 1000, 1)
                # Для HTTP-портов — шлём probe
                probe = b""
                if port in (80, 8080, 8000, 8008, 8088, 8888, 9000,
                            9090, 9200, 5601, 3000):
                    probe = _HTTP_PROBE
                banner = await _try_banner(reader, writer, probe,
                                            timeout=timeout)
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                return PortResult(
                    port=port, protocol="tcp", open=True,
                    service=COMMON_SERVICES.get(port, "unknown"),
                    version=_detect_version(banner),
                    banner=banner,
                    latency_ms=latency,
                )
            except asyncio.TimeoutError:
                last_err = "timeout"
            except ConnectionRefusedError:
                last_err = "refused"
            except OSError as exc:
                last_err = str(exc)[:60]
            except Exception as exc:  # noqa: BLE001
                last_err = str(exc)[:60]
            if last_err == "refused":
                break
            if attempt < retry:
                await asyncio.sleep(0.2)
        return PortResult(port=port, protocol="tcp", open=False)


async def _port_scan_async(
    host: str, ports: list[int], concurrency: int,
    timeout: float, retry: int, rate_limit: float,
    progress: Progress | None = None, task_id: Any = None,
) -> list[PortResult]:
    sem = asyncio.Semaphore(concurrency)
    results: list[PortResult] = []
    total = len(ports)
    done = 0

    async def _wrap(p: int) -> PortResult:
        nonlocal done
        if rate_limit > 0:
            await asyncio.sleep(rate_limit)
        r = await _scan_one_port(host, p, sem, timeout, retry)
        done += 1
        if progress and task_id is not None:
            progress.update(task_id, completed=done,
                             info=f"{host}:{p}" if r.open else host)
        return r

    tasks = [_wrap(p) for p in ports]
    for coro in asyncio.as_completed(tasks):
        r = await coro
        if r.open:
            results.append(r)
    return results


def _print_port_table(host: str, results: list[PortResult],
                      title_suffix: str = "") -> None:
    if not results:
        console.print(f"[yellow]{host}: открытых портов "
                      f"не найдено {title_suffix}[/yellow]")
        return
    table = Table(title=f"🔓 {host} — {len(results)} открытых портов "
                        f"{title_suffix}")
    table.add_column("Port", style="green", width=8)
    table.add_column("Proto", style="dim", width=6)
    table.add_column("Service", style="magenta", width=14)
    table.add_column("Version", style="cyan", max_width=32)
    table.add_column("Lat", style="dim", width=8)
    table.add_column("Banner", style="white", max_width=50)
    for r in sorted(results, key=lambda x: (x.port, x.protocol)):
        table.add_row(
            str(r.port), r.protocol, r.service,
            r.version[:32], f"{r.latency_ms}ms",
            r.banner[:50],
        )
    console.print(table)


def async_port_scan(
    target: str,
    ports_spec: str = "1-1024",
    concurrency: int = 500,
    timeout: float = 1.0,
    retry: int = 0,
    rate_limit: float = 0.0,
    export: bool = True,
) -> list[PortResult]:
    """TCP-портскан с резолвом, баннерами и версиями."""
    if not confirm_external(target):
        return []

    ips = _resolve_target(target)
    if not ips:
        console.print(f"[red]Не удалось резолвить {target}[/red]")
        return []

    ports = _parse_ports(ports_spec)
    if not ports:
        console.print("[red]Пустой список портов.[/red]")
        return []

    console.print(f"[cyan]🎯 TCP-скан: {target} → {len(ips)} IP "
                  f"× {len(ports)} портов, concurrent={concurrency}, "
                  f"timeout={timeout}s[/cyan]")

    all_results: dict[str, list[PortResult]] = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        for ip in ips:
            task = progress.add_task(f"scan {ip}", total=len(ports))
            try:
                results = asyncio.run(_port_scan_async(
                    ip, ports, concurrency, timeout, retry, rate_limit,
                    progress, task,
                ))
            except KeyboardInterrupt:
                console.print("\n[yellow]Прервано.[/yellow]")
                break
            except Exception as exc:  # noqa: BLE001
                console.print(f"[red]Ошибка на {ip}: {exc}[/red]")
                results = []
            all_results[ip] = results

    # Печать
    for ip, results in all_results.items():
        _print_port_table(ip, results)

    # Сохранение
    if export:
        payload = {
            "target": target,
            "ips": ips,
            "ports_scanned": len(ports),
            "ts": datetime.now().isoformat(timespec="seconds"),
            "results": {
                ip: [asdict(r) for r in res]
                for ip, res in all_results.items()
            },
        }
        _save_results_json(target, payload)
        csv_rows: list[dict] = []
        for ip, res in all_results.items():
            for r in res:
                csv_rows.append({"ip": ip, **asdict(r)})
        _save_results_csv(target, csv_rows)

    # В БД
    try:
        db.save_scan("async_portscan", target, {
            "ips": ips,
            "results": {
                ip: [{"port": r.port, "service": r.service,
                      "version": r.version, "banner": r.banner}
                     for r in res]
                for ip, res in all_results.items()
            },
        })
    except Exception as exc:  # noqa: BLE001
        log.warning("save db: %s", exc)

    return [r for res in all_results.values() for r in res]


def async_port_scan_batch(
    targets: list[str], ports_spec: str = "1-1024",
    concurrency: int = 300, timeout: float = 1.0,
) -> dict[str, list[PortResult]]:
    """Batch: несколько целей за один вызов."""
    out: dict[str, list[PortResult]] = {}
    for i, t in enumerate(targets, 1):
        console.print(f"\n[bold cyan]({i}/{len(targets)}) {t}[/bold cyan]")
        try:
            out[t] = async_port_scan(t, ports_spec, concurrency, timeout,
                                      export=False)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]{t}: {exc}[/red]")
            out[t] = []
    # Сводный экспорт
    _save_results_json(f"batch_{len(targets)}", {
        t: [asdict(r) for r in res] for t, res in out.items()
    })
    return out


# ===========================================================================
# UDP-скан (для DNS/NTP/SNMP/SSDP)
# ===========================================================================

UDP_PROBES: dict[int, bytes] = {
    53:  b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         b"\x07version\x04bind\x00\x00\x10\x00\x03",  # DNS CHAOS
    123: b"\x1b" + b"\x00" * 47,  # NTP client
    161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19"
         b"\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00"
         b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",  # SNMP v2c
    1900: b"M-SEARCH * HTTP/1.1\r\n"
          b"HOST: 239.255.255.250:1900\r\n"
          b"MAN: \"ssdp:discover\"\r\n"
          b"MX: 1\r\nST: ssdp:all\r\n\r\n",  # SSDP
}


class _UDPProto(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.data = b""
        self.done = asyncio.Event()

    def datagram_received(self, data: bytes, addr) -> None:
        self.data = data
        self.done.set()

    def error_received(self, exc) -> None:
        self.done.set()


async def _udp_probe(host: str, port: int, timeout: float,
                     sem: asyncio.Semaphore) -> PortResult:
    async with sem:
        start = time.time()
        loop = asyncio.get_event_loop()
        proto = _UDPProto()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: proto, remote_addr=(host, port),
            )
            probe = UDP_PROBES.get(port, b"\x00")
            transport.sendto(probe)
            try:
                await asyncio.wait_for(proto.done.wait(), timeout=timeout)
                banner = proto.data.decode("utf-8", errors="ignore")[:200]
                latency = round((time.time() - start) * 1000, 1)
                return PortResult(
                    port=port, protocol="udp", open=True,
                    service=COMMON_SERVICES.get(port, "unknown"),
                    version=_detect_version(banner),
                    banner=banner, latency_ms=latency,
                )
            except asyncio.TimeoutError:
                return PortResult(port=port, protocol="udp", open=False)
            finally:
                transport.close()
        except Exception:  # noqa: BLE001
            return PortResult(port=port, protocol="udp", open=False)


async def _udp_scan_async(host: str, ports: list[int],
                           timeout: float,
                           concurrency: int) -> list[PortResult]:
    sem = asyncio.Semaphore(concurrency)
    tasks = [_udp_probe(host, p, timeout, sem) for p in ports]
    out: list[PortResult] = []
    for coro in asyncio.as_completed(tasks):
        r = await coro
        if r.open:
            out.append(r)
    return out


def async_udp_scan(
    target: str,
    ports_spec: str = "53,123,161,1900",
    timeout: float = 2.0,
    concurrency: int = 100,
) -> list[PortResult]:
    """UDP-скан для DNS/NTP/SNMP/SSDP."""
    if not confirm_external(target):
        return []
    ips = _resolve_target(target)
    ports = _parse_ports(ports_spec)

    console.print(f"[cyan]🎯 UDP-скан: {target} → {len(ips)} IP "
                  f"× {len(ports)} портов[/cyan]")

    all_results: list[PortResult] = []
    for ip in ips:
        try:
            results = asyncio.run(
                _udp_scan_async(ip, ports, timeout, concurrency)
            )
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]UDP ошибка на {ip}: {exc}[/red]")
            continue
        all_results.extend(results)
        _print_port_table(ip, results, "(UDP)")

    _save_results_json(f"udp_{target}",
                       [asdict(r) for r in all_results])
    return all_results


# ===========================================================================
# HTTP-скан
# ===========================================================================

async def _http_check(
    session: aiohttp.ClientSession, url: str, method: str,
    timeout: float, sem: asyncio.Semaphore, follow: bool,
) -> HttpResult:
    async with sem:
        start = time.time()
        try:
            async with session.request(
                method, url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=follow, ssl=False,
            ) as resp:
                body = await resp.text(errors="ignore")
                latency = round((time.time() - start) * 1000, 1)
                # Title
                title = ""
                low = body.lower()
                if "<title>" in low:
                    s = low.index("<title>") + 7
                    e = low.find("</title>", s)
                    if e > s:
                        title = body[s:e].strip()[:120]
                return HttpResult(
                    url=url, method=method, status=resp.status,
                    title=title, server=resp.headers.get("Server", ""),
                    length=len(body),
                    content_type=resp.headers.get("Content-Type", "")[:60],
                    redirect_to=resp.headers.get("Location", "")[:120],
                    latency_ms=latency,
                )
        except asyncio.TimeoutError:
            return HttpResult(url=url, method=method, error="timeout")
        except aiohttp.ClientConnectorError as exc:
            return HttpResult(url=url, method=method,
                              error=f"conn: {str(exc)[:60]}")
        except Exception as exc:  # noqa: BLE001
            return HttpResult(url=url, method=method,
                              error=str(exc)[:80])


async def _http_scan_async(
    urls: list[str], methods: list[str], concurrency: int,
    timeout: float, follow: bool,
    progress: Progress | None = None, task_id: Any = None,
) -> list[HttpResult]:
    sem = asyncio.Semaphore(concurrency)
    headers = {"User-Agent": config.USER_AGENT or DEFAULT_UA}
    connector = aiohttp.TCPConnector(ssl=False, limit=concurrency,
                                      force_close=True)
    results: list[HttpResult] = []
    total = len(urls) * len(methods)
    done = 0

    async with aiohttp.ClientSession(headers=headers,
                                     connector=connector) as session:
        tasks = []
        for url in urls:
            for method in methods:
                tasks.append(_http_check(session, url, method,
                                          timeout, sem, follow))
        for coro in asyncio.as_completed(tasks):
            r = await coro
            done += 1
            if progress and task_id is not None:
                progress.update(task_id, completed=done)
            results.append(r)
    return results


def async_http_scan(
    target: str,
    paths_spec: str = "admin,login,api,robots.txt,.env",
    concurrency: int = 50,
    timeout: float = 5.0,
    methods: str = "GET",
    follow: bool = True,
    export: bool = True,
) -> list[HttpResult]:
    """HTTP-скан с методами и follow-redirect."""
    if not confirm_external(target):
        return []

    base = normalize_url(target).rstrip("/")
    paths = [p.strip().lstrip("/") for p in paths_spec.split(",")
             if p.strip()]
    if not paths:
        console.print("[red]Пустой список путей.[/red]")
        return []

    urls = [f"{base}/{p}" if p else base for p in paths]
    method_list = [m.strip().upper() for m in methods.split(",")
                   if m.strip()]
    if not method_list:
        method_list = ["GET"]

    console.print(f"[cyan]🎯 HTTP-скан: {len(urls)} URL × "
                  f"{len(method_list)} методов, concurrent={concurrency}"
                  f"[/cyan]")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("http-scan",
                                      total=len(urls) * len(method_list))
            results = asyncio.run(_http_scan_async(
                urls, method_list, concurrency, timeout, follow,
                progress, task,
            ))
    except KeyboardInterrupt:
        console.print("\n[yellow]Прервано.[/yellow]")
        return []
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return []

    _print_http_table(base, results)

    if export:
        _save_results_json(f"http_{base}",
                           [asdict(r) for r in results])
        _save_results_csv(f"http_{base}",
                          [asdict(r) for r in results])

    try:
        db.save_scan("async_http_scan", base,
                     [asdict(r) for r in results])
    except Exception as exc:  # noqa: BLE001
        log.warning("save db: %s", exc)
    return results


def _print_http_table(base: str, results: list[HttpResult]) -> None:
    if not results:
        console.print("[yellow]Пусто.[/yellow]")
        return
    table = Table(title=f"🌐 HTTP-скан {base} — {len(results)} ответов")
    table.add_column("Method", style="dim", width=6)
    table.add_column("Status", style="green", width=7)
    table.add_column("Len", style="cyan", width=8)
    table.add_column("Lat", style="dim", width=8)
    table.add_column("Title", style="magenta", max_width=35)
    table.add_column("URL", style="white", max_width=60)

    def _sort_key(r: HttpResult) -> tuple:
        return (r.status or 999, r.url)

    for r in sorted(results, key=_sort_key):
        if r.error:
            table.add_row(r.method, "[red]err[/red]", "—", "—",
                          r.error[:30], r.url[:60])
            continue
        if 200 <= r.status < 300:
            color = "green"
        elif 300 <= r.status < 400:
            color = "yellow"
        elif r.status >= 500:
            color = "red"
        else:
            color = "white"
        table.add_row(r.method, f"[{color}]{r.status}[/{color}]",
                      str(r.length), f"{r.latency_ms:.0f}ms",
                      r.title[:35] or "—", r.url[:60])
    console.print(table)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]⚡ Async Engine[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "TCP-портскан (быстрый)"),
        ("2", "TCP-портскан (с retry + rate-limit)"),
        ("3", "TCP-портскан batch (несколько целей)"),
        ("4", "UDP-скан (DNS/NTP/SNMP/SSDP)"),
        ("5", "HTTP-скан URL-списка"),
        ("6", "HTTP-скан с методами (GET,HEAD,POST)"),
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
        host = Prompt.ask("Хост")
        ports = Prompt.ask("Порты", default="1-1024")
        conc = IntPrompt.ask("Параллельно", default=300)
        to = float(Prompt.ask("Timeout", default="1.5"))
        retry = IntPrompt.ask("Retry", default=1)
        rl = float(Prompt.ask("Rate-limit (сек/порт)", default="0.0"))
        async_port_scan(host, ports, conc, to, retry, rl)
    elif c == "3":
        src = Prompt.ask("Файл или хосты через запятую")
        import os
        if os.path.isfile(src):
            targets = [l.strip() for l in open(src, encoding="utf-8",
                                                errors="ignore")
                       if l.strip()]
        else:
            targets = [t.strip() for t in src.split(",") if t.strip()]
        ports = Prompt.ask("Порты", default="1-1024")
        async_port_scan_batch(targets, ports)
    elif c == "4":
        host = Prompt.ask("Хост")
        ports = Prompt.ask("UDP-порты", default="53,123,161,1900")
        async_udp_scan(host, ports)
    elif c == "5":
        target = Prompt.ask("Базовый URL")
        paths = Prompt.ask("Пути", default="admin,login,api,robots.txt,.env")
        conc = IntPrompt.ask("Параллельно", default=50)
        async_http_scan(target, paths, conc)
    elif c == "6":
        target = Prompt.ask("Базовый URL")
        paths = Prompt.ask("Пути", default=",admin,api,robots.txt")
        methods = Prompt.ask("Методы через запятую",
                             default="GET,HEAD,OPTIONS")
        conc = IntPrompt.ask("Параллельно", default=30)
        async_http_scan(target, paths, conc, methods=methods)