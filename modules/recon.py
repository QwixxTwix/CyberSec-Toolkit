"""Модуль разведки: WHOIS, DNS, subdomains, порты, geoip, fingerprint."""
import socket
import concurrent.futures
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

import dns.resolver
import requests
import whois as whois_lib

from core.config import config, WORDLIST_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, extract_host, print_kv, normalize_url

console = Console()
log = get_logger(__name__)

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "Postgres",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def parse_ports(spec: str) -> list[int]:
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


def whois_lookup(target: str) -> None:
    """WHOIS lookup домена."""
    if not confirm_external(target):
        return
    host = extract_host(target)
    console.print(f"[cyan]WHOIS → {host}[/cyan]")
    try:
        data = whois_lib.whois(host)
        result = {
            "domain": data.domain_name,
            "registrar": data.registrar,
            "creation_date": str(data.creation_date),
            "expiration_date": str(data.expiration_date),
            "name_servers": data.name_servers,
            "org": data.org,
            "country": data.country,
        }
        print_kv(result)
        db.save_scan("whois", host, result)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]WHOIS ошибка: {exc}[/red]")
        log.error("WHOIS %s: %s", host, exc)


def dns_enum(target: str) -> None:
    """DNS-энумерация: A, AAAA, MX, NS, TXT, CNAME, SOA."""
    host = extract_host(target)
    console.print(f"[cyan]DNS enumeration → {host}[/cyan]")
    result: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            answers = dns.resolver.resolve(host, rtype, lifetime=5)
            result[rtype] = [str(a).strip('"') for a in answers]
        except Exception:  # noqa: BLE001
            result[rtype] = []
    table = Table(title=f"DNS {host}")
    table.add_column("Тип", style="magenta")
    table.add_column("Значение", style="green")
    for rtype, values in result.items():
        for v in values:
            table.add_row(rtype, v)
    console.print(table)
    db.save_scan("dns", host, result)


def _check_subdomain(sub: str, domain: str) -> tuple[str, str] | None:
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return fqdn, ip
    except socket.gaierror:
        return None


def subdomain_scan(target: str, threads: int = 50) -> None:
    """Брутфорс поддоменов по словарю."""
    domain = extract_host(target)
    wordlist_file = WORDLIST_DIR / "subdomains.txt"
    if not wordlist_file.exists():
        console.print("[red]Нет wordlists/subdomains.txt[/red]")
        return
    words = [w.strip() for w in wordlist_file.read_text().splitlines() if w.strip()]
    console.print(f"[cyan]Сканирую {len(words)} поддоменов для {domain}...[/cyan]")
    found: list[tuple[str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_check_subdomain, w, domain) for w in words]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                found.append(res)
                console.print(f"[green]✓ {res[0]} → {res[1]}[/green]")
    db.save_scan("subdomains", domain, found)


def _grab_banner(sock: socket.socket) -> str:
    try:
        sock.settimeout(1.5)
        data = sock.recv(1024)
        return data.decode(errors="ignore").strip().splitlines()[0][:120]
    except Exception:  # noqa: BLE001
        return ""


def _scan_port(host: str, port: int) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            if s.connect_ex((host, port)) == 0:
                banner = _grab_banner(s)
                return {
                    "port": port,
                    "service": COMMON_PORTS.get(port, "unknown"),
                    "banner": banner,
                }
    except Exception:  # noqa: BLE001
        return None
    return None


def port_scan(target: str, ports_spec: str = "1-1024", threads: int | None = None) -> None:
    """Многопоточный TCP-скан с баннерами."""
    if not confirm_external(target):
        return
    host = extract_host(target)
    ports = parse_ports(ports_spec)
    threads = threads or config.MAX_THREADS
    console.print(f"[cyan]Скан {host}, портов: {len(ports)}, потоков: {threads}[/cyan]")
    open_ports: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_scan_port, host, p): p for p in ports}
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                open_ports.append(res)
                console.print(
                    f"[green]✓ {res['port']:>5}/tcp[/green]  "
                    f"[magenta]{res['service']:<10}[/magenta]  {res['banner']}"
                )
    if not open_ports:
        console.print("[yellow]Открытых портов не найдено.[/yellow]")
    db.save_scan("portscan", host, sorted(open_ports, key=lambda x: x["port"]))


def ip_geolocation(target: str) -> None:
    """Геолокация IP + reverse DNS."""
    host = extract_host(target)
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        console.print("[red]Не удалось резолвить хост.[/red]")
        return
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=config.REQUEST_TIMEOUT)
        data = r.json()
        print_kv({
            k: data.get(k) for k in
            ("query", "country", "regionName", "city", "isp", "org", "as", "timezone")
        })
        try:
            reverse = socket.gethostbyaddr(ip)[0]
            console.print(f"  [cyan]reverse_dns[/cyan]        → {reverse}")
        except socket.herror:
            pass
        db.save_scan("geoip", ip, data)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка geoip: {exc}[/red]")


def tech_fingerprint(target: str) -> None:
    """Определение технологий по заголовкам и HTML."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    try:
        r = requests.get(
            url, timeout=config.REQUEST_TIMEOUT, allow_redirects=True,
            headers={"User-Agent": config.USER_AGENT},
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return
    findings: dict[str, str] = {}
    for h in ("Server", "X-Powered-By", "X-Generator", "Via"):
        if r.headers.get(h):
            findings[h] = r.headers[h]
    body = r.text.lower()
    patterns = {
        "WordPress": "wp-content",
        "Joomla": "joomla",
        "Drupal": "drupal",
        "React": "react",
        "Vue.js": "vue",
        "Bootstrap": "bootstrap",
        "jQuery": "jquery",
        "Cloudflare": "cloudflare",
    }
    for name, marker in patterns.items():
        if marker in body:
            findings[name] = "detected in HTML"
    print_kv(findings or {"info": "технологии не определены"})
    db.save_scan("fingerprint", url, findings)


def google_dork(query: str) -> None:
    """Генератор Google dork-ссылок."""
    dorks = [
        f'site:{query} ext:sql | ext:env | ext:log',
        f'site:{query} intitle:"index of"',
        f'site:{query} inurl:admin',
        f'site:{query} inurl:login',
        f'site:{query} ext:pdf | ext:doc | ext:xls',
        f'site:pastebin.com "{query}"',
        f'site:github.com "{query}" password',
    ]
    for d in dorks:
        url = "https://www.google.com/search?q=" + requests.utils.quote(d)
        console.print(f"[cyan]{url}[/cyan]")


def shodan_lookup(query: str) -> None:
    """Поиск в Shodan (нужен SHODAN_API_KEY)."""
    if not config.SHODAN_API_KEY:
        console.print("[yellow]SHODAN_API_KEY не задан в .env[/yellow]")
        return
    try:
        r = requests.get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": config.SHODAN_API_KEY, "query": query},
            timeout=config.REQUEST_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        console.print(f"[green]Найдено: {data.get('total', 0)} результатов[/green]")
        for m in data.get("matches", [])[:10]:
            console.print(
                f"  [cyan]{m.get('ip_str')}[/cyan]:{m.get('port')} "
                f"({m.get('org', '?')}) — {m.get('product', '')}"
            )
        db.save_scan("shodan", query, data)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Shodan ошибка: {exc}[/red]")


def menu() -> None:
    """Меню модуля Recon."""
    table = Table(title="[bold]Reconnaissance[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    options = [
        ("1", "WHOIS lookup"),
        ("2", "DNS enumeration"),
        ("3", "Subdomain scan"),
        ("4", "Port scan"),
        ("5", "IP geolocation + reverse DNS"),
        ("6", "Technology fingerprint"),
        ("7", "Google dork generator"),
        ("8", "Shodan lookup"),
    ]
    for n, t in options:
        table.add_row(n, t)
    console.print(table)
    choice = Prompt.ask("Выбор", choices=[o[0] for o in options])
    if choice == "1":
        whois_lookup(Prompt.ask("Домен"))
    elif choice == "2":
        dns_enum(Prompt.ask("Домен"))
    elif choice == "3":
        subdomain_scan(Prompt.ask("Домен"))
    elif choice == "4":
        port_scan(Prompt.ask("Хост"), Prompt.ask("Порты", default="1-1024"))
    elif choice == "5":
        ip_geolocation(Prompt.ask("Хост"))
    elif choice == "6":
        tech_fingerprint(Prompt.ask("URL"))
    elif choice == "7":
        google_dork(Prompt.ask("Домен"))
    elif choice == "8":
        shodan_lookup(Prompt.ask("Shodan query"))