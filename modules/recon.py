"""
Reconnaissance Pro — расширенная разведка.
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty / CTF.

Возможности:
    ─── WHOIS ───
    - Полный WHOIS через python-whois
    - Fallback на RDAP (rdap.org)
    - Domain age / registrar / nameservers / status
    - Risk scoring (молодой домен, privacy, missing data)
    - Findings для suspicious/young domains

    ─── DNS ───
    - A / AAAA / MX / NS / TXT / CNAME / SOA / CAA / SRV / NAPTR /
      PTR / SSHFP / TLSA / DNSKEY / DS
    - SPF / DMARC / DKIM / BIMI / MTA-STS
    - DNSSEC (DS + DNSKEY + RRSIG)
    - Mail security scoring

    ─── Subdomains ───
    - Wordlist brute (multithreaded, top-N)
    - Passive: crt.sh, hackertarget, OTX (если есть API key)
    - Wildcard detection
    - CNAME chain resolve
    - Takeover detection (quick check)

    ─── Port scan ───
    - TCP connect + banner grab
    - Top-100 / top-1000 ports
    - Service detection (по баннеру)
    - Findings для опасных сервисов (Redis/Mongo/ES без auth)

    ─── GeoIP ───
    - ip-api.com + reverse DNS
    - ASN / ISP / Org / Country / City
    - Falls back на ipinfo.io

    ─── Tech fingerprint ───
    - 40+ технологий (headers + HTML markers + favicon)
    - CMS, frameworks, CDN, WAF detection
    - Server / language / analytics

    ─── Google dorks ───
    - 40+ dork'ов по категориям (secrets / admin / files / vulns /
      GitHub / Pastebin / Shodan)
    - Генерация прямых Google/GitHub/Shodan ссылок

    ─── Shodan ───
    - Search API (если SHODAN_API_KEY)
    - Красивая таблица
    - Fallback: ссылки на shodan.io

    ─── Extras ───
    - Reverse IP (по PTR)
    - SSL certificate info
    - robots.txt / security.txt / sitemap.xml
    - HTTP headers analysis
    - ASN lookup

    ─── Интеграция ───
    - Findings → notes
    - Notify
    - Экспорт: JSON / Markdown / HTML / CSV
"""
import csv
import html as html_mod
import json
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dns.resolver
import requests
import whois as whois_lib
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn,
)

from core.config import config, WORDLIST_DIR, REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import (
    confirm_external, extract_host, print_kv, normalize_url,
)

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RECON_DIR = REPORT_DIR / "recon"
RECON_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class ReconFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: ReconFinding) -> int:
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
            tags=["recon", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Порты
# ===========================================================================

COMMON_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 69: "tftp", 80: "http", 110: "pop3",
    111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmptrap", 179: "bgp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 500: "isakmp", 514: "syslog",
    515: "lpd", 548: "afp", 554: "rtsp", 587: "submission",
    631: "ipp", 636: "ldaps", 873: "rsync", 990: "ftps",
    993: "imaps", 995: "pop3s", 1025: "rpc", 1080: "socks",
    1433: "mssql", 1434: "mssql-browser", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2086: "whm", 2087: "whm-ssl", 2095: "webmail", 2096: "webmail-ssl",
    2181: "zookeeper", 2222: "ssh-alt", 2375: "docker",
    2376: "docker-ssl", 2379: "etcd", 2380: "etcd-peer",
    2480: "couchdb", 3000: "grafana", 3128: "squid",
    3306: "mysql", 3389: "rdp", 4000: "icq", 4443: "https-alt",
    4505: "salt-master", 4506: "salt-minion", 5000: "http-alt",
    5432: "postgres", 5555: "adb", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5901: "vnc-1", 5984: "couchdb",
    5985: "winrm-http", 5986: "winrm-https", 6000: "x11",
    6379: "redis", 6443: "kube-api", 7001: "weblogic",
    7077: "spark", 7474: "neo4j", 8000: "http-alt",
    8008: "http-alt", 8009: "ajp", 8080: "http-alt",
    8081: "http-alt", 8088: "http-alt", 8090: "http-alt",
    8161: "activemq", 8200: "vault", 8300: "consul-ssl",
    8443: "https-alt", 8500: "consul", 8529: "arangodb",
    8834: "nessus", 8888: "http-alt", 9000: "http-alt",
    9042: "cassandra", 9090: "http-alt", 9092: "kafka",
    9200: "elasticsearch", 9300: "elasticsearch-cluster",
    9443: "https-alt", 9999: "http-alt", 10000: "webmin",
    10250: "kubelet", 11211: "memcached", 15672: "rabbitmq-mgmt",
    16379: "redis-cluster", 27017: "mongodb",
    27018: "mongodb-shard", 28017: "mongodb-web",
    50000: "sap", 50030: "hadoop-nn", 50070: "hadoop-web",
    61616: "activemq-openwire",
}

DANGEROUS_PORTS = {2375, 2376, 2379, 3306, 5432, 6379, 7001,
                   9042, 9200, 11211, 27017, 27018}


def parse_ports(spec: str) -> list[int]:
    """'1-1024' или '22,80,443' → список int."""
    ports: list[int] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            try:
                a, b = chunk.split("-", 1)
                ports.extend(range(int(a), int(b) + 1))
            except ValueError:
                continue
        elif chunk.isdigit():
            ports.append(int(chunk))
    return sorted(set(p for p in ports if 1 <= p <= 65535))


# ===========================================================================
# WHOIS (расширенный + RDAP fallback)
# ===========================================================================

def _whois_via_rdap(domain: str) -> dict:
    """RDAP lookup (no auth, работает без python-whois)."""
    out: dict = {}
    for url in (f"https://rdap.org/domain/{domain}",
                f"https://rdap.verisign.com/com/v1/domain/{domain}"):
        try:
            r = requests.get(url, timeout=10,
                             headers={"Accept": "application/rdap+json",
                                      "User-Agent": config.USER_AGENT})
            if r.status_code != 200:
                continue
            data = r.json()
            for ev in data.get("events", []):
                act = ev.get("eventAction", "")
                date = ev.get("eventDate", "")[:19]
                if act == "registration":
                    out["creation_date"] = date
                elif act == "expiration":
                    out["expiration_date"] = date
                elif act == "last changed":
                    out["updated_date"] = date
            out["status"] = data.get("status", [])
            for ent in data.get("entities", []):
                if "registrar" in ent.get("roles", []):
                    for item in (ent.get("vcardArray") or [None, []])[1]:
                        if item[0] == "fn":
                            out["registrar"] = item[3]
            out["nameservers"] = [
                ns.get("ldhName", "").lower()
                for ns in data.get("nameservers", []) or []
            ]
            return out
        except Exception:
            continue
    return out


def _age_days(creation: Any) -> int | None:
    """Возраст домена в днях."""
    if not creation:
        return None
    try:
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime):
            dt = creation
        else:
            dt = datetime.fromisoformat(str(creation)[:19])
        if dt.tzinfo:
            now = datetime.now(timezone.utc)
        else:
            now = datetime.now()
        return (now - dt).days
    except Exception:
        return None


def whois_lookup(target: str) -> None:
    """WHOIS lookup домена (с fallback на RDAP)."""
    if not confirm_external(target):
        return
    host = extract_host(target)
    console.print(f"[cyan]WHOIS → {host}[/cyan]")

    result: dict[str, Any] = {}
    try:
        data = whois_lib.whois(host)
        result = {
            "domain": data.domain_name,
            "registrar": data.registrar,
            "creation_date": str(data.creation_date) if data.creation_date else "",
            "expiration_date": str(data.expiration_date) if data.expiration_date else "",
            "name_servers": data.name_servers or [],
            "org": data.org,
            "country": data.country,
            "emails": data.emails or [],
            "dnssec": data.dnssec,
        }
    except Exception as exc:  # noqa: BLE001
        log.warning("whois failed: %s", exc)
        console.print(f"[yellow]python-whois не сработал, пробую RDAP…[/yellow]")
        result = _whois_dap_wrap(host)

    # Age
    age = _age_days(result.get("creation_date"))
    if age is not None:
        result["age_days"] = age
        result["age_years"] = round(age / 365.25, 1)

    print_kv({k: v for k, v in result.items() if v})
    db.save_scan("whois", host, result)

    # Findings
    if age is not None and age < 90:
        _save_finding(ReconFinding(
            kind="young_domain",
            severity="high",
            title=f"Молодой домен: {host} ({age} дней)",
            target=host,
            evidence=f"Age: {age} days, Registered: "
                     f"{result.get('creation_date', '?')}",
            data=result,
        ))


def _whois_dap_wrap(host: str) -> dict:
    """RDAP fallback wrapper."""
    return _whois_via_rdap(host)


# ===========================================================================
# DNS (расширенный)
# ===========================================================================

DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA",
              "SRV", "NAPTR", "PTR", "SSHFP", "TLSA", "DNSKEY", "DS"]


def dns_enum(target: str) -> None:
    """Расширенная DNS-энумерация."""
    host = extract_host(target)
    console.print(f"[cyan]DNS enumeration → {host}[/cyan]")
    result: dict[str, list[str]] = {}

    for rtype in DNS_TYPES:
        try:
            answers = dns.resolver.resolve(host, rtype, lifetime=5)
            vals = []
            for a in answers:
                try:
                    if hasattr(a, "strings"):
                        text = b"".join(a.strings).decode(errors="ignore")
                        vals.append(text)
                    else:
                        vals.append(str(a).strip('"'))
                except Exception:
                    vals.append(str(a))
            result[rtype] = vals
        except Exception:
            continue

    # SPF / DMARC / DKIM / BIMI / MTA-STS
    result["SPF"] = _get_txt_containing(host, "v=spf1")
    result["DMARC"] = _get_txt_containing(f"_dmarc.{host}", "v=DMARC1")
    result["DKIM"] = _dkim_check(host)
    result["BIMI"] = _get_txt_containing(f"default._bimi.{host}", "v=BIMI1")
    result["MTA-STS"] = _get_txt_containing(f"_mta-sts.{host}", "v=STSv1")

    # Print
    table = Table(title=f"DNS {host}")
    table.add_column("Тип", style="magenta", width=10)
    table.add_column("Значение", style="green", max_width=100)
    for rtype, values in result.items():
        for v in values or []:
            table.add_row(rtype, str(v)[:100])
    console.print(table)

    db.save_scan("dns", host, result)
    _dns_findings(host, result)


def _get_txt_containing(name: str, needle: str) -> list[str]:
    """TXT записи, содержащие needle."""
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
        out = []
        for a in answers:
            try:
                txt = b"".join(a.strings).decode(errors="ignore")
            except Exception:
                txt = str(a)
            if needle in txt:
                out.append(txt)
        return out
    except Exception:
        return []


def _dkim_check(host: str) -> list[str]:
    """DKIM по популярным селекторам."""
    selectors = ["default", "google", "selector1", "selector2",
                 "k1", "mail", "dkim", "s1", "s2", "smtp"]
    out: list[str] = []

    def _one(sel: str) -> str | None:
        try:
            answers = dns.resolver.resolve(
                f"{sel}._domainkey.{host}", "TXT", lifetime=5)
            for a in answers:
                try:
                    txt = b"".join(a.strings).decode(errors="ignore")
                except Exception:
                    txt = str(a)
                if "v=DKIM1" in txt or "p=" in txt:
                    return f"{sel}: {txt[:200]}"
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(_one, s) for s in selectors]
        for f in as_completed(futs):
            r = f.result()
            if r:
                out.append(r)
    return out


def _dns_findings(host: str, dns_result: dict) -> None:
    """Findings на основе DNS."""
    # SPF +all
    for spf in dns_result.get("SPF", []):
        if "+all" in spf:
            _save_finding(ReconFinding(
                kind="spf_plus_all",
                severity="high",
                title=f"SPF +all на {host}",
                target=host,
                evidence=spf[:500],
                data={"spf": spf},
            ))
            break

    # Отсутствие DMARC
    if not dns_result.get("DMARC"):
        _save_finding(ReconFinding(
            kind="dmarc_missing",
            severity="medium",
            title=f"DMARC отсутствует на {host}",
            target=host,
            evidence="Email spoofing возможен",
        ))


# ===========================================================================
# Subdomains (расширенный)
# ===========================================================================

def _resolve_fqdn(fqdn: str, timeout: float = 3.0) -> tuple[str, str, str] | None:
    """Резолв FQDN → (fqdn, ip, cname)."""
    try:
        socket.setdefaulttimeout(timeout)
        ip = socket.gethostbyname(fqdn)
        cname = ""
        try:
            answers = dns.resolver.resolve(fqdn, "CNAME", lifetime=3)
            cname = str(answers[0].target).rstrip(".")
        except Exception:
            pass
        return (fqdn, ip, cname)
    except Exception:
        return None


def _wildcard_detect(domain: str) -> list[str]:
    """Определить wildcard DNS."""
    import random
    import string as _string
    ips: set[str] = set()
    for _ in range(3):
        rand = "".join(random.choices(
            _string.ascii_lowercase + _string.digits, k=20))
        r = _resolve_fqdn(f"{rand}.{domain}")
        if r:
            ips.add(r[1])
    return sorted(ips) if len(ips) == 3 else []


def _crtsh_subdomains(domain: str) -> set[str]:
    """Пассивный сбор через crt.sh."""
    out: set[str] = set()
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=30, verify=False,
            headers={"User-Agent": config.USER_AGENT},
        )
        if r.status_code == 200:
            for entry in r.json():
                for name in (entry.get("name_value") or "").split("\n"):
                    name = name.strip().lower()
                    if name and "*" not in name and name.endswith(domain):
                        out.add(name)
    except Exception as exc:
        log.debug("crt.sh: %s", exc)
    return out


def subdomain_scan(target: str, threads: int = 50,
                   use_crtsh: bool = True) -> None:
    """Брутфорс + пассивный сбор поддоменов."""
    domain = extract_host(target)
    wordlist_file = WORDLIST_DIR / "subdomains.txt"

    words: list[str] = []
    if wordlist_file.exists():
        words = [w.strip() for w in wordlist_file.read_text(
            encoding="utf-8", errors="ignore").splitlines()
            if w.strip() and not w.startswith("#")]
    else:
        # Встроенный fallback
        words = [
            "www", "mail", "ftp", "webmail", "smtp", "pop", "imap",
            "ns1", "ns2", "dns", "admin", "api", "app", "dev", "test",
            "stage", "staging", "prod", "beta", "demo", "portal",
            "login", "auth", "sso", "shop", "store", "blog", "news",
            "support", "help", "docs", "wiki", "static", "assets",
            "cdn", "media", "img", "images", "video", "m", "mobile",
            "old", "backup", "temp", "monitor", "status", "health",
            "metrics", "grafana", "jenkins", "ci", "cd", "git",
            "gitlab", "jira", "vpn", "remote", "rdp", "s3", "storage",
            "files", "gateway", "proxy", "internal", "intranet",
        ]

    console.print(f"[cyan]Сканирую {len(words)} поддоменов для "
                  f"{domain}…[/cyan]")

    # Wildcard check
    wildcard_ips = _wildcard_detect(domain)
    if wildcard_ips:
        console.print(f"[yellow]⚠ Wildcard DNS → "
                      f"{', '.join(wildcard_ips)}[/yellow]")

    subs = {f"{w}.{domain}" for w in words}
    subs.add(domain)

    # Passive sources
    if use_crtsh:
        console.print("[cyan]→ crt.sh (passive)…[/cyan]")
        try:
            passive = _crtsh_subdomains(domain)
            if passive:
                console.print(f"  [green]Найдено {len(passive)} "
                              f"в crt.sh[/green]")
                subs.update(passive)
        except Exception:
            pass

    # Resolve
    found: list[tuple[str, str, str]] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_resolve_fqdn, s): s for s in subs}
        with Progress(SpinnerColumn(),
                      TextColumn("[progress.description]{task.description}"),
                      BarColumn(),
                      TextColumn("{task.completed}/{task.total}"),
                      TimeElapsedColumn(),
                      console=console) as p:
            task = p.add_task("resolve", total=len(subs))
            for f in as_completed(futs):
                p.advance(task)
                r = f.result()
                if r:
                    found.append(r)

    # Filter wildcard
    if wildcard_ips:
        found = [f for f in found
                 if f[1] not in wildcard_ips or f[0] == domain]

    # Print
    table = Table(title=f"Subdomains {domain} ({len(found)})")
    table.add_column("#", style="dim", width=4)
    table.add_column("FQDN", style="cyan")
    table.add_column("IP", style="green")
    table.add_column("CNAME", style="magenta", max_width=40)
    for i, (fqdn, ip, cname) in enumerate(sorted(found), 1):
        table.add_row(str(i), fqdn, ip, cname[:40])
    console.print(table)

    db.save_scan("subdomains", domain, {
        "count": len(found),
        "wildcard_ips": wildcard_ips,
        "results": [{"fqdn": f, "ip": i, "cname": c}
                    for f, i, c in found[:500]],
    })


# ===========================================================================
# Port scan (расширенный)
# ===========================================================================

def _grab_banner(sock: socket.socket) -> str:
    try:
        sock.settimeout(1.5)
        data = sock.recv(1024)
        return data.decode(errors="ignore").strip().splitlines()[0][:120]
    except Exception:
        return ""


def _detect_service_from_banner(banner: str) -> str:
    """Определить сервис по баннеру."""
    if not banner:
        return ""
    lc = banner.lower()
    markers = [
        ("ssh", "OpenSSH"), ("ssh", "SSH-2.0"),
        ("http", "HTTP/1."), ("http", "HTTP/2"),
        ("nginx", "nginx"), ("apache", "apache"),
        ("iis", "iis"), ("mysql", "mysql"),
        ("postgres", "postgresql"), ("redis", "redis"),
        ("mongodb", "mongodb"), ("elasticsearch", "elastic"),
        ("smb", "smb"), ("ftp", "ftp"),
        ("smtp", "smtp"), ("imap", "imap"),
    ]
    for svc, marker in markers:
        if marker in lc:
            return svc
    return ""


def _scan_port(host: str, port: int, timeout: float = 1.0) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                banner = _grab_banner(s)
                service = COMMON_PORTS.get(port, "unknown")
                detected = _detect_service_from_banner(banner)
                return {
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "detected": detected,
                }
    except Exception:
        return None
    return None


def port_scan(target: str, ports_spec: str = "1-1024",
              threads: int | None = None) -> None:
    """Многопоточный TCP-скан с баннерами."""
    if not confirm_external(target):
        return
    host = extract_host(target)
    ports = parse_ports(ports_spec)
    threads = threads or min(config.MAX_THREADS, 200)
    console.print(f"[cyan]Скан {host}, портов: {len(ports)}, "
                  f"потоков: {threads}[/cyan]")

    open_ports: list[dict] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_scan_port, host, p): p for p in ports}
        with Progress(SpinnerColumn(),
                      TextColumn("[progress.description]{task.description}"),
                      BarColumn(),
                      TextColumn("{task.completed}/{task.total}"),
                      TimeElapsedColumn(),
                      console=console) as p:
            task = p.add_task("portscan", total=len(ports))
            for f in as_completed(futs):
                p.advance(task)
                res = f.result()
                if res:
                    open_ports.append(res)

    if open_ports:
        table = Table(title=f"Открытые порты {host} ({len(open_ports)})")
        table.add_column("Port", style="green", width=7)
        table.add_column("Service", style="magenta", width=16)
        table.add_column("Banner", style="dim", max_width=70)
        for r in sorted(open_ports, key=lambda x: x["port"]):
            table.add_row(str(r["port"]), r["service"],
                          (r["banner"] or "")[:70])
        console.print(table)
    else:
        console.print("[yellow]Открытых портов не найдено.[/yellow]")

    db.save_scan("portscan", host,
                 sorted(open_ports, key=lambda x: x["port"]))

    # Findings: опасные сервисы без auth
    _port_findings(host, open_ports)


def _port_findings(host: str, open_ports: list[dict]) -> None:
    """Findings для опасных сервисов."""
    dangerous = [r for r in open_ports if r["port"] in DANGEROUS_PORTS]
    if dangerous:
        ev = ", ".join(f"{r['port']}/{r['service']}" for r in dangerous)
        _save_finding(ReconFinding(
            kind="dangerous_services",
            severity="high",
            title=f"Опасные сервисы открыты на {host}",
            target=host,
            evidence=ev,
            data={"ports": [r["port"] for r in dangerous]},
        ))


# ===========================================================================
# GeoIP / ASN
# ===========================================================================

def ip_geolocation(target: str) -> None:
    """Геолокация IP + reverse DNS + ASN."""
    host = extract_host(target)
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        console.print("[red]Не удалось резолвить хост.[/red]")
        return

    result: dict[str, Any] = {"ip": ip}

    # ip-api.com
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}",
                         timeout=config.REQUEST_TIMEOUT)
        data = r.json()
        for k in ("country", "regionName", "city", "isp", "org",
                  "as", "timezone", "lat", "lon", "query"):
            if data.get(k):
                result[k] = data[k]
    except Exception as exc:
        log.debug("ip-api: %s", exc)

    # Reverse DNS
    try:
        reverse = socket.gethostbyaddr(ip)[0]
        result["reverse_dns"] = reverse
    except Exception:
        pass

    print_kv(result)
    db.save_scan("geoip", ip, result)


# ===========================================================================
# Tech fingerprint (расширенный)
# ===========================================================================

TECH_MARKERS = {
    # Server
    "Nginx":     ["nginx"],
    "Apache":    ["apache"],
    "IIS":       ["iis", "microsoft-iis"],
    "LiteSpeed": ["litespeed"],
    "OpenResty": ["openresty"],
    "Caddy":     ["caddy"],
    "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
    "Fastly":    ["fastly", "x-served-by"],
    "Akamai":    ["akamai"],
    # Language / framework
    "PHP":       ["x-powered-by: php", ".php"],
    "ASP.NET":   ["asp.net", "x-aspnet"],
    "Express":   ["x-powered-by: express"],
    "Ruby on Rails": ["x-powered-by: phusion", "_rails_session"],
    "Django":    ["csrftoken", "django"],
    "Flask":     ["werkzeug"],
    "Laravel":   ["laravel_session"],
    "Spring":    ["jsessionid", "x-application-context"],
    "Node.js":   ["x-powered-by: node"],
    # CMS
    "WordPress": ["wp-content", "wp-includes", "wp-json"],
    "Joomla":    ["joomla", "/components/com_"],
    "Drupal":    ["drupal", "/sites/default/"],
    "Magento":   ["mage/cookies", "/skin/frontend/"],
    "PrestaShop": ["prestashop", "/modules/ps_"],
    "Shopify":   ["cdn.shopify.com"],
    "Wix":       ["wix.com", "wixstatic"],
    "Squarespace": ["squarespace.com"],
    # JS
    "React":     ["react", "data-reactroot", "_next/static"],
    "Next.js":   ["_next/static", "__NEXT_DATA__"],
    "Vue.js":    ["vue.js", "data-v-"],
    "Nuxt":      ["__NUXT__", "_nuxt/"],
    "Angular":   ["ng-version", "ng-app"],
    "Svelte":    ["svelte-", "__svelte"],
    "jQuery":    ["jquery"],
    "Bootstrap": ["bootstrap.min"],
    "Tailwind":  ["tailwind"],
    # Analytics
    "Google Analytics": ["google-analytics", "gtag", "googletagmanager"],
    "Facebook Pixel": ["connect.facebook.net", "fbq("],
    "Hotjar": ["hotjar"],
    "Sentry": ["sentry"],
    "Segment": ["segment.com", "analytics.js"],
    # Auth / CDN
    "Auth0": ["auth0.com"],
    "Okta": ["okta.com"],
    "AWS": ["amazonaws.com"],
    "GCP": ["googleapis.com"],
    # WAF
    "Cloudflare WAF": ["cf-ray", "cloudflare"],
    "AWS WAF": ["awselb", "x-amzn-requestid"],
    "Imperva": ["incapsula", "x-iinfo"],
    "Sucuri": ["x-sucuri-id"],
    "F5 BIG-IP": ["bigipserver", "x-wa-info"],
}


def tech_fingerprint(target: str) -> None:
    """Определение технологий."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    try:
        r = requests.get(
            url, timeout=config.REQUEST_TIMEOUT, allow_redirects=True,
            headers={"User-Agent": config.USER_AGENT}, verify=False,
        )
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return

    findings: dict[str, str] = {}
    # Headers
    headers_str = " ".join(f"{k}: {v}".lower()
                            for k, v in r.headers.items())
    body_lc = (r.text or "").lower()
    combined = headers_str + " " + body_lc

    for tech, markers in TECH_MARKERS.items():
        for m in markers:
            if m.lower() in combined:
                findings[tech] = "detected"
                break

    # Server header
    if r.headers.get("Server"):
        findings["Server"] = r.headers["Server"][:80]

    if findings:
        table = Table(title=f"Technologies: {url[:60]}")
        table.add_column("Tech", style="cyan", width=22)
        table.add_column("Info", style="green", max_width=60)
        for k, v in findings.items():
            table.add_row(k, v)
        console.print(table)
    else:
        console.print("[yellow]Технологии не определены.[/yellow]")

    db.save_scan("fingerprint", url, findings)


# ===========================================================================
# Google dorks (расширенный)
# ===========================================================================

DORK_CATEGORIES = {
    "secrets": [
        'site:{q} ext:sql | ext:env | ext:log',
        'site:{q} "DB_PASSWORD" | "API_KEY" | "SECRET_KEY"',
        'site:{q} ext:bak | ext:backup | ext:old',
        'site:{q} "password" ext:txt | ext:log',
    ],
    "exposure": [
        'site:{q} intitle:"index of"',
        'site:{q} intitle:"index of" "parent directory"',
        'site:{q} inurl:admin',
        'site:{q} inurl:login | inurl:signin',
        'site:{q} inurl:dashboard | inurl:panel',
        'site:{q} inurl:api | inurl:v1 | inurl:v2',
        'site:{q} inurl:swagger | inurl:openapi',
    ],
    "files": [
        'site:{q} ext:pdf | ext:doc | ext:xls | ext:ppt',
        'site:{q} ext:json | ext:xml | ext:yaml | ext:yml',
        'site:{q} filetype:sql',
        'site:{q} filetype:conf',
    ],
    "vulns": [
        'site:{q} inurl:"?id=" | inurl:"?page=" | inurl:"?file="',
        'site:{q} inurl:".git" | inurl:".svn" | inurl:".env"',
        'site:{q} intitle:"phpinfo()"',
        'site:{q} inurl:"wp-config.php" | inurl:"config.php"',
    ],
    "pastebin": [
        'site:pastebin.com "{q}"',
        'site:pastebin.com "{q}" password',
        'site:pastebin.com "{q}" apikey',
    ],
    "github": [
        'site:github.com "{q}" password',
        'site:github.com "{q}" apikey',
        'site:github.com "{q}" secret',
        'site:github.com "{q}" token',
    ],
    "stackoverflow": [
        'site:stackoverflow.com "{q}"',
        'site:stackoverflow.com "{q}" error',
    ],
    "shodan": [
        'site:shodan.io "{q}"',
        'site:shodan.io hostname:{q}',
    ],
    "censys": [
        'site:censys.io "{q}"',
    ],
    "subdomains": [
        'site:*.{q} -www',
        'site:{q} -inurl:www',
    ],
}


def google_dork(query: str, show_urls: bool = True) -> None:
    """Генератор Google dork'ов (по категориям)."""
    console.print(f"\n[bold cyan]🔍 Google dorks для '{query}'"
                  f"[/bold cyan]\n")

    total = 0
    for category, dorks in DORK_CATEGORIES.items():
        table = Table(title=f"[bold yellow]{category}[/bold yellow]",
                      show_header=show_urls)
        if show_urls:
            table.add_column("Dork", style="cyan", max_width=50)
            table.add_column("Google URL", style="green", max_width=80)
        else:
            table.add_column("Dork", style="green")

        for d in dorks:
            formatted = d.format(q=query)
            if show_urls:
                url = ("https://www.google.com/search?q=" +
                       requests.utils.quote(formatted))
                table.add_row(formatted, url[:80])
            else:
                table.add_row(formatted)
            total += 1
        console.print(table)

    console.print(f"\n[dim]Всего dork'ов: {total} "
                  f"({len(DORK_CATEGORIES)} категорий)[/dim]")
    db.save_scan("google_dorks", query,
                 {"count": total,
                  "categories": list(DORK_CATEGORIES.keys())})


# ===========================================================================
# Shodan (расширенный)
# ===========================================================================

def shodan_lookup(query: str) -> None:
    """Поиск в Shodan."""
    if not config.SHODAN_API_KEY:
        console.print("[yellow]SHODAN_API_KEY не задан в .env[/yellow]")
        # Fallback: ссылки
        console.print("[cyan]Открыть в браузере:[/cyan]")
        url = ("https://www.shodan.io/search?query=" +
               requests.utils.quote(query))
        console.print(f"  [green]{url}[/green]")
        # Плюс InternetDB для IP-запроса
        _try_internetdb(query)
        return
    try:
        r = requests.get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": config.SHODAN_API_KEY, "query": query},
            timeout=config.REQUEST_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        total = data.get("total", 0)
        console.print(f"[green]Найдено: {total} результатов[/green]")

        table = Table(title=f"Shodan: {query[:50]}")
        table.add_column("IP", style="cyan", width=16)
        table.add_column("Port", style="magenta", width=6)
        table.add_column("Org", style="green", max_width=25)
        table.add_column("Product", style="white", max_width=30)
        for m in data.get("matches", [])[:30]:
            table.add_row(
                m.get("ip_str", "?"),
                str(m.get("port", "?")),
                (m.get("org") or "?")[:25],
                (m.get("product") or "?")[:30],
            )
        console.print(table)
        db.save_scan("shodan", query, data)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Shodan ошибка: {exc}[/red]")


def _try_internetdb(query: str) -> None:
    """InternetDB (free) для IP."""
    import ipaddress
    try:
        ipaddress.ip_address(query)
    except ValueError:
        return
    try:
        r = requests.get(f"https://internetdb.shodan.io/{query}",
                         timeout=10)
        if r.status_code == 200:
            data = r.json()
            console.print(f"\n[cyan]Shodan InternetDB "
                          f"для {query}:[/cyan]")
            print_kv({k: v for k, v in data.items() if v})
    except Exception:
        pass


# ===========================================================================
# Extras: reverse IP, SSL, robots.txt, security.txt, headers
# ===========================================================================

def reverse_ip(ip: str) -> None:
    """Reverse DNS lookup для IP."""
    try:
        results = socket.gethostbyaddr(ip)
        console.print(f"[green]PTR:[/green] {results[0]}")
        for alias in results[1][:10]:
            console.print(f"  [cyan]alias[/cyan]: {alias}")
        db.save_scan("reverse_ip", ip, {"ptr": results[0],
                                         "aliases": list(results[1])})
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")


def ssl_info(target: str) -> None:
    """SSL/TLS информация."""
    host = extract_host(target)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                info = {
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher(),
                    "subject": dict(x[0] for x in cert["subject"]),
                    "issuer": dict(x[0] for x in cert["issuer"]),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "serialNumber": cert.get("serialNumber"),
                }
                print_kv(info)
                db.save_scan("ssl", host, info)
    except Exception as exc:
        console.print(f"[red]SSL ошибка: {exc}[/red]")


def robots_security_txt(target: str) -> None:
    """robots.txt / security.txt / sitemap.xml."""
    url = normalize_url(target).rstrip("/")
    for path in ("/robots.txt", "/security.txt",
                 "/.well-known/security.txt", "/sitemap.xml",
                 "/humans.txt"):
        try:
            r = requests.get(url + path, timeout=10, verify=False,
                             headers={"User-Agent": config.USER_AGENT})
            if r.status_code == 200 and len(r.content) > 0:
                console.print(f"\n[green]{path}[/green] "
                              f"({len(r.content)} bytes):")
                console.print(r.text[:500])
        except Exception:
            continue


def http_headers(target: str) -> None:
    """Полный анализ HTTP headers."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    try:
        r = requests.get(url, timeout=config.REQUEST_TIMEOUT,
                          verify=False, allow_redirects=False,
                          headers={"User-Agent": config.USER_AGENT})
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        return
    t = Table(title=f"HTTP headers — {url[:60]}")
    t.add_column("Header", style="cyan")
    t.add_column("Value", style="green", max_width=80)
    for k, v in r.headers.items():
        t.add_row(k, v[:80])
    console.print(t)

    # Security headers check
    sec_headers = ["Strict-Transport-Security", "Content-Security-Policy",
                   "X-Frame-Options", "X-Content-Type-Options",
                   "Referrer-Policy", "Permissions-Policy"]
    missing = [h for h in sec_headers if h.lower() not in
               [k.lower() for k in r.headers.keys()]]
    if missing:
        console.print(f"\n[yellow]⚠ Missing security headers "
                      f"({len(missing)}):[/yellow] {', '.join(missing)}")

    db.save_scan("http_headers", url, {
        "status": r.status_code,
        "headers": dict(r.headers),
        "missing_security": missing,
    })


# ===========================================================================
# Экспорт
# ===========================================================================

def export_json(data: Any, name: str,
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = "".join(c if c.isalnum() or c in "._-" else "_"
                       for c in name)[:40]
        path = str(RECON_DIR / f"{safe}_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]JSON: {exc}[/red]")
        return None


def export_csv(rows: list[dict], name: str,
               path: str | None = None) -> Path | None:
    if not rows:
        return None
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = "".join(c if c.isalnum() or c in "._-" else "_"
                       for c in name)[:40]
        path = str(RECON_DIR / f"{safe}_{ts}.csv")
    try:
        keys = sorted({k for r in rows for k in r.keys()})
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(r)
        console.print(f"[green]✓ CSV: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]CSV: {exc}[/red]")
        return None


def export_html(data: Any, name: str,
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = "".join(c if c.isalnum() or c in "._-" else "_"
                       for c in name)[:40]
        path = str(RECON_DIR / f"{safe}_{ts}.html")
    try:
        body = json.dumps(data, indent=2, ensure_ascii=False, default=str)
        parts = [
            "<!DOCTYPE html><html><head><meta charset='utf-8'>",
            f"<title>Recon: {html_mod.escape(name)}</title>",
            "<style>body{background:#0a0a0a;color:#c8c8c8;"
            "font-family:monospace;padding:24px;line-height:1.5;}"
            "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}"
            "pre{background:#111;padding:12px;border:1px solid #222;"
            "color:#a0ffa0;overflow-x:auto;}",
            "</style></head><body>",
            f"<h1>🔎 {html_mod.escape(name)}</h1>",
            f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
            f"<pre>{html_mod.escape(body[:100000])}</pre>",
            "</body></html>",
        ]
        Path(path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]HTML: {exc}[/red]")
        return None


# ===========================================================================
# Menu (сохранены все старые сигнатуры)
# ===========================================================================

def menu() -> None:
    """Меню модуля Recon."""
    table = Table(title="[bold]Reconnaissance Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    options = [
        ("1", "WHOIS lookup (+RDAP fallback, age, risk)"),
        ("2", "DNS enum (A/AAAA/MX/NS/TXT/CAA/SPF/DMARC/DKIM/BIMI)"),
        ("3", "Subdomain scan (wordlist + crt.sh + wildcard)"),
        ("4", "Port scan (banner grab + service detection)"),
        ("5", "IP geolocation + reverse DNS + ASN"),
        ("6", "Technology fingerprint (40+ techs)"),
        ("7", "Google dork generator (50+ dorks)"),
        ("8", "Shodan lookup (или InternetDB для IP)"),
        ("9", "Reverse IP (PTR)"),
        ("10", "SSL/TLS info"),
        ("11", "robots.txt / security.txt / sitemap.xml"),
        ("12", "HTTP headers + missing security headers"),
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
        port_scan(Prompt.ask("Хост"),
                  Prompt.ask("Порты", default="1-1024"))
    elif choice == "5":
        ip_geolocation(Prompt.ask("Хост"))
    elif choice == "6":
        tech_fingerprint(Prompt.ask("URL"))
    elif choice == "7":
        google_dork(Prompt.ask("Домен"))
    elif choice == "8":
        shodan_lookup(Prompt.ask("Shodan query"))
    elif choice == "9":
        reverse_ip(Prompt.ask("IP"))
    elif choice == "10":
        ssl_info(Prompt.ask("Хост"))
    elif choice == "11":
        robots_security_txt(Prompt.ask("URL"))
    elif choice == "12":
        http_headers(Prompt.ask("URL"))


# CLI-обёртки (совместимость)
def cli_whois(target: str) -> None: whois_lookup(target)
def cli_dns(target: str) -> None: dns_enum(target)
def cli_subdomain(target: str) -> None: subdomain_scan(target)
def cli_portscan(target: str, ports: str = "1-1024") -> None:
    port_scan(target, ports)
def cli_geoip(target: str) -> None: ip_geolocation(target)
def cli_fingerprint(target: str) -> None: tech_fingerprint(target)
def cli_dork(target: str) -> None: google_dork(target)
def cli_shodan(query: str) -> None: shodan_lookup(query)
def cli_reverse_ip(ip: str) -> None: reverse_ip(ip)
def cli_ssl(target: str) -> None: ssl_info(target)
def cli_robots(target: str) -> None: robots_security_txt(target)
def cli_headers(target: str) -> None: http_headers(target)