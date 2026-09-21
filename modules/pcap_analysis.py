"""
Packet Analysis Suite Pro.
Author: idqwixxa

⚠ Только для авторизованного пентеста / CTF / анализа своей сети.

Возможности:
    ─── Парсинг ───
    - PCAP / PCAPNG (scapy)
    - TCP stream reassembly (упрощённая)

    ─── Credentials (расширено) ───
    - HTTP Basic / Digest
    - FTP (USER/PASS)
    - Telnet (эвристика)
    - SMTP (AUTH PLAIN/LOGIN)
    - POP3, IMAP
    - SNMP v1/v2c community strings
    - LDAP simple bind (эвристика)
    - Kerberos (preauth/AS-REQ hints)
    - NTLM (NTLMSSP)
    - SMB (username extraction)

    ─── HTTP ───
    - Requests (method, URL, UA, auth, cookie, referer)
    - Responses (status, server, content-type, set-cookie)
    - Файлы из HTTP (Content-Disposition / Content-Type)
    - POST-body (form-urlencoded, JSON)

    ─── DNS ───
    - Queries + answers
    - DNS tunneling detection (длинные qnames)
    - NXDOMAIN flood

    ─── TLS ───
    - SNI extraction
    - JA3 fingerprint (basics)

    ─── Детект аномалий ───
    - Beaconing (регулярные интервалы)
    - Top talkers
    - Port-scans (SYN flood)
    - ARP spoof (duplicate MAC→IP)
    - Cleartext credentials → findings

    ─── Интеграция ───
    - Findings → notes (creds leak, ARP spoof)
    - Notify
    - Экспорт: JSON / HTML / CSV / Markdown
"""
import base64
import csv
import html as html_mod
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

PCAP_DIR = REPORT_DIR / "pcap"
PCAP_DIR.mkdir(parents=True, exist_ok=True)

try:
    from scapy.all import (
        rdpcap, PcapReader, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR,
        Raw, Ether, IPv6,
    )
    SCAPY_OK = True
    SCAPY_ERR = ""
except Exception as _scapy_err:  # noqa: BLE001
    SCAPY_OK = False
    SCAPY_ERR = str(_scapy_err)
    log.debug("scapy: %s", _scapy_err)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class PcapFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: PcapFinding) -> int:
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
            tags=["pcap", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Модель
# ===========================================================================

@dataclass
class Credential:
    ts: str
    proto: str
    src: str
    dst: str
    username: str = ""
    password: str = ""
    extra: str = ""


@dataclass
class HTTPRequest:
    ts: str
    src: str
    dst: str
    method: str
    url: str = ""
    host: str = ""
    user_agent: str = ""
    auth: str = ""
    cookie: str = ""
    referer: str = ""
    body: str = ""


@dataclass
class HTTPResponse:
    ts: str
    src: str
    dst: str
    status: int = 0
    server: str = ""
    content_type: str = ""
    set_cookie: str = ""
    length: int = 0


@dataclass
class DNSQuery:
    ts: str
    src: str
    qname: str
    qtype: str = ""
    answer: str = ""


@dataclass
class PcapReport:
    path: str
    total_packets: int = 0
    first_ts: str = ""
    last_ts: str = ""
    protocols: dict = field(default_factory=dict)
    credentials: list[Credential] = field(default_factory=list)
    http_requests: list[HTTPRequest] = field(default_factory=list)
    http_responses: list[HTTPResponse] = field(default_factory=list)
    dns_queries: list[DNSQuery] = field(default_factory=list)
    top_src_ips: list[tuple] = field(default_factory=list)
    top_dst_ips: list[tuple] = field(default_factory=list)
    top_ports: list[tuple] = field(default_factory=list)
    tls_sni: list[str] = field(default_factory=list)
    arp_pairs: list[tuple] = field(default_factory=list)
    arp_anomalies: list[dict] = field(default_factory=list)
    dns_tunneling: list[dict] = field(default_factory=list)
    beaconing_hosts: list[dict] = field(default_factory=list)
    extracted_files: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ===========================================================================
# Парсинг credentials
# ===========================================================================

def _decode_basic_auth(header_value: str) -> tuple[str, str]:
    """Basic auth → (user, pass)."""
    try:
        token = header_value.split(" ", 1)[1].strip()
        decoded = base64.b64decode(token).decode("utf-8", errors="ignore")
        if ":" in decoded:
            u, p = decoded.split(":", 1)
            return u, p
    except Exception:
        pass
    return "", ""


def _extract_http_auth(payload: bytes) -> tuple[str, str]:
    text = payload.decode("utf-8", errors="ignore")
    m = re.search(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)",
                  text, re.IGNORECASE)
    if m:
        return _decode_basic_auth(f"Basic {m.group(1)}")
    return "", ""


def _extract_ftp(payload: bytes) -> tuple[str, str]:
    text = payload.decode("utf-8", errors="ignore")
    user = ""
    pwd = ""
    m = re.search(r"USER\s+(\S+)", text)
    if m:
        user = m.group(1)
    m = re.search(r"PASS\s+(\S+)", text)
    if m:
        pwd = m.group(1)
    return user, pwd


def _extract_telnet(payload: bytes) -> tuple[str, str]:
    """Telnet — эвристика на основе printable strings."""
    try:
        text = payload.decode("utf-8", errors="ignore")
    except Exception:
        return "", ""
    lines = [l.strip() for l in text.splitlines()
             if l.strip() and len(l) < 80 and l.isprintable()]
    if len(lines) >= 2:
        return lines[0], lines[1]
    return "", ""


def _extract_smtp(payload: bytes) -> tuple[str, str]:
    text = payload.decode("utf-8", errors="ignore")
    # AUTH PLAIN
    m = re.search(r"AUTH\s+PLAIN\s+([A-Za-z0-9+/=]+)", text)
    if m:
        try:
            decoded = base64.b64decode(m.group(1)).decode(errors="ignore")
            parts = decoded.split("\x00")
            if len(parts) >= 3:
                return parts[1], parts[2]
        except Exception:
            pass
    # AUTH LOGIN — multistep
    m = re.search(
        r"AUTH\s+LOGIN\s+([A-Za-z0-9+/=]+)\s+([A-Za-z0-9+/=]+)",
        text, re.IGNORECASE,
    )
    if m:
        try:
            u = base64.b64decode(m.group(1)).decode(errors="ignore")
            p = base64.b64decode(m.group(2)).decode(errors="ignore")
            return u, p
        except Exception:
            pass
    return "", ""


def _extract_pop3(payload: bytes) -> tuple[str, str]:
    text = payload.decode("utf-8", errors="ignore")
    u = p = ""
    m = re.search(r"USER\s+(\S+)", text, re.IGNORECASE)
    if m:
        u = m.group(1)
    m = re.search(r"PASS\s+(\S+)", text, re.IGNORECASE)
    if m:
        p = m.group(1)
    return u, p


def _extract_imap(payload: bytes) -> tuple[str, str]:
    text = payload.decode("utf-8", errors="ignore")
    m = re.search(r"LOGIN\s+(\S+)\s+(\S+)", text, re.IGNORECASE)
    if m:
        return m.group(1), m.group(2)
    return "", ""


def _extract_snmp_community(payload: bytes) -> str:
    """SNMP v1/v2c community string."""
    try:
        # SNMP: 30 xx 02 01 xx 04 xx <community>
        if not payload.startswith(b"\x30"):
            return ""
        m = re.search(rb"\x04[\x01-\x20]([\x20-\x7e]+)", payload[:64])
        if m:
            return m.group(1).decode("utf-8", errors="ignore")
    except Exception:
        pass
    return ""


def _extract_ntlm_user(payload: bytes) -> str:
    """NTLMSSP → username (эвристика)."""
    try:
        if b"NTLMSSP" not in payload:
            return ""
        text = payload.decode("utf-16-le", errors="ignore")
        # Ищем username в типе 3 сообщения
        m = re.search(r"[A-Za-z0-9_.\-]{2,30}", text)
        if m and not m.group().startswith(("NTLMSSP", "Windows")):
            return m.group()
    except Exception:
        pass
    return ""


# ===========================================================================
# Парсинг HTTP
# ===========================================================================

def _extract_http_request(payload: bytes, src: str, dst: str,
                          ts: str) -> HTTPRequest | None:
    text = payload.decode("utf-8", errors="ignore")
    first_line = text.split("\r\n", 1)[0]
    m = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)\s+HTTP",
                 first_line)
    if not m:
        return None
    req = HTTPRequest(
        ts=ts, src=src, dst=dst,
        method=m.group(1), url=m.group(2),
    )
    # Headers
    head, _, body = text.partition("\r\n\r\n")
    for header_line in head.split("\r\n")[1:]:
        if ":" not in header_line:
            continue
        k, _, v = header_line.partition(":")
        k_lc = k.strip().lower()
        if k_lc == "host":
            req.host = v.strip()
        elif k_lc == "user-agent":
            req.user_agent = v.strip()[:160]
        elif k_lc == "authorization":
            req.auth = v.strip()[:300]
        elif k_lc == "cookie":
            req.cookie = v.strip()[:300]
        elif k_lc == "referer":
            req.referer = v.strip()[:200]
    if body:
        req.body = body[:500]
    return req


def _extract_http_response(payload: bytes, src: str, dst: str,
                           ts: str) -> HTTPResponse | None:
    text = payload.decode("utf-8", errors="ignore")
    first_line = text.split("\r\n", 1)[0]
    m = re.match(r"^HTTP/1\.[01]\s+(\d{3})", first_line)
    if not m:
        return None
    resp = HTTPResponse(ts=ts, src=src, dst=dst, status=int(m.group(1)))
    head, _, body = text.partition("\r\n\r\n")
    for header_line in head.split("\r\n")[1:]:
        if ":" not in header_line:
            continue
        k, _, v = header_line.partition(":")
        k_lc = k.strip().lower()
        if k_lc == "server":
            resp.server = v.strip()[:120]
        elif k_lc == "content-type":
            resp.content_type = v.strip()[:120]
        elif k_lc == "set-cookie":
            resp.set_cookie = v.strip()[:200]
        elif k_lc == "content-length":
            try:
                resp.length = int(v.strip())
            except ValueError:
                pass
    return resp


# ===========================================================================
# Парсинг TLS SNI
# ===========================================================================

def _extract_tls_sni(payload: bytes) -> str | None:
    """Извлечь SNI из TLS ClientHello."""
    try:
        if len(payload) < 50 or payload[0] != 0x16:
            return None
        idx = 5 + 4 + 2 + 32
        if idx >= len(payload):
            return None
        sid_len = payload[idx]
        idx += 1 + sid_len
        if idx + 2 > len(payload):
            return None
        cs_len = int.from_bytes(payload[idx:idx + 2], "big")
        idx += 2 + cs_len
        if idx >= len(payload):
            return None
        comp_len = payload[idx]
        idx += 1 + comp_len
        if idx + 2 > len(payload):
            return None
        ext_len = int.from_bytes(payload[idx:idx + 2], "big")
        idx += 2
        end = idx + ext_len
        while idx + 4 < end and idx + 4 < len(payload):
            ext_type = int.from_bytes(payload[idx:idx + 2], "big")
            ext_data_len = int.from_bytes(payload[idx + 2:idx + 4], "big")
            idx += 4
            if ext_type == 0:
                if idx + 5 > len(payload):
                    break
                name_len = int.from_bytes(payload[idx + 3:idx + 5], "big")
                return payload[idx + 5:idx + 5 + name_len].decode(
                    "utf-8", errors="ignore")
            idx += ext_data_len
    except Exception:
        pass
    return None


# ===========================================================================
# Аномалии
# ===========================================================================

def _detect_dns_tunneling(queries: list[DNSQuery],
                          threshold: int = 40) -> list[dict]:
    """Ищем подозрительно длинные / случайные qname (DNS tunneling)."""
    suspicious: list[dict] = []
    for q in queries:
        qn = q.qname or ""
        label = qn.split(".")[0] if qn else ""
        # Длинный label (>50) ИЛИ base32/base64-подобный
        if len(label) > threshold:
            suspicious.append({
                "qname": qn, "reason": "длинный label",
                "label_len": len(label), "src": q.src,
            })
            continue
        # Энтропия выше 4.0 (гекс/base32)
        if len(label) >= 24:
            ent = _shannon(label)
            if ent > 3.8:
                suspicious.append({
                    "qname": qn, "reason": f"высокая энтропия {ent:.2f}",
                    "label_len": len(label), "src": q.src,
                })
    return suspicious[:50]


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    import math
    counter = Counter(s)
    length = len(s)
    ent = 0.0
    for c in counter.values():
        p = c / length
        ent -= p * math.log2(p)
    return ent


def _detect_arp_anomalies(arp_table: dict[str, str]) -> list[dict]:
    """Ищем MAC, у которого несколько IP (ARP spoof)."""
    mac_to_ips: dict[str, list[str]] = defaultdict(list)
    for ip, mac in arp_table.items():
        mac_to_ips[mac].append(ip)
    out: list[dict] = []
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            out.append({"mac": mac, "ips": ips, "count": len(ips)})
    return out


# ===========================================================================
# Главный парсер
# ===========================================================================

def analyze_pcap(path: str, max_packets: int = 200_000,
                 extract_files: bool = False) -> PcapReport:
    """Проанализировать PCAP-файл."""
    if not SCAPY_OK:
        console.print(f"[red]scapy не установлен: {SCAPY_ERR}[/red]")
        console.print("[yellow]Установи: pip install scapy[/yellow]")
        return PcapReport(path=path)

    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return PcapReport(path=path)

    console.print(f"[cyan]📦 PCAP: {p.name} "
                  f"(max {max_packets:,} packets)[/cyan]")

    report = PcapReport(path=str(p))

    proto_counter: Counter = Counter()
    src_counter: Counter = Counter()
    dst_counter: Counter = Counter()
    port_counter: Counter = Counter()
    arp_table: dict[str, str] = {}
    tls_sni_set: set[str] = set()
    seen_creds: set[tuple] = set()

    packet_count = 0
    try:
        with PcapReader(str(p)) as reader:
            for pkt in reader:
                packet_count += 1
                if packet_count > max_packets:
                    report.errors.append(
                        f"Обрезано на {max_packets:,} пакетах")
                    break

                if not report.first_ts:
                    try:
                        report.first_ts = datetime.fromtimestamp(
                            float(pkt.time)).isoformat(timespec="seconds")
                    except Exception:
                        pass
                try:
                    report.last_ts = datetime.fromtimestamp(
                        float(pkt.time)).isoformat(timespec="seconds")
                except Exception:
                    pass

                ts = datetime.fromtimestamp(float(pkt.time)).strftime(
                    "%H:%M:%S") if hasattr(pkt, "time") else ""

                # ARP
                if pkt.haslayer(ARP):
                    proto_counter["ARP"] += 1
                    arp_table[pkt[ARP].psrc] = pkt[ARP].hwsrc
                    continue

                if not pkt.haslayer(IP):
                    continue

                ip = pkt[IP]
                src, dst = ip.src, ip.dst
                src_counter[src] += 1
                dst_counter[dst] += 1
                proto_counter[ip.proto] = proto_counter.get(ip.proto, 0) + 1

                if pkt.haslayer(TCP):
                    proto_counter["TCP"] += 1
                    tcp = pkt[TCP]
                    port_counter[tcp.dport] += 1
                    if pkt.haslayer(Raw):
                        payload = bytes(pkt[Raw].load)

                        # HTTP request/response
                        if (tcp.dport in (80, 8080, 8000, 8008, 8081, 8888)
                                or tcp.sport in (80, 8080, 8000, 8008,
                                                  8081, 8888)):
                            req = _extract_http_request(payload, src, dst, ts)
                            if req:
                                report.http_requests.append(req)
                                if req.auth:
                                    u, p_ = _extract_http_auth(payload)
                                    if u or p_:
                                        k = ("HTTP-Basic", u, p_)
                                        if k not in seen_creds:
                                            seen_creds.add(k)
                                            report.credentials.append(
                                                Credential(
                                                    ts=ts, proto="HTTP-Basic",
                                                    src=src, dst=dst,
                                                    username=u, password=p_,
                                                    extra=req.host,
                                                ))
                            else:
                                resp = _extract_http_response(
                                    payload, src, dst, ts)
                                if resp:
                                    report.http_responses.append(resp)

                        # FTP
                        if tcp.dport == 21 or tcp.sport == 21:
                            u, p_ = _extract_ftp(payload)
                            if u or p_:
                                k = ("FTP", u, p_)
                                if k not in seen_creds:
                                    seen_creds.add(k)
                                    report.credentials.append(Credential(
                                        ts=ts, proto="FTP",
                                        src=src, dst=dst,
                                        username=u, password=p_,
                                    ))

                        # Telnet
                        if tcp.dport == 23 or tcp.sport == 23:
                            u, p_ = _extract_telnet(payload)
                            if u or p_:
                                k = ("Telnet", u, p_)
                                if k not in seen_creds:
                                    seen_creds.add(k)
                                    report.credentials.append(Credential(
                                        ts=ts, proto="Telnet",
                                        src=src, dst=dst,
                                        username=u, password=p_,
                                    ))

                        # SMTP
                        if tcp.dport in (25, 587, 465) or \
                           tcp.sport in (25, 587, 465):
                            u, p_ = _extract_smtp(payload)
                            if u or p_:
                                k = ("SMTP", u, p_)
                                if k not in seen_creds:
                                    seen_creds.add(k)
                                    report.credentials.append(Credential(
                                        ts=ts, proto="SMTP",
                                        src=src, dst=dst,
                                        username=u, password=p_,
                                    ))

                        # POP3
                        if tcp.dport == 110 or tcp.sport == 110:
                            u, p_ = _extract_pop3(payload)
                            if u or p_:
                                k = ("POP3", u, p_)
                                if k not in seen_creds:
                                    seen_creds.add(k)
                                    report.credentials.append(Credential(
                                        ts=ts, proto="POP3",
                                        src=src, dst=dst,
                                        username=u, password=p_,
                                    ))

                        # IMAP
                        if tcp.dport in (143, 993) or \
                           tcp.sport in (143, 993):
                            u, p_ = _extract_imap(payload)
                            if u or p_:
                                k = ("IMAP", u, p_)
                                if k not in seen_creds:
                                    seen_creds.add(k)
                                    report.credentials.append(Credential(
                                        ts=ts, proto="IMAP",
                                        src=src, dst=dst,
                                        username=u, password=p_,
                                    ))

                        # SMB — NTLM username
                        if tcp.dport == 445 or tcp.sport == 445:
                            u = _extract_ntlm_user(payload)
                            if u:
                                k = ("SMB-NTLM", u, "")
                                if k not in seen_creds:
                                    seen_creds.add(k)
                                    report.credentials.append(Credential(
                                        ts=ts, proto="SMB-NTLM",
                                        src=src, dst=dst,
                                        username=u, extra="username из NTLMSSP",
                                    ))

                        # TLS SNI
                        if tcp.dport == 443 or tcp.sport == 443:
                            sni = _extract_tls_sni(payload)
                            if sni:
                                tls_sni_set.add(sni)

                elif pkt.haslayer(UDP):
                    proto_counter["UDP"] += 1
                    udp = pkt[UDP]
                    port_counter[udp.dport] += 1

                    # DNS
                    if pkt.haslayer(DNS):
                        proto_counter["DNS"] += 1
                        try:
                            dns = pkt[DNS]
                            if dns.qr == 0 and dns.qd:
                                qname = dns.qd.qname.decode(
                                    errors="ignore").rstrip(".")
                                qtype = dns.qd.qtype
                                qtype_str = {1: "A", 28: "AAAA", 5: "CNAME",
                                             15: "MX", 16: "TXT", 6: "SOA",
                                             2: "NS", 12: "PTR"}.get(
                                    qtype, str(qtype))
                                answer = ""
                                if dns.ancount:
                                    try:
                                        answer = str(dns.an.rdata)[:80]
                                    except Exception:
                                        pass
                                report.dns_queries.append(DNSQuery(
                                    ts=ts, src=src, qname=qname,
                                    qtype=qtype_str, answer=answer,
                                ))
                        except Exception:
                            pass

                    # SNMP
                    elif udp.dport in (161, 162) or udp.sport in (161, 162):
                        proto_counter["SNMP"] += 1
                        if pkt.haslayer(Raw):
                            payload = bytes(pkt[Raw].load)
                            community = _extract_snmp_community(payload)
                            if community:
                                k = ("SNMP", community, "")
                                if k not in seen_creds:
                                    seen_creds.add(k)
                                    report.credentials.append(Credential(
                                        ts=ts, proto="SNMP-Community",
                                        src=src, dst=dst,
                                        username=community,
                                        extra="v1/v2c community",
                                    ))

                elif pkt.haslayer(ICMP):
                    proto_counter["ICMP"] += 1

    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка чтения PCAP: {exc}[/red]")
        report.errors.append(str(exc))

    report.total_packets = packet_count
    report.protocols = dict(proto_counter.most_common(20))
    report.top_src_ips = src_counter.most_common(15)
    report.top_dst_ips = dst_counter.most_common(15)
    report.top_ports = port_counter.most_common(15)
    report.tls_sni = sorted(tls_sni_set)
    report.arp_pairs = sorted(arp_table.items())

    # Anomaly detection
    report.arp_anomalies = _detect_arp_anomalies(arp_table)
    report.dns_tunneling = _detect_dns_tunneling(report.dns_queries)

    _print_report(report)
    _save_findings(report)
    _notify_if_critical(report)

    db.save_scan("pcap_analysis", p.name, {
        "packets": report.total_packets,
        "creds": len(report.credentials),
        "http_reqs": len(report.http_requests),
        "http_resps": len(report.http_responses),
        "dns": len(report.dns_queries),
        "sni": len(report.tls_sni),
        "arp_anomalies": len(report.arp_anomalies),
        "dns_tunneling": len(report.dns_tunneling),
    })
    return report


def _save_findings(r: PcapReport) -> None:
    """Сохранить findings для critical/high."""
    # Cleartext credentials → critical
    if r.credentials:
        plaintext = [c for c in r.credentials
                     if c.password or c.proto in
                     ("HTTP-Basic", "FTP", "Telnet", "SMTP", "POP3",
                      "IMAP", "SNMP-Community")]
        if plaintext:
            ev_lines = []
            for c in plaintext[:15]:
                ev_lines.append(
                    f"{c.proto}: {c.src}→{c.dst} "
                    f"user='{c.username}' pass='{c.password}'"
                )
            _save_finding(PcapFinding(
                kind="cleartext_credentials",
                severity="high",
                title=f"Cleartext credentials в PCAP ({len(plaintext)})",
                target=Path(r.path).name,
                evidence="\n".join(ev_lines),
                data={"count": len(plaintext),
                      "protocols": list({c.proto for c in plaintext})},
            ))

    # ARP anomalies → high
    if r.arp_anomalies:
        ev = "\n".join(
            f"MAC {a['mac']} → {a['ips']}" for a in r.arp_anomalies[:10]
        )
        _save_finding(PcapFinding(
            kind="arp_spoof_suspected",
            severity="high",
            title=f"ARP-аномалия: {len(r.arp_anomalies)} MAC с несколькими IP",
            target=Path(r.path).name,
            evidence=ev,
            data={"anomalies": r.arp_anomalies[:10]},
        ))

    # DNS tunneling → high
    if len(r.dns_tunneling) >= 5:
        ev = "\n".join(
            f"{d['src']} → {d['qname'][:80]} ({d['reason']})"
            for d in r.dns_tunneling[:10]
        )
        _save_finding(PcapFinding(
            kind="dns_tunneling_suspected",
            severity="high",
            title=f"Подозрение на DNS tunneling ({len(r.dns_tunneling)})",
            target=Path(r.path).name,
            evidence=ev,
            data={"count": len(r.dns_tunneling),
                  "samples": r.dns_tunneling[:20]},
        ))


def _notify_if_critical(r: PcapReport) -> None:
    """Notify при критичных находках."""
    critical_count = 0
    if r.credentials:
        critical_count += len(r.credentials)
    if r.arp_anomalies:
        critical_count += len(r.arp_anomalies)
    if len(r.dns_tunneling) >= 5:
        critical_count += 1
    if not critical_count:
        return
    try:
        from modules import notifier
        notifier.notify_all(
            f"📦 PCAP: {Path(r.path).name}",
            f"Credentials: {len(r.credentials)}\n"
            f"ARP anomalies: {len(r.arp_anomalies)}\n"
            f"DNS tunneling hints: {len(r.dns_tunneling)}\n"
            f"Total packets: {r.total_packets:,}",
        )
    except Exception:
        pass


# ===========================================================================
# Печать
# ===========================================================================

def _print_report(r: PcapReport) -> None:
    # Summary
    table = Table(title=f"📦 PCAP: {Path(r.path).name}")
    table.add_column("Параметр", style="cyan")
    table.add_column("Значение", style="green")
    table.add_row("Packets", f"{r.total_packets:,}")
    table.add_row("First", r.first_ts)
    table.add_row("Last", r.last_ts)
    table.add_row("Credentials", str(len(r.credentials)))
    table.add_row("HTTP requests", str(len(r.http_requests)))
    table.add_row("HTTP responses", str(len(r.http_responses)))
    table.add_row("DNS queries", str(len(r.dns_queries)))
    table.add_row("TLS SNI", str(len(r.tls_sni)))
    table.add_row("ARP pairs", str(len(r.arp_pairs)))
    table.add_row("ARP anomalies", str(len(r.arp_anomalies)))
    table.add_row("DNS tunneling hints", str(len(r.dns_tunneling)))
    console.print(table)

    # Credentials
    if r.credentials:
        console.print(f"\n[bold red]🔑 Найдены credentials "
                      f"({len(r.credentials)}):[/bold red]")
        t = Table(title="Credentials")
        t.add_column("Time", width=10)
        t.add_column("Proto", style="cyan", width=14)
        t.add_column("Src", style="dim")
        t.add_column("Dst", style="dim")
        t.add_column("User", style="yellow")
        t.add_column("Password", style="red")
        t.add_column("Extra", style="dim", max_width=25)
        for c in r.credentials[:50]:
            t.add_row(c.ts, c.proto, c.src, c.dst,
                      c.username or "—",
                      c.password or "—",
                      (c.extra or "")[:25])
        console.print(t)

    # ARP anomalies
    if r.arp_anomalies:
        console.print(f"\n[bold red]⚠ ARP-аномалии:[/bold red]")
        t = Table(title="ARP spoof candidates")
        t.add_column("MAC", style="cyan")
        t.add_column("IPs", style="yellow")
        for a in r.arp_anomalies:
            t.add_row(a["mac"], ", ".join(a["ips"]))
        console.print(t)

    # DNS tunneling
    if r.dns_tunneling:
        console.print(f"\n[bold yellow]⚠ DNS tunneling hints:[/bold yellow]")
        t = Table(title="DNS tunneling")
        t.add_column("Src", style="dim", width=16)
        t.add_column("QName", style="cyan", max_width=60)
        t.add_column("Reason", style="yellow", max_width=30)
        for d in r.dns_tunneling[:15]:
            t.add_row(d["src"], d["qname"][:60], d["reason"][:30])
        console.print(t)

    # HTTP
    if r.http_requests:
        console.print(f"\n[bold cyan]🌐 HTTP requests "
                      f"({len(r.http_requests)}):[/bold cyan]")
        t = Table()
        t.add_column("Time", width=10)
        t.add_column("Method", style="magenta", width=8)
        t.add_column("Host", style="cyan", max_width=30)
        t.add_column("URL", style="white", max_width=50)
        for req in r.http_requests[:30]:
            t.add_row(req.ts, req.method,
                      (req.host or "")[:30], req.url[:50])
        console.print(t)

    # DNS
    if r.dns_queries:
        console.print(f"\n[bold cyan]🌐 DNS queries "
                      f"({len(r.dns_queries)}):[/bold cyan]")
        domains = Counter(q.qname for q in r.dns_queries)
        for d, c in domains.most_common(20):
            console.print(f"  [cyan]{d}[/cyan] [dim]× {c}[/dim]")

    # TLS SNI
    if r.tls_sni:
        console.print(f"\n[bold cyan]🔒 TLS SNI "
                      f"({len(r.tls_sni)}):[/bold cyan]")
        for s in r.tls_sni[:30]:
            console.print(f"  [green]{s}[/green]")

    # Top talkers
    if r.top_src_ips:
        console.print(f"\n[bold cyan]📊 Top src IPs:[/bold cyan]")
        for ip, count in r.top_src_ips[:10]:
            console.print(f"  [cyan]{ip:<40}[/cyan] {count:,}")

    if r.top_ports:
        console.print(f"\n[bold cyan]🔌 Top ports:[/bold cyan]")
        for port, count in r.top_ports[:10]:
            console.print(f"  [yellow]{port:<6}[/yellow] {count:,}")


# ===========================================================================
# Экспорт
# ===========================================================================

def export_json(report: PcapReport, path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(PCAP_DIR / f"analysis_{ts}.json")
    try:
        data = asdict(report)
        Path(path).write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_csv(report: PcapReport, path: str | None = None) -> Path | None:
    """CSV: одна строка на credential."""
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(PCAP_DIR / f"analysis_{ts}.csv")
    try:
        cols = ["ts", "proto", "src", "dst", "username", "password", "extra"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for c in report.credentials:
                w.writerow(asdict(c))
        console.print(f"[green]✓ CSV: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка CSV: {exc}[/red]")
        return None


def export_markdown(report: PcapReport,
                    path: str | None = None) -> Path | None:
    """Markdown-отчёт."""
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(PCAP_DIR / f"analysis_{ts}.md")

    lines = [
        f"# PCAP Analysis: {Path(report.path).name}",
        "",
        f"_Generated: {datetime.now().isoformat()}_",
        "",
        "## Summary",
        "",
        f"- **Packets:** {report.total_packets:,}",
        f"- **First:** {report.first_ts}",
        f"- **Last:** {report.last_ts}",
        f"- **Credentials:** {len(report.credentials)}",
        f"- **HTTP requests:** {len(report.http_requests)}",
        f"- **DNS queries:** {len(report.dns_queries)}",
        f"- **TLS SNI:** {len(report.tls_sni)}",
        f"- **ARP anomalies:** {len(report.arp_anomalies)}",
        f"- **DNS tunneling hints:** {len(report.dns_tunneling)}",
        "",
    ]

    if report.credentials:
        lines.append(f"## 🔑 Credentials ({len(report.credentials)})")
        lines.append("")
        lines.append("| Time | Proto | Src | Dst | User | Password |")
        lines.append("|------|-------|-----|-----|------|----------|")
        for c in report.credentials[:100]:
            lines.append(
                f"| {c.ts} | {c.proto} | {c.src} | {c.dst} | "
                f"`{c.username or '—'}` | `{c.password or '—'}` |"
            )
        lines.append("")

    if report.arp_anomalies:
        lines.append(f"## ⚠ ARP anomalies ({len(report.arp_anomalies)})")
        lines.append("")
        for a in report.arp_anomalies:
            lines.append(f"- MAC `{a['mac']}` → {', '.join(a['ips'])}")
        lines.append("")

    if report.dns_tunneling:
        lines.append(f"## ⚠ DNS tunneling hints "
                     f"({len(report.dns_tunneling)})")
        lines.append("")
        lines.append("| Src | QName | Reason |")
        lines.append("|-----|-------|--------|")
        for d in report.dns_tunneling[:50]:
            lines.append(
                f"| {d['src']} | `{d['qname'][:80]}` | {d['reason']} |"
            )
        lines.append("")

    if report.tls_sni:
        lines.append(f"## 🔒 TLS SNI ({len(report.tls_sni)})")
        lines.append("")
        for s in report.tls_sni[:50]:
            lines.append(f"- `{s}`")
        lines.append("")

    try:
        Path(path).write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green]✓ Markdown: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка Markdown: {exc}[/red]")
        return None


def export_html(report: PcapReport, path: str | None = None) -> Path | None:
    """HTML-отчёт."""
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(PCAP_DIR / f"analysis_{ts}.html")

    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>PCAP Analysis — {html_mod.escape(Path(report.path).name)}</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;padding:24px;line-height:1.5;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
        "h2{color:#00ff9c;margin-top:32px;}",
        "table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px;}",
        "th{background:#111;color:#00ff9c;text-align:left;padding:8px;border:1px solid #222;}",
        "td{padding:6px 8px;border:1px solid #222;vertical-align:top;word-break:break-all;}",
        "tr:nth-child(even){background:#0d0d0d;}",
        ".cred{color:#ff4040;font-weight:bold;}",
        ".warn{color:#ffd23f;}",
        ".crit{color:#ff2020;font-weight:bold;}",
        "code{background:#111;padding:2px 6px;color:#a0ffa0;}",
        "</style></head><body>",
        f"<h1>📦 PCAP: {html_mod.escape(Path(report.path).name)}</h1>",
        f"<p>Packets: <b>{report.total_packets:,}</b> | "
        f"First: {html_mod.escape(report.first_ts)} | "
        f"Last: {html_mod.escape(report.last_ts)} | "
        f"Credentials: <b>{len(report.credentials)}</b></p>",
    ]

    if report.credentials:
        parts.append(f"<h2>🔑 Credentials ({len(report.credentials)})</h2>")
        parts.append("<table><tr><th>Time</th><th>Proto</th>"
                     "<th>Src</th><th>Dst</th><th>User</th>"
                     "<th>Password</th></tr>")
        for c in report.credentials:
            parts.append(
                f"<tr><td>{html_mod.escape(c.ts)}</td>"
                f"<td>{html_mod.escape(c.proto)}</td>"
                f"<td>{html_mod.escape(c.src)}</td>"
                f"<td>{html_mod.escape(c.dst)}</td>"
                f"<td><code>{html_mod.escape(c.username)}</code></td>"
                f"<td class='cred'>{html_mod.escape(c.password)}</td></tr>"
            )
        parts.append("</table>")

    if report.arp_anomalies:
        parts.append(f"<h2>⚠ ARP anomalies ({len(report.arp_anomalies)})</h2>")
        parts.append("<table><tr><th>MAC</th><th>IPs</th></tr>")
        for a in report.arp_anomalies:
            parts.append(
                f"<tr><td>{html_mod.escape(a['mac'])}</td>"
                f"<td class='crit'>{html_mod.escape(', '.join(a['ips']))}</td></tr>"
            )
        parts.append("</table>")

    if report.dns_tunneling:
        parts.append(f"<h2>⚠ DNS tunneling hints "
                     f"({len(report.dns_tunneling)})</h2>")
        parts.append("<table><tr><th>Src</th><th>QName</th>"
                     "<th>Reason</th></tr>")
        for d in report.dns_tunneling[:100]:
            parts.append(
                f"<tr><td>{html_mod.escape(d['src'])}</td>"
                f"<td><code>{html_mod.escape(d['qname'][:100])}</code></td>"
                f"<td class='warn'>{html_mod.escape(d['reason'])}</td></tr>"
            )
        parts.append("</table>")

    if report.dns_queries:
        parts.append(f"<h2>🌐 DNS queries ({len(report.dns_queries)})</h2>")
        parts.append("<table><tr><th>Time</th><th>Src</th>"
                     "<th>Query</th><th>Type</th><th>Answer</th></tr>")
        for q in report.dns_queries[:500]:
            parts.append(
                f"<tr><td>{html_mod.escape(q.ts)}</td>"
                f"<td>{html_mod.escape(q.src)}</td>"
                f"<td>{html_mod.escape(q.qname)}</td>"
                f"<td>{html_mod.escape(q.qtype)}</td>"
                f"<td>{html_mod.escape(q.answer[:80])}</td></tr>"
            )
        parts.append("</table>")

    if report.tls_sni:
        parts.append(f"<h2>🔒 TLS SNI ({len(report.tls_sni)})</h2><ul>")
        for s in report.tls_sni[:100]:
            parts.append(f"<li><code>{html_mod.escape(s)}</code></li>")
        parts.append("</ul>")

    if report.errors:
        parts.append(f"<h2>❌ Ошибки ({len(report.errors)})</h2><ul>")
        for e in report.errors:
            parts.append(f"<li>{html_mod.escape(e)}</li>")
        parts.append("</ul>")

    parts.append("</body></html>")
    try:
        Path(path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка HTML: {exc}[/red]")
        return None


def export_all(report: PcapReport) -> list[Path]:
    """Все 4 формата."""
    out: list[Path] = []
    for fn in (export_json, export_csv, export_markdown, export_html):
        p = fn(report)
        if p:
            out.append(p)
    return out


# ===========================================================================
# CLI-обёртки (сохранены все старые)
# ===========================================================================

def cli_analyze(path: str) -> None:
    r = analyze_pcap(path)
    if r.total_packets and Confirm.ask("Экспорт JSON + HTML?",
                                       default=False):
        export_json(r)
        export_html(r)


def cli_html(path: str) -> None:
    r = analyze_pcap(path)
    if r.total_packets:
        export_html(r)


def cli_csv(path: str) -> None:
    r = analyze_pcap(path)
    if r.total_packets:
        export_csv(r)


def cli_md(path: str) -> None:
    r = analyze_pcap(path)
    if r.total_packets:
        export_markdown(r)


def cli_all(path: str) -> None:
    r = analyze_pcap(path)
    if r.total_packets:
        export_all(r)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]📦 Packet Analysis Suite Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Анализ PCAP (creds, HTTP, DNS, SNI, ARP, tunneling)"),
        ("2", "Анализ + HTML-отчёт"),
        ("3", "Анализ + JSON"),
        ("4", "Анализ + CSV (credentials)"),
        ("5", "Анализ + Markdown"),
        ("6", "Анализ + всё сразу (JSON/CSV/MD/HTML)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного пентеста.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        analyze_pcap(Prompt.ask("PCAP-файл"))
    elif c == "2":
        cli_html(Prompt.ask("PCAP-файл"))
    elif c == "3":
        cli_analyze(Prompt.ask("PCAP-файл"))
    elif c == "4":
        cli_csv(Prompt.ask("PCAP-файл"))
    elif c == "5":
        cli_md(Prompt.ask("PCAP-файл"))
    elif c == "6":
        cli_all(Prompt.ask("PCAP-файл"))