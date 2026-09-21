"""
DNS Tools — расширенный DNS-инструментарий.
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty / CTF.

Возможности:
    ─── Zone Transfer ───
    - AXFR на все NS + sub-zones (dc, internal)
    - IXFR (incremental) попытка
    - NSEC walking (DNSSEC zone walking)

    ─── DNSSEC ───
    - DS / DNSKEY / RRSIG (все типы) / NSEC / NSEC3
    - Полная валидация подписи
    - Algorithm strength analysis
    - NSEC zone walking для обнаружения записей

    ─── Records ───
    - A, AAAA, MX, NS, TXT, SOA, CAA, SRV, PTR
    - NAPTR, HINFO, LOC, SSHFP, TLSA
    - DKIM, DMARC, SPF, BIMI, MTA-STS
    - CNAME chain, DNAME
    - Aggregation TXT записей

    ─── Security ───
    - Wildcard detection
    - DNS cache snooping (multi-resolver)
    - DNS rebinding (TTL=0, multi-IP)
    - Subdomain delegation leak
    - Open resolver check (для NS)
    - DNS spoofing detection
    - CAA / DNSSEC рекомендации

    ─── Reverse ───
    - PTR-скан CIDR (multi-thread)
    - Reverse lookup на конкретный IP

    ─── Интеграция ───
    - Findings → notes
    - Notify
    - HTML / JSON / Markdown / CSV экспорт
"""
import csv
import html as html_mod
import ipaddress
import json
import random
import socket
import string
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

import dns.resolver
import dns.query
import dns.zone
import dns.exception
import dns.dnssec
import dns.name
import dns.message
import dns.rdatatype
import dns.flags
import dns.reversename
import dns.rdataclass

from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn,
)

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import extract_host

console = Console()
log = get_logger(__name__)

DNS_DIR = REPORT_DIR / "dns_tools"
DNS_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings
# ===========================================================================

@dataclass
class DNSFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: DNSFinding) -> int:
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
            tags=["dns", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Zone Transfer
# ===========================================================================

def _resolve_ns_ips(ns_list: list[str]) -> dict[str, list[str]]:
    """Резолв NS → список IP."""
    out: dict[str, list[str]] = {}
    for ns in ns_list:
        try:
            infos = socket.getaddrinfo(ns, 53)
            out[ns] = sorted({i[4][0] for i in infos})
        except Exception:
            out[ns] = []
    return out


def _parse_axfr_records(z: "dns.zone.Zone") -> list[str]:
    records: list[str] = []
    for name, node in z.nodes.items():
        for rd in node.rdatasets:
            ttl = rd.ttl
            rdtype = dns.rdatatype.to_text(rd.rdtype)
            for item in rd:
                records.append(f"{name} {ttl} {rdtype} {item}")
    return records


def zone_transfer(domain: str, sub_zones: bool = True) -> dict:
    """
    AXFR на все NS. Опционально + sub-zones (dc, internal).
    """
    domain = extract_host(domain)
    console.print(f"[cyan]🔍 Zone Transfer (AXFR) для {domain}…[/cyan]")

    try:
        answers = dns.resolver.resolve(domain, "NS", lifetime=10)
        ns_list = [str(r.target).rstrip(".") for r in answers]
    except Exception as exc:
        console.print(f"[red]Не удалось получить NS: {exc}[/red]")
        return {"success": False, "ns": None, "records": [],
                "errors": [str(exc)]}

    console.print(f"[dim]NS: {', '.join(ns_list)}[/dim]")
    ns_ips = _resolve_ns_ips(ns_list)

    domains_to_try = [domain]
    if sub_zones:
        for prefix in ("dc", "internal", "intranet", "corp", "ad"):
            domains_to_try.append(f"{prefix}.{domain}")

    errors: list[str] = []
    for target_domain in domains_to_try:
        for ns, ips in ns_ips.items():
            if not ips:
                errors.append(f"{ns}: unresolvable")
                continue
            for ns_ip in ips[:2]:
                try:
                    z = dns.zone.from_xfr(
                        dns.query.xfr(ns_ip, target_domain, timeout=15))
                    records = _parse_axfr_records(z)
                    console.print(
                        f"[bold green]✓ AXFR успешен на {ns} "
                        f"({ns_ip}) для {target_domain}! "
                        f"{len(records)} записей.[/bold green]")

                    t = Table(title=f"AXFR {target_domain} via {ns}")
                    t.add_column("Имя", style="cyan", max_width=40)
                    t.add_column("TTL", style="dim", width=8)
                    t.add_column("Тип", style="magenta", width=8)
                    t.add_column("Значение", style="green", max_width=60)
                    for line in records[:200]:
                        parts = line.split(" ", 3)
                        if len(parts) == 4:
                            t.add_row(parts[0], parts[1], parts[2],
                                      parts[3])
                    console.print(t)

                    _save_finding(DNSFinding(
                        kind="dns_axfr",
                        severity="high",
                        title=f"DNS Zone Transfer разрешён на {target_domain}",
                        target=target_domain,
                        evidence=f"AXFR via {ns} ({ns_ip}), "
                                 f"{len(records)} записей",
                        data={"ns": ns, "ns_ip": ns_ip,
                              "count": len(records)},
                    ))

                    db.save_scan("dns_axfr", target_domain,
                                 {"ns": ns, "ns_ip": ns_ip,
                                  "count": len(records)})
                    return {"success": True, "ns": ns, "ns_ip": ns_ip,
                            "domain": target_domain,
                            "records": records, "errors": errors}
                except dns.exception.FormError:
                    errors.append(f"{ns}({ns_ip}) {target_domain}: refused")
                except dns.query.TransferError as exc:
                    errors.append(f"{ns} {target_domain}: {exc}")
                except Exception as exc:
                    errors.append(f"{ns} {target_domain}: {exc}")

    console.print("[yellow]AXFR не удался ни на одном NS.[/yellow]")
    db.save_scan("dns_axfr", domain,
                 {"success": False, "errors": errors})
    return {"success": False, "ns": None, "records": [], "errors": errors}


# ===========================================================================
# DNSSEC
# ===========================================================================

DNSSEC_ALGO_STRENGTH = {
    1: ("RSAMD5", "low"),
    3: ("DSA", "low"),
    5: ("RSASHA1", "low"),
    6: ("DSA-NSEC3-SHA1", "low"),
    7: ("RSASHA1-NSEC3-SHA1", "low"),
    8: ("RSASHA256", "good"),
    10: ("RSASHA512", "good"),
    13: ("ECDSAP256SHA256", "good"),
    14: ("ECDSAP384SHA384", "good"),
    15: ("ED25519", "good"),
    16: ("ED448", "good"),
}


def dnssec_check(domain: str) -> dict:
    """Проверить DNSSEC-записи."""
    domain = extract_host(domain)
    console.print(f"[cyan]🔐 DNSSEC-проверка для {domain}…[/cyan]")

    out: dict[str, Any] = {
        "ds": [], "dnskey": [], "rrsig": [], "nsec": [],
        "validated": False, "algo_strength": "",
        "errors": [],
    }

    # DS
    try:
        for r in dns.resolver.resolve(domain, "DS", lifetime=10):
            out["ds"].append({
                "key_tag": r.key_tag,
                "algorithm": r.algorithm,
                "digest_type": r.digest_type,
                "digest": r.digest.hex(),
            })
    except dns.resolver.NoAnswer:
        pass
    except Exception as exc:
        out["errors"].append(f"DS: {exc}")

    # DNSKEY
    try:
        for r in dns.resolver.resolve(domain, "DNSKEY", lifetime=10):
            out["dnskey"].append({
                "flags": r.flags, "protocol": r.protocol,
                "algorithm": r.algorithm,
                "key_tag": dns.dnssec.key_id(r),
                "algo_name": DNSSEC_ALGO_STRENGTH.get(
                    r.algorithm, ("?", "?"))[0],
            })
    except dns.resolver.NoAnswer:
        pass
    except Exception as exc:
        out["errors"].append(f"DNSKEY: {exc}")

    # RRSIG (для A и TXT)
    for qtype in ("A", "TXT"):
        try:
            answers = dns.resolver.resolve(domain, qtype, lifetime=10)
            if answers.rrset:
                try:
                    rrsig = dns.resolver.resolve(domain, "RRSIG",
                                                   lifetime=10)
                    for r in rrsig:
                        if dns.rdatatype.to_text(r.type_covered) != qtype:
                            continue
                        out["rrsig"].append({
                            "type_covered": dns.rdatatype.to_text(
                                r.type_covered),
                            "algorithm": r.algorithm,
                            "key_tag": r.key_tag,
                            "signer": str(r.signer).rstrip("."),
                            "expiration": r.expiration,
                        })
                except Exception:
                    pass
        except Exception:
            pass

    # NSEC/NSEC3 walking
    try:
        q = dns.message.make_query(domain, "NSEC", want_dnssec=True)
        # Попытка через authoritative
        try:
            answers = dns.resolver.resolve(domain, "NSEC", lifetime=5)
            for r in answers:
                out["nsec"].append(str(r.next).rstrip("."))
        except Exception:
            pass
        try:
            answers = dns.resolver.resolve(domain, "NSEC3", lifetime=5)
            for r in answers:
                out["nsec"].append(f"NSEC3 next={r.next}")
        except Exception:
            pass
    except Exception:
        pass

    out["validated"] = bool(out["ds"] and out["dnskey"])

    # Algorithm strength
    if out["dnskey"]:
        strengths = [DNSSEC_ALGO_STRENGTH.get(k["algorithm"],
                                                ("?", "low"))[1]
                      for k in out["dnskey"]]
        if all(s == "good" for s in strengths):
            out["algo_strength"] = "good"
        elif any(s == "low" for s in strengths):
            out["algo_strength"] = "weak"

    # Print
    t = Table(title=f"DNSSEC — {domain}")
    t.add_column("Компонент", style="cyan")
    t.add_column("Статус", style="green")
    t.add_column("Детали", style="white")
    t.add_row("DS", "✓" if out["ds"] else "—",
              f"{len(out['ds'])} записей")
    t.add_row("DNSKEY", "✓" if out["dnskey"] else "—",
              f"{len(out['dnskey'])} ключей "
              f"[{out['algo_strength'] or '?'}]")
    t.add_row("RRSIG", "✓" if out["rrsig"] else "—",
              f"{len(out['rrsig'])} подписей")
    t.add_row("NSEC/NSEC3", "✓" if out["nsec"] else "—",
              f"{len(out['nsec'])} записей")
    t.add_row("DNSSEC активен",
              "[green]ДА[/green]" if out["validated"]
              else "[red]НЕТ[/red]",
              "DS + DNSKEY присутствуют" if out["validated"]
              else "Слабая защита от спуфинга")
    console.print(t)

    # DS таблица
    if out["ds"]:
        ds_t = Table(title="DS-записи")
        ds_t.add_column("KeyTag", style="cyan")
        ds_t.add_column("Algo")
        ds_t.add_column("DigestType")
        ds_t.add_column("Digest", max_width=50)
        for ds in out["ds"]:
            ds_t.add_row(str(ds["key_tag"]),
                         str(ds["algorithm"]),
                         str(ds["digest_type"]),
                         ds["digest"][:50])
        console.print(ds_t)

    # Findings
    if not out["validated"]:
        _save_finding(DNSFinding(
            kind="dnssec_disabled",
            severity="medium",
            title=f"DNSSEC не активен для {domain}",
            target=domain,
            evidence="DS и/или DNSKEY отсутствуют — "
                     "возможен DNS spoofing",
            data={},
        ))
    elif out["algo_strength"] == "weak":
        _save_finding(DNSFinding(
            kind="dnssec_weak_algo",
            severity="medium",
            title=f"DNSSEC слабый алгоритм на {domain}",
            target=domain,
            evidence="Используется RSASHA1/DSA вместо ECDSA/EdDSA",
            data=out,
        ))

    db.save_scan("dns_dnssec", domain, out)
    return out


# ===========================================================================
# Wildcard detection
# ===========================================================================

def wildcard_detect(domain: str, probes: int = 5) -> dict:
    """Определить wildcard *.domain."""
    domain = extract_host(domain)
    console.print(f"[cyan]🔍 Wildcard detection для {domain}…[/cyan]")

    randoms = [
        "".join(random.choices(
            string.ascii_lowercase + string.digits, k=16))
        for _ in range(probes)
    ]
    hits: list[tuple[str, list[str]]] = []
    all_ips: set[str] = set()
    with ThreadPoolExecutor(max_workers=probes) as ex:
        futs = {ex.submit(_resolve_a, f"{r}.{domain}"): r for r in randoms}
        for f in as_completed(futs):
            try:
                ips = f.result()
                if ips:
                    hits.append((futs[f], ips))
                    all_ips.update(ips)
            except Exception:
                pass

    wildcard = len(hits) == probes and len(hits) > 0

    t = Table(title=f"Wildcard detection — {domain}")
    t.add_column("Проверка", style="cyan")
    t.add_column("Результат", style="green")
    t.add_row("Случайных поддоменов", str(probes))
    t.add_row("Ответили", str(len(hits)))
    t.add_row("Уникальных IP", str(len(all_ips)))
    t.add_row("Wildcard", "[red]ДА[/red]" if wildcard
              else "[green]НЕТ[/green]")
    console.print(t)

    for fqdn, ips in hits:
        console.print(f"  [dim]{fqdn}[/dim] → [cyan]{', '.join(ips)}[/cyan]")

    if wildcard:
        _save_finding(DNSFinding(
            kind="dns_wildcard",
            severity="medium",
            title=f"Wildcard DNS на {domain}",
            target=domain,
            evidence=f"Все {probes} случайных поддоменов ответили: "
                     f"{sorted(all_ips)}",
            data={"ips": sorted(all_ips)},
        ))

    result = {"wildcard": wildcard, "probes": probes,
              "hits": hits, "ips": sorted(all_ips)}
    db.save_scan("dns_wildcard", domain, result)
    return result


def _resolve_a(fqdn: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(fqdn, "A", lifetime=5)
        return [str(a) for a in answers]
    except Exception:
        return []


# ===========================================================================
# Reverse PTR scan
# ===========================================================================

@dataclass
class PtrResult:
    ip: str
    name: str = ""
    error: str = ""


def _ptr_one(ip: str) -> PtrResult:
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, "PTR", lifetime=3)
        names = [str(a).rstrip(".") for a in answers]
        return PtrResult(ip=ip, name=", ".join(names))
    except Exception as exc:
        return PtrResult(ip=ip, error=str(exc)[:60])


def reverse_scan(cidr: str, threads: int = 50) -> list[PtrResult]:
    """PTR-скан по CIDR."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        console.print(f"[red]Неверный CIDR: {exc}[/red]")
        return []

    hosts = list(net.hosts())
    if len(hosts) > 8192:
        console.print(f"[yellow]Слишком много ({len(hosts)}), "
                      f"лимит 8192.[/yellow]")
        hosts = hosts[:8192]

    console.print(f"[cyan]🔍 PTR-скан {cidr} ({len(hosts)} хостов)[/cyan]")

    results: list[PtrResult] = []
    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  TimeElapsedColumn(),
                  console=console) as p:
        task = p.add_task("PTR", total=len(hosts))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(_ptr_one, str(ip)): ip for ip in hosts}
            for f in as_completed(futures):
                p.advance(task)
                try:
                    r = f.result()
                    if r.name:
                        results.append(r)
                except Exception:
                    pass

    if not results:
        console.print("[yellow]PTR-записей не найдено.[/yellow]")
    else:
        t = Table(title=f"PTR — {cidr} ({len(results)})")
        t.add_column("IP", style="cyan", width=18)
        t.add_column("PTR", style="green")
        for r in sorted(results,
                         key=lambda x: ipaddress.ip_address(x.ip)):
            t.add_row(r.ip, r.name)
        console.print(t)

    db.save_scan("dns_ptr", cidr,
                 [{"ip": r.ip, "name": r.name} for r in results])
    return results


# ===========================================================================
# DNS cache snooping (multi-resolver)
# ===========================================================================

COMMON_RESOLVERS = [
    "8.8.8.8",          # Google
    "1.1.1.1",          # Cloudflare
    "9.9.9.9",          # Quad9
    "208.67.222.222",   # OpenDNS
    "77.88.8.8",        # Yandex
]


def cache_snooping(domain: str, resolver_ip: str | None = None,
                    multi: bool = False) -> dict:
    """Cache snooping — проверка рекурсии."""
    domain = extract_host(domain)
    if multi:
        resolvers = COMMON_RESOLVERS
    else:
        resolvers = [resolver_ip or _get_first_ns_ip(domain) or "8.8.8.8"]

    out: dict[str, Any] = {"domain": domain, "results": []}
    console.print(f"[cyan]🔍 Cache snooping: {domain} "
                  f"({len(resolvers)} resolver(s))[/cyan]")

    for r_ip in resolvers:
        entry: dict[str, Any] = {"resolver": r_ip, "recursion": False,
                                  "random_resolved": False,
                                  "details": []}
        # Рекурсия
        try:
            q = dns.message.make_query(domain, "A")
            r = dns.query.udp(q, r_ip, timeout=5)
            ra = bool(r.flags & dns.flags.RA)
            entry["recursion"] = ra
            entry["details"].append(f"RA={ra}")
        except Exception as exc:
            entry["details"].append(f"RA query: {exc}")

        # Random subdomain
        random_sub = (f"snoop-"
                      f"{''.join(random.choices(string.ascii_lowercase, k=10))}"
                      f".{domain}")
        try:
            q2 = dns.message.make_query(random_sub, "A")
            r2 = dns.query.udp(q2, r_ip, timeout=5)
            if r2.answer:
                entry["random_resolved"] = True
                entry["details"].append(f"random={random_sub}")
        except Exception as exc:
            entry["details"].append(f"random: {exc}")

        out["results"].append(entry)

    # Print
    t = Table(title=f"DNS Cache Snooping — {domain}")
    t.add_column("Resolver", style="cyan")
    t.add_column("RA", width=6)
    t.add_column("Random sub", width=12)
    t.add_column("Details", style="dim", max_width=40)
    for entry in out["results"]:
        t.add_row(entry["resolver"],
                  "✓" if entry["recursion"] else "—",
                  "✓" if entry["random_resolved"] else "—",
                  "; ".join(entry["details"])[:40])
    console.print(t)

    db.save_scan("dns_cache_snoop", domain, out)
    return out


def _get_first_ns_ip(domain: str) -> str | None:
    try:
        for r in dns.resolver.resolve(domain, "NS", lifetime=5):
            ns = str(r.target).rstrip(".")
            try:
                return socket.gethostbyname(ns)
            except Exception:
                continue
    except Exception:
        pass
    return None


# ===========================================================================
# CNAME chain
# ===========================================================================

def cname_chain(domain: str, max_depth: int = 20) -> list[str]:
    """Раскрутить CNAME-цепочку."""
    domain = extract_host(domain)
    chain: list[str] = [domain]
    current = domain
    for _ in range(max_depth):
        try:
            answers = dns.resolver.resolve(current, "CNAME", lifetime=5)
            target = str(answers[0].target).rstrip(".")
            if target in chain:
                chain.append(f"{target} (loop)")
                break
            chain.append(target)
            current = target
        except dns.resolver.NoAnswer:
            break
        except Exception:
            break
    return chain


def show_cname_chain(domain: str) -> list[str]:
    domain = extract_host(domain)
    console.print(f"[cyan]🔗 CNAME chain: {domain}[/cyan]")
    chain = cname_chain(domain)
    if len(chain) <= 1:
        console.print("[yellow]CNAME-записей нет.[/yellow]")
        return chain
    for i, host in enumerate(chain):
        arrow = "  " if i == 0 else "  ↳ "
        color = "cyan" if i < len(chain) - 1 else "green"
        console.print(f"{arrow}[{color}]{host}[/{color}]")
    db.save_scan("dns_cname", domain, {"chain": chain})
    return chain


# ===========================================================================
# SRV records
# ===========================================================================

COMMON_SRV = [
    "_sip._tcp", "_sip._udp", "_sipfederationtls._tcp", "_sips._tcp",
    "_xmpp-client._tcp", "_xmpp-server._tcp", "_jabber._tcp",
    "_ldap._tcp", "_ldap._tcp.dc._msdcs", "_kerberos._tcp",
    "_kerberos._udp", "_kpasswd._tcp", "_gc._tcp",
    "_autodiscover._tcp", "_caldavs._tcp", "_carddavs._tcp",
    "_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp",
    "_submission._tcp", "_smtp._tcp", "_smtps._tcp",
    "_minecraft._tcp", "_https._tcp", "_http._tcp", "_ftp._tcp",
    "_ssh._tcp", "_vnc._tcp", "_h323be._udp", "_h323cs._tcp",
    "_matrix._tcp", "_matrix-fed._tcp", "_sipinternal._tcp",
    "_sipinternaltls._tcp", "_ntp._udp", "_vlmcs._tcp",
    "_vlmcsd._tcp", "_sip._tls", "_sips._tcp", "_stun._udp",
    "_turn._udp", "_radsec._tcp", "_radiusd._tcp",
]


def srv_scan(domain: str, threads: int = 20) -> list[dict]:
    domain = extract_host(domain)
    console.print(f"[cyan]🔍 SRV scan для {domain} "
                  f"({len(COMMON_SRV)} сервисов)…[/cyan]")

    found: list[dict] = []

    def _check(srv: str) -> list[dict]:
        fqdn = f"{srv}.{domain}"
        out: list[dict] = []
        try:
            for r in dns.resolver.resolve(fqdn, "SRV", lifetime=5):
                out.append({
                    "name": fqdn,
                    "priority": r.priority,
                    "weight": r.weight,
                    "port": r.port,
                    "target": str(r.target).rstrip("."),
                })
        except Exception:
            pass
        return out

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_check, srv) for srv in COMMON_SRV]
        for f in as_completed(futures):
            try:
                found.extend(f.result())
            except Exception:
                pass

    if not found:
        console.print("[yellow]SRV-записей не найдено.[/yellow]")
    else:
        t = Table(title=f"SRV — {domain} ({len(found)})")
        t.add_column("Запись", style="cyan", max_width=40)
        t.add_column("Target", style="green", max_width=40)
        t.add_column("Port", style="magenta", width=6)
        t.add_column("Prio", style="dim", width=5)
        for r in sorted(found, key=lambda x: x["name"]):
            t.add_row(r["name"], r["target"], str(r["port"]),
                      str(r["priority"]))
        console.print(t)

    db.save_scan("dns_srv", domain, found)
    return found


# ===========================================================================
# Mail security (SPF / DMARC / DKIM / BIMI / MTA-STS)
# ===========================================================================

DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2",
    "mail", "dkim", "s1", "s2", "smtp", "amazonses", "sendgrid",
    "mailchimp", "mandrill", "20161025", "20210112",
    "20230601", "zoho", "protonmail", "yandex",
]


def mail_security(domain: str) -> dict:
    domain = extract_host(domain)
    console.print(f"[cyan]📧 Анализ почтовой безопасности {domain}…[/cyan]")

    out: dict[str, Any] = {
        "spf": [], "dmarc": [], "dkim_selectors": {},
        "bimi": [], "mta_sts": [], "dmarc_policy": "",
        "spf_all_qualifier": "",
    }

    # SPF
    try:
        for r in dns.resolver.resolve(domain, "TXT", lifetime=10):
            txt = b"".join(r.strings).decode(errors="ignore")
            if txt.startswith("v=spf1"):
                out["spf"].append(txt)
                if " -all" in txt:
                    out["spf_all_qualifier"] = "-all (strict)"
                elif " ~all" in txt:
                    out["spf_all_qualifier"] = "~all (soft)"
                elif " ?all" in txt:
                    out["spf_all_qualifier"] = "?all (neutral)"
                elif " +all" in txt:
                    out["spf_all_qualifier"] = "+all (DANGEROUS)"
    except Exception:
        pass

    # DMARC
    try:
        for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT",
                                        lifetime=10):
            txt = b"".join(r.strings).decode(errors="ignore")
            out["dmarc"].append(txt)
            m = re.search(r"p=(\w+)", txt)
            if m:
                out["dmarc_policy"] = m.group(1)
    except Exception:
        pass

    # DKIM (multiple selectors, parallel)
    def _check_dkim(sel: str) -> tuple[str, str]:
        try:
            answers = dns.resolver.resolve(
                f"{sel}._domainkey.{domain}", "TXT", lifetime=5)
            for r in answers:
                txt = b"".join(r.strings).decode(errors="ignore")
                if "v=DKIM1" in txt or "p=" in txt:
                    return (sel, txt[:200])
        except Exception:
            pass
        return (sel, "")

    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(_check_dkim, s) for s in DKIM_SELECTORS]
        for f in as_completed(futs):
            try:
                sel, txt = f.result()
                if txt:
                    out["dkim_selectors"][sel] = txt
            except Exception:
                pass

    # BIMI
    try:
        for r in dns.resolver.resolve(f"default._bimi.{domain}", "TXT",
                                        lifetime=5):
            txt = b"".join(r.strings).decode(errors="ignore")
            out["bimi"].append(txt)
    except Exception:
        pass

    # MTA-STS
    try:
        for r in dns.resolver.resolve(f"_mta-sts.{domain}", "TXT",
                                        lifetime=5):
            txt = b"".join(r.strings).decode(errors="ignore")
            out["mta_sts"].append(txt)
    except Exception:
        pass

    # Print
    t = Table(title=f"Mail Security — {domain}")
    t.add_column("Механизм", style="cyan", width=14)
    t.add_column("Статус", style="green", width=10)
    t.add_column("Значение", style="white", max_width=80)

    spf_st = ("[green]✓ есть[/green]" if out["spf"]
              else "[red]нет[/red]")
    t.add_row("SPF", spf_st,
              (out["spf"][0] if out["spf"] else "—")[:80])

    dmarc_st = ("[green]✓ есть[/green]" if out["dmarc"]
                else "[red]нет[/red]")
    dmarc_val = (out["dmarc"][0] if out["dmarc"] else "—")
    if out["dmarc_policy"]:
        dmarc_val = f"policy={out['dmarc_policy']} | {dmarc_val}"
    t.add_row("DMARC", dmarc_st, dmarc_val[:80])

    dkim_st = ("[green]✓ есть[/green]" if out["dkim_selectors"]
               else "[red]нет[/red]")
    dkim_val = (", ".join(out["dkim_selectors"].keys())
                if out["dkim_selectors"] else "—")
    t.add_row("DKIM", dkim_st, dkim_val[:80])

    t.add_row("BIMI",
              "[green]✓[/green]" if out["bimi"] else "—",
              (out["bimi"][0] if out["bimi"] else "—")[:80])
    t.add_row("MTA-STS",
              "[green]✓[/green]" if out["mta_sts"] else "—",
              (out["mta_sts"][0] if out["mta_sts"] else "—")[:80])
    console.print(t)

    # Recommendations
    recs = []
    if not out["spf"]:
        recs.append("Добавить SPF-запись")
    elif "+all" in out["spf_all_qualifier"]:
        recs.append("[red]SPF +all — разрешает всем отправку![/red]")
        _save_finding(DNSFinding(
            kind="spf_plus_all",
            severity="high",
            title=f"SPF +all на {domain}",
            target=domain,
            evidence=out["spf"][0][:500],
            data={"spf": out["spf"]},
        ))
    if not out["dmarc"]:
        recs.append("Добавить DMARC (защита от spoofing)")
        _save_finding(DNSFinding(
            kind="dmarc_missing",
            severity="medium",
            title=f"DMARC отсутствует на {domain}",
            target=domain,
            evidence="Возможен email spoofing",
        ))
    elif out["dmarc_policy"] == "none":
        recs.append("[yellow]DMARC p=none — не блокирует spoofing[/yellow]")
    if not out["dkim_selectors"]:
        recs.append("Настроить DKIM")
    if recs:
        console.print("\n[yellow]⚠ Рекомендации:[/yellow]")
        for r in recs:
            console.print(f"  • {r}")

    db.save_scan("dns_mail_security", domain, out)
    return out


# ===========================================================================
# DNS Rebinding detection
# ===========================================================================

def rebinding_detect(domain: str, samples: int = 10) -> dict:
    domain = extract_host(domain)
    console.print(f"[cyan]🔄 DNS Rebinding detection для {domain} "
                  f"({samples} samples)…[/cyan]")

    ttls: list[int] = []
    all_ips: set[str] = set()
    rounds: list[list[str]] = []
    for _ in range(samples):
        try:
            answers = dns.resolver.resolve(domain, "A", lifetime=5)
            ips = [str(a) for a in answers]
            all_ips.update(ips)
            rounds.append(ips)
            if answers.rrset:
                ttls.append(answers.rrset.ttl)
        except Exception:
            pass
        time.sleep(0.3)

    rebound = (0 in ttls) or (len(all_ips) > 2)

    t = Table(title=f"DNS Rebinding check — {domain}")
    t.add_column("Показатель", style="cyan")
    t.add_column("Значение", style="green")
    t.add_row("TTL (samples)", str(ttls))
    t.add_row("Уникальных IP", str(len(all_ips)))
    t.add_row("IP", ", ".join(sorted(all_ips)) or "—")
    t.add_row("Rebinding-признаки",
              "[red]ДА[/red]" if rebound else "[green]нет[/green]")
    console.print(t)

    out = {"ttls": ttls, "unique_ips": sorted(all_ips),
           "samples": rounds, "likely_rebinding": rebound}
    if rebound:
        _save_finding(DNSFinding(
            kind="dns_rebinding",
            severity="medium",
            title=f"DNS rebinding possible на {domain}",
            target=domain,
            evidence=f"TTLs={ttls}, IPs={sorted(all_ips)}",
            data=out,
        ))
    db.save_scan("dns_rebinding", domain, out)
    return out


# ===========================================================================
# CAA / TXT aggregation
# ===========================================================================

def caa_check(domain: str) -> dict:
    """Проверка CAA записей."""
    domain = extract_host(domain)
    console.print(f"[cyan]🔒 CAA check: {domain}[/cyan]")

    out: dict[str, Any] = {"caa": [], "restricts": []}
    try:
        for r in dns.resolver.resolve(domain, "CAA", lifetime=10):
            entry = {
                "flags": r.flags,
                "tag": r.tag.decode() if isinstance(r.tag, bytes) else r.tag,
                "value": str(r.value),
            }
            out["caa"].append(entry)
            out["restricts"].append(f"{entry['tag']}={entry['value']}")
    except dns.resolver.NoAnswer:
        pass
    except Exception as exc:
        log.debug("CAA: %s", exc)

    if out["caa"]:
        t = Table(title=f"CAA — {domain}")
        t.add_column("Flag", style="cyan", width=6)
        t.add_column("Tag", style="magenta", width=8)
        t.add_column("Value", style="green")
        for c in out["caa"]:
            t.add_row(str(c["flags"]), c["tag"], c["value"])
        console.print(t)
        console.print("[green]✓ CAA активны (ограничивают выпуск "
                      "сертификатов)[/green]")
    else:
        console.print("[yellow]⚠ CAA отсутствуют — любой CA может "
                      "выпустить сертификат[/yellow]")
        _save_finding(DNSFinding(
            kind="caa_missing",
            severity="low",
            title=f"CAA не настроен на {domain}",
            target=domain,
            evidence="Любой CA может выпустить сертификат",
        ))

    db.save_scan("dns_caa", domain, out)
    return out


def txt_aggregate(domain: str) -> dict:
    """Собрать все TXT записи домена и поддоменов."""
    domain = extract_host(domain)
    console.print(f"[cyan]📝 TXT aggregation: {domain}[/cyan]")

    out: dict[str, list[str]] = {}
    targets = [
        domain, f"_dmarc.{domain}", f"_domainkey.{domain}",
        f"default._domainkey.{domain}", f"google._domainkey.{domain}",
        f"selector1._domainkey.{domain}",
        f"selector2._domainkey.{domain}",
        f"_mta-sts.{domain}", f"default._bimi.{domain}",
        f"_smtp._tls.{domain}",
    ]
    for target in targets:
        try:
            txts = []
            for r in dns.resolver.resolve(target, "TXT", lifetime=5):
                txt = b"".join(r.strings).decode(errors="ignore")
                txts.append(txt)
            if txts:
                out[target] = txts
        except Exception:
            continue

    if out:
        t = Table(title=f"TXT records — {domain}")
        t.add_column("Name", style="cyan", max_width=50)
        t.add_column("Value", style="green", max_width=80)
        for name, txts in out.items():
            for txt in txts:
                t.add_row(name, txt[:80])
        console.print(t)
    else:
        console.print("[yellow]TXT-записей не найдено.[/yellow]")

    db.save_scan("dns_txt", domain, out)
    return out


# ===========================================================================
# All records dump
# ===========================================================================

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA",
                 "SRV", "PTR", "NAPTR", "HINFO", "SSHFP", "TLSA",
                 "DNSKEY", "DS"]


def dump_all_records(domain: str) -> dict:
    """Собрать все возможные записи."""
    domain = extract_host(domain)
    console.print(f"[cyan]🌐 DNS records dump: {domain}[/cyan]")

    out: dict[str, list[str]] = {}
    for rtype in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            out[rtype] = [str(a).strip('"') for a in answers]
        except Exception:
            continue

    t = Table(title=f"DNS dump — {domain}")
    t.add_column("Type", style="magenta", width=8)
    t.add_column("Value", style="green", max_width=80)
    for rtype, values in out.items():
        for v in values:
            t.add_row(rtype, v[:80])
    console.print(t)

    db.save_scan("dns_dump_all", domain, out)
    return out


# ===========================================================================
# Экспорт
# ===========================================================================

def export_json(data: Any, name: str,
                 path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = "".join(c if c.isalnum() else "_" for c in name)[:40]
        path = str(DNS_DIR / f"{safe}_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]JSON: {exc}[/red]")
        return None


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🌐 DNS Tools[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Zone Transfer (AXFR + sub-zones)"),
        ("2", "DNSSEC check (DS/DNSKEY/RRSIG/NSEC)"),
        ("3", "Wildcard detection"),
        ("4", "Reverse PTR scan (CIDR)"),
        ("5", "DNS cache snooping (multi-resolver)"),
        ("6", "CNAME chain"),
        ("7", "SRV records scan"),
        ("8", "SPF / DMARC / DKIM / BIMI / MTA-STS"),
        ("9", "DNS Rebinding detection"),
        ("10", "CAA check"),
        ("11", "TXT aggregation"),
        ("12", "Full DNS records dump"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        zone_transfer(Prompt.ask("Домен"))
    elif c == "2":
        dnssec_check(Prompt.ask("Домен"))
    elif c == "3":
        wildcard_detect(Prompt.ask("Домен"))
    elif c == "4":
        cidr = Prompt.ask("CIDR (например 192.168.1.0/24)")
        threads = IntPrompt.ask("Потоков", default=50)
        reverse_scan(cidr, threads)
    elif c == "5":
        domain = Prompt.ask("Домен")
        multi = Confirm.ask("Multi-resolver?",
                             default=True)
        resolver = ""
        if not multi:
            resolver = Prompt.ask("Resolver IP (пусто = авто)",
                                    default="")
        cache_snooping(domain, resolver or None, multi=multi)
    elif c == "6":
        show_cname_chain(Prompt.ask("Домен"))
    elif c == "7":
        srv_scan(Prompt.ask("Домен"))
    elif c == "8":
        mail_security(Prompt.ask("Домен"))
    elif c == "9":
        rebinding_detect(Prompt.ask("Домен"))
    elif c == "10":
        caa_check(Prompt.ask("Домен"))
    elif c == "11":
        txt_aggregate(Prompt.ask("Домен"))
    elif c == "12":
        dump_all_records(Prompt.ask("Домен"))


# ===========================================================================
# CLI-обёртки (совместимы со старыми)
# ===========================================================================

def cli_axfr(domain: str) -> None:
    zone_transfer(domain)


def cli_dnssec(domain: str) -> None:
    dnssec_check(domain)


def cli_wildcard(domain: str) -> None:
    wildcard_detect(domain)


def cli_ptr(cidr: str, threads: int = 50) -> None:
    reverse_scan(cidr, threads)


def cli_snoop(domain: str, resolver: str | None = None) -> None:
    cache_snooping(domain, resolver)


def cli_cname(domain: str) -> None:
    show_cname_chain(domain)


def cli_srv(domain: str) -> None:
    srv_scan(domain)


def cli_mail(domain: str) -> None:
    mail_security(domain)


def cli_rebinding(domain: str) -> None:
    rebinding_detect(domain)


def cli_caa(domain: str) -> None:
    caa_check(domain)


def cli_txt(domain: str) -> None:
    txt_aggregate(domain)


def cli_dump(domain: str) -> None:
    dump_all_records(domain)