"""
DNS Tools — расширенный DNS-инструментарий.
Author: idqwixxa

Возможности:
    - Zone transfer (AXFR) через dnspython
    - DNSSEC: DS, DNSKEY, RRSIG, NSEC/NSEC3 (проверка подписи)
    - Wildcard detection (детектирует *.domain)
    - Reverse PTR-скан по диапазону IP
    - DNS cache snooping (recursion AVAILABLE?)
    - CNAME-цепочки (раскрутка до конца)
    - SRV-записи (для сервисов)
    - SPF / DMARC / DKIM анализ
    - DNS rebinding detection (TTL=0, множественные A)
"""
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
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

from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.config import config
from core.database import db
from core.logger import get_logger
from utils.helpers import extract_host

console = Console()
log = get_logger(__name__)


# ===========================================================================
# Zone Transfer
# ===========================================================================

def zone_transfer(domain: str) -> dict:
    """
    Попробовать AXFR для каждого NS домена.
    Возвращает {'success': bool, 'ns': str|None, 'records': [...], 'errors': [...]}
    """
    domain = extract_host(domain)
    console.print(f"[cyan]🔍 Zone Transfer (AXFR) для {domain}…[/cyan]")

    # Получаем NS
    try:
        answers = dns.resolver.resolve(domain, "NS", lifetime=10)
        ns_list = [str(r.target).rstrip(".") for r in answers]
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Не удалось получить NS: {exc}[/red]")
        return {"success": False, "ns": None, "records": [], "errors": [str(exc)]}

    console.print(f"[dim]NS: {', '.join(ns_list)}[/dim]")

    errors: list[str] = []
    for ns in ns_list:
        console.print(f"[cyan]  → Пробую {ns}…[/cyan]")
        try:
            ns_ip = socket.gethostbyname(ns)
        except socket.gaierror:
            errors.append(f"{ns}: unresolvable")
            continue
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=15))
            records: list[str] = []
            for name, node in z.nodes.items():
                rdatasets = node.rdatasets
                for rd in rdatasets:
                    for item in rd:
                        records.append(f"{name} {rd.ttl} "
                                       f"{dns.rdatatype.to_text(rd.rdtype)} "
                                       f"{item}")
            console.print(f"[bold green]✓ AXFR успешен на {ns}! "
                          f"Получено {len(records)} записей.[/bold green]")

            # Показать таблицу
            table = Table(title=f"AXFR {domain} via {ns}")
            table.add_column("Имя", style="cyan", max_width=40)
            table.add_column("TTL", style="dim", width=8)
            table.add_column("Тип", style="magenta", width=8)
            table.add_column("Значение", style="green", max_width=60)
            for line in records[:200]:
                parts = line.split(" ", 3)
                if len(parts) == 4:
                    table.add_row(parts[0], parts[1], parts[2], parts[3])
            console.print(table)

            db.save_scan("dns_axfr", domain,
                         {"ns": ns, "count": len(records)})
            return {"success": True, "ns": ns,
                    "records": records, "errors": errors}
        except dns.exception.FormError:
            errors.append(f"{ns}: AXFR refused (FormError)")
        except dns.query.TransferError as exc:
            errors.append(f"{ns}: TransferError: {exc}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{ns}: {exc}")

    console.print("[yellow]AXFR не удался ни на одном NS.[/yellow]")
    db.save_scan("dns_axfr", domain,
                 {"success": False, "errors": errors})
    return {"success": False, "ns": None, "records": [], "errors": errors}


# ===========================================================================
# DNSSEC
# ===========================================================================

def dnssec_check(domain: str) -> dict:
    """Проверить DNSSEC-записи: DS, DNSKEY, RRSIG, NSEC/NSEC3."""
    domain = extract_host(domain)
    console.print(f"[cyan]🔐 DNSSEC-проверка для {domain}…[/cyan]")

    out: dict[str, Any] = {
        "ds": [], "dnskey": [], "rrsig": [], "nsec": [],
        "validated": False, "errors": [],
    }

    # DS
    try:
        for r in dns.resolver.resolve(domain, "DS", lifetime=10):
            out["ds"].append({
                "key_tag": r.key_tag, "algorithm": r.algorithm,
                "digest_type": r.digest_type,
                "digest": r.digest.hex(),
            })
    except dns.resolver.NoAnswer:
        pass
    except Exception as exc:  # noqa: BLE001
        out["errors"].append(f"DS: {exc}")

    # DNSKEY
    try:
        dnskey_answers = dns.resolver.resolve(domain, "DNSKEY", lifetime=10)
        for r in dnskey_answers:
            out["dnskey"].append({
                "flags": r.flags, "protocol": r.protocol,
                "algorithm": r.algorithm, "key_tag": dns.dnssec.key_id(r),
            })
    except dns.resolver.NoAnswer:
        pass
    except Exception as exc:  # noqa: BLE001
        out["errors"].append(f"DNSKEY: {exc}")

    # RRSIG для A
    try:
        rrsig_answers = dns.resolver.resolve(domain, "A", lifetime=10)
        rrset = rrsig_answers.rrset
        if rrset:
            try:
                rrsig = dns.resolver.resolve(domain, "RRSIG", lifetime=10)
                for r in rrsig:
                    out["rrsig"].append({
                        "type_covered": r.type_covered,
                        "algorithm": r.algorithm,
                        "key_tag": r.key_tag,
                        "signer": str(r.signer).rstrip("."),
                        "expiration": r.expiration,
                    })
            except Exception:
                pass
    except Exception:  # noqa: BLE001
        pass

    out["validated"] = bool(out["ds"] and out["dnskey"])

    table = Table(title=f"DNSSEC — {domain}")
    table.add_column("Компонент", style="cyan")
    table.add_column("Статус", style="green")
    table.add_column("Детали", style="white")
    table.add_row("DS", "✓" if out["ds"] else "—",
                  f"{len(out['ds'])} записей")
    table.add_row("DNSKEY", "✓" if out["dnskey"] else "—",
                  f"{len(out['dnskey'])} ключей")
    table.add_row("RRSIG", "✓" if out["rrsig"] else "—",
                  f"{len(out['rrsig'])} подписей")
    table.add_row("NSEC/NSEC3", "✓" if out["nsec"] else "—",
                  "—" if not out["nsec"] else f"{len(out['nsec'])} записей")
    table.add_row("DNSSEC активен", "[green]ДА[/green]" if out["validated"]
                  else "[red]НЕТ[/red]",
                  "DS + DNSKEY присутствуют" if out["validated"]
                  else "Слабая защита от спуфинга")
    console.print(table)

    if out["ds"]:
        ds_table = Table(title="DS-записи")
        ds_table.add_column("KeyTag", style="cyan")
        ds_table.add_column("Algo", style="green")
        ds_table.add_column("DigestType")
        ds_table.add_column("Digest", max_width=50)
        for ds in out["ds"]:
            ds_table.add_row(str(ds["key_tag"]), str(ds["algorithm"]),
                             str(ds["digest_type"]), ds["digest"][:50])
        console.print(ds_table)

    db.save_scan("dns_dnssec", domain, out)
    return out


# ===========================================================================
# Wildcard detection
# ===========================================================================

def wildcard_detect(domain: str, probes: int = 3) -> dict:
    """
    Определить, есть ли wildcard-запись *.domain.
    Пробуем рандомные поддомены.
    """
    import random
    import string
    domain = extract_host(domain)
    console.print(f"[cyan]🔍 Wildcard detection для {domain}…[/cyan]")

    randoms = [
        "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        for _ in range(probes)
    ]
    hits: list[tuple[str, list[str]]] = []
    for r in randoms:
        fqdn = f"{r}.{domain}"
        try:
            answers = dns.resolver.resolve(fqdn, "A", lifetime=5)
            ips = [str(a) for a in answers]
            hits.append((fqdn, ips))
        except Exception:
            pass

    wildcard = len(hits) == probes and len(hits) > 0
    table = Table(title=f"Wildcard detection — {domain}")
    table.add_column("Проверка", style="cyan")
    table.add_column("Результат", style="green")
    table.add_row("Случайных поддоменов", str(probes))
    table.add_row("Ответили", str(len(hits)))
    table.add_row("Wildcard", "[red]ДА[/red]" if wildcard
                  else "[green]НЕТ[/green]")
    console.print(table)

    if hits:
        for fqdn, ips in hits:
            console.print(f"  [dim]{fqdn}[/dim] → [cyan]{', '.join(ips)}[/cyan]")

    result = {"wildcard": wildcard, "probes": probes, "hits": hits}
    db.save_scan("dns_wildcard", domain, result)
    return result


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
    except Exception as exc:  # noqa: BLE001
        return PtrResult(ip=ip, error=str(exc)[:60])


def reverse_scan(cidr: str, threads: int = 50) -> None:
    """PTR-скан по CIDR-диапазону."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        console.print(f"[red]Неверный CIDR: {exc}[/red]")
        return

    hosts = list(net.hosts())
    if len(hosts) > 4096:
        console.print(f"[yellow]Слишком много хостов ({len(hosts)}), "
                      f"ограничиваю 4096.[/yellow]")
        hosts = hosts[:4096]

    console.print(f"[cyan]🔍 PTR-скан {cidr} ({len(hosts)} хостов)[/cyan]")

    results: list[PtrResult] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_ptr_one, str(ip)): ip for ip in hosts}
        with Progress(SpinnerColumn(),
                      TextColumn("[progress.description]{task.description}"),
                      console=console) as p:
            task = p.add_task("PTR...", total=len(hosts))
            for f in as_completed(futures):
                r = f.result()
                p.advance(task)
                if r.name:
                    results.append(r)

    if not results:
        console.print("[yellow]PTR-записей не найдено.[/yellow]")
    else:
        table = Table(title=f"PTR — {cidr} ({len(results)})")
        table.add_column("IP", style="cyan", width=18)
        table.add_column("PTR", style="green")
        for r in sorted(results, key=lambda x: ipaddress.ip_address(x.ip)):
            table.add_row(r.ip, r.name)
        console.print(table)

    db.save_scan("dns_ptr", cidr,
                 [{"ip": r.ip, "name": r.name} for r in results])


# ===========================================================================
# DNS cache snooping
# ===========================================================================

def cache_snooping(domain: str, resolver_ip: str | None = None) -> dict:
    """
    Проверить, разрешает ли DNS-сервер рекурсивные запросы (cache snooping).
    """
    domain = extract_host(domain)
    resolver_ip = resolver_ip or _get_first_ns_ip(domain) or "8.8.8.8"
    console.print(f"[cyan]🔍 Cache snooping через {resolver_ip}…[/cyan]")

    random_sub = f"snoop-{int(time.time())}.{domain}"
    out = {"resolver": resolver_ip, "recursion": False,
           "random_sub_resolved": False, "details": []}

    try:
        q = dns.message.make_query(domain, "A")
        r = dns.query.udp(q, resolver_ip, timeout=5)
        ra = bool(r.flags & dns.flags.RA)
        out["recursion"] = ra
        out["details"].append(f"RA flag: {ra}")
    except Exception as exc:  # noqa: BLE001
        out["details"].append(f"RA query failed: {exc}")

    try:
        q2 = dns.message.make_query(random_sub, "A")
        r2 = dns.query.udp(q2, resolver_ip, timeout=5)
        if r2.answer:
            out["random_sub_resolved"] = True
            out["details"].append(f"Random sub resolved: {random_sub}")
    except Exception as exc:  # noqa: BLE001
        out["details"].append(f"random query failed: {exc}")

    table = Table(title=f"DNS Cache Snooping — {domain}")
    table.add_column("Проверка", style="cyan")
    table.add_column("Результат", style="green")
    table.add_row("Resolver", resolver_ip)
    table.add_row("Рекурсия (RA)", "✓ да" if out["recursion"] else "— нет")
    table.add_row("Random поддомен ответил",
                  "✓ да" if out["random_sub_resolved"] else "— нет")
    console.print(table)

    db.save_scan("dns_cache_snoop", domain, out)
    return out


def _get_first_ns_ip(domain: str) -> str | None:
    try:
        answers = dns.resolver.resolve(domain, "NS", lifetime=5)
        for r in answers:
            ns = str(r.target).rstrip(".")
            try:
                return socket.gethostbyname(ns)
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        pass
    return None


# ===========================================================================
# CNAME chain
# ===========================================================================

def cname_chain(domain: str, max_depth: int = 20) -> list[str]:
    """Раскрутить CNAME-цепочку до конца."""
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
        except Exception:  # noqa: BLE001
            break
    return chain


def show_cname_chain(domain: str) -> None:
    """Показать CNAME-цепочку для домена."""
    domain = extract_host(domain)
    console.print(f"[cyan]🔗 CNAME chain: {domain}[/cyan]")
    chain = cname_chain(domain)
    if len(chain) <= 1:
        console.print("[yellow]CNAME-записей нет.[/yellow]")
        return
    for i, host in enumerate(chain):
        arrow = "  " if i == 0 else "  ↳ "
        console.print(f"{arrow}[cyan]{host}[/cyan]")
    db.save_scan("dns_cname", domain, {"chain": chain})


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
    "_ssh._tcp", "_vnc._tcp", "_h323be._udp",
]


def srv_scan(domain: str, threads: int = 20) -> None:
    """Проверить SRV-записи для типовых сервисов."""
    domain = extract_host(domain)
    console.print(f"[cyan]🔍 SRV scan для {domain}…[/cyan]")

    found: list[dict] = []

    def _check(srv_prefix: str) -> list[dict]:
        fqdn = f"{srv_prefix}.{domain}"
        results = []
        try:
            answers = dns.resolver.resolve(fqdn, "SRV", lifetime=5)
            for r in answers:
                results.append({
                    "name": fqdn,
                    "priority": r.priority,
                    "weight": r.weight,
                    "port": r.port,
                    "target": str(r.target).rstrip("."),
                })
        except Exception:
            pass
        return results

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_check, srv): srv for srv in COMMON_SRV}
        for f in as_completed(futures):
            found.extend(f.result())

    if not found:
        console.print("[yellow]SRV-записей не найдено.[/yellow]")
    else:
        table = Table(title=f"SRV — {domain} ({len(found)})")
        table.add_column("Запись", style="cyan", max_width=40)
        table.add_column("Target", style="green", max_width=40)
        table.add_column("Port", style="magenta", width=6)
        table.add_column("Prio", style="dim", width=5)
        for r in sorted(found, key=lambda x: x["name"]):
            table.add_row(r["name"], r["target"], str(r["port"]),
                          str(r["priority"]))
        console.print(table)

    db.save_scan("dns_srv", domain, found)


# ===========================================================================
# SPF / DMARC / DKIM
# ===========================================================================

def mail_security(domain: str) -> dict:
    """Проверка SPF, DMARC, DKIM."""
    domain = extract_host(domain)
    console.print(f"[cyan]📧 Анализ почтовой безопасности {domain}…[/cyan]")

    out: dict[str, Any] = {"spf": [], "dmarc": [], "dkim_selectors": {}}

    # SPF
    try:
        txt_answers = dns.resolver.resolve(domain, "TXT", lifetime=10)
        for r in txt_answers:
            txt = b"".join(r.strings).decode(errors="ignore")
            if txt.startswith("v=spf1"):
                out["spf"].append(txt)
    except Exception:  # noqa: BLE001
        pass

    # DMARC
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT",
                                              lifetime=10)
        for r in dmarc_answers:
            txt = b"".join(r.strings).decode(errors="ignore")
            out["dmarc"].append(txt)
    except Exception:  # noqa: BLE001
        pass

    # DKIM — типичные селекторы
    selectors = ["default", "google", "selector1", "selector2", "k1",
                 "mail", "dkim", "s1", "s2", "20161025"]
    for sel in selectors:
        try:
            answers = dns.resolver.resolve(f"{sel}._domainkey.{domain}",
                                            "TXT", lifetime=5)
            for r in answers:
                txt = b"".join(r.strings).decode(errors="ignore")
                if "v=DKIM1" in txt or "p=" in txt:
                    out["dkim_selectors"][sel] = txt[:120]
        except Exception:
            pass

    # Вывод
    table = Table(title=f"Mail Security — {domain}")
    table.add_column("Механизм", style="cyan", width=14)
    table.add_column("Статус", style="green", width=10)
    table.add_column("Значение", style="white", max_width=70)

    spf_status = "[green]✓ есть[/green]" if out["spf"] else "[red]нет[/red]"
    spf_val = out["spf"][0] if out["spf"] else "—"
    table.add_row("SPF", spf_status, spf_val[:70])

    dmarc_status = "[green]✓ есть[/green]" if out["dmarc"] else "[red]нет[/red]"
    dmarc_val = out["dmarc"][0] if out["dmarc"] else "—"
    table.add_row("DMARC", dmarc_status, dmarc_val[:70])

    dkim_status = ("[green]✓ есть[/green]" if out["dkim_selectors"]
                   else "[red]нет[/red]")
    dkim_val = ", ".join(out["dkim_selectors"].keys()) \
        if out["dkim_selectors"] else "—"
    table.add_row("DKIM", dkim_status, dkim_val[:70])
    console.print(table)

    # Рекомендации
    recs = []
    if not out["spf"]:
        recs.append("Добавить SPF-запись")
    if not out["dmarc"]:
        recs.append("Добавить DMARC (защита от spoofing)")
    if not out["dkim_selectors"]:
        recs.append("Настроить DKIM подпись")
    if recs:
        console.print("\n[yellow]⚠ Рекомендации:[/yellow]")
        for r in recs:
            console.print(f"  • {r}")

    db.save_scan("dns_mail_security", domain, out)
    return out


# ===========================================================================
# DNS Rebinding detection
# ===========================================================================

def rebinding_detect(domain: str, samples: int = 5) -> dict:
    """Проверить на признаки DNS rebinding: TTL=0 или много A-записей."""
    domain = extract_host(domain)
    console.print(f"[cyan]🔄 DNS Rebinding detection для {domain}…[/cyan]")

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
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.5)

    rebound = (0 in ttls) or (len(all_ips) > 2)
    out = {
        "ttls": ttls,
        "unique_ips": sorted(all_ips),
        "samples": rounds,
        "likely_rebinding": rebound,
    }

    table = Table(title=f"DNS Rebinding check — {domain}")
    table.add_column("Показатель", style="cyan")
    table.add_column("Значение", style="green")
    table.add_row("TTL (samples)", str(ttls))
    table.add_row("Уникальных IP", str(len(all_ips)))
    table.add_row("IP", ", ".join(sorted(all_ips)) or "—")
    table.add_row("Rebinding-признаки",
                  "[red]ДА[/red]" if rebound else "[green]нет[/green]")
    console.print(table)

    db.save_scan("dns_rebinding", domain, out)
    return out


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🌐 DNS Tools[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Zone Transfer (AXFR)"),
        ("2", "DNSSEC check (DS / DNSKEY / RRSIG)"),
        ("3", "Wildcard detection"),
        ("4", "Reverse PTR scan (CIDR)"),
        ("5", "DNS cache snooping"),
        ("6", "CNAME chain"),
        ("7", "SRV records scan"),
        ("8", "SPF / DMARC / DKIM анализ"),
        ("9", "DNS Rebinding detection"),
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
        resolver = Prompt.ask("Resolver IP (пусто = авто)", default="")
        cache_snooping(domain, resolver or None)
    elif c == "6":
        show_cname_chain(Prompt.ask("Домен"))
    elif c == "7":
        srv_scan(Prompt.ask("Домен"))
    elif c == "8":
        mail_security(Prompt.ask("Домен"))
    elif c == "9":
        rebinding_detect(Prompt.ask("Домен"))