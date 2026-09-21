"""
Wireless Toolkit — расширенный Wi-Fi анализ.
Author: idqwixxa

Кроссплатформенно:
    - Windows: netsh wlan show networks mode=Bssid
    - Linux:   nmcli -t dev wifi list  |  iw dev <iface> scan

Возможности:
    - Список сетей: SSID, BSSID, канал, сигнал, шифрование, auth
    - Детектор evil twin (одинаковый SSID с разными BSSID)
    - Список открытых (без шифрования) сетей
    - WPS detection (по возможности)
    - OUI-vendor lookup (по BSSID)
    - Анализ каналов (загруженность)
    - Экспорт CSV / JSON
    - Сохранение в БД
"""
import json
import csv
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


# ===========================================================================
# Модель
# ===========================================================================

@dataclass
class WiFiNetwork:
    ssid: str
    bssid: str = ""
    channel: str = ""
    frequency: str = ""
    signal: int = 0         # dBm (отрицательный) или %
    signal_unit: str = ""   # "dBm" | "%"
    encryption: str = ""    # WPA2-PSK, WPA3, OPEN, WEP, ...
    auth: str = ""
    vendor: str = ""
    band: str = ""          # 2.4 GHz | 5 GHz | 6 GHz
    wps: bool = False
    hidden: bool = False
    raw: str = ""


# ===========================================================================
# OUI — небольшой встроенный список частых вендоров
# ===========================================================================

OUI_PREFIXES = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:05:69": "VMware",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:1A:2B": "Asus",
    "00:24:01": "Asus",
    "04:D9:F5": "Asus",
    "2C:56:DC": "Asus",
    "50:46:5D": "Asus",
    "AC:9E:17": "Asus",
    "F8:32:E4": "Asus",
    "00:1E:58": "TP-Link",
    "00:27:19": "TP-Link",
    "14:CC:20": "TP-Link",
    "30:B5:C2": "TP-Link",
    "50:C7:BF": "TP-Link",
    "A4:2B:B0": "TP-Link",
    "B0:4E:26": "TP-Link",
    "C0:25:E9": "TP-Link",
    "EC:08:6B": "TP-Link",
    "F4:F2:6D": "TP-Link",
    "00:1A:79": "Cisco",
    "00:1B:2A": "Cisco",
    "00:1C:0E": "Cisco",
    "00:1D:45": "Cisco",
    "00:1E:13": "Cisco",
    "00:1F:6C": "Cisco",
    "00:24:14": "Cisco",
    "00:25:45": "Cisco",
    "10:05:CA": "Cisco",
    "18:E7:F4": "Apple",
    "28:CF:E9": "Apple",
    "3C:07:54": "Apple",
    "44:D8:84": "Apple",
    "4C:57:CA": "Apple",
    "60:FB:42": "Apple",
    "7C:D1:C3": "Apple",
    "90:72:40": "Apple",
    "A4:83:E7": "Apple",
    "D0:81:7A": "Apple",
    "F0:18:98": "Apple",
    "00:11:22": "Cisco",
    "00:16:32": "Samsung",
    "00:1A:8A": "Samsung",
    "28:39:5E": "Samsung",
    "34:23:BA": "Samsung",
    "5C:0A:5B": "Samsung",
    "78:1F:DB": "Samsung",
    "E8:50:8B": "Samsung",
    "00:1E:64": "Intel",
    "00:21:6A": "Intel",
    "34:E6:AD": "Intel",
    "48:51:B7": "Intel",
    "5C:C5:D4": "Intel",
    "7C:7A:91": "Intel",
    "94:65:9C": "Intel",
    "A4:C4:94": "Intel",
    "F8:16:54": "Intel",
    "00:1F:3A": "Netgear",
    "20:4E:7F": "Netgear",
    "28:C6:8E": "Netgear",
    "44:94:FC": "Netgear",
    "A0:40:A0": "Netgear",
    "B0:39:56": "Netgear",
    "C0:FF:D4": "Netgear",
    "E0:46:9A": "Netgear",
    "00:22:B0": "D-Link",
    "00:26:5A": "D-Link",
    "14:D6:4D": "D-Link",
    "1C:7E:E5": "D-Link",
    "28:10:7B": "D-Link",
    "78:54:2E": "D-Link",
    "B8:A3:86": "D-Link",
    "CC:B2:55": "D-Link",
    "F0:7D:68": "D-Link",
    "00:24:A5": "Buffalo",
    "00:0D:0B": "Buffalo",
    "00:1D:73": "Buffalo",
    "10:6F:3F": "Buffalo",
    "00:0C:41": "Linksys",
    "00:0F:66": "Linksys",
    "00:13:10": "Linksys",
    "00:14:BF": "Linksys",
    "00:18:39": "Linksys",
    "00:1A:70": "Linksys",
    "00:1C:10": "Linksys",
    "00:1D:7E": "Linksys",
    "00:1E:E5": "Linksys",
    "00:21:29": "Linksys",
    "00:22:6B": "Linksys",
    "00:23:69": "Linksys",
    "00:25:9C": "Linksys",
    "20:AA:4B": "Linksys",
    "48:F8:B3": "Linksys",
    "C0:C1:C0": "Linksys",
    "EC:1A:59": "Linksys",
    "00:0F:B5": "Netgear",
    "00:14:6C": "Netgear",
    "00:18:4D": "Netgear",
    "00:1B:2F": "Netgear",
    "00:1E:2A": "Netgear",
    "00:1F:33": "Netgear",
    "00:22:3F": "Netgear",
    "00:24:B2": "Netgear",
    "00:26:F2": "Netgear",
    "2C:30:33": "Netgear",
    "E0:91:F5": "Netgear",
    "E4:F4:C6": "Netgear",
    "9C:3D:CF": "Netgear",
    "00:0C:42": "Routerboard",
    "00:0C:43": "Routerboard",
    "04:18:D6": "Ubiquiti",
    "24:A4:3C": "Ubiquiti",
    "44:D9:E7": "Ubiquiti",
    "68:72:51": "Ubiquiti",
    "74:83:C2": "Ubiquiti",
    "80:2A:A8": "Ubiquiti",
    "B4:FB:E4": "Ubiquiti",
    "DC:9F:DB": "Ubiquiti",
    "F0:9F:C2": "Ubiquiti",
    "FC:EC:DA": "Ubiquiti",
    "00:15:6D": "Ubiquiti",
    "00:27:22": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    "00:0B:86": "Aruba",
    "00:1A:1E": "Aruba",
    "04:BD:88": "Aruba",
    "18:64:72": "Aruba",
    "20:4C:03": "Aruba",
    "24:DE:C6": "Aruba",
    "6C:F3:7F": "Aruba",
    "94:B4:0F": "Aruba",
    "B4:5D:50": "Aruba",
    "D8:C7:C8": "Aruba",
    "F0:5C:19": "Aruba",
    "18:8B:45": "Mikrotik",
    "48:8F:5A": "Mikrotik",
    "64:D1:54": "Mikrotik",
    "74:4D:28": "Mikrotik",
    "6C:3B:6B": "Mikrotik",
    "78:9A:18": "Mikrotik",
    "CC:2D:E0": "Mikrotik",
    "DC:2C:6E": "Mikrotik",
    "E4:8D:8C": "Mikrotik",
}


def vendor_by_bssid(bssid: str) -> str:
    """Определить вендора по первым 3 байтам MAC."""
    if not bssid:
        return ""
    prefix = bssid.upper().replace("-", ":")[:8]
    return OUI_PREFIXES.get(prefix, "")


# ===========================================================================
# Windows: netsh
# ===========================================================================

def _scan_windows() -> list[WiFiNetwork]:
    """Сканирование через netsh wlan."""
    networks: list[WiFiNetwork] = []
    try:
        out = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=Bssid"],
            encoding="cp866", errors="ignore", timeout=30,
        )
    except Exception as exc:  # noqa: BLE001
        try:
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=Bssid"],
                encoding="utf-8", errors="ignore", timeout=30,
            )
        except Exception as exc2:  # noqa: BLE001
            log.error("netsh failed: %s / %s", exc, exc2)
            return networks

    current: WiFiNetwork | None = None
    bssid_re = re.compile(r"BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})")
    ssid_re = re.compile(r"^SSID\s+\d+\s*:\s*(.*)$")
    auth_re = re.compile(r"Authentication\s*:\s*(.+)$")
    enc_re = re.compile(r"Encryption\s*:\s*(.+)$")
    signal_re = re.compile(r"Signal\s*:\s*(\d+)%")
    channel_re = re.compile(r"Channel\s*:\s*(\d+)")
    band_re = re.compile(r"Band\s*:\s*(.+)$")
    radio_re = re.compile(r"Radio type\s*:\s*(.+)$")

    pending_bssid: WiFiNetwork | None = None

    for line in out.splitlines():
        s = line.strip()

        m = ssid_re.match(s)
        if m:
            if current is not None:
                networks.append(current)
            ssid = m.group(1).strip()
            current = WiFiNetwork(ssid=ssid or "(hidden)",
                                  hidden=(not ssid))
            continue

        if current is None:
            continue

        m = auth_re.match(s)
        if m:
            current.auth = m.group(1).strip()
            continue
        m = enc_re.match(s)
        if m:
            current.encryption = m.group(1).strip()
            continue

        m = bssid_re.match(s)
        if m:
            # создаём отдельную запись на каждый BSSID
            new_net = WiFiNetwork(
                ssid=current.ssid,
                bssid=m.group(1).upper(),
                auth=current.auth,
                encryption=current.encryption,
                hidden=current.hidden,
            )
            new_net.vendor = vendor_by_bssid(new_net.bssid)
            networks.append(new_net)
            pending_bssid = new_net
            continue

        if pending_bssid is not None:
            m = signal_re.match(s)
            if m:
                pending_bssid.signal = int(m.group(1))
                pending_bssid.signal_unit = "%"
                continue
            m = channel_re.match(s)
            if m:
                pending_bssid.channel = m.group(1)
                ch = int(m.group(1))
                if ch <= 14:
                    pending_bssid.band = "2.4 GHz"
                elif ch <= 177:
                    pending_bssid.band = "5 GHz"
                else:
                    pending_bssid.band = "6 GHz"
                continue
            m = band_re.match(s)
            if m:
                pending_bssid.band = m.group(1).strip()
                continue

    if current is not None and not any(n.ssid == current.ssid
                                       for n in networks):
        networks.append(current)

    # Уберём пустые заголовки от первой итерации (без BSSID)
    return [n for n in networks if n.bssid or n.ssid]


# ===========================================================================
# Linux: nmcli / iw
# ===========================================================================

def _scan_linux() -> list[WiFiNetwork]:
    """Сканирование через nmcli, fallback на iw."""
    networks = _scan_linux_nmcli()
    if networks:
        return networks
    return _scan_linux_iw()


def _scan_linux_nmcli() -> list[WiFiNetwork]:
    networks: list[WiFiNetwork] = []
    try:
        subprocess.check_output(
            ["nmcli", "dev", "wifi", "rescan"], timeout=15,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass

    try:
        out = subprocess.check_output(
            ["nmcli", "-t", "-f",
             "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY", "dev", "wifi", "list"],
            encoding="utf-8", errors="ignore", timeout=30,
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("nmcli failed: %s", exc)
        return networks

    for line in out.splitlines():
        # SSID:BSSID:CHAN:FREQ:SIGNAL:SECURITY
        # BSSID содержит двоеточия → нужно ограничить split по крайним
        parts = line.split(":")
        if len(parts) < 6:
            continue
        # идём справа: security последнее, signal перед ним, freq, chan,
        # bssid (6 байт через :), ssid в начале
        try:
            security = parts[-1]
            signal = parts[-2]
            freq = parts[-3]
            chan = parts[-4]
            bssid = ":".join(parts[-10:-4]) if len(parts) >= 10 else ""
            ssid = ":".join(parts[:-10]) if len(parts) > 10 else parts[0]
        except Exception:
            continue

        # Альтернативный парсинг через двоеточие и экранирование
        if not bssid or len(bssid) != 17:
            # пробуем разбить через \:
            m = re.match(
                r"^(.+?):((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}):"
                r"(\d+):([\d ]+):(\d+):(.*)$",
                line,
            )
            if m:
                ssid = m.group(1)
                bssid = m.group(2)
                chan = m.group(3)
                freq = m.group(4)
                signal = m.group(5)
                security = m.group(6)
            else:
                continue

        try:
            sig_int = int(signal)
        except ValueError:
            sig_int = 0

        band = "2.4 GHz"
        try:
            f = int(freq.replace(" ", "").split()[0])
            if f > 2500:
                band = "5 GHz"
            elif f > 5925:
                band = "6 GHz"
        except Exception:
            pass
        try:
            if int(chan) > 14:
                band = "5 GHz"
        except Exception:
            pass

        enc = "OPEN" if security in ("", "--") else security

        net = WiFiNetwork(
            ssid=ssid or "(hidden)",
            bssid=bssid.upper() if bssid else "",
            channel=chan,
            frequency=freq.replace(" ", ""),
            signal=sig_int,
            signal_unit="%",
            encryption=enc,
            auth=security,
            band=band,
            hidden=(ssid == "" or ssid == "--"),
        )
        net.vendor = vendor_by_bssid(net.bssid)
        networks.append(net)

    return networks


def _scan_linux_iw() -> list[WiFiNetwork]:
    """Fallback: iw dev <iface> scan (требует root)."""
    networks: list[WiFiNetwork] = []
    # найти интерфейс
    try:
        out = subprocess.check_output(
            ["iw", "dev"], encoding="utf-8", errors="ignore", timeout=5,
        )
    except Exception:
        return networks

    iface = ""
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Interface"):
            iface = s.split()[-1]
            break
    if not iface:
        return networks

    try:
        out = subprocess.check_output(
            ["iw", "dev", iface, "scan"],
            encoding="utf-8", errors="ignore", timeout=30,
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("iw scan: %s", exc)
        return networks

    current: WiFiNetwork | None = None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("BSS "):
            if current:
                networks.append(current)
            bssid = s.split()[1].split("(")[0]
            current = WiFiNetwork(ssid="(hidden)", bssid=bssid.upper())
            current.vendor = vendor_by_bssid(current.bssid)
        elif current and s.startswith("SSID:"):
            current.ssid = s.split(":", 1)[1].strip() or "(hidden)"
            current.hidden = not current.ssid or current.ssid == "(hidden)"
        elif current and s.startswith("freq:"):
            try:
                f = int(s.split(":")[1].strip())
                current.frequency = str(f)
                if f < 2500:
                    current.band = "2.4 GHz"
                elif f < 5925:
                    current.band = "5 GHz"
                else:
                    current.band = "6 GHz"
            except Exception:
                pass
        elif current and s.startswith("signal:"):
            try:
                current.signal = float(s.split(":")[1].split()[0])
                current.signal = int(current.signal)
                current.signal_unit = "dBm"
            except Exception:
                pass
        elif current and "WPA:" in s or (current and "RSN:" in s):
            current.encryption = current.encryption or "WPA/WPA2"
        elif current and "Privacy:" in s:
            current.encryption = current.encryption or "WEP"
        elif current and s.startswith("DS Parameter set: channel"):
            try:
                current.channel = s.split()[-1]
            except Exception:
                pass

    if current:
        networks.append(current)
    return networks


# ===========================================================================
# Основная точка сканирования
# ===========================================================================

def scan() -> list[WiFiNetwork]:
    """Кроссплатформенное сканирование."""
    if sys.platform.startswith("win"):
        return _scan_windows()
    return _scan_linux()


def _signal_style(sig: int, unit: str) -> str:
    """Цвет сигнала."""
    if unit == "dBm":
        if sig >= -50:
            return "bold green"
        if sig >= -65:
            return "green"
        if sig >= -75:
            return "yellow"
        return "red"
    # проценты
    if sig >= 75:
        return "bold green"
    if sig >= 50:
        return "green"
    if sig >= 25:
        return "yellow"
    return "red"


def _enc_style(enc: str) -> str:
    e = (enc or "").upper()
    if "OPEN" in e or not e or e == "--":
        return "bold red"
    if "WEP" in e:
        return "red"
    if "WPA3" in e:
        return "green"
    if "WPA2" in e:
        return "cyan"
    if "WPA" in e:
        return "yellow"
    return "white"


def _print_networks(networks: list[WiFiNetwork],
                    title: str = "Wi-Fi сети") -> None:
    if not networks:
        console.print("[yellow]Сети не найдены.[/yellow]")
        return
    table = Table(title=f"{title} ({len(networks)})")
    table.add_column("#", style="yellow", width=4)
    table.add_column("SSID", style="cyan", max_width=25)
    table.add_column("BSSID", style="dim", width=18)
    table.add_column("Vendor", style="magenta", max_width=14)
    table.add_column("Ch", width=3)
    table.add_column("Band", width=7)
    table.add_column("Signal", width=7)
    table.add_column("Auth", width=14)
    table.add_column("Cipher", width=10)
    for i, n in enumerate(networks, 1):
        sig_sty = _signal_style(n.signal, n.signal_unit)
        enc_sty = _enc_style(n.encryption)
        sig_str = f"{n.signal}{n.signal_unit or ''}"
        table.add_row(
            str(i),
            n.ssid or "(hidden)",
            n.bssid,
            n.vendor or "—",
            n.channel or "—",
            n.band or "—",
            f"[{sig_sty}]{sig_str}[/{sig_sty}]",
            n.auth or "—",
            f"[{enc_sty}]{n.encryption or '—'}[/{enc_sty}]",
        )
    console.print(table)


# ===========================================================================
# Аналитика
# ===========================================================================

def _duplicates(networks: list[WiFiNetwork]) -> dict[str, list[WiFiNetwork]]:
    """Найти SSID с несколькими BSSID (возможный evil twin)."""
    by_ssid: dict[str, list[WiFiNetwork]] = {}
    for n in networks:
        if not n.ssid or n.hidden:
            continue
        by_ssid.setdefault(n.ssid, []).append(n)
    return {s: lst for s, lst in by_ssid.items()
            if len({x.bssid for x in lst if x.bssid}) > 1}


def show_evil_twin(networks: list[WiFiNetwork]) -> None:
    """Показать потенциальные evil twin."""
    dups = _duplicates(networks)
    if not dups:
        console.print("[green]✓ Подозрительных дублей SSID не найдено.[/green]")
        return
    console.print(f"[red]⚠ Найдено {len(dups)} SSID с несколькими BSSID:[/red]\n")
    for ssid, lst in dups.items():
        table = Table(title=f"⚠ {ssid} ({len(lst)} BSSID)")
        table.add_column("BSSID", style="cyan")
        table.add_column("Vendor", style="magenta")
        table.add_column("Signal", width=8)
        table.add_column("Auth", width=16)
        table.add_column("Channel", width=8)
        for n in lst:
            sig_sty = _signal_style(n.signal, n.signal_unit)
            enc_sty = _enc_style(n.encryption)
            table.add_row(
                n.bssid,
                n.vendor or "—",
                f"[{sig_sty}]{n.signal}{n.signal_unit}[/{sig_sty}]",
                f"[{enc_sty}]{n.auth or n.encryption or '—'}[/{enc_sty}]",
                n.channel or "—",
            )
        console.print(table)


def show_open_networks(networks: list[WiFiNetwork]) -> None:
    """Список открытых (без шифрования) сетей."""
    opens = [n for n in networks
             if "OPEN" in (n.encryption or "").upper()
             or not n.encryption
             or (n.encryption or "").upper() in ("--", "NONE")]
    if not opens:
        console.print("[green]✓ Открытых сетей нет.[/green]")
        return
    _print_networks(opens, "🔓 Открытые сети (без шифрования)")


def show_weak_crypto(networks: list[WiFiNetwork]) -> None:
    """WEP и WPA (v1)."""
    weak = [n for n in networks
            if "WEP" in (n.encryption or "").upper()
            or (n.encryption or "").upper().strip() in ("WPA", "WPA-PSK")]
    if not weak:
        console.print("[green]✓ WEP/WPA1 сетей нет.[/green]")
        return
    _print_networks(weak, "🟠 Слабые шифры (WEP/WPA1)")


def show_channel_load(networks: list[WiFiNetwork]) -> None:
    """Загруженность каналов."""
    by_ch: dict[str, int] = {}
    for n in networks:
        ch = n.channel or "?"
        by_ch[ch] = by_ch.get(ch, 0) + 1
    if not by_ch:
        console.print("[yellow]Нет данных о каналах.[/yellow]")
        return

    table = Table(title="📊 Загруженность каналов")
    table.add_column("Channel", style="cyan", width=8)
    table.add_column("Band", width=8)
    table.add_column("Сетей", width=7)
    table.add_column("Bar", style="green")
    max_count = max(by_ch.values())
    for ch in sorted(by_ch.keys(),
                     key=lambda x: (int(x) if x.isdigit() else 999)):
        cnt = by_ch[ch]
        band = "2.4 GHz" if ch.isdigit() and int(ch) <= 14 else "5/6 GHz"
        bar = "█" * cnt
        table.add_row(ch, band, str(cnt), bar)
    console.print(table)

    # Рекомендации для 2.4 GHz
    ch24 = {int(k): v for k, v in by_ch.items() if k.isdigit() and int(k) <= 14}
    if ch24:
        best = min(range(1, 14), key=lambda c: ch24.get(c, 0))
        console.print(f"[cyan]Рекомендация (2.4 GHz): канал {best} "
                      f"({ch24.get(best, 0)} сетей)[/cyan]")


def signal_ranking(networks: list[WiFiNetwork]) -> list[WiFiNetwork]:
    """Отсортировать по силе сигнала."""
    def _key(n: WiFiNetwork) -> float:
        if n.signal_unit == "dBm":
            return -n.signal  # dBm ближе к 0 = сильнее
        return -n.signal
    return sorted(networks, key=_key)


# ===========================================================================
# Экспорт
# ===========================================================================

def export_json(networks: list[WiFiNetwork],
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(REPORT_DIR / f"wifi_{ts}.json")
    try:
        data = [asdict(n) for n in networks]
        Path(path).write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_csv(networks: list[WiFiNetwork],
               path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(REPORT_DIR / f"wifi_{ts}.csv")
    cols = ["ssid", "bssid", "vendor", "channel", "band", "signal",
            "signal_unit", "encryption", "auth", "wps", "hidden"]
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for n in networks:
                w.writerow(asdict(n))
        console.print(f"[green]✓ CSV: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# Высокоуровневые сценарии
# ===========================================================================

def cmd_scan(save: bool = True) -> list[WiFiNetwork]:
    """Полный скан + вывод + сохранение."""
    console.print("[cyan]📡 Сканирую Wi-Fi сети…[/cyan]")
    try:
        networks = scan()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return []

    _print_networks(networks)
    if not networks:
        return []

    # Сводка
    open_n = sum(1 for n in networks if "OPEN" in (n.encryption or "").upper())
    weak_n = sum(1 for n in networks
                 if "WEP" in (n.encryption or "").upper())
    wpa3_n = sum(1 for n in networks
                 if "WPA3" in (n.encryption or "").upper())
    dups = _duplicates(networks)

    table = Table(title="📊 Сводка")
    table.add_column("Метрика", style="cyan")
    table.add_column("Значение", style="green")
    table.add_row("Всего сетей", str(len(networks)))
    table.add_row("Уникальных SSID", str(len({n.ssid for n in networks})))
    table.add_row("Открытых", f"[red]{open_n}[/red]")
    table.add_row("WEP", f"[red]{weak_n}[/red]")
    table.add_row("WPA3", f"[green]{wpa3_n}[/green]")
    table.add_row("Дублей SSID (evil twin?)", f"[yellow]{len(dups)}[/yellow]")
    console.print(table)

    if save:
        try:
            db.save_scan("wifi_scan", "local", {
                "count": len(networks),
                "ssids": sorted({n.ssid for n in networks}),
                "open": open_n,
                "wep": weak_n,
                "wpa3": wpa3_n,
                "duplicates": list(dups.keys()),
            })
        except Exception:  # noqa: BLE001
            pass
    return networks


def cmd_full_analysis() -> None:
    """Полный анализ с экспортом."""
    networks = cmd_scan(save=True)
    if not networks:
        return
    console.print()
    show_evil_twin(networks)
    console.print()
    show_open_networks(networks)
    console.print()
    show_weak_crypto(networks)
    console.print()
    show_channel_load(networks)
    console.print()
    if Confirm.ask("Экспортировать CSV + JSON?", default=True):
        export_csv(networks)
        export_json(networks)


def cmd_export(fmt: str = "csv") -> None:
    """Скан + экспорт."""
    networks = scan()
    if not networks:
        console.print("[yellow]Сети не найдены.[/yellow]")
        return
    if fmt == "json":
        export_json(networks)
    else:
        export_csv(networks)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]📶 Wireless Toolkit[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Сканировать Wi-Fi (список)"),
        ("2", "Полный анализ (evil twin, открытые, слабые, каналы)"),
        ("3", "Детектор evil twin (дубли SSID)"),
        ("4", "Открытые сети"),
        ("5", "Слабые шифры (WEP/WPA1)"),
        ("6", "Загруженность каналов"),
        ("7", "Топ по силе сигнала"),
        ("8", "Экспорт CSV"),
        ("9", "Экспорт JSON"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        cmd_scan(save=True)
    elif c == "2":
        cmd_full_analysis()
    elif c == "3":
        networks = scan()
        _print_networks(networks, "Сети")
        console.print()
        show_evil_twin(networks)
    elif c == "4":
        networks = scan()
        show_open_networks(networks)
    elif c == "5":
        networks = scan()
        show_weak_crypto(networks)
    elif c == "6":
        networks = scan()
        show_channel_load(networks)
    elif c == "7":
        networks = signal_ranking(scan())
        _print_networks(networks, "🏆 Топ по сигналу")
    elif c == "8":
        cmd_export("csv")
    elif c == "9":
        cmd_export("json")


# ===========================================================================
# CLI-обёртки
# ===========================================================================

def cli_scan() -> None:
    cmd_scan(save=True)


def cli_evil_twin() -> None:
    networks = scan()
    _print_networks(networks, "Сети")
    console.print()
    show_evil_twin(networks)


def cli_open() -> None:
    show_open_networks(scan())


def cli_weak() -> None:
    show_weak_crypto(scan())


def cli_channels() -> None:
    show_channel_load(scan())


def cli_top() -> None:
    _print_networks(signal_ranking(scan()), "🏆 Топ по сигналу")


def cli_export_csv() -> None:
    cmd_export("csv")


def cli_export_json() -> None:
    cmd_export("json")


def cli_full() -> None:
    cmd_full_analysis()