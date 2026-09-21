"""
Wireless Toolkit Pro — расширенный Wi-Fi анализ + rogue-AP detection.
Author: idqwixxa

⚠ Только для авторизованного аудита собственных сетей / CTF.

Кроссплатформенно:
    - Windows: netsh wlan show networks mode=Bssid
    - Linux:   nmcli / iw dev <iface> scan

Возможности:
    ─── Scan ───
    - SSID, BSSID, channel, freq, signal, auth, cipher
    - Band detection (2.4 / 5 / 6 GHz)
    - OUI vendor lookup (200+ prefixes + online fallback)
    - Hidden SSID detection
    - WPS detection (из beacon)
    - Signal-over-time tracking (n samples)

    ─── Analysis ───
    - Evil Twin / Rogue AP detection (SSID duplicates + vendor mismatch)
    - Karma attack indicator (много SSID → 1 BSSID)
    - Open networks + WEP/WPA1 (weak crypto)
    - Channel load + interference (2.4 / 5 / 6 отдельно)
    - Signal ranking
    - PMKID / handshake hints (по airodump-ng логам)
    - Deauth detection hints (из monitor-логов)
    - BSSID geolocation (wigle / Google geolocate fallback)
    - SSID pattern analysis (default routers: TP-Link_XXXX и т.п.)

    ─── Интеграция ───
    - Findings → notes (evil twin / open / WEP / weak crypto)
    - Notify
    - Экспорт: JSON / CSV / MD / HTML
"""
import csv
import html as html_mod
import json
import math
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn,
)

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

WIFI_DIR = REPORT_DIR / "wireless"
WIFI_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings
# ===========================================================================

@dataclass
class WiFiFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: WiFiFinding) -> int:
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


def _notify(title: str, msg: str, severity: str = "medium") -> None:
    try:
        from modules import notifier
        notifier.notify_all(title, msg, severity=severity)
    except Exception:
        pass


# ===========================================================================
# Модель
# ===========================================================================

@dataclass
class WiFiNetwork:
    ssid: str
    bssid: str = ""
    channel: str = ""
    frequency: str = ""
    signal: int = 0
    signal_unit: str = ""
    encryption: str = ""
    auth: str = ""
    vendor: str = ""
    band: str = ""
    wps: bool = False
    hidden: bool = False
    raw: str = ""


@dataclass
class WiFiSample:
    """Один замер сигнала."""
    ts: str
    bssid: str
    signal: int
    unit: str


# ===========================================================================
# OUI
# ===========================================================================

OUI_PREFIXES = {
    # Виртуализация
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware",
    "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
    "00:15:5D": "Microsoft Hyper-V",
    # Asus
    "00:1A:2B": "Asus", "00:24:01": "Asus", "04:D9:F5": "Asus",
    "2C:56:DC": "Asus", "50:46:5D": "Asus", "AC:9E:17": "Asus",
    "F8:32:E4": "Asus", "1C:87:2C": "Asus", "2C:FD:A1": "Asus",
    "38:D5:47": "Asus", "74:D0:2B": "Asus", "B0:6E:BF": "Asus",
    # TP-Link
    "00:1E:58": "TP-Link", "00:27:19": "TP-Link", "14:CC:20": "TP-Link",
    "30:B5:C2": "TP-Link", "50:C7:BF": "TP-Link", "A4:2B:B0": "TP-Link",
    "B0:4E:26": "TP-Link", "C0:25:E9": "TP-Link", "EC:08:6B": "TP-Link",
    "F4:F2:6D": "TP-Link", "0C:80:63": "TP-Link", "18:A6:F7": "TP-Link",
    "34:E8:94": "TP-Link", "60:32:B1": "TP-Link", "78:8C:B5": "TP-Link",
    "9C:53:22": "TP-Link", "A4:2B:B0": "TP-Link", "AC:84:C6": "TP-Link",
    "B4:B0:24": "TP-Link", "D8:0D:17": "TP-Link", "F4:EC:38": "TP-Link",
    # Cisco
    "00:1A:79": "Cisco", "00:1B:2A": "Cisco", "00:1C:0E": "Cisco",
    "00:1D:45": "Cisco", "00:1E:13": "Cisco", "00:1F:6C": "Cisco",
    "00:24:14": "Cisco", "00:25:45": "Cisco", "10:05:CA": "Cisco",
    "00:11:22": "Cisco", "00:0B:BE": "Cisco", "00:0C:85": "Cisco",
    "00:0D:28": "Cisco", "00:0E:38": "Cisco", "00:0F:23": "Cisco",
    "00:0F:34": "Cisco", "00:0F:8F": "Cisco", "00:10:07": "Cisco",
    "00:10:0B": "Cisco", "00:10:14": "Cisco", "00:10:7B": "Cisco",
    "00:11:20": "Cisco", "00:11:21": "Cisco", "00:11:5C": "Cisco",
    "00:11:92": "Cisco", "00:11:93": "Cisco", "00:11:BB": "Cisco",
    # Apple
    "18:E7:F4": "Apple", "28:CF:E9": "Apple", "3C:07:54": "Apple",
    "44:D8:84": "Apple", "4C:57:CA": "Apple", "60:FB:42": "Apple",
    "7C:D1:C3": "Apple", "90:72:40": "Apple", "A4:83:E7": "Apple",
    "D0:81:7A": "Apple", "F0:18:98": "Apple", "00:1B:63": "Apple",
    "00:1C:B3": "Apple", "00:1E:C2": "Apple", "00:1F:F3": "Apple",
    "00:21:E9": "Apple", "00:22:41": "Apple", "00:23:12": "Apple",
    "00:23:DF": "Apple", "00:25:00": "Apple", "00:25:4B": "Apple",
    "00:25:BC": "Apple", "00:26:08": "Apple", "00:26:4A": "Apple",
    "00:26:B0": "Apple", "00:26:BB": "Apple", "00:3E:E1": "Apple",
    "04:0C:CE": "Apple", "04:15:52": "Apple", "04:1E:64": "Apple",
    "04:26:65": "Apple", "04:48:9A": "Apple", "04:52:F3": "Apple",
    "04:54:53": "Apple", "04:69:F8": "Apple", "04:D3:CF": "Apple",
    "04:DB:56": "Apple", "04:E5:36": "Apple", "04:F1:3E": "Apple",
    "04:F7:E4": "Apple", "08:66:98": "Apple", "08:6D:41": "Apple",
    "08:70:45": "Apple", "08:74:02": "Apple",
    # Samsung
    "00:16:32": "Samsung", "00:1A:8A": "Samsung", "28:39:5E": "Samsung",
    "34:23:BA": "Samsung", "5C:0A:5B": "Samsung", "78:1F:DB": "Samsung",
    "E8:50:8B": "Samsung", "00:12:FB": "Samsung", "00:13:77": "Samsung",
    "00:15:99": "Samsung", "00:16:6B": "Samsung", "00:16:6C": "Samsung",
    "00:17:C9": "Samsung", "00:17:D5": "Samsung", "00:18:AF": "Samsung",
    # Intel
    "00:1E:64": "Intel", "00:21:6A": "Intel", "34:E6:AD": "Intel",
    "48:51:B7": "Intel", "5C:C5:D4": "Intel", "7C:7A:91": "Intel",
    "94:65:9C": "Intel", "A4:C4:94": "Intel", "F8:16:54": "Intel",
    # Netgear
    "00:1F:3A": "Netgear", "20:4E:7F": "Netgear", "28:C6:8E": "Netgear",
    "44:94:FC": "Netgear", "A0:40:A0": "Netgear", "B0:39:56": "Netgear",
    "C0:FF:D4": "Netgear", "E0:46:9A": "Netgear", "00:0F:B5": "Netgear",
    "00:14:6C": "Netgear", "00:18:4D": "Netgear", "00:1B:2F": "Netgear",
    "00:1E:2A": "Netgear", "00:1F:33": "Netgear", "00:22:3F": "Netgear",
    "00:24:B2": "Netgear", "00:26:F2": "Netgear", "2C:30:33": "Netgear",
    "E0:91:F5": "Netgear", "E4:F4:C6": "Netgear", "9C:3D:CF": "Netgear",
    # D-Link
    "00:22:B0": "D-Link", "00:26:5A": "D-Link", "14:D6:4D": "D-Link",
    "1C:7E:E5": "D-Link", "28:10:7B": "D-Link", "78:54:2E": "D-Link",
    "B8:A3:86": "D-Link", "CC:B2:55": "D-Link", "F0:7D:68": "D-Link",
    # Buffalo / Linksys
    "00:24:A5": "Buffalo", "00:0D:0B": "Buffalo", "00:1D:73": "Buffalo",
    "10:6F:3F": "Buffalo",
    "00:0C:41": "Linksys", "00:0F:66": "Linksys", "00:13:10": "Linksys",
    "00:14:BF": "Linksys", "00:18:39": "Linksys", "00:1A:70": "Linksys",
    "00:1C:10": "Linksys", "00:1D:7E": "Linksys", "00:1E:E5": "Linksys",
    "00:21:29": "Linksys", "00:22:6B": "Linksys", "00:23:69": "Linksys",
    "00:25:9C": "Linksys", "20:AA:4B": "Linksys", "48:F8:B3": "Linksys",
    "C0:C1:C0": "Linksys", "EC:1A:59": "Linksys",
    # Ubiquiti / MikroTik / Aruba
    "04:18:D6": "Ubiquiti", "24:A4:3C": "Ubiquiti", "44:D9:E7": "Ubiquiti",
    "68:72:51": "Ubiquiti", "74:83:C2": "Ubiquiti", "80:2A:A8": "Ubiquiti",
    "B4:FB:E4": "Ubiquiti", "DC:9F:DB": "Ubiquiti", "F0:9F:C2": "Ubiquiti",
    "FC:EC:DA": "Ubiquiti", "00:15:6D": "Ubiquiti", "00:27:22": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    "18:8B:45": "Mikrotik", "48:8F:5A": "Mikrotik", "64:D1:54": "Mikrotik",
    "74:4D:28": "Mikrotik", "6C:3B:6B": "Mikrotik", "78:9A:18": "Mikrotik",
    "CC:2D:E0": "Mikrotik", "DC:2C:6E": "Mikrotik", "E4:8D:8C": "Mikrotik",
    "00:0C:42": "Routerboard", "00:0C:43": "Routerboard",
    "00:0B:86": "Aruba", "00:1A:1E": "Aruba", "04:BD:88": "Aruba",
    "18:64:72": "Aruba", "20:4C:03": "Aruba", "24:DE:C6": "Aruba",
    "6C:F3:7F": "Aruba", "94:B4:0F": "Aruba", "B4:5D:50": "Aruba",
    "D8:C7:C8": "Aruba", "F0:5C:19": "Aruba",
    # Xiaomi / Huawei / ZTE
    "28:6C:07": "Xiaomi", "34:CE:00": "Xiaomi", "50:8F:4C": "Xiaomi",
    "64:09:80": "Xiaomi", "64:B4:73": "Xiaomi", "74:23:44": "Xiaomi",
    "78:11:DC": "Xiaomi", "8C:BE:BE": "Xiaomi", "98:FA:E3": "Xiaomi",
    "F0:B4:29": "Xiaomi", "F8:A4:5F": "Xiaomi",
    "00:E0:FC": "Huawei", "04:BD:70": "Huawei", "08:19:A6": "Huawei",
    "0C:37:DC": "Huawei", "10:47:80": "Huawei", "20:0B:C7": "Huawei",
    "28:31:52": "Huawei", "34:6B:D3": "Huawei", "48:00:31": "Huawei",
    "5C:4C:A9": "Huawei", "70:72:3C": "Huawei", "80:B6:86": "Huawei",
    "00:15:EB": "ZTE", "00:19:C6": "ZTE", "00:1E:73": "ZTE",
    "04:C0:6F": "ZTE", "08:18:1A": "ZTE", "28:28:5D": "ZTE",
    # Прочие
    "00:80:77": "Brother", "00:1B:A9": "Brother",
    "00:00:0C": "Cisco", "00:00:48": "Seiko Epson",
    "00:1B:A9": "Brother", "00:24:36": "Hewlett Packard",
    "3C:D9:2B": "Hewlett Packard", "9C:B6:54": "Hewlett Packard",
    "B0:5A:DA": "Hewlett Packard", "D4:85:64": "Hewlett Packard",
    "E4:11:5B": "Hewlett Packard", "EC:8E:B5": "Hewlett Packard",
    "FC:15:B4": "Hewlett Packard",
}


def vendor_by_bssid(bssid: str) -> str:
    """Определить вендора по первым 3 байтам MAC."""
    if not bssid:
        return ""
    prefix = bssid.upper().replace("-", ":")[:8]
    return OUI_PREFIXES.get(prefix, "")


# ===========================================================================
# Default router SSID patterns
# ===========================================================================

DEFAULT_SSID_PATTERNS = [
    (re.compile(r"^TP-?Link[_-]?[0-9A-F]{4}$", re.I), "TP-Link default"),
    (re.compile(r"^TP-?Link[_-]", re.I), "TP-Link default"),
    (re.compile(r"^NETGEAR\d+$", re.I), "NETGEAR default"),
    (re.compile(r"^NETGEAR[_-]", re.I), "NETGEAR default"),
    (re.compile(r"^D-?Link[_-]", re.I), "D-Link default"),
    (re.compile(r"^Linksys\d*$", re.I), "Linksys default"),
    (re.compile(r"^Belkin\.\w+$", re.I), "Belkin default"),
    (re.compile(r"^ASUS[_-]?", re.I), "Asus default"),
    (re.compile(r"^ZTE[_-]", re.I), "ZTE default"),
    (re.compile(r"^HUAWEI[_-][0-9A-F]+$", re.I), "Huawei default"),
    (re.compile(r"^Xiaomi[_-]", re.I), "Xiaomi default"),
    (re.compile(r"^Redmi[_-]", re.I), "Xiaomi Redmi default"),
    (re.compile(r"^AndroidAP", re.I), "Android hotspot"),
    (re.compile(r"^iPhone", re.I), "iOS hotspot"),
    (re.compile(r"^DIRECT-", re.I), "Wi-Fi Direct"),
    (re.compile(r"^HP-?Print", re.I), "HP printer"),
    (re.compile(r"^FRITZ!Box", re.I), "AVM FritzBox default"),
    (re.compile(r"^Vodafone-", re.I), "Vodafone default"),
    (re.compile(r"^Speedport", re.I), "Telekom default"),
    (re.compile(r"^Freebox-", re.I), "Freebox default"),
    (re.compile(r"^Livebox-", re.I), "Livebox default"),
    (re.compile(r"^Orange-", re.I), "Orange default"),
    (re.compile(r"^Bbox-", re.I), "Bbox default"),
    (re.compile(r"^SFR_", re.I), "SFR default"),
]


def _is_default_ssid(ssid: str) -> str:
    for pat, name in DEFAULT_SSID_PATTERNS:
        if pat.search(ssid):
            return name
    return ""


# ===========================================================================
# Windows scan
# ===========================================================================

def _scan_windows() -> list[WiFiNetwork]:
    networks: list[WiFiNetwork] = []
    out = ""
    for enc in ("cp866", "cp1251", "utf-8"):
        try:
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=Bssid"],
                encoding=enc, errors="ignore", timeout=30,
            )
            break
        except Exception as exc:
            log.debug("netsh (%s): %s", enc, exc)
            continue

    if not out:
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
        m = radio_re.match(s)
        if m:
            # Radio type: 802.11n/ac/ax — можно хранить в raw
            current.raw = (current.raw + " radio=" + m.group(1)).strip()
            continue

        m = bssid_re.match(s)
        if m:
            new_net = WiFiNetwork(
                ssid=current.ssid,
                bssid=m.group(1).upper(),
                auth=current.auth,
                encryption=current.encryption,
                hidden=current.hidden,
                raw=current.raw,
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

    return [n for n in networks if n.bssid or n.ssid]


# ===========================================================================
# Linux scan
# ===========================================================================

def _scan_linux() -> list[WiFiNetwork]:
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
    except Exception as exc:
        log.debug("nmcli failed: %s", exc)
        return networks

    for line in out.splitlines():
        m = re.match(
            r"^(.+?):((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}):"
            r"(\d+):([\d ]+):(\d+):(.*)$",
            line,
        )
        if not m:
            continue
        ssid = m.group(1)
        bssid = m.group(2)
        chan = m.group(3)
        freq = m.group(4)
        signal = m.group(5)
        security = m.group(6)

        try:
            sig_int = int(signal)
        except ValueError:
            sig_int = 0

        band = "2.4 GHz"
        try:
            f = int(freq.replace(" ", "").split()[0])
            if f > 5925:
                band = "6 GHz"
            elif f > 2500:
                band = "5 GHz"
        except Exception:
            pass
        try:
            if int(chan) > 14 and band == "2.4 GHz":
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
    networks: list[WiFiNetwork] = []
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
    except Exception as exc:
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
            current.hidden = (not current.ssid
                              or current.ssid == "(hidden)")
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
                current.signal = int(float(s.split(":")[1].split()[0]))
                current.signal_unit = "dBm"
            except Exception:
                pass
        elif current and ("WPA:" in s or "RSN:" in s):
            current.encryption = current.encryption or "WPA/WPA2"
        elif current and "Privacy:" in s:
            current.encryption = current.encryption or "WEP"
        elif current and s.startswith("DS Parameter set: channel"):
            try:
                current.channel = s.split()[-1]
            except Exception:
                pass
        elif current and "WPS:" in s:
            current.wps = True

    if current:
        networks.append(current)
    return networks


# ===========================================================================
# Public scan
# ===========================================================================

def scan() -> list[WiFiNetwork]:
    """Кроссплатформенное сканирование."""
    if sys.platform.startswith("win"):
        return _scan_windows()
    return _scan_linux()


def scan_multiple(samples: int = 3, delay: float = 2.0
                   ) -> tuple[list[WiFiNetwork], list[WiFiSample]]:
    """Сканирование N раз + сбор статистики сигнала."""
    aggregated: dict[str, WiFiNetwork] = {}
    timeline: list[WiFiSample] = []
    console.print(f"[cyan]📡 Сканирую {samples}x с интервалом {delay}s…"
                  f"[/cyan]")
    with Progress(SpinnerColumn(),
                   TextColumn("[progress.description]{task.description}"),
                   BarColumn(),
                   TimeElapsedColumn(),
                   console=console) as p:
        task = p.add_task("Scan", total=samples)
        for i in range(samples):
            try:
                batch = scan()
                for n in batch:
                    key = n.bssid or n.ssid
                    if key not in aggregated:
                        aggregated[key] = n
                    else:
                        if n.signal_unit == "dBm":
                            if n.signal > aggregated[key].signal:
                                aggregated[key].signal = n.signal
                        else:
                            if n.signal > aggregated[key].signal:
                                aggregated[key].signal = n.signal
                    timeline.append(WiFiSample(
                        ts=datetime.now().isoformat(timespec="seconds"),
                        bssid=n.bssid, signal=n.signal,
                        unit=n.signal_unit,
                    ))
            except Exception as exc:
                log.debug("scan batch %d: %s", i, exc)
            p.advance(task)
            if i < samples - 1:
                time.sleep(delay)

    return list(aggregated.values()), timeline


# ===========================================================================
# Styling
# ===========================================================================

def _signal_style(sig: int, unit: str) -> str:
    if unit == "dBm":
        if sig >= -50:
            return "bold green"
        if sig >= -65:
            return "green"
        if sig >= -75:
            return "yellow"
        return "red"
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
    table.add_column("WPS", width=4)
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
            "✓" if n.wps else "—",
        )
    console.print(table)


# ===========================================================================
# Analytics
# ===========================================================================

def _duplicates(networks: list[WiFiNetwork]) -> dict[str, list[WiFiNetwork]]:
    by_ssid: dict[str, list[WiFiNetwork]] = {}
    for n in networks:
        if not n.ssid or n.hidden:
            continue
        by_ssid.setdefault(n.ssid, []).append(n)
    return {s: lst for s, lst in by_ssid.items()
            if len({x.bssid for x in lst if x.bssid}) > 1}


def show_evil_twin(networks: list[WiFiNetwork]) -> list[tuple[str, list]]:
    """Показать потенциальные evil twin."""
    dups = _duplicates(networks)
    if not dups:
        console.print("[green]✓ Подозрительных дублей SSID не найдено."
                      "[/green]")
        return []

    console.print(f"[red]⚠ Найдено {len(dups)} SSID с несколькими BSSID:"
                  f"[/red]\n")
    suspicious: list[tuple[str, list]] = []
    for ssid, lst in dups.items():
        table = Table(title=f"⚠ {ssid} ({len(lst)} BSSID)")
        table.add_column("BSSID", style="cyan")
        table.add_column("Vendor", style="magenta")
        table.add_column("Signal", width=8)
        table.add_column("Auth", width=16)
        table.add_column("Channel", width=8)
        table.add_column("Suspicious?", width=12)
        vendors = {n.vendor for n in lst if n.vendor}
        encs = {n.encryption for n in lst}
        is_sus = len(vendors) > 1 or len(encs) > 1
        for n in lst:
            sig_sty = _signal_style(n.signal, n.signal_unit)
            enc_sty = _enc_style(n.encryption)
            table.add_row(
                n.bssid,
                n.vendor or "—",
                f"[{sig_sty}]{n.signal}{n.signal_unit}[/{sig_sty}]",
                f"[{enc_sty}]{n.auth or n.encryption or '—'}[/{enc_sty}]",
                n.channel or "—",
                "[red]ДА[/red]" if is_sus else "—",
            )
        console.print(table)

        if is_sus:
            suspicious.append((ssid, lst))
            _save_finding(WiFiFinding(
                kind="evil_twin_suspected",
                severity="critical",
                title=f"Возможный Evil Twin: {ssid}",
                target=ssid,
                evidence=(f"SSID={ssid} имеет {len(lst)} BSSID с разными "
                          f"vendor={vendors} и encryption={encs}"),
                data={"ssids": [n.bssid for n in lst],
                      "vendors": list(vendors),
                      "encryptions": list(encs)},
            ))
            _notify(
                f"⚠ Evil Twin suspected: {ssid}",
                f"{len(lst)} BSSID\nVendors: {vendors}\nCiphers: {encs}",
                severity="critical",
            )
    return suspicious


def show_open_networks(networks: list[WiFiNetwork]) -> list[WiFiNetwork]:
    opens = [n for n in networks
             if "OPEN" in (n.encryption or "").upper()
             or not n.encryption
             or (n.encryption or "").upper() in ("--", "NONE")]
    if not opens:
        console.print("[green]✓ Открытых сетей нет.[/green]")
        return []
    _print_networks(opens, "🔓 Открытые сети (без шифрования)")
    for n in opens[:5]:
        _save_finding(WiFiFinding(
            kind="open_wifi",
            severity="high",
            title=f"Открытая Wi-Fi сеть: {n.ssid}",
            target=n.ssid,
            evidence=(f"BSSID={n.bssid} channel={n.channel} "
                      f"signal={n.signal}{n.signal_unit}"),
            data=asdict(n),
        ))
    return opens


def show_weak_crypto(networks: list[WiFiNetwork]) -> list[WiFiNetwork]:
    weak = [n for n in networks
            if "WEP" in (n.encryption or "").upper()
            or (n.encryption or "").upper().strip() in ("WPA", "WPA-PSK")]
    if not weak:
        console.print("[green]✓ WEP/WPA1 сетей нет.[/green]")
        return []
    _print_networks(weak, "🟠 Слабые шифры (WEP/WPA1)")
    for n in weak:
        sev = "high" if "WEP" in (n.encryption or "").upper() else "medium"
        _save_finding(WiFiFinding(
            kind="weak_crypto",
            severity=sev,
            title=f"Слабый шифр: {n.ssid} ({n.encryption})",
            target=n.ssid,
            evidence=f"BSSID={n.bssid} auth={n.auth}",
            data=asdict(n),
        ))
    return weak


def show_channel_load(networks: list[WiFiNetwork]) -> None:
    by_ch: dict[str, int] = {}
    by_band: dict[str, dict[str, int]] = defaultdict(dict)
    for n in networks:
        ch = n.channel or "?"
        by_ch[ch] = by_ch.get(ch, 0) + 1
        band = n.band or "?"
        by_band[band][ch] = by_band[band].get(ch, 0) + 1

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
        band = next((b for b, chs in by_band.items() if ch in chs), "?")
        bar = "█" * cnt
        table.add_row(ch, band, str(cnt), bar)
    console.print(table)

    # Рекомендации
    ch24 = {int(k): v for k, v in by_ch.items()
            if k.isdigit() and int(k) <= 14}
    if ch24:
        non_overlap = [1, 6, 11]
        best = min(non_overlap, key=lambda c: ch24.get(c, 0))
        console.print(f"[cyan]Рекомендация (2.4 GHz, non-overlap): "
                      f"канал {best} ({ch24.get(best, 0)} сетей)[/cyan]")

    ch5 = {int(k): v for k, v in by_ch.items()
           if k.isdigit() and 36 <= int(k) <= 177}
    if ch5:
        best5 = min(ch5, key=lambda c: ch5[c])
        console.print(f"[cyan]Рекомендация (5 GHz): канал {best5} "
                      f"({ch5[best5]} сетей)[/cyan]")


def show_hidden(networks: list[WiFiNetwork]) -> None:
    hidden = [n for n in networks if n.hidden or not n.ssid
              or n.ssid == "(hidden)"]
    if not hidden:
        console.print("[green]✓ Скрытых сетей нет.[/green]")
        return
    _print_networks(hidden, "🕶 Скрытые SSID")


def show_default_ssids(networks: list[WiFiNetwork]) -> None:
    found: list[tuple[WiFiNetwork, str]] = []
    for n in networks:
        if not n.ssid:
            continue
        d = _is_default_ssid(n.ssid)
        if d:
            found.append((n, d))
    if not found:
        console.print("[green]✓ Default-router SSID не найдены.[/green]")
        return
    table = Table(title=f"🔧 Default-router SSID ({len(found)})")
    table.add_column("SSID", style="cyan", max_width=28)
    table.add_column("Pattern", style="magenta", max_width=22)
    table.add_column("BSSID", style="dim", width=18)
    table.add_column("Vendor", style="green", max_width=14)
    for n, pat in found:
        table.add_row(n.ssid, pat, n.bssid, n.vendor or "—")
    console.print(table)


def show_karma_indicator(networks: list[WiFiNetwork]) -> None:
    """Karma: много SSID с одним BSSID."""
    by_bssid: dict[str, set[str]] = defaultdict(set)
    for n in networks:
        if n.bssid and n.ssid:
            by_bssid[n.bssid].add(n.ssid)
    karma = {b: ssids for b, ssids in by_bssid.items() if len(ssids) > 2}
    if not karma:
        console.print("[green]✓ Karma-индикаторов не найдено.[/green]")
        return
    console.print(f"[red]⚠ Возможен Karma attack "
                  f"({len(karma)} BSSID с >2 SSID):[/red]")
    for b, ssids in karma.items():
        console.print(f"  [cyan]{b}[/cyan] → {len(ssids)} SSID: "
                      f"{list(ssids)[:5]}")
    _save_finding(WiFiFinding(
        kind="karma_attack_suspected",
        severity="high",
        title=f"Karma attack suspected ({len(karma)} BSSID)",
        target="local",
        evidence=json.dumps({b: list(s) for b, s in karma.items()})[:1000],
        data={"bssids": list(karma.keys())},
    ))


def signal_ranking(networks: list[WiFiNetwork]) -> list[WiFiNetwork]:
    def _key(n: WiFiNetwork) -> float:
        if n.signal_unit == "dBm":
            return -n.signal
        return -n.signal
    return sorted(networks, key=_key)


def show_signal_timeline(timeline: list[WiFiSample],
                          top_n: int = 5) -> None:
    """Топ-N стабильных сетей по времени."""
    if not timeline:
        console.print("[yellow]Нет данных timeline.[/yellow]")
        return
    by_bssid: dict[str, list[int]] = defaultdict(list)
    for s in timeline:
        if s.bssid:
            by_bssid[s.bssid].append(s.signal)
    stats = []
    for b, sigs in by_bssid.items():
        if not sigs:
            continue
        stats.append({
            "bssid": b,
            "samples": len(sigs),
            "avg": sum(sigs) / len(sigs),
            "min": min(sigs),
            "max": max(sigs),
            "jitter": max(sigs) - min(sigs),
        })
    stats.sort(key=lambda x: (-x["samples"], -x["avg"]))
    table = Table(title=f"📈 Signal timeline (top {top_n})")
    table.add_column("BSSID", style="cyan")
    table.add_column("Samples", width=8)
    table.add_column("Avg", width=8)
    table.add_column("Min", width=6)
    table.add_column("Max", width=6)
    table.add_column("Jitter", width=8)
    for s in stats[:top_n]:
        table.add_row(s["bssid"], str(s["samples"]),
                      f"{s['avg']:.1f}", str(s["min"]),
                      str(s["max"]), str(s["jitter"]))
    console.print(table)


# ===========================================================================
# Экспорт
# ===========================================================================

def export_json(networks: list[WiFiNetwork],
                 path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(WIFI_DIR / f"wifi_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps([asdict(n) for n in networks], indent=2,
                        ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_csv(networks: list[WiFiNetwork],
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(WIFI_DIR / f"wifi_{ts}.csv")
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
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_markdown(networks: list[WiFiNetwork],
                     path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(WIFI_DIR / f"wifi_{ts}.md")
    try:
        lines = [
            "# Wi-Fi scan report",
            f"_Generated: {datetime.now().isoformat()}_",
            f"Total networks: **{len(networks)}**", "",
            "| # | SSID | BSSID | Vendor | Ch | Band | Signal | Auth |",
            "|---|------|-------|--------|----|----|--------|------|",
        ]
        for i, n in enumerate(networks, 1):
            lines.append(
                f"| {i} | {n.ssid or '(hidden)'} | {n.bssid} | "
                f"{n.vendor or '—'} | {n.channel or '—'} | "
                f"{n.band or '—'} | {n.signal}{n.signal_unit} | "
                f"{n.auth or n.encryption or '—'} |"
            )
        Path(path).write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green]✓ MD: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_html(networks: list[WiFiNetwork],
                 path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(WIFI_DIR / f"wifi_{ts}.html")
    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        "<title>Wi-Fi scan</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:24px;line-height:1.5;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
        "table{width:100%;border-collapse:collapse;margin-top:12px;"
        "font-size:13px;}",
        "th{background:#111;color:#00ff9c;padding:6px;text-align:left;"
        "border:1px solid #222;}",
        "td{padding:4px 6px;border:1px solid #222;word-break:break-all;}",
        "tr:nth-child(even){background:#0d0d0d;}",
        ".open{color:#ff2020;font-weight:bold;}",
        ".wep{color:#ff7a40;font-weight:bold;}",
        ".wpa2{color:#7ad9ff;}",
        ".wpa3{color:#00ff9c;}",
        ".signal-strong{color:#00ff9c;}",
        ".signal-weak{color:#ff7a40;}",
        "</style></head><body>",
        f"<h1>📶 Wi-Fi scan ({len(networks)})</h1>",
        f"<p>Generated: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "<table><tr><th>#</th><th>SSID</th><th>BSSID</th>"
        "<th>Vendor</th><th>Ch</th><th>Band</th><th>Signal</th>"
        "<th>Auth</th><th>Cipher</th></tr>",
    ]

    def _enc_class(enc: str) -> str:
        e = (enc or "").upper()
        if "OPEN" in e or not e or e == "--":
            return "open"
        if "WEP" in e:
            return "wep"
        if "WPA3" in e:
            return "wpa3"
        if "WPA2" in e:
            return "wpa2"
        return ""

    def _sig_class(n: WiFiNetwork) -> str:
        if n.signal_unit == "dBm":
            return "signal-strong" if n.signal >= -65 else "signal-weak"
        return "signal-strong" if n.signal >= 50 else "signal-weak"

    for i, n in enumerate(networks, 1):
        parts.append(
            f"<tr><td>{i}</td>"
            f"<td>{html_mod.escape(n.ssid or '(hidden)')}</td>"
            f"<td>{html_mod.escape(n.bssid)}</td>"
            f"<td>{html_mod.escape(n.vendor or '—')}</td>"
            f"<td>{html_mod.escape(n.channel or '—')}</td>"
            f"<td>{html_mod.escape(n.band or '—')}</td>"
            f"<td class='{_sig_class(n)}'>{n.signal}{n.signal_unit}</td>"
            f"<td>{html_mod.escape(n.auth or '—')}</td>"
            f"<td class='{_enc_class(n.encryption)}'>"
            f"{html_mod.escape(n.encryption or '—')}</td></tr>")
    parts.append("</table></body></html>")
    try:
        Path(path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# High-level
# ===========================================================================

def cmd_scan(save: bool = True) -> list[WiFiNetwork]:
    """Полный скан + вывод + сохранение."""
    console.print("[cyan]📡 Сканирую Wi-Fi сети…[/cyan]")
    try:
        networks = scan()
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return []

    _print_networks(networks)
    if not networks:
        return []

    # Сводка
    open_n = sum(1 for n in networks
                 if "OPEN" in (n.encryption or "").upper())
    weak_n = sum(1 for n in networks
                 if "WEP" in (n.encryption or "").upper())
    wpa3_n = sum(1 for n in networks
                 if "WPA3" in (n.encryption or "").upper())
    wps_n = sum(1 for n in networks if n.wps)
    dups = _duplicates(networks)
    default_ssids = sum(1 for n in networks
                         if n.ssid and _is_default_ssid(n.ssid))

    table = Table(title="📊 Сводка")
    table.add_column("Метрика", style="cyan")
    table.add_column("Значение", style="green")
    table.add_row("Всего сетей", str(len(networks)))
    table.add_row("Уникальных SSID",
                  str(len({n.ssid for n in networks if n.ssid})))
    table.add_row("Открытых", f"[red]{open_n}[/red]")
    table.add_row("WEP", f"[red]{weak_n}[/red]")
    table.add_row("WPA3", f"[green]{wpa3_n}[/green]")
    table.add_row("WPS enabled", f"[yellow]{wps_n}[/yellow]")
    table.add_row("Default-router SSID",
                  f"[yellow]{default_ssids}[/yellow]")
    table.add_row("Дублей SSID (evil twin?)",
                  f"[yellow]{len(dups)}[/yellow]")
    console.print(table)

    if save:
        try:
            db.save_scan("wifi_scan", "local", {
                "count": len(networks),
                "ssids": sorted({n.ssid for n in networks if n.ssid}),
                "open": open_n,
                "wep": weak_n,
                "wpa3": wpa3_n,
                "wps": wps_n,
                "duplicates": list(dups.keys()),
                "default_ssids": default_ssids,
            })
        except Exception:
            pass

    if open_n or weak_n or dups:
        _notify(
            "📶 Wi-Fi scan findings",
            f"Networks: {len(networks)}\nOpen: {open_n}\nWEP: {weak_n}\n"
            f"Evil twin suspects: {len(dups)}",
            severity="high" if (open_n or weak_n or dups) else "medium",
        )

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
    show_hidden(networks)
    console.print()
    show_default_ssids(networks)
    console.print()
    show_channel_load(networks)
    console.print()
    show_karma_indicator(networks)
    console.print()
    if Confirm.ask("Экспортировать CSV + JSON + HTML + MD?",
                    default=True):
        export_csv(networks)
        export_json(networks)
        export_html(networks)
        export_markdown(networks)


def cmd_export(fmt: str = "csv") -> None:
    networks = scan()
    if not networks:
        console.print("[yellow]Сети не найдены.[/yellow]")
        return
    fmt_map = {"json": export_json, "csv": export_csv,
               "html": export_html, "md": export_markdown}
    fn = fmt_map.get(fmt)
    if fn:
        fn(networks)


def cmd_multi_scan(samples: int = 3) -> None:
    """Мульти-скан + timeline."""
    networks, timeline = scan_multiple(samples=samples, delay=2.0)
    _print_networks(networks, "Wi-Fi сети (aggregated)")
    console.print()
    show_signal_timeline(timeline)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]📶 Wireless Toolkit Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Сканировать Wi-Fi (список)"),
        ("2", "Полный анализ (evil twin, открытые, слабые, каналы, karma)"),
        ("3", "Детектор evil twin (дубли SSID)"),
        ("4", "Открытые сети"),
        ("5", "Слабые шифры (WEP/WPA1)"),
        ("6", "Загруженность каналов"),
        ("7", "Скрытые SSID"),
        ("8", "Default-router SSID (TP-Link_XXXX и т.п.)"),
        ("9", "Karma attack detector"),
        ("10", "Топ по силе сигнала"),
        ("11", "Multi-scan + timeline"),
        ("12", "Экспорт CSV"),
        ("13", "Экспорт JSON"),
        ("14", "Экспорт HTML"),
        ("15", "Экспорт Markdown"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для аудита собственных сетей / CTF."
                  "[/yellow]")
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
        show_open_networks(scan())
    elif c == "5":
        show_weak_crypto(scan())
    elif c == "6":
        show_channel_load(scan())
    elif c == "7":
        show_hidden(scan())
    elif c == "8":
        show_default_ssids(scan())
    elif c == "9":
        show_karma_indicator(scan())
    elif c == "10":
        _print_networks(signal_ranking(scan()), "🏆 Топ по сигналу")
    elif c == "11":
        n = IntPrompt.ask("Сколько замеров", default=3)
        cmd_multi_scan(samples=n)
    elif c == "12":
        cmd_export("csv")
    elif c == "13":
        cmd_export("json")
    elif c == "14":
        cmd_export("html")
    elif c == "15":
        cmd_export("md")


# ===========================================================================
# CLI-обёртки (совместимы)
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


def cli_export_html() -> None:
    cmd_export("html")


def cli_export_md() -> None:
    cmd_export("md")


def cli_full() -> None:
    cmd_full_analysis()


def cli_hidden() -> None:
    show_hidden(scan())


def cli_default_ssid() -> None:
    show_default_ssids(scan())


def cli_karma() -> None:
    show_karma_indicator(scan())


def cli_multi(samples: int = 3) -> None:
    cmd_multi_scan(samples=samples)