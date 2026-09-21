"""
Roadmap Pro — обучение, квиз, сертификации, трекер прогресса.
Author: idqwixxa

Возможности:
    ─── Roadmap ───
    - 7 путей: Junior / Middle / Senior / Expert / Red Team / Blue Team / Web
    - Каждая тема: название + ссылки на ресурсы + практика
    - Уровни покрывают OSCP/OSWE/CRTO/CRTP/CISSP-path

    ─── Ресурсы ───
    - 40+ проверенных ресурсов по категориям
    - TryHackMe / HTB / PortSwigger / PentesterLab / VulnHub / …

    ─── Сертификации ───
    - 15+ сертификаций: eJPT / OSCP / OSWE / OSEP / CRTO / CRTP / CISSP /
      CEH / GPEN / GCIH / Burp Certified / AWS Security…

    ─── Квиз ───
    - 60+ вопросов по категориям
      (сеть / linux / web / crypto / AD / cloud / red team / forensics)
    - Режим: короткий (10) / полный (все) / по категории
    - Начисление очков, стрик

    ─── Прогресс ───
    - SQLite-backed: статус каждой темы
    - Daily streak (сколько дней подряд занимаешься)
    - Timeline активности
    - Экспорт: JSON / Markdown / HTML / CSV

    ─── Интеграция ───
    - Findings → notes при получении сертификации / milestone
    - Notify о streak / milestone
"""
import csv
import html as html_mod
import json
import random
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

ROADMAP_DIR = REPORT_DIR / "roadmap"
ROADMAP_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class RoadmapFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: RoadmapFinding) -> int:
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
            tags=["roadmap", "learning", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Roadmap (расширенный: 7 путей)
# ===========================================================================

ROADMAP = {
    "Junior": [
        "Networking basics (OSI, TCP/IP, DNS, HTTP)",
        "Linux CLI (bash, permissions, processes, systemd)",
        "Python scripting basics (requests, sockets)",
        "Web basics (HTML, JS, HTTP methods, cookies, sessions)",
        "TryHackMe: Pre Security Path",
        "Основы криптографии (хеши, симметрия/асимметрия, TLS)",
        "Git basics",
        "Virtualization (VMware/VirtualBox, снапшоты)",
    ],
    "Middle": [
        "OWASP Top 10 — все уязвимости",
        "Burp Suite (Repeater, Intruder, Scanner, Collaborator)",
        "ffuf / gobuster / feroxbuster — fuzzing",
        "nmap / masscan — port scan",
        "sqlmap — SQL injection",
        "Linux privilege escalation (LinPEAS, GTFOBins, capab.)",
        "Windows privilege escalation (WinPEAS, PowerUp, SeImpersonate)",
        "HackTheBox: Easy/Medium machines (20+)",
        "Active Directory basics (LDAP, Kerberos, SMB)",
        "Recon: Shodan, Censys, subdomain enumeration",
        "Базовый пентест-отчёт (CVSS, executive summary)",
    ],
    "Senior": [
        "Active Directory attacks (Kerberoasting, AS-REP, DCSync)",
        "BloodHound + SharpHound (пути атаки)",
        "Reverse engineering basics (IDA Free, Ghidra)",
        "Malware analysis (static + dynamic, sandbox)",
        "Cloud security (AWS/Azure/GCP IAM, IMDS)",
        "Exploit development (buffer overflow x86/x64, ROP)",
        "Fuzzing (AFL++, boofuzz)",
        "Bug bounty — write-ups, HackerOne/Bugcrowd",
        "Red teaming (C2, opsec, persistence, evasion)",
        "Forensics & incident response (Volatility, Autopsy)",
        "Web3 / smart contract audits",
        "Compliance: PCI-DSS, ISO 27001, SOC2",
    ],
    "Expert": [
        "Kernel exploitation (Linux/Windows)",
        "Hardware attacks (JTAG, SPI, fault injection)",
        "Custom C2 development (protocol, obfuscation)",
        "EDR/AV evasion research",
        "Advanced AD (ADCS ESC1-ESC8, trust attacks, RBCD)",
        "Cloud-native attack paths (K8s, containers, serverless)",
        "Supply chain attacks (dependency confusion, typosquatting)",
        "Zero-day research & responsible disclosure",
        "Threat hunting / detection engineering (Sigma, KQL)",
        "Purple teaming (atomic red team, MITRE ATT&CK)",
    ],
    "Red Team": [
        "OpSec: VPS, redirectors, domain fronting, malleable C2",
        "C2 frameworks: Cobalt Strike, Sliver, Havoc, Mythic",
        "AMSI/ETW bypass, PPID spoofing, unhooking",
        "Phishing: GoPhish, Evilginx, приманки",
        "Physical: lockpicking, RFID (для red team engagements)",
        "Social engineering (претекстинг, vishing)",
        "Долгосрочное удержание (persistence, LDAP, WMI)",
        "Data exfil channels (DNS, HTTPS, cloud storage)",
        "Работа с EDR (методика обхода)",
    ],
    "Blue Team": [
        "SIEM (Splunk, ELK, Wazuh) — обзор",
        "Detection engineering (Sigma rules)",
        "Threat hunting (hypothesis-driven)",
        "Incident Response (PICERL)",
        "Forensics: Volatility, Autopsy, Eric Zimmerman tools",
        "YARA rules development",
        "Network monitoring (Zeek, Suricata)",
        "Endpoint monitoring (Sysmon, osquery)",
        "Threat intel platforms (MISP, OpenCTI)",
    ],
    "Web Deep": [
        "Burp Suite Pro (все расширения + API)",
        "HTTP Request Smuggling (CL.TE / TE.CL / H2)",
        "Deserialization attacks (Java, PHP, Python, .NET)",
        "Race Conditions (single-packet attack)",
        "GraphQL deep dive (introspection, aliases, batching)",
        "JWT attacks (alg-none, confusion, kid inject)",
        "OAuth/OIDC attack surface",
        "Web Cache Poisoning & Deception",
        "Prototype Pollution (client + server)",
        "SSTI (Jinja2, Twig, Freemarker, ...)",
    ],
}


# ===========================================================================
# Resources (расширенный)
# ===========================================================================

RESOURCES = [
    # ─── General / Labs ───
    ("TryHackMe", "https://tryhackme.com"),
    ("HackTheBox", "https://hackthebox.com"),
    ("VulnHub", "https://www.vulnhub.com"),
    ("PentesterLab", "https://pentesterlab.com"),
    ("PortSwigger Academy", "https://portswigger.net/web-security"),
    ("OffSec Proving Grounds", "https://www.offensive-security.com/labs"),
    ("HTB Academy", "https://academy.hackthebox.com"),
    ("RangeForce", "https://www.rangeforce.com"),
    ("CyberDefenders", "https://cyberdefenders.org"),
    ("Blue Team Labs Online", "https://blueteamlabs.online"),
    # ─── Reference ───
    ("OWASP", "https://owasp.org"),
    ("HackTricks", "https://book.hacktricks.xyz"),
    ("GTFOBins", "https://gtfobins.github.io"),
    ("LOLBAS", "https://lolbas-project.github.io"),
    ("PayloadsAllTheThings", "https://github.com/swisskyrepo/PayloadsAllTheThings"),
    ("MITRE ATT&CK", "https://attack.mitre.org"),
    ("CVEDetails", "https://www.cvedetails.com"),
    ("Exploit-DB", "https://www.exploit-db.com"),
    # ─── Blogs / Write-ups ───
    ("PortSwigger Research", "https://portswigger.net/research"),
    ("Google Project Zero", "https://googleprojectzero.blogspot.com"),
    ("HackerOne Hacktivity", "https://hackerone.com/hacktivity"),
    ("Bugcrowd Blog", "https://www.bugcrowd.com/blog"),
    ("Orange Tsai Blog", "https://blog.orange.tw"),
    ("Sam Curry Blog", "https://samcurry.net"),
    ("Project Zero CVE feed", "https://bugs.chromium.org/p/project-zero"),
    # ─── Red Team ───
    ("ired.team", "https://www.ired.team"),
    ("SpecterOps Blog", "https://posts.specterops.io"),
    ("Cobalt Strike Blog", "https://www.cobaltstrike.com/blog"),
    ("Red Team Notes", "https://www.rtnotes.com"),
    ("Malware Unicorn", "https://malwareunicorn.org"),
    # ─── Blue Team ───
    ("SANS DFIR Cheat Sheets", "https://digital-forensics.sans.org/community/cheat-sheets"),
    ("Sigma HQ", "https://github.com/SigmaHQ/sigma"),
    ("YARA docs", "https://yara.readthedocs.io"),
    # ─── Books ───
    ("Web App Hacker's Handbook", "https://www.amazon.com/dp/1118026470"),
    ("Hacking: Art of Exploitation", "https://www.amazon.com/dp/1593271441"),
    ("Practical Malware Analysis", "https://www.amazon.com/dp/1593272901"),
    ("Red Team Field Manual", "https://www.amazon.com/dp/1494709710"),
    ("Windows Internals", "https://www.amazon.com/dp/0735684189"),
]


# ===========================================================================
# Certifications
# ===========================================================================

CERTIFICATIONS = [
    # Entry
    ("eJPT", "eLearnSecurity Junior Penetration Tester",
     "entry", "https://elearnsecurity.com/product/ejpt-certification/"),
    ("CompTIA Security+", "CompTIA", "entry",
     "https://www.comptia.org/certifications/security"),
    ("CEH", "Certified Ethical Hacker", "entry",
     "https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/"),
    ("PNPT", "Practical Network Penetration Tester", "entry",
     "https://certifications.tcm-sec.com/pnpt/"),
    # Middle
    ("OSCP", "Offensive Security Certified Professional", "middle",
     "https://www.offensive-security.com/pwk-oscp/"),
    ("CRTP", "Certified Red Team Professional", "middle",
     "https://www.alteredsecurity.com/adlab"),
    ("GPEN", "GIAC Penetration Tester", "middle",
     "https://www.giac.org/certifications/penetration-tester-gpen/"),
    ("HTB CPTS", "HTB Certified Penetration Testing Specialist", "middle",
     "https://academy.hackthebox.com/preview/certifications/htb-certified-penetration-testing-specialist/"),
    # Advanced
    ("OSWE", "Offensive Security Web Expert", "advanced",
     "https://www.offensive-security.com/awae-oswe/"),
    ("OSEP", "Offensive Security Experienced Penetration Tester", "advanced",
     "https://www.offensive-security.com/pen300-osep/"),
    ("CRTO", "Certified Red Team Operator", "advanced",
     "https://training.zeropointsecurity.co.uk/courses/red-team-ops"),
    ("CRTL", "Certified Red Team Lead", "advanced",
     "https://training.zeropointsecurity.co.uk/courses/red-team-ops-2"),
    ("OSED", "Offensive Security Exploit Developer", "advanced",
     "https://www.offensive-security.com/exp301-osed/"),
    # GRC / Management
    ("CISSP", "Certified Information Systems Security Professional", "grc",
     "https://www.isc2.org/Certifications/CISSP"),
    ("CISM", "Certified Information Security Manager", "grc",
     "https://www.isaca.org/credentialing/cism"),
    # Cloud
    ("AWS Security Specialty", "AWS Certified Security – Specialty", "cloud",
     "https://aws.amazon.com/certification/certified-security-specialty/"),
    ("Azure Security Engineer", "Microsoft Certified: Azure Security Engineer",
     "cloud", "https://learn.microsoft.com/en-us/certifications/azure-security-engineer/"),
    ("GCP Professional Cloud Security Engineer", "Google Cloud", "cloud",
     "https://cloud.google.com/certification/cloud-security-engineer"),
]


# ===========================================================================
# Quiz (60+ вопросов по категориям)
# ===========================================================================

QUIZ = [
    # ─── Network ───
    {"cat": "network",
     "q": "Какой порт используется по умолчанию для HTTPS?",
     "options": ["80", "443", "22", "8080"], "answer": "2"},
    {"cat": "network",
     "q": "Что проверяет HSTS-заголовок?",
     "options": ["CORS", "Принудительный HTTPS", "CSRF", "SQLi"],
     "answer": "2"},
    {"cat": "network",
     "q": "На каком уровне OSI работает TCP?",
     "options": ["Network", "Transport", "Session", "Data Link"],
     "answer": "2"},
    {"cat": "network",
     "q": "Какой протокол использует UDP: 53?",
     "options": ["HTTP", "DNS", "SMTP", "SSH"], "answer": "2"},
    {"cat": "network",
     "q": "Что делает команда `nmap -sS`?",
     "options": ["SYN-сканирование (stealth)", "UDP-сканирование",
                 "Пинг-скан", "TCP connect scan"], "answer": "1"},
    {"cat": "network",
     "q": "Какой порт у MySQL по умолчанию?",
     "options": ["3306", "5432", "1433", "6379"], "answer": "1"},
    {"cat": "network",
     "q": "Что такое ARP?",
     "options": ["Протокол трансляции IP → MAC",
                 "Протокол аутентификации",
                 "Протокол маршрутизации",
                 "Протокол шифрования"], "answer": "1"},
    {"cat": "network",
     "q": "Какой протокол работает поверх TCP: 22?",
     "options": ["Telnet", "SSH", "FTP", "SMTP"], "answer": "2"},

    # ─── Linux ───
    {"cat": "linux",
     "q": "Что делает команда `chmod 777 file`?",
     "options": ["Даёт всем полный доступ", "Удаляет файл",
                 "Меняет владельца", "Делает root-only"], "answer": "1"},
    {"cat": "linux",
     "q": "Что возвращает `whoami`?",
     "options": ["Каталог", "Имя текущего пользователя",
                 "Список процессов", "IP"], "answer": "2"},
    {"cat": "linux",
     "q": "Файл с SUID битом — что это значит?",
     "options": ["Исполняется с правами владельца файла",
                 "Исполняется с правами root всегда",
                 "Зашифрован",
                 "Запрещает удаление"], "answer": "1"},
    {"cat": "linux",
     "q": "Какой командой посмотреть открытые порты?",
     "options": ["ls -la", "ps aux", "ss -tulnp", "df -h"], "answer": "3"},
    {"cat": "linux",
     "q": "Что делает `sudo -l`?",
     "options": ["Удаляет логи",
                 "Показывает разрешённые команды sudo",
                 "Показывает локальных юзеров",
                 "Логин под root"], "answer": "2"},

    # ─── Web ───
    {"cat": "web",
     "q": "Какой из этих заголовков защищает от XSS?",
     "options": ["X-Frame-Options", "Content-Security-Policy",
                 "Referrer-Policy", "Permissions-Policy"], "answer": "2"},
    {"cat": "web",
     "q": "Что такое SQL-инъекция?",
     "options": ["Внедрение SQL через user input", "Ошибка в СУБД",
                 "XSS", "DoS"], "answer": "1"},
    {"cat": "web",
     "q": "Что такое CSRF?",
     "options": ["Cross-Site Request Forgery",
                 "Cross-Site Scripting Filter",
                 "Client-Side Response Filter",
                 "Central Server Request Format"], "answer": "1"},
    {"cat": "web",
     "q": "Что такое SSRF?",
     "options": ["Server-Side Request Forgery", "Secure Socket RF",
                 "SQL Server Reference", "Session Side Rename"], "answer": "1"},
    {"cat": "web",
     "q": "Какой параметр cookie защищает от CSRF?",
     "options": ["Secure", "HttpOnly", "SameSite", "Path"], "answer": "3"},
    {"cat": "web",
     "q": "Что эксплуатирует `' OR 1=1--`?",
     "options": ["SQLi", "XSS", "LFI", "SSRF"], "answer": "1"},
    {"cat": "web",
     "q": "Что делает CSP `script-src 'self'`?",
     "options": ["Запрещает inline и внешние скрипты",
                 "Разрешает любой JS",
                 "Блокирует изображения",
                 "Ускоряет загрузку"], "answer": "1"},
    {"cat": "web",
     "q": "Что такое IDOR?",
     "options": ["Insecure Direct Object Reference",
                 "Insufficient Data Ownership Rule",
                 "Invalid Domain Origin Registration",
                 "Inline Document Object Relay"], "answer": "1"},
    {"cat": "web",
     "q": "Какая уязвимость в XXE?",
     "options": ["XML External Entity Injection",
                 "XSS External Extension",
                 "Cross XML Execution",
                 "eXtreme XML Encryption"], "answer": "1"},
    {"cat": "web",
     "q": "Что такое SSTI?",
     "options": ["Server-Side Template Injection",
                 "Secure Socket Transport Injection",
                 "Static Site Testing Interface",
                 "Server Side Token Identification"], "answer": "1"},

    # ─── Crypto ───
    {"cat": "crypto",
     "q": "Какой алгоритм хеширования устарел?",
     "options": ["bcrypt", "argon2", "MD5", "SHA-256"], "answer": "3"},
    {"cat": "crypto",
     "q": "Что такое salt в хешировании?",
     "options": ["Случайные данные для защиты от rainbow",
                 "Пароль",
                 "Алгоритм",
                 "Ключ шифрования"], "answer": "1"},
    {"cat": "crypto",
     "q": "Какой алгоритм хеша для паролей сейчас рекомендуется?",
     "options": ["MD5", "SHA1", "bcrypt / argon2", "CRC32"], "answer": "3"},
    {"cat": "crypto",
     "q": "Что такое асимметричная криптография?",
     "options": ["Публичный + приватный ключ",
                 "Один ключ для шифрования",
                 "Хеш",
                 "Кодирование base64"], "answer": "1"},
    {"cat": "crypto",
     "q": "Что такое JWT?",
     "options": ["JSON Web Token",
                 "Java Web Transfer",
                 "Just Web Tag",
                 "Joint Wrap Tunnel"], "answer": "1"},

    # ─── AD ───
    {"cat": "ad",
     "q": "Что такое Kerberoasting?",
     "options": ["Запрос TGS для оффлайн-крэка",
                 "Фишинг AD",
                 "DDoS на DC",
                 "MITM атака"], "answer": "1"},
    {"cat": "ad",
     "q": "Что такое AS-REP Roasting?",
     "options": ["Запрос AS-REP без preauth",
                 "Кража hash из SAM",
                 "Инъекция в LSA",
                 "Фишинг"], "answer": "1"},
    {"cat": "ad",
     "q": "Что такое DCSync?",
     "options": ["Имитация DC для репликации NTLM",
                 "Синхронизация времени",
                 "Синхронизация файлов",
                 "Атака на SMB"], "answer": "1"},
    {"cat": "ad",
     "q": "Что такое Golden Ticket?",
     "options": ["Поддельный TGT для krbtgt",
                 "Фишинг", "Ошибка DNS", "Тип JWT"], "answer": "1"},
    {"cat": "ad",
     "q": "Что такое BloodHound?",
     "options": ["Инструмент для картирования AD",
                 "Антивирус",
                 "Файрвол",
                 "Burp Suite плагин"], "answer": "1"},

    # ─── Cloud ───
    {"cat": "cloud",
     "q": "Что такое IMDS?",
     "options": ["Instance Metadata Service (169.254.169.254)",
                 "Identity Mapper for Domain",
                 "Internal Message Dispatch",
                 "Image Metadata Store"], "answer": "1"},
    {"cat": "cloud",
     "q": "Что можно получить из AWS IMDSv1?",
     "options": ["IAM credentials", "Только hostname",
                 "Только IP", "Публичные ключи"], "answer": "1"},
    {"cat": "cloud",
     "q": "Как защититься от SSRF → IMDSv1?",
     "options": ["Включить IMDSv2 (token-required)",
                 "Уменьшить TTL",
                 "Сменить ключи",
                 "Заблокировать 443"], "answer": "1"},
    {"cat": "cloud",
     "q": "Что такое S3 bucket takeover?",
     "options": ["Регистрация удалённого бакета с известным именем",
                 "SQLi в S3",
                 "XSS через CDN",
                 "DDoS на S3"], "answer": "1"},
    {"cat": "cloud",
     "q": "Что проверяет `aws sts get-caller-identity`?",
     "options": ["Текущие AWS credentials",
                 "Список bucket",
                 "IAM users",
                 "MFA status"], "answer": "1"},

    # ─── Red Team ───
    {"cat": "red",
     "q": "Что такое C2?",
     "options": ["Command and Control",
                 "Cyber Config",
                 "Clone Containers",
                 "Cache Coherence"], "answer": "1"},
    {"cat": "red",
     "q": "Что такое beacon jitter?",
     "options": ["Случайный разброс интервалов C2",
                 "Задержка DNS",
                 "Ошибка в TCP",
                 "Тип туннеля"], "answer": "1"},
    {"cat": "red",
     "q": "Что делает AMSI?",
     "options": ["Сканирует скрипты (Windows)",
                 "Шифрует диск",
                 "Проверяет пароль",
                 "Мониторит сеть"], "answer": "1"},
    {"cat": "red",
     "q": "Что такое domain fronting?",
     "options": ["Маскировка C2 через CDN",
                 "Атака на DNS",
                 "DDoS",
                 "MITM"], "answer": "1"},
    {"cat": "red",
     "q": "Что делает reflective loading?",
     "options": ["Загрузка PE в память без диска",
                 "Скачивание файла",
                 "Установка драйвера",
                 "Распаковка ZIP"], "answer": "1"},

    # ─── Forensics ───
    {"cat": "forensics",
     "q": "Что такое IOC?",
     "options": ["Indicator of Compromise",
                 "Input-Output Counter",
                 "Internal Output Cache",
                 "Identity of Certificate"], "answer": "1"},
    {"cat": "forensics",
     "q": "Что делает Volatility?",
     "options": ["Анализ дампов памяти",
                 "Скан портов",
                 "Брутфорс",
                 "Шифрование"], "answer": "1"},
    {"cat": "forensics",
     "q": "Что такое Sysmon?",
     "options": ["Windows-сервис логирования событий",
                 "Linux fire",
                 "Антивирус",
                 "Тип трояна"], "answer": "1"},
    {"cat": "forensics",
     "q": "Что показывает Sysmon EventID 1?",
     "options": ["Process creation", "Network connect",
                 "File create", "Registry change"], "answer": "1"},
    {"cat": "forensics",
     "q": "Что такое YARA?",
     "options": ["Pattern matching для malware",
                 "Монитор сети",
                 "Сканер уязвимостей",
                 "Хеш-функция"], "answer": "1"},

    # ─── General ───
    {"cat": "general",
     "q": "Что такое privilege escalation?",
     "options": ["Повышение прав", "Понижение прав",
                 "Шифрование", "Резервное копирование"], "answer": "1"},
    {"cat": "general",
     "q": "Что такое CVE?",
     "options": ["Common Vulnerabilities and Exposures",
                 "Cyber Vulnerabilities Engine",
                 "Certified Vulnerability Expert",
                 "Central Vulnerability Examiner"], "answer": "1"},
    {"cat": "general",
     "q": "Что такое CVSS?",
     "options": ["Common Vulnerability Scoring System",
                 "Central Vulnerability Score Sheet",
                 "Cyber Vulnerability Score Scale",
                 "Common Verified Security Standard"], "answer": "1"},
    {"cat": "general",
     "q": "Что такое OWASP?",
     "options": ["Open Worldwide Application Security Project",
                 "Open Web Attack Security Protocol",
                 "Organization of Web App Security Providers",
                 "Operational Web App Security Program"], "answer": "1"},
    {"cat": "general",
     "q": "Что такое MITRE ATT&CK?",
     "options": ["База тактик/техник атакующих",
                 "Antivirus",
                 "Сканер портов",
                 "Хеш-функция"], "answer": "1"},
    {"cat": "general",
     "q": "Что такое 0-day?",
     "options": ["Уязвимость без патча",
                 "Публичный эксплойт",
                 "Известная уязвимость",
                 "False positive"], "answer": "1"},
    {"cat": "general",
     "q": "Что такое CTF?",
     "options": ["Capture The Flag",
                 "Computer Technology Framework",
                 "Cyber Threat Feed",
                 "Central Test Facility"], "answer": "1"},
    {"cat": "general",
     "q": "Что такое bug bounty?",
     "options": ["Программа вознаграждения за уязвимости",
                 "Antivirus",
                 "Тип malware",
                 "Протокол"], "answer": "1"},
    {"cat": "general",
     "q": "Что такое pentest?",
     "options": ["Авторизованное тестирование на проникновение",
                 "DoS-атака",
                 "Тип firewall",
                 "Сканер кода"], "answer": "1"},
    {"cat": "general",
     "q": "Что такое red team?",
     "options": ["Команда эмуляции атакующего",
                 "Команда защиты",
                 "Тип сети",
                 "Инцидент-менеджмент"], "answer": "1"},
    {"cat": "general",
     "q": "Что такое blue team?",
     "options": ["Команда защиты и детекта",
                 "Команда атак",
                 "Разработчики",
                 "Legal"], "answer": "1"},
]


# ===========================================================================
# Progress / streak tracking
# ===========================================================================

def _init_progress_schema() -> None:
    """Дополнительная таблица для activity/streak."""
    try:
        cur = db.conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS learning_activity (
                day TEXT PRIMARY KEY,
                topic_count INTEGER DEFAULT 0,
                quiz_count INTEGER DEFAULT 0,
                quiz_score INTEGER DEFAULT 0,
                quiz_total INTEGER DEFAULT 0
            );
        """)
        db.conn.commit()
    except Exception as exc:
        log.warning("learning_activity: %s", exc)


try:
    _init_progress_schema()
except Exception:
    pass


def _mark_activity(kind: str = "topic", score: int = 0,
                    total: int = 0) -> None:
    """Отметить активность за сегодня."""
    day = datetime.now().strftime("%Y-%m-%d")
    try:
        cur = db.conn.cursor()
        cur.execute(
            "INSERT INTO learning_activity(day, topic_count, quiz_count, "
            "quiz_score, quiz_total) VALUES (?, 0, 0, 0, 0) "
            "ON CONFLICT(day) DO NOTHING", (day,))
        if kind == "topic":
            cur.execute(
                "UPDATE learning_activity SET topic_count = "
                "topic_count + 1 WHERE day = ?", (day,))
        elif kind == "quiz":
            cur.execute(
                "UPDATE learning_activity SET quiz_count = quiz_count + 1, "
                "quiz_score = quiz_score + ?, quiz_total = quiz_total + ? "
                "WHERE day = ?", (score, total, day))
        db.conn.commit()
    except Exception:
        pass


def _streak() -> int:
    """Дней подряд с активностью."""
    try:
        cur = db.conn.cursor()
        cur.execute(
            "SELECT day FROM learning_activity ORDER BY day DESC LIMIT 400")
        days = [r["day"] for r in cur.fetchall()]
    except Exception:
        return 0
    if not days:
        return 0
    streak = 0
    today = datetime.now().date()
    for i, d in enumerate(days):
        try:
            dt = datetime.strptime(d, "%Y-%m-%d").date()
        except Exception:
            continue
        expected = today - timedelta(days=i)
        if dt == expected:
            streak += 1
        elif dt == expected + timedelta(days=1) and i == 0:
            # допускаем старт вчера
            continue
        else:
            break
    return streak


def _activity_timeline(days_back: int = 60) -> dict[str, dict]:
    """Timeline активности."""
    try:
        cur = db.conn.cursor()
        cur.execute(
            "SELECT * FROM learning_activity ORDER BY day DESC LIMIT ?",
            (days_back,))
        return {r["day"]: dict(r) for r in cur.fetchall()}
    except Exception:
        return {}


# ===========================================================================
# Show roadmap / resources / certifications
# ===========================================================================

def show_roadmap(level: str | None = None) -> None:
    """Показать Roadmap (все уровни или конкретный)."""
    if level and level in ROADMAP:
        items = ROADMAP[level]
        t = Table(title=f"[bold cyan]{level}[/bold cyan] ({len(items)})")
        t.add_column("#", style="yellow", width=3)
        t.add_column("Тема")
        for i, topic in enumerate(items, 1):
            t.add_row(str(i), topic)
        console.print(t)
        return

    # Все уровни — компактно
    summary = Table(title=f"🗺  Roadmap ({len(ROADMAP)} путей)")
    summary.add_column("Путь", style="cyan")
    summary.add_column("Тем", style="green", width=6)
    summary.add_column("Примеры", style="dim", max_width=60)
    for lvl, items in ROADMAP.items():
        summary.add_row(lvl, str(len(items)),
                         ", ".join(items[:2])[:60])
    console.print(summary)


def show_resources() -> None:
    """Показать ресурсы (40+)."""
    t = Table(title=f"📚 Resources ({len(RESOURCES)})")
    t.add_column("#", style="yellow", width=4)
    t.add_column("Название", style="cyan", max_width=30)
    t.add_column("URL", style="green", max_width=60)
    for i, (name, url) in enumerate(RESOURCES, 1):
        t.add_row(str(i), name, url)
    console.print(t)


def show_certifications() -> None:
    """Показать сертификации."""
    t = Table(title=f"🎓 Certifications ({len(CERTIFICATIONS)})")
    t.add_column("#", style="yellow", width=4)
    t.add_column("Slug", style="cyan", width=28)
    t.add_column("Full name", style="green", max_width=45)
    t.add_column("Level", style="magenta", width=10)
    for i, (slug, full, level, url) in enumerate(CERTIFICATIONS, 1):
        t.add_row(str(i), slug, full, level)
    console.print(t)
    console.print("\n[dim]URL'ы сертификаций — в экспорте (roadmap-export).[/dim]")


# ===========================================================================
# Quiz
# ===========================================================================

def _pick_questions(mode: str = "short",
                    category: str | None = None) -> list[dict]:
    """Выбрать вопросы по режиму/категории."""
    pool = QUIZ
    if category:
        pool = [q for q in pool if q.get("cat") == category]
    if mode == "short":
        return random.sample(pool, min(10, len(pool)))
    if mode == "medium":
        return random.sample(pool, min(25, len(pool)))
    if mode == "full":
        return list(pool)
    return list(pool)


def run_quiz(mode: str = "short",
             category: str | None = None) -> dict:
    """Пройти квиз. Возвращает результат."""
    questions = _pick_questions(mode, category)
    if not questions:
        console.print("[red]Нет вопросов по фильтру.[/red]")
        return {}

    console.print(f"\n[cyan]🧠 Квиз: {len(questions)} вопросов "
                  f"(mode={mode}"
                  + (f", cat={category}" if category else "")
                  + ")[/cyan]")

    score = 0
    for i, q in enumerate(questions, 1):
        console.print(f"\n[bold]Q{i}/{len(questions)}[/bold] "
                      f"[dim][{q.get('cat', '?')}][/dim] {q['q']}")
        for j, opt in enumerate(q["options"], 1):
            console.print(f"  {j}) {opt}")
        ans = Prompt.ask(
            "Ответ",
            choices=[str(x) for x in range(1, len(q["options"]) + 1)],
        )
        if ans == q["answer"]:
            score += 1
            console.print("[green]✓ Верно[/green]")
        else:
            correct = q["options"][int(q["answer"]) - 1]
            console.print(f"[red]✗ Правильно: {q['answer']}) {correct}[/red]")

    total = len(questions)
    pct = round(score / total * 100)
    console.print(f"\n[bold cyan]Итог: {score}/{total} ({pct}%)[/bold cyan]")

    # Уровень
    if pct >= 90:
        console.print("[green]🏆 Отлично! Уровень: продвинутый[/green]")
    elif pct >= 70:
        console.print("[yellow]👍 Хорошо! Продолжай в том же духе[/yellow]")
    elif pct >= 50:
        console.print("[yellow]📚 Норм, но есть куда расти[/yellow]")
    else:
        console.print("[red]📖 Стоит перечитать темы[/red]")

    db.save_scan("quiz", "roadmap",
                 {"score": score, "total": total, "mode": mode,
                  "category": category or "all"})
    _mark_activity("quiz", score, total)

    # Findings при milestone
    if pct >= 90 and total >= 10:
        _save_finding(RoadmapFinding(
            kind="quiz_milestone",
            severity="high",
            title=f"Квиз пройден отлично ({score}/{total})",
            target="roadmap",
            evidence=f"Score: {pct}% | mode={mode} | cat={category or 'all'}",
            data={"score": score, "total": total, "pct": pct},
        ))

    # Notify
    try:
        from modules import notifier
        if pct >= 90:
            notifier.notify_all(
                "🎓 Roadmap: отличный результат!",
                f"Quiz: {score}/{total} ({pct}%)\n"
                f"Mode: {mode}\nCat: {category or 'all'}",
                severity="info")
    except Exception:
        pass

    return {"score": score, "total": total, "pct": pct}


# ===========================================================================
# Progress
# ===========================================================================

def track_progress() -> None:
    """Обновить статус темы."""
    topic = Prompt.ask("Тема")
    if not topic:
        return
    status = Prompt.ask(
        "Статус",
        choices=["todo", "in-progress", "done"],
        default="todo",
    )
    db.set_progress(topic, status)
    console.print(f"[green]✓ {topic} → {status}[/green]")
    _mark_activity("topic")

    # Finding при завершении
    if status == "done":
        _save_finding(RoadmapFinding(
            kind="topic_completed",
            severity="high",
            title=f"Тема завершена: {topic}",
            target="roadmap",
            evidence=f"Status: {status}",
            data={"topic": topic},
        ))


def show_progress() -> None:
    """Показать весь прогресс + streak."""
    data = db.get_progress()
    streak = _streak()
    activity = _activity_timeline(30)

    # Streak
    if streak >= 30:
        console.print(f"[bold green]🔥 Стрик: {streak} дней подряд! "
                      f"Огонь![/bold green]")
    elif streak >= 7:
        console.print(f"[green]🔥 Стрик: {streak} дней[/green]")
    elif streak:
        console.print(f"[yellow]Стрик: {streak} дней[/yellow]")
    else:
        console.print("[dim]Стрик: 0 — начни сегодня![/dim]")

    if not data:
        console.print("[yellow]Прогресс пуст.[/yellow]")
        return

    # По статусам
    counts = Counter(data.values())
    t0 = Table(title=f"📊 Прогресс ({len(data)} тем)")
    t0.add_column("Статус", style="cyan")
    t0.add_column("Кол-во", style="green", width=8)
    for k in ("todo", "in-progress", "done"):
        t0.add_row(k, str(counts.get(k, 0)))
    console.print(t0)

    # По темам
    t = Table(title="Темы")
    t.add_column("Тема", style="cyan", max_width=50)
    t.add_column("Статус", style="green", width=12)
    for k, v in sorted(data.items()):
        color = {"todo": "red", "in-progress": "yellow",
                 "done": "green"}.get(v, "white")
        t.add_row(k, f"[{color}]{v}[/{color}]")
    console.print(t)

    # Timeline
    if activity:
        t2 = Table(title="📅 Активность (30 дней)")
        t2.add_column("День", style="cyan", width=12)
        t2.add_column("Тем", width=5)
        t2.add_column("Квизов", width=7)
        t2.add_column("Ср. очко", width=8)
        for day in sorted(activity.keys(), reverse=True)[:30]:
            a = activity[day]
            avg = (a.get("quiz_score", 0) / a["quiz_total"]
                   if a.get("quiz_total") else 0)
            t2.add_row(day, str(a.get("topic_count", 0)),
                       str(a.get("quiz_count", 0)),
                       f"{avg*100:.0f}%" if avg else "—")
        console.print(t2)


# ===========================================================================
# Export
# ===========================================================================

def export_roadmap(fmt: str = "json",
                   out_path: str | None = None) -> Path | None:
    """Экспорт roadmap + ресурсов + сертификаций + прогресса."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not out_path:
        ext = {"json": ".json", "md": ".md",
               "html": ".html", "csv": ".csv"}.get(fmt, ".json")
        out_path = str(ROADMAP_DIR / f"roadmap_{ts}{ext}")
    path = Path(out_path)

    try:
        if fmt == "json":
            data = {
                "roadmap": ROADMAP,
                "resources": [{"name": n, "url": u} for n, u in RESOURCES],
                "certifications": [
                    {"slug": s, "name": n, "level": l, "url": u}
                    for s, n, l, u in CERTIFICATIONS
                ],
                "progress": db.get_progress(),
                "streak": _streak(),
                "activity": _activity_timeline(90),
                "exported": datetime.now().isoformat(),
            }
            path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8")
        elif fmt == "md":
            lines = [
                "# Roadmap / Learning Path",
                f"_Generated: {datetime.now().isoformat()}_",
                f"_Streak: {_streak()} days_", "",
            ]
            for lvl, items in ROADMAP.items():
                lines.append(f"## {lvl} ({len(items)})")
                for t in items:
                    lines.append(f"- {t}")
                lines.append("")
            lines.append("## Resources")
            for name, url in RESOURCES:
                lines.append(f"- [{name}]({url})")
            lines.append("")
            lines.append("## Certifications")
            lines.append("| Slug | Name | Level | URL |")
            lines.append("|------|------|-------|-----|")
            for slug, full, level, url in CERTIFICATIONS:
                lines.append(f"| {slug} | {full} | {level} | {url} |")
            path.write_text("\n".join(lines), encoding="utf-8")
        elif fmt == "csv":
            with path.open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["type", "level/tag", "name", "url_or_status"])
                for lvl, items in ROADMAP.items():
                    for t in items:
                        w.writerow(["roadmap", lvl, t, "todo"])
                for name, url in RESOURCES:
                    w.writerow(["resource", "", name, url])
                for slug, full, lvl, url in CERTIFICATIONS:
                    w.writerow(["certification", lvl, slug, url])
                for topic, status in db.get_progress().items():
                    w.writerow(["progress", "", topic, status])
        elif fmt == "html":
            parts = [
                "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
                "<title>Roadmap</title>",
                "<style>",
                "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
                "padding:24px;line-height:1.5;max-width:1100px;margin:0 auto;}",
                "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
                "h2{color:#00ff9c;margin-top:32px;}",
                "table{width:100%;border-collapse:collapse;margin-top:12px;"
                "font-size:13px;}",
                "th{background:#111;color:#00ff9c;padding:6px;text-align:left;"
                "border:1px solid #222;}",
                "td{padding:4px 6px;border:1px solid #222;}",
                "tr:nth-child(even){background:#0d0d0d;}",
                "a{color:#7ad9ff;}",
                "code{background:#111;padding:2px 6px;color:#a0ffa0;}",
                "</style></head><body>",
                f"<h1>🎓 Roadmap</h1>",
                f"<p>Streak: <b>{_streak()} дней</b> | "
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
            ]
            for lvl, items in ROADMAP.items():
                parts.append(f"<h2>{html_mod.escape(lvl)} ({len(items)})</h2><ul>")
                for t in items:
                    parts.append(f"<li>{html_mod.escape(t)}</li>")
                parts.append("</ul>")
            parts.append(f"<h2>📚 Resources ({len(RESOURCES)})</h2><table>"
                         "<tr><th>Name</th><th>URL</th></tr>")
            for name, url in RESOURCES:
                parts.append(f"<tr><td>{html_mod.escape(name)}</td>"
                             f"<td><a href='{html_mod.escape(url)}'>"
                             f"{html_mod.escape(url)}</a></td></tr>")
            parts.append("</table>")
            parts.append(f"<h2>🎓 Certifications ({len(CERTIFICATIONS)})</h2>"
                         "<table><tr><th>Slug</th><th>Name</th>"
                         "<th>Level</th><th>URL</th></tr>")
            for slug, full, lvl, url in CERTIFICATIONS:
                parts.append(f"<tr><td><code>{html_mod.escape(slug)}</code></td>"
                             f"<td>{html_mod.escape(full)}</td>"
                             f"<td>{html_mod.escape(lvl)}</td>"
                             f"<td><a href='{html_mod.escape(url)}'>link</a></td>"
                             f"</tr>")
            parts.append("</table></body></html>")
            path.write_text("\n".join(parts), encoding="utf-8")
        else:
            console.print(f"[red]Неизвестный формат: {fmt}[/red]")
            return None
        console.print(f"[green]✓ {fmt.upper()}: {path}[/green]")
        db.save_scan("roadmap_export", fmt, {"path": str(path)})
        return path
    except Exception as exc:
        console.print(f"[red]Ошибка экспорта: {exc}[/red]")
        return None


def reset_progress() -> None:
    """Сбросить весь прогресс обучения."""
    if not Confirm.ask("Удалить ВЕСЬ прогресс обучения?", default=False):
        return
    try:
        cur = db.conn.cursor()
        cur.execute("DELETE FROM progress")
        cur.execute("DELETE FROM learning_activity")
        db.conn.commit()
        console.print("[yellow]Прогресс сброшен.[/yellow]")
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    """Меню Roadmap."""
    table = Table(title="[bold]🎓 Roadmap Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", f"Показать Roadmap ({len(ROADMAP)} путей)"),
        ("2", f"Ресурсы ({len(RESOURCES)})"),
        ("3", f"Сертификации ({len(CERTIFICATIONS)})"),
        ("4", "Квиз — короткий (10 вопросов)"),
        ("5", "Квиз — средний (25)"),
        ("6", "Квиз — полный (все)"),
        ("7", "Квиз по категории"),
        ("8", "Обновить прогресс по теме"),
        ("9", "Показать прогресс + streak"),
        ("10", "📤 Экспорт (json/md/html/csv)"),
        ("11", "🔄 Сбросить прогресс"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        # Выбор уровня или все
        lvl = Prompt.ask(
            "Уровень (Enter = все)",
            choices=[""] + list(ROADMAP.keys()),
            default="",
        ).strip() or None
        show_roadmap(lvl)
    elif c == "2":
        show_resources()
    elif c == "3":
        show_certifications()
    elif c == "4":
        run_quiz("short")
    elif c == "5":
        run_quiz("medium")
    elif c == "6":
        run_quiz("full")
    elif c == "7":
        cats = sorted({q.get("cat", "?") for q in QUIZ})
        cat = Prompt.ask("Категория", choices=cats, default=cats[0])
        mode = Prompt.ask("Режим", choices=["short", "full"],
                          default="short")
        run_quiz(mode, cat)
    elif c == "8":
        track_progress()
    elif c == "9":
        show_progress()
    elif c == "10":
        fmt = Prompt.ask("Формат",
                         choices=["json", "md", "html", "csv"],
                         default="json")
        export_roadmap(fmt)
    elif c == "11":
        reset_progress()


# ===========================================================================
# CLI-обёртки
# ===========================================================================

def cli_roadmap(level: str | None = None) -> None:
    show_roadmap(level)


def cli_resources() -> None:
    show_resources()


def cli_certs() -> None:
    show_certifications()


def cli_quiz(mode: str = "short",
             category: str | None = None) -> None:
    run_quiz(mode, category)


def cli_progress() -> None:
    show_progress()


def cli_export(fmt: str = "json") -> None:
    export_roadmap(fmt)


def cli_streak() -> None:
    s = _streak()
    console.print(f"[cyan]Streak:[/cyan] {s} дней")