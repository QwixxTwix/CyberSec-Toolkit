<div align="center">

```
   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝   ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗   ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║   ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝
                             T O O L K I T
```

**Модульный пентест-тулкит для этичного хакинга, bug bounty и CTF.**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)]()
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()

</div>

---

> ⚠️ **Только для этичного использования.** Собственные системы, bug bounty (в рамках scope), CTF и лаборатории. Несанкционированный доступ преследуется по закону.

---

## ✨ Что внутри

**🔎 Разведка**
WHOIS · DNS · subdomain brute · portscan (TCP/async) · geoip · fingerprint · Shodan · Censys · Google dorks · CVE Feeds (NVD + CISA KEV) · Threat Intel (17 источников) · DNS Tools (AXFR, DNSSEC, SPF/DMARC/DKIM, rebinding)

**⚔ Атаки**
Web (SQLi, XSS, LFI, CSRF, redirect, dirb) · WordPress Scanner · GraphQL/API Discovery · Subdomain Takeover · Web Crawler · Web Fuzzer (ffuf-like) · Payload Factory (XSS/SQLi/LFI/SSRF/CMDi/SSTI) · Network (ARP, sniffer, MITM detector) · Wi-Fi анализ · Pivot Helpers (shells, tunneling, privesc) · Social Engineering (CTF) · HTTP/HTTPS Proxy (MITM) · Shell Manager

**🛠 Инструменты**
Hash cracker · Password generator · Wordlist Tools · Wordlist Updater · Screenshot · Steganography Pro (PNG/WAV + AES-256-GCM) · Password Vault (Fernet) · Notes & Findings

**📊 Отчёты**
Report Templates Pack (HackerOne, Bugcrowd, Intigriti, YesWeHack, Immunefi, CVE) · Auto-Report Pro (HTML/PDF/JSON) · Graph & Statistics (matplotlib) · Bug Bounty Auto-Scan (6-стадийный пайплайн) · Scheduler · Notifier (Telegram/Discord/Email/Desktop) · Telegram Bot

**🎨 Интерфейсы**
CLI с меню · TUI на Textual (тёмная тема) · Плагин-система с hot-reload

---

## 🚀 Установка

### Linux / macOS

```bash
git clone https://github.com/idqwixxa/cyber-toolkit.git
cd cyber-toolkit

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
playwright install chromium

cp .env.example .env
```

### Windows

```cmd
git clone https://github.com/idqwixxa/cyber-toolkit.git
cd cyber-toolkit

python -m venv .venv
.venv\Scripts\activate.bat

pip install -r requirements.txt
playwright install chromium

copy .env.example .env
```

Или просто запусти `start.bat` — он сам всё поставит.

---

## 🎯 Быстрый старт

```bash
# TUI (тёмная тема, меню, hotkeys)
python main.py --tui

# CLI — интерактивное меню
python main.py

# Быстрые команды
python main.py whois example.com
python main.py portscan example.com -p 1-1024
python main.py ti-auto 8.8.8.8
python main.py autoscan-run example.com --profile quick
```

---

## 📖 Примеры команд

```bash
# Разведка
python main.py dns example.com
python main.py subdomain example.com
python main.py asyncscan example.com -p 1-1024

# Web
python main.py headers https://example.com
python main.py sqli "https://example.com?id=1"
python main.py wp-scan https://example.com
python main.py gql-scan https://example.com
python main.py takeover-scan example.com

# DNS
python main.py dns-axfr example.com
python main.py dns-mail example.com
python main.py dns-dnssec example.com

# Threat Intel
python main.py ti-ip 8.8.8.8
python main.py ti-domain example.com
python main.py ti-hash <sha256>

# CVE
python main.py cve-kev-update
python main.py cve-top -d 7 --min-score 7.0

# Утилиты
python main.py hashid 5f4dcc3b5aa765d61d8327deb882cf99
python main.py genpass -l 24
python main.py revshell 10.0.0.1 -p 4444

# Отчёты
python main.py report-pro-html --open
python main.py stats-graphs --open

# Bug Bounty Auto-Scan
python main.py autoscan-run example.com --profile full
```

---

## ⚙️ Конфиг

Все API-ключи **опциональны** — модули работают и без них, используя публичные источники.

```bash
nano .env
```

```env
# Threat Intel
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=
IPQS_API_KEY=

# Basic
SHODAN_API_KEY=
HIBP_API_KEY=
GITHUB_TOKEN=
CENSYS_API_ID=
CENSYS_API_SECRET=

# Telegram bot
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# Уведомления
NOTIFY_ENABLED=false
DISCORD_WEBHOOK_URL=
```

---

## 🧩 Плагины

Просто брось `.py` файл в `plugins/`:

```python
from rich.console import Console

PLUGIN_INFO = {
    "name": "my_plugin",
    "version": "1.0",
    "author": "you",
    "description": "Мой плагин",
}

def hello() -> None:
    Console().print("[green]Hello![/green]")

def echo(target: str) -> None:
    Console().print(f"[cyan]{target}[/cyan]")

ACTIONS = [
    {"name": "hello", "description": "Привет", "func": hello, "arg_hint": "none"},
    {"name": "echo",  "description": "Эхо",   "func": echo,  "arg_hint": "target"},
]
```

```bash
python main.py plugins-reload
python main.py plugin-run my_plugin.hello
```

---

## 🖥 TUI

```bash
python main.py --tui
```

- 📂 Боковое меню: 7 групп модулей
- 🎯 Быстрые действия внизу: выбираешь → вводишь аргумент → `Ctrl+R`
- 📊 Живой статусбар: сканы, CVE, vault, proxy, shell
- 🔄 Hot-reload плагинов кнопкой
- ⌨️ `q` выход · `r` история · `c` очистить

---

## 🔧 Решение проблем

**`playwright: browser not found`**
```bash
playwright install chromium
```

**Scapy: `Permission denied`**
```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))
```

**Telegram-бот не отвечает**
- Проверь `TELEGRAM_BOT_TOKEN`: `python main.py bot-info`
- Напиши боту `/start` в Telegram

---

## 📜 License

MIT © [idqwixxa](https://github.com/idqwixxa)

---

<div align="center">

**Хакинг — это ответственность.**

</div>
