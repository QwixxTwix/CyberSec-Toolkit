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

<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/3bee9317-030a-4246-b906-563dba1b03a0" />

**Модульный пентест-тулкит для этичного хакинга, bug bounty и CTF.**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)]()
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()

</div>

---

> ⚠️ **Только для этичного использования.** Собственные системы, bug bounty (в рамках scope), CTF и лаборатории. Несанкционированный доступ преследуется по закону.

---

## 📑 Содержание

- [Возможности](#-возможности)
- [Установка](#-установка)
- [Быстрый старт](#-быстрый-старт)
- [Интерфейсы](#-интерфейсы)
- [Команды CLI](#-команды-cli)
- [Конфигурация](#️-конфигурация)
- [Плагины](#-плагины)
- [Структура проекта](#-структура-проекта)
- [Решение проблем](#-решение-проблем)
- [License](#-license)

---

## ✨ Возможности

### 🔎 Разведка
| Модуль | Что делает |
|---|---|
| **Recon** | WHOIS, DNS enumeration, subdomain brute-force, portscan (TCP + async), geoip, tech fingerprint, Google dorks, Shodan |
| **DNS Tools** | Zone transfer (AXFR), DNSSEC (DS/DNSKEY/RRSIG), wildcard detection, reverse PTR, cache snooping, CNAME chain, SRV, SPF/DMARC/DKIM, DNS rebinding |
| **OSINT** | Username check (14 платформ), HIBP, phone lookup, EXIF extractor, GitHub dorks |
| **Censys** | Поиск хостов, сервисов, сертификатов |
| **CVE Feeds** | NVD API 2.0, CISA KEV, Google dork-генератор для CVE |
| **Threat Intel** | 17 источников: Shodan IDB, GreyNoise, AbuseIPDB, VirusTotal, OTX, IPQS, URLhaus, MalwareBazaar, ThreatFox, PhishTank + единый verdict |
| **Async Engine** | Портскан и HTTP-скан на asyncio (в 5–10× быстрее ThreadPool) |

### ⚔ Атаки
| Модуль | Что делает |
|---|---|
| **Web Vulnerabilities** | Security headers, SSL/TLS, SQLi, XSS, LFI, dir-brute, CMS detect, open redirect, CSRF |
| **WordPress Scanner** | Детект, версия, users, plugins, themes, xmlrpc, REST API + мини-база CVE |
| **GraphQL / API Discovery** | Introspection, suggestions attack, Swagger/OpenAPI, REST enumeration, JS endpoints |
| **Subdomain Takeover** | 30+ сервисов (GitHub Pages, S3, Heroku, Azure, Netlify, Vercel, Cloudflare и др.) |
| **Web Crawler** | Формы, параметры, cookies, JS-эндпоинты |
| **Web Fuzzer** | ffuf-like: параметры, директории, заголовки |
| **Payload Factory** | XSS/SQLi/LFI/SSRF/CMDi/SSTI + encoding (URL, hex, base64) + обход WAF |
| **Network** | ARP-scan, sniffer, MITM detector, DNS-spoof detector, Wi-Fi analyzer |
| **Wireless Toolkit** | Wi-Fi скан (netsh/nmcli/iw), evil twin detector, открытые сети, слабые шифры, анализ каналов |
| **Pivot / Post-Exploit** | Reverse/bind shells (15+), TTY upgrade, file transfer, tunneling (SSH/socat/chisel/ligolo), Linux/Windows privesc checklists |
| **Social Engineering** | Фишинг-шаблоны, QR, email/SMS шаблоны, клонирование страниц, обфускация URL |
| **HTTP/HTTPS Proxy** | MITM с собственным CA + правила модификации запросов/ответов |
| **Shell Manager** | TCP listener + REPL для reverse-shell сессий |

### 🛠 Инструменты
| Модуль | Что делает |
|---|---|
| **Passwords & Hashes** | Hash identifier, dictionary cracker, mask-cracker, strength analyzer, generator |
| **Wordlist Tools** | Генератор (leet, регистр, суффиксы, годы, комбинации) |
| **Wordlist Updater** | Автоматическое скачивание SecLists с GitHub |
| **Screenshot** | Playwright-скриншоты страниц |
| **Steganography Pro** | PNG/WAV + AES-256-GCM + chi-square анализ |
| **Password Vault** | Шифрованное хранилище (PBKDF2-SHA256 200k → Fernet) |
| **Notes & Findings** | Заметки/находки, severity, статусы, теги, экспорт в MD |

### 📊 Отчёты и автоматизация
| Модуль | Что делает |
|---|---|
| **Report Templates Pack** | 6 платформ (HackerOne, Bugcrowd, Intigriti, YesWeHack, Immunefi, CVE) × 13 пресетов уязвимостей + CVSS v3.1 калькулятор |
| **Auto-Report Pro** | Единый HTML/PDF/JSON отчёт со сканами, findings, графиками и скриншотами |
| **Graph & Statistics** | matplotlib: timeline, top-модули, top-цели, часы, pie, dashboard 2×2 |
| **Bug Bounty Auto-Scan** | 6-стадийный пайплайн: subs → ports → http → hints → screenshots → report |
| **Scheduler** | YAML-планировщик задач с уведомлениями |
| **Notifier** | Telegram, Discord, Email (SMTP), Desktop |
| **Telegram Bot** | Управление сканами из чата (17 команд + whitelist) |

---

## 🚀 Установка

### Требования

- **Python 3.10+**
- **pip** и **venv**
- Linux / macOS / Windows

### Linux / macOS

```bash
git clone https://github.com/idqwixxa/cyber-toolkit.git
cd cyber-toolkit

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
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

pip install --upgrade pip
pip install -r requirements.txt
playwright install chromium

copy .env.example .env
```

Либо просто запусти **`start.bat`** — он сам установит зависимости и создаст `.env`.

### Scapy на Linux (для ARP / sniffer)

Запускай от `root` **или** выдай capability Python-интерпретатору:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))
```

---

## 🎯 Быстрый старт

```bash
# TUI — тёмная тема, меню, hotkeys
python main.py --tui

# CLI — интерактивное меню
python main.py

# Отдельные команды
python main.py whois example.com
python main.py portscan example.com -p 1-1024
python main.py ti-auto 8.8.8.8
python main.py autoscan-run example.com --profile quick
```

---

## 🖥 Интерфейсы

### CLI

Интерактивное меню из 40+ пунктов, разбитых по категориям. Каждая команда доступна и напрямую:

```bash
python main.py <command> [args]
```

Полный список команд — `python main.py --help` или в разделе [Команды CLI](#-команды-cli).

### TUI (Textual)

```bash
python main.py --tui
```

**Возможности:**
- 📂 **Боковое меню** — 7 групп модулей (Разведка, Атаки, Инструменты, Хранилище, Отчёты, Плагины, Обучение)
- 🎯 **Быстрые действия** — селект внизу: выбираешь модуль → вводишь аргумент → `Ctrl+R`
- 📊 **Живой статусбар** — количество сканов, CVE в БД, статус vault, notes, proxy, shell
- 🔄 **Hot-reload плагинов** — кнопка «Reload plugins»
- ⌨️ **Hotkeys:**
  - `q` — выход
  - `r` — история сканов
  - `c` — очистить лог
  - `Ctrl+R` — запустить выбранное действие
  - `Ctrl+P` — command palette
  - `Esc` — фокус на поле ввода аргумента

---

## 📖 Команды CLI

<details>
<summary><b>🔎 Recon</b></summary>

| Команда | Описание |
|---|---|
| `whois <target>` | WHOIS lookup |
| `dns <target>` | DNS enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA) |
| `subdomain <target>` | Subdomain brute-force по словарю |
| `portscan <target> [-p 1-1024]` | TCP port scan с баннерами |
| `geoip <target>` | IP geolocation + reverse DNS |
| `fingerprint <url>` | Tech fingerprint (WordPress, React, Cloudflare и др.) |
| `dork <domain>` | Google dork-генератор |
| `shodan <query>` | Shodan lookup |
| `censys <query>` | Censys search |
| `asyncscan <target> [-p ...] [-c 500]` | Async portscan (быстрее в 5–10×) |
| `asyncweb <url> [-P paths]` | Async HTTP-скан набора путей |

</details>

<details>
<summary><b>🌍 DNS Tools</b></summary>

| Команда | Описание |
|---|---|
| `dns-axfr <domain>` | Zone Transfer |
| `dns-dnssec <domain>` | DNSSEC (DS, DNSKEY, RRSIG) |
| `dns-wildcard <domain>` | Wildcard detection |
| `dns-ptr <cidr>` | Reverse PTR scan |
| `dns-snoop <domain>` | DNS cache snooping |
| `dns-cname <domain>` | CNAME chain |
| `dns-srv <domain>` | SRV enumeration |
| `dns-mail <domain>` | SPF / DMARC / DKIM |
| `dns-rebinding <domain>` | DNS rebinding detection |

</details>

<details>
<summary><b>⚔ Web Vulnerabilities</b></summary>

| Команда | Описание |
|---|---|
| `headers <url>` | Security headers analysis |
| `ssl <host>` | SSL/TLS checker |
| `sqli <url>` | Error-based SQLi scan |
| `xss <url>` | Reflected XSS scan |
| `lfi <url>` | LFI detector |
| `dirb <url>` | Directory brute-force |
| `cms <url>` | CMS detection (WordPress, Joomla, Drupal) |
| `redirect <url>` | Open redirect detection |
| `csrf <url>` | CSRF token check |
| `crawl <url> [-d 1] [-m 50]` | Web crawler |
| `fuzz paths\|params\|headers <url>` | Web fuzzer (ffuf-like) |
| `screenshot <url>` | Playwright-скриншот |

</details>

<details>
<summary><b>🔍 WordPress Scanner</b></summary>

| Команда | Описание |
|---|---|
| `wp` | Интерактивное меню |
| `wp-scan <url> [--aggressive]` | Полный скан (детект, версия, users, plugins, themes, xmlrpc, REST, CVE) |
| `wp-detect <url>` | Только детект версии |
| `wp-users <url>` | Перечисление пользователей |
| `wp-plugins <url>` | Перечисление плагинов |
| `wp-xmlrpc <url>` | Проверка xmlrpc.php |
| `wp-vulns <url>` | Известные уязвимости по версии и плагинам |

</details>

<details>
<summary><b>🔎 GraphQL / API Discovery</b></summary>

| Команда | Описание |
|---|---|
| `gql` | Интерактивное меню |
| `gql-scan <url>` | Полный скан (GraphQL + Swagger + REST + JS) |
| `gql-discover <url>` | Поиск GraphQL endpoint'ов |
| `gql-introspect <endpoint>` | Introspection конкретного endpoint'а |
| `api-swagger <url>` | Поиск Swagger / OpenAPI |
| `api-rest <url>` | REST endpoint enumeration |
| `api-js <url>` | Поиск API-URL в JS/HTML |

</details>

<details>
<summary><b>🎯 Subdomain Takeover</b></summary>

| Команда | Описание |
|---|---|
| `takeover` | Интерактивное меню |
| `takeover-scan <domain>` | Брут по словарю + проверка takeover |
| `takeover-check <subdomain>` | Проверить один поддомен |
| `takeover-batch <file>` | Проверить список (файл или через запятую) |
| `takeover-services` | Показать базу сервисов |

</details>

<details>
<summary><b>📡 CVE Feeds</b></summary>

| Команда | Описание |
|---|---|
| `cve` | Интерактивное меню |
| `cve-download [-k keyword] [-d days] [-n max]` | Скачать CVE из NVD |
| `cve-search <keyword> [--min-score 7.0] [--kev]` | Поиск в кеше |
| `cve-top [-d 7] [--min-score 7.0]` | Топ свежих критичных |
| `cve-kev [-n 100]` | Список CISA KEV |
| `cve-kev-update` | Обновить базу KEV |
| `cve-show <cve-id>` | Детали CVE |
| `cve-dorks <product> [--version X] [--cve-id Y]` | Google dorks для CVE |
| `cve-stats` | Статистика кеша |

</details>

<details>
<summary><b>🟡 Threat Intelligence</b></summary>

| Команда | Описание |
|---|---|
| `ti` | Интерактивное меню |
| `ti-ip <ip>` | Проверить IP (6 источников) |
| `ti-domain <domain>` | Проверить домен (4 источника) |
| `ti-hash <hash>` | Проверить хеш (4 источника) |
| `ti-url <url>` | Проверить URL (3 источника) |
| `ti-auto <ioc>` | Авто-детект типа IOC |
| `ti-bulk <file> [-t 4]` | Массовая проверка |
| `ti-sources` | Статус источников (какие ключи заданы) |

</details>

<details>
<summary><b>🔐 Passwords & Vault</b></summary>

| Команда | Описание |
|---|---|
| `hashid <hash>` | Identify hash type |
| `crack <hash>` | Dictionary attack |
| `genpass [-l 16]` | Генерация пароля |
| `vault` | Интерактивное меню |
| `vault-init` | Создать vault |
| `vault-status` | Статус vault |
| `vault-add <title> [-g]` | Добавить запись (генерация пароля) |
| `vault-list` | Список записей |
| `vault-get <title>` | Показать запись |
| `vault-search <query>` | Поиск |
| `vault-del <title>` | Удалить |
| `vault-export <path>` | Экспорт (шифрованный) |
| `vault-import <path>` | Импорт |
| `vault-change-master` | Сменить мастер-пароль |

</details>

<details>
<summary><b>📝 Notes & Findings</b></summary>

| Команда | Описание |
|---|---|
| `notes` | Интерактивное меню |
| `note-add <title> [-b body] [-t target]` | Добавить заметку |
| `finding-add <title> -t <target> -s <sev>` | Добавить находку |
| `note-list [--kind finding]` | Список |
| `note-show <id>` | Показать |
| `note-edit <id>` | Редактировать |
| `note-del <id>` | Удалить |
| `note-search <query>` | Поиск |
| `findings-export [-t target] [-o out]` | Экспорт в Markdown |
| `note-stats` | Статистика |

</details>

<details>
<summary><b>📊 Отчёты</b></summary>

| Команда | Описание |
|---|---|
| `report-pro` | Auto-Report Pro — интерактивное меню |
| `report-pro-html [--template hackerone]` | HTML-отчёт |
| `report-pro-pdf [--template bugcrowd]` | PDF-отчёт |
| `report-pro-json` | JSON-экспорт |
| `export-html [-n 500]` | История → HTML |
| `export-pdf [-n 300]` | История → PDF |
| `stats` | Текстовая статистика |
| `stats-graphs [--open]` | Построить все графики |

</details>

<details>
<summary><b>📝 Report Templates Pack</b></summary>

| Команда | Описание |
|---|---|
| `report-pack` | Интерактивное меню |
| `rp-new [--platform hackerone]` | Новый отчёт (wizard) |
| `rp-preset <preset> [--platform ...]` | Отчёт из пресета |
| `rp-from-finding <id>` | Отчёт из finding |
| `rp-bulk [-t target]` | Bulk: все findings → отчёты |
| `rp-platforms` | Список платформ |
| `rp-presets` | Список пресетов уязвимостей |
| `rp-cvss "<vector>"` | CVSS вектор → score |
| `rp-list` | Список сохранённых отчётов |

**Пресеты:** `xss-stored`, `xss-reflected`, `sqli`, `ssrf`, `idor`, `rce`, `auth-bypass`, `subdomain-takeover`, `open-redirect`, `csrf`, `xxe`, `race-condition`, `business-logic`, `info-disclosure`.

</details>

<details>
<summary><b>🟢 Bug Bounty Auto-Scan</b></summary>

| Команда | Описание |
|---|---|
| `autoscan` | Интерактивное меню |
| `autoscan-run <domain> --profile quick` | 500 subs, top-100 ports (~1–3 мин) |
| `autoscan-run <domain> --profile full` | 5000 subs, top-1000 ports (~5–15 мин) |
| `autoscan-run <domain> --profile deep` | 20000 subs + hints (~20+ мин) |
| `autoscan-run <domain> --skip subs,ports` | Пропустить стадии |
| `autoscan-profiles` | Показать профили |
| `autoscan-past` | Прошлые сканы |

**Стадии пайплайна:** `subs` → `ports` → `http` → `hints` → `screenshots` → `report`.

</details>

<details>
<summary><b>🎭 Social Engineering (CTF)</b></summary>

| Команда | Описание |
|---|---|
| `se` | Интерактивное меню |
| `se-templates` | Список всех шаблонов |
| `se-phish <template> [-o out]` | Сгенерировать HTML-страницу |
| `se-server [-p 8000]` | Телеметрийный сервер |
| `se-qr <data>` | QR-код генератор |
| `se-email <template>` | Email шаблон (.eml) |
| `se-sms <template>` | SMS шаблон |
| `se-clone <url>` | Клонировать веб-страницу |
| `se-obfuscate <url>` | Обфускация URL (decimal-ip, punycode, @-trick) |
| `se-pixel` | Tracking pixel |

</details>

<details>
<summary><b>🔀 Pivot / Post-Exploitation</b></summary>

| Команда | Описание |
|---|---|
| `pivot` | Интерактивное меню |
| `pivot-reverse [-l LHOST] [-p LPORT]` | Reverse shells (bash, python, nc, php, perl, powershell) |
| `pivot-bind [-p LPORT]` | Bind shells |
| `pivot-tty` | TTY upgrade (python PTY, script, socat) |
| `pivot-transfer [-l LHOST]` | File transfer (base64, nc, socat, certutil, SMB) |
| `pivot-tunnel [-l LHOST] [-t TARGET]` | Tunneling (SSH -L/-R/-D, chisel, ligolo, sshuttle) |
| `pivot-linux [-t TARGET]` | Linux privesc checklists |
| `pivot-windows [-l LHOST]` | Windows privesc checklists |
| `pivot-encode` | Payload encoding (base64, PowerShell, gzip) |

</details>

<details>
<summary><b>🌐 Proxy / Shell / Bot</b></summary>

| Команда | Описание |
|---|---|
| `proxy` | Интерактивное меню |
| `proxy-start [-p 8080] [--no-mitm]` | Запустить MITM-прокси |
| `proxy-status` | Статус |
| `proxy-ca` | Инфо о CA |
| `proxy-rules` | Список правил |
| `proxy-rule-add <target> <action> <match>` | Добавить правило |
| `proxy-rules-clear` | Очистить правила |
| `shell` | Shell Manager REPL |
| `shell-start [-H host] [-p 4444]` | Запустить listener |
| `shell-list` | Список сессий |
| `shell-stop` | Остановить |
| `bot` | Telegram-бот (foreground) |
| `bot-info` | Инфо о боте |

</details>

<details>
<summary><b>🛠 Утилиты</b></summary>

| Команда | Описание |
|---|---|
| `b64encode <text>` / `b64decode <text>` | Base64 |
| `filehash <path>` | MD5 + SHA-256 файла |
| `revshell <lhost> [-p 4444]` | Reverse shell one-liners |
| `stego-pro` | Steganography Pro — интерактивное меню |
| `stego-chi-png <path>` | Chi-square анализ PNG |
| `stego-chi-wav <path>` | Chi-square анализ WAV |
| `plugins` | Список плагинов |
| `plugins-menu` | Интерактивное меню плагинов |
| `plugins-reload` | Hot-reload |
| `plugin-run <key> [arg]` | Запустить действие плагина |
| `scheduler-list` | Показать задачи |
| `scheduler-run` | Запустить планировщик |
| `notify-status` | Статус каналов |
| `notify-test` | Тест всех каналов |

</details>

<details>
<summary><b>📶 Wireless Toolkit</b></summary>

| Команда | Описание |
|---|---|
| `wifi` | Интерактивное меню |
| `wifi-scan` | Сканировать Wi-Fi |
| `wifi-full` | Полный анализ (evil twin, открытые, слабые, каналы) |
| `wifi-evil` | Детектор evil twin |
| `wifi-open` | Открытые сети |
| `wifi-weak` | WEP / WPA1 |
| `wifi-channels` | Загруженность каналов |
| `wifi-top` | Топ по силе сигнала |
| `wifi-export-csv` / `wifi-export-json` | Экспорт |

</details>

---

## ⚙️ Конфигурация

Все API-ключи **опциональны** — модули работают и без них, используя публичные источники.

```bash
cp .env.example .env
nano .env
```

```env
# ─── Базовые ───
SHODAN_API_KEY=
HIBP_API_KEY=
GITHUB_TOKEN=
CENSYS_API_ID=
CENSYS_API_SECRET=

# ─── Threat Intel ───
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
IPQS_API_KEY=
GREYNOISE_API_KEY=
OTX_API_KEY=
URLSCAN_API_KEY=
PHISHTANK_APP_KEY=
NVD_API_KEY=

# ─── Сеть ───
REQUEST_TIMEOUT=10
MAX_THREADS=100

# ─── Уведомления ───
NOTIFY_ENABLED=false

TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
BOT_EXTRA_USERS=

DISCORD_WEBHOOK_URL=

SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
SMTP_FROM=
SMTP_TO=
```

### Где взять ключи

| Сервис | Ссылка |
|---|---|
| Shodan | https://account.shodan.io/ |
| HIBP | https://haveibeenpwned.com/API/Key |
| GitHub | https://github.com/settings/tokens (scope: `public_repo`) |
| Censys | https://search.censys.io/account/api |
| VirusTotal | https://www.virustotal.com/gui/my-apikey |
| AbuseIPDB | https://www.abuseipdb.com/account/api |
| IPQualityScore | https://www.ipqualityscore.com/user/settings |
| GreyNoise | https://viz.greynoise.io/account |
| AlienVault OTX | https://otx.alienvault.com/settings |
| NVD | https://nvd.nist.gov/developers/request-an-api-key |
| Telegram Bot | https://t.me/BotFather |

---

## 🧩 Плагины

Просто брось `.py` файл в `plugins/`:

```python
from rich.console import Console
from core.database import db

PLUGIN_INFO = {
    "name": "my_plugin",
    "version": "1.0",
    "author": "you",
    "description": "Мой плагин",
}

def hello() -> None:
    Console().print("[green]Hello![/green]")
    db.save_scan("plugin", "my_plugin.hello", {})

def echo(target: str) -> None:
    Console().print(f"[cyan]Получено: {target}[/cyan]")

ACTIONS = [
    {"name": "hello", "description": "Привет", "func": hello, "arg_hint": "none"},
    {"name": "echo",  "description": "Эхо",   "func": echo,  "arg_hint": "target"},
]
```

```bash
python main.py plugins-reload
python main.py plugin-run my_plugin.hello
python main.py plugin-run my_plugin.echo "test"
```

В TUI плагины появятся в группе **🧩 Плагины**. Шаблон — `plugins/_template.py`.

**Доступные `arg_hint`:** `none`, `target`, `url`, `host`, `domain`, `hash`, `path`, `query`, `username`, `email`, `phone`, `ip`, `sha`, `network`, `word`.

---

## 🔧 Решение проблем

**`ModuleNotFoundError: textual`**
```bash
pip install -r requirements.txt
```

**`playwright: browser not found`**
```bash
playwright install chromium
```

**Scapy: `Permission denied`**
```bash
sudo python main.py network
# или
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))
```

**`dns.resolver.NoNameservers`**
```bash
echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf
```

**Telegram-бот не отвечает**
- Проверь токен: `python main.py bot-info`
- Убедись, что написал боту `/start` в Telegram
- Твой `chat_id` должен быть в `TELEGRAM_CHAT_ID` или в списке `/users`

**TUI не открывается (Windows)**
- Запусти через `start_tui.bat` — он открывает максимизированное окно
- Или вручную: `chcp 65001` → `python main.py --tui`

**Отчёты не сохраняются**
- Проверь права на папку `reports/`
- Папки `logs/`, `reports/`, `wordlists/` создаются автоматически

---

## 📜 License

MIT © [idqwixxa](https://github.com/idqwixxa)

См. [LICENSE](LICENSE).

---

<div align="center">

**Хакинг — это ответственность.**

</div>
