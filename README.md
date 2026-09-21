# 🛡️ CyberSec Toolkit

<div align="center">

```
     ██████╗██╗   ██╗██████╗ ███████╗██████╗ ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
    ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝   ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗   ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║   ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝
```

<img width="1919" height="1030" alt="image" src="https://github.com/user-attachments/assets/e5d5bb24-b426-4919-9606-d987aa9f8939" />

**Модульный пентест-тулкит для этичного хакинга, bug bounty, red team и CTF.**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)]()
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

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
| **Recon** | WHOIS (RDAP fallback + age), DNS enum (A/AAAA/MX/NS/TXT/CAA/SPF/DMARC/DKIM/BIMI), subdomain brute + crt.sh, portscan с баннерами, geoip + ASN, tech fingerprint (40+ techs), Google dorks (50+), Shodan + InternetDB, reverse IP, SSL info, robots/security.txt, HTTP headers |
| **DNS Tools** | AXFR, DNSSEC (DS/DNSKEY/RRSIG/NSEC), wildcard detect, reverse PTR, cache snooping, CNAME chain, SRV, SPF/DMARC/DKIM/BIMI/MTA-STS, DNS rebinding |
| **OSINT** | Username (60+ платформ), HIBP email breach, phone lookup, EXIF extractor (+GPS), GitHub dorks (17 шаблонов) |
| **OSINT Pro** | Username (100+ платформ по категориям), Telegram, Gravatar (+linked accounts), Wayback (sensitive URLs), domain age (RDAP), DNS dump, GitHub/GitLab, email intel, phone intel, reverse image search |
| **Censys** | Поиск хостов, сервисов, сертификатов через Censys API |
| **CVE Feeds** | NVD API 2.0, CISA KEV, EPSS enrichment, OSV query, watch-list, Google dorks под CVE |
| **Threat Intel** | Мульти-API IOC (IP/domain/hash/URL): Shodan IDB, GreyNoise, AbuseIPDB, VirusTotal, OTX, IPQS, URLhaus, MalwareBazaar, ThreatFox, PhishTank, urlscan |
| **Threat Hunting** | Sigma rules (20+), hunt playbooks (12 тактик), MITRE ATT&CK mapping (37 TTPs), Navigator layer |
| **Async Engine** | Быстрый портскан (asyncio), UDP-скан, HTTP-скан URL-списка |

### ⚔️ Web / API

| Модуль | Что делает |
|---|---|
| **Web Vulnerabilities** | Security headers, SSL/TLS, SQLi, XSS, LFI, SSTI, CMDi, NoSQLi, XXE, CRLF, Host-header, open redirect, CORS, CSRF, dir-brute, CMS detect, JWT |
| **WordPress Scanner** | Детект + версия, users, plugins, themes, xmlrpc, REST API, sensitive files, CVE база (40+ плагинов) |
| **GraphQL / API Discovery** | Поиск GraphQL (60+ путей), introspection, Swagger/OpenAPI (25+), REST endpoints, JS-эндпоинты, Apollo/Relay detect |
| **GraphQL Security Suite** | Introspection, suggestions, batching, alias bomb, depth attack, directive abuse, CSRF via GET, rate-limit, mutation fuzz |
| **API Fuzzing Suite** | OpenAPI/Swagger 2.0+3.x, Postman, HAR, auth-bypass, method/content-type confusion, mass assignment, BOLA/IDOR, SSRF, rate-limit, JWT |
| **JS Secrets Scanner** | 130+ паттернов (AWS/GCP/Azure/Stripe/GitHub/Slack/Discord/OpenAI/Anthropic/HuggingFace), entropy detection, валидация |
| **Web Cache Poisoning** | Unkeyed headers (40+), cache deception, parameter cloaking, vary/cache-control, fat GET, method override, host header, smuggling hints |
| **Web Crawler** | HTML/JS/robots/sitemap, sensitive paths, forms, JS endpoints, extract secrets, cloud buckets, admin paths |
| **Web Fuzzer** | Paths, params, headers, cookies, methods, subdomains, vhosts, JSON body + фильтры (status/size/words/regex/time) |
| **Payload Factory** | XSS (33), SQLi (30), NoSQLi (14), LFI (30), SSRF (37), CMDi (33), SSTI (33), LDAP, XPath, XXE, Prototype Pollution, CRLF, GraphQL + кодирование (19) + обход WAF |

### ☁️ Cloud

| Модуль | Что делает |
|---|---|
| **Cloud Storage** | S3 / GCS / Azure / DO / Linode / B2 / Wasabi / Alibaba / R2 / Firebase: public-list/read/write/ACL/policy |
| **Cloud IAM Analyzer** | AWS STS/IAM (25+ permissions, privesc paths), GCP service account, Azure CLI (subscriptions/roles), env vars scan, credential files scan |
| **Cloud Attack Pro** | IMDS chains (AWS/GCP/Azure/DO/Alibaba/OCI/Linode/Hetzner/K8s/Docker/Vault/etcd), 16 AWS privesc, SSRF bypass headers, live AWS chain, SSRF→metadata, dorks, Lambda dump |

### 🏢 AD / K8s / DB

| Модуль | Что делает |
|---|---|
| **AD Attack Suite** | LDAP anon, LDAP enum, password policy, SMB signing, null session, GPP cpassword, Zerologon, PetitPotam, delegation enum, ADCS (ESC1-ESC8), Kerberoasting, AS-REP, DCSync, spray, BloodHound |
| **Kubernetes Scanner** | K8s порты + PaaS (ArgoCD/Rancher/Harbor/Vault/Consul), kube-apiserver anon (RBAC enum), kubelet, etcd, Docker API, container escape checks, CVE KB |
| **Container Escape** | Runtime detect (docker/containerd/CRI-O/podman/K8s/LXC), capabilities (41), namespaces, seccomp, AppArmor/SELinux, sockets, host mounts, cgroup, eBPF, 14 kernel CVE |
| **Database Attack** | MongoDB, Redis, Elasticsearch, Memcached, CouchDB, Cassandra, Neo4j, InfluxDB, ClickHouse, ArangoDB, Solr, RabbitMQ + SQLMap launcher + NoSQL payloads + hydra |

### 📡 Сеть / Wireless

| Модуль | Что делает |
|---|---|
| **Network** | Интерфейсы, ARP-скан (vendor lookup), SYN/FIN/XMAS/NULL/ACK scan, packet sniffer (HTTP/DNS/creds), MITM detector, DNS-spoof detector, Wi-Fi analyzer, MITM simulator |
| **Wireless Toolkit** | Кроссплатформенный Wi-Fi анализ: SSID/BSSID/channel/signal/vendor, evil-twin, открытые сети, слабые шифры, каналы (2.4/5/6), karma, multi-scan |
| **Wireless Attack Helper** | 18 инструментов, WPA workflow, PMKID, WPS-PIN, WPA3-Transition, evil-twin lab (hostapd + dnsmasq + captive portal), deauth-detector |
| **Wireless Attack Pro** | WPA3 SAE, PMKID v2, KARMA/MANA, Pixie Dust, deauth + beacon flood, EAPHammer, FragAttacks, Wifite |
| **Packet Analysis** | PCAP/PCAPNG: credentials, HTTP, DNS + tunneling, TLS SNI, ARP-spoof, beaconing, top talkers |

### ⚔️ Red Team

| Модуль | Что делает |
|---|---|
| **Pivot / Post-Exploit** | 40+ reverse/bind shells, TTY stabilization, file transfer (25+), pivoting (SSH/socat/chisel/ligolo/sshuttle/dnscat2/rpivot/gost), Linux privesc (60+), Windows privesc (40+), container escape, cloud metadata, cred dump, persistence, payload encoding |
| **Red Team C2** | 15 фреймворков (Sliver/Havoc/Mythic/Cobalt Strike/Metasploit/Empire/Covenant/PoshC2/Merlin/NimPlant/Villain/Caldera), MSFVenom (15 категорий), 12 payload generators, 6 listeners, infrastructure (redirectors, domain fronting), defense evasion (AMSI/ETW/injection), OpSec, MITRE mapping |
| **Shell Manager** | Multi-session TCP listener + REPL, autorecon, автопарсинг артефактов, asciinema-запись, upload/download, broadcast |
| **Shell Listener Pro** | Multi-session + auto-reconnect, persistence, payload generator, labels/tags, TTY auto-upgrade (10+), asciinema |
| **Adversary Emulation** | 60+ TTPs по 14 тактикам MITRE ATT&CK, atomic-style проверки, detection advice |

### 🎯 Bug Bounty

| Модуль | Что делает |
|---|---|
| **Bug Bounty Toolkit** | CVSS v3.1 (base+temporal+env), 13 пресетов уязвимостей, 6 шаблонов платформ (H1/Bugcrowd/Intigriti/YesWeHack/Immunefi/CVE), quality-checker |
| **Auto-Scan** | 6-стадийный пайплайн: subs → ports → http → hints → screenshots → report (checkpoint/resume) |
| **Autopilot** | 13 стадий: subs → live → tech → ports → takeover → dir brute → wayback → JS secrets → JS endpoints → CORS → GraphQL → findings → report |
| **Report Templates Pack** | 12 шаблонов платформ, 35+ пресетов уязвимостей, CVSS v3.1 full, wizard, quality-check, bulk export, timeline |
| **Report Export** | HTML (TOC, фильтры, timeline), PDF, CSV, MD, JSON |
| **Auto-Report Pro** | Единый отчёт (scans + findings + notes + CVEs + screenshots + graphs), executive summary, timeline, methodology, diff |

### 🎭 Social / SSRF / Web3 / Mobile

| Модуль | Что делает |
|---|---|
| **Social Engineering** | 15+ phishing-шаблонов, telemetry server, 15+ email-шаблонов (.eml + SMTP), 11 SMS, 5 vishing-скриптов, QR (12 типов), website clone, URL obfuscation (20+), tracking pixel |
| **SSRF Pro** | Cloud metadata (20+ провайдеров), IP bypass (decimal/octal/hex/IPv6/NAT64/6to4/nip.io), scheme payloads (gopher/dict/file/ftp/ldap/jar/netdoc), parser confusion, DNS rebinding, blind helpers, SSRF→RCE chains |
| **Web3 Security** | Solidity static analysis (35+ паттернов), ERC20/721/1155 detect, proxy (EIP-1967/1822/UUPS), multi-chain (10 сетей), private keys (12 типов), honeypot heuristics, drainer patterns |
| **Mobile Security** | APK (manifest, permissions, exported components, deeplinks, DEX IOC, 130+ secrets, NSC, pinning) / IPA (Info.plist, ATS, entitlements, frameworks) |
| **Reverse Engineering** | Magic-детект (60+), Shannon entropy (+graph), strings (ASCII + UTF-16), 25+ IOC patterns, PE parser (sections, DLLs, imphash, PDB, packers), ELF, Mach-O, YARA (18 rules), shellcode, miner, ransomware |
| **Forensics & IR** | IOC extractor (40+ паттернов), timeline, Sysmon XML (26 EventIDs), auth.log, auditd, browser history, hash verification, YARA |

### 🛠️ Инструменты

| Модуль | Что делает |
|---|---|
| **Passwords & Hashes** | Hash identifier (65+), cracker, mask-cracker, strength analyzer, generator, passphrase, L33t, wordlist generator |
| **Hash Cracking Suite** | 90+ типов хешей, built-in cracker, wordlist, mask, combinator, 16 типов rules, hashcat, john, hcxpcapngtool, aircrack |
| **Password Vault** | AES-256 + PBKDF2-200k, history, audit log, health-check (weak/reused/old), password generator, экспорт encrypted/JSON/CSV/HTML |
| **HTTP/HTTPS Proxy** | MITM с собственным CA, HTTP/1.1 keep-alive, chunked, gzip/deflate/br, правила (replace/add-header/remove-header/drop/inject-body), SQLite logging, HAR export |
| **Steganography Pro** | PNG (LSB 1/2/4) / WAV / FLAC, AES-256-GCM, zlib/lzma, Chi-square, RS-анализ, Sample-Pair Analysis |
| **Utils** | Encoder/Decoder (30+), AES, XOR, шифры (Caesar/Vigenère/Atbash/Rail fence), hashes файлов, reverse shell, LSB-stego |
| **Screenshot** | Playwright (chromium/firefox/webkit), viewports (7), full-page/element/PDF, wait-стратегии, batch, multi-viewport, compare |
| **Wordlist Updater** | 50+ источников (SecLists/PayloadsAllTheThings/fuzzdb), параллельная загрузка, integrity check, dedup |
| **Wordlist Tools** | Генерация (leet, регистр, суффиксы, годы), mask, hashcat rules (16), combinator, stats, crack-time |

### 📊 Notes / Автоматизация

| Модуль | Что делает |
|---|---|
| **Notes & Findings** | FTS5-поиск, теги, related notes, timeline, bulk-операции, wizard с пресетами, экспорт MD/JSON/CSV/HTML/Kanban |
| **Graph & Statistics** | Текстовая сводка + аномалии, PNG-графики (timeline/top modules/targets/hourly/pie/severity/heatmap/cumulative/dashboard), HTML-dashboard |
| **Scheduler** | 40+ actions, расписание (interval/daily/weekly/cron/one-shot), retry, SQLite history, dry-run, pause/resume |
| **Notifier** | 14 каналов (Telegram/Discord/Slack/Mattermost/Rocket.Chat/Teams/Gotify/ntfy/Pushover/PagerDuty/Email/Webhook/Syslog/Desktop) |
| **Telegram Bot** | Управление из чата (/dns, /whois, /portscan, /screenshot, ...), whitelist |

### 📋 Compliance / SDK / Обучение

| Модуль | Что делает |
|---|---|
| **Compliance & Audit** | CIS Linux (80+ live checks), CIS Docker, OWASP Top 10, ASVS 4.0, PCI-DSS 4.0, ISO 27001, NIST 800-53 |
| **Plugin SDK** | 7 шаблонов (basic/network/web/crypto/forensics/recon/custom), генерация + валидация |
| **Roadmap** | 7 путей (Junior/Middle/Senior/Expert/Red Team/Blue Team/Web Deep), 40+ ресурсов, 18 сертификаций, квиз (60+ вопросов), progress tracker |

---

## 🚀 Установка

### Требования

- **Python 3.10+**
- **pip** и **venv**
- Linux / macOS / Windows

### Linux / macOS

```bash
git clone https://github.com/QwixxTwix/CyberSec-Toolkit.git
cd CyberSec-Toolkit

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
playwright install chromium

cp .env.example .env
```

### Windows

```cmd
git clone https://github.com/QwixxTwix/CyberSec-Toolkit.git
cd CyberSec-Toolkit

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
python main.py ap-run example.com --profile full
```

---

## 🖥️ Интерфейсы

### CLI

Интерактивное меню из 120+ пунктов, разбитых по категориям. Каждая команда доступна и напрямую:

```bash
python main.py <command> [args]
```

Полный список команд — `python main.py --help` или в разделе [Команды CLI](#-команды-cli).

### TUI (Textual)

```bash
python main.py --tui
```

**Возможности:**
- 📂 **Боковое меню** — 13 групп модулей (Разведка, Web/API, Cloud, AD/K8s/DB, Сеть/Wireless, Red Team, Bug Bounty, Social/SSRF/Web3, Пароли, Инструменты, Notes, Compliance, Плагины, Обучение)
- 🎯 **Быстрые действия** — селект внизу: выбираешь модуль → вводишь аргумент → `Ctrl+R`
- 📊 **Живой статусбар** — сканы, CVE, vault, notes, findings, plugins, proxy, shell
- 🔄 **Hot-reload плагинов** — кнопка «Reload plugins»
- ⌨️ **Hotkeys:**
  - `q` — выход
  - `r` — история сканов
  - `c` — очистить лог
  - `Ctrl+R` — запустить выбранное действие
  - `Ctrl+P` — command palette
  - `Ctrl+L` / `Esc` — фокус на поле аргумента

---

## 📖 Команды CLI

<details>
<summary><b>🔎 Recon / DNS / OSINT</b></summary>

| Команда | Описание |
|---|---|
| `whois <target>` | WHOIS lookup |
| `dns <target>` | DNS enumeration |
| `subdomain <target>` | Subdomain brute-force |
| `portscan <target> [-p 1-1024]` | TCP port scan |
| `geoip <target>` | IP geolocation + reverse DNS |
| `fingerprint <url>` | Tech fingerprint |
| `dork <domain>` | Google dork-генератор |
| `shodan <query>` | Shodan lookup |
| `censys <query>` | Censys search |
| `asyncscan <target>` | Async portscan |
| `asyncweb <url>` | Async HTTP-скан |
| `dns-axfr <domain>` | Zone Transfer |
| `dns-dnssec <domain>` | DNSSEC |
| `dns-wildcard <domain>` | Wildcard detection |
| `dns-ptr <cidr>` | Reverse PTR scan |
| `dns-snoop <domain>` | DNS cache snooping |
| `dns-cname <domain>` | CNAME chain |
| `dns-srv <domain>` | SRV enumeration |
| `dns-mail <domain>` | SPF / DMARC / DKIM |
| `dns-rebinding <domain>` | DNS rebinding |
| `username <user>` | OSINT: username |
| `hibp <email>` | OSINT: HIBP |
| `phone <phone>` | OSINT: phone |
| `exif <path>` | OSINT: EXIF |
| `ghdork <query>` | OSINT: GitHub dorks |
| `osint-pro` | OSINT Pro меню |
| `op-username <user>` | OSINT Pro: username (100+) |
| `op-telegram <user>` | OSINT Pro: Telegram |
| `op-gravatar <email>` | OSINT Pro: Gravatar |
| `op-wayback <domain>` | OSINT Pro: Wayback |
| `op-age <domain>` | OSINT Pro: domain age |
| `op-dns <domain>` | OSINT Pro: DNS dump |
| `op-github <user>` | OSINT Pro: GitHub |
| `op-email <email>` | OSINT Pro: email |
| `op-image <url>` | OSINT Pro: reverse image |

</details>

<details>
<summary><b>📡 CVE / Threat Intel / Threat Hunting</b></summary>

| Команда | Описание |
|---|---|
| `cve` | CVE Feeds меню |
| `cve-download [-k keyword] [-d days]` | Скачать CVE из NVD |
| `cve-search <keyword> [--min-score 7.0]` | Поиск в кеше |
| `cve-top [-d 7]` | Топ свежих критичных |
| `cve-kev [-n 100]` | CISA KEV |
| `cve-kev-update` | Обновить KEV |
| `cve-show <cve-id>` | Детали CVE |
| `cve-dorks <product>` | Google dorks под CVE |
| `cve-stats` | Статистика кеша |
| `ti` | Threat Intel меню |
| `ti-ip <ip>` | Проверить IP |
| `ti-domain <domain>` | Проверить домен |
| `ti-hash <hash>` | Проверить хеш |
| `ti-url <url>` | Проверить URL |
| `ti-auto <ioc>` | Авто-детект IOC |
| `ti-bulk <file>` | Массовая проверка |
| `ti-sources` | Статус источников |
| `ti-cache` | Статистика кэша |
| `hunting` | Threat Hunting меню |
| `hunting-sigma` | Sigma rules |
| `hunting-playbooks` | Hunt playbooks |
| `hunting-mitre` | MITRE ATT&CK mapping |
| `hunting-export-navigator` | Navigator layer |
| `hunting-export-dashboard` | HTML dashboard |

</details>

<details>
<summary><b>🌐 Web / API</b></summary>

| Команда | Описание |
|---|---|
| `headers <url>` | Security headers analysis |
| `ssl <host>` | SSL/TLS checker |
| `sqli <url>` | Error-based SQLi |
| `xss <url>` | Reflected XSS |
| `lfi <url>` | LFI detector |
| `dirb <url>` | Directory brute-force |
| `cms <url>` | CMS detection |
| `redirect <url>` | Open redirect |
| `csrf <url>` | CSRF check |
| `crawl <url> [-d 1]` | Web crawler |
| `fuzz <mode> <url>` | Web fuzzer |
| `screenshot <url>` | Playwright-скриншот |
| `wp` | WordPress Scanner меню |
| `wp-scan <url> [--aggressive]` | WP полный скан |
| `wp-detect <url>` | WP детект версии |
| `wp-users <url>` | WP пользователи |
| `wp-plugins <url>` | WP плагины |
| `wp-xmlrpc <url>` | WP xmlrpc |
| `wp-vulns <url>` | WP уязвимости |
| `wp-rest <url>` | WP REST probes |
| `gql` | GraphQL Discovery меню |
| `gql-scan <url>` | GraphQL + API полный скан |
| `gql-discover <url>` | GraphQL endpoint'ы |
| `gql-introspect <endpoint>` | Introspection |
| `api-swagger <url>` | Swagger / OpenAPI |
| `api-rest <url>` | REST endpoints |
| `api-js <url>` | API-URL в JS |
| `gql-sec` | GraphQL Security Suite меню |
| `gql-sec-scan <endpoint>` | GQLSec полный скан |
| `gql-sec-introspect <endpoint>` | GQLSec introspection |
| `gql-sec-suggest <endpoint>` | GQLSec suggestions |
| `gql-sec-batch <endpoint>` | GQLSec batching |
| `gql-sec-alias <endpoint>` | GQLSec alias bomb |
| `gql-sec-csrf <endpoint>` | GQLSec CSRF |
| `api-fuzz` | API Fuzzing Suite меню |
| `api-fuzz-scan <spec>` | API полный скан |
| `api-fuzz-ratelimit <url>` | Rate-limit test |
| `api-fuzz-graphql <url>` | GraphQL scan |
| `api-fuzz-bola <base> <ep>` | BOLA/IDOR |
| `secrets` | JS Secrets Scanner меню |
| `secrets-scan <url> [--validate]` | Скан URL на секреты |
| `secrets-js <url>` | Скан одного JS |
| `cache-poison` | Web Cache Poisoning меню |
| `cache-scan <url>` | Cache full scan |
| `cache-unkeyed <url>` | Unkeyed headers |
| `cache-deception <url>` | Cache deception |
| `cache-vary <url>` | Vary/cache-control |
| `cache-fat <url>` | Fat GET |
| `cache-param <url>` | Parameter cloaking |
| `cache-host <url>` | Host-header injection |
| `payload <kind>` | Payload generator (xss/sqli/lfi/ssrf/cmdi/ssti) |

</details>

<details>
<summary><b>☁️ Cloud / AD / K8s / DB</b></summary>

| Команда | Описание |
|---|---|
| `cloud` | Cloud Storage меню |
| `cloud-scan <domain>` | Cloud S3 scan |
| `cloud-all <domain>` | Cloud все провайдеры |
| `cloud-check <name>` | Один бакет |
| `cloud-batch <src>` | Batch бакетов |
| `cloud-azure <account>` | Azure blob |
| `cloud-providers` | Провайдеры |
| `cloud-iam` | Cloud IAM меню |
| `cloud-iam-aws` | AWS аудит |
| `cloud-iam-gcp` | GCP аудит |
| `cloud-iam-azure` | Azure аудит |
| `cloud-iam-env` | Env scan |
| `cloud-iam-files` | Files scan |
| `cloud-iam-full` | Full audit |
| `cap` | Cloud Attack Pro меню |
| `cap-imds` | IMDS chains |
| `cap-privesc` | AWS privesc |
| `cap-ssrf-headers` | SSRF headers |
| `cap-aws-chain <ak> <sk>` | AWS cred chain |
| `cap-metadata-ssrf <url>` | SSRF→metadata |
| `cap-dorks <org>` | Secret dorks |
| `cap-lambda` | Lambda dump |
| `cap-ip-bypass` | IP bypass variants |
| `ad` | AD Attack меню |
| `ad-tools` | AD tools |
| `ad-cheatsheets` | AD cheatsheets |
| `ad-cheat <name>` | AD cheat-sheet |
| `ad-smb-signing <dc>` | SMB signing |
| `ad-ldap-anon <dc>` | LDAP anon |
| `ad-null-session <dc>` | NULL session |
| `k8s` | K8s Scanner меню |
| `k8s-scan <host>` | K8s full scan |
| `k8s-api <host>` | K8s API |
| `k8s-etcd <host>` | K8s etcd |
| `k8s-docker <host>` | K8s Docker API |
| `k8s-escape` | Container escape checks |
| `k8s-ports` | K8s ports list |
| `k8s-cve-kb` | K8s CVE KB |
| `escape` | Container Escape меню |
| `escape-scan` | Container escape scan |
| `escape-cves` | Kernel CVEs list |
| `escape-cve <cve>` | CVE details |
| `escape-caps` | Capabilities |
| `db` | DB Attack меню |
| `db-scan <host>` | DB scan |
| `db-mongo <host>` | MongoDB |
| `db-redis <host>` | Redis |
| `db-es <host>` | Elasticsearch |
| `db-sqlmap <url>` | SQLMap launcher |
| `db-payloads [kind]` | NoSQL payloads |
| `db-ports` | DB ports list |

</details>

<details>
<summary><b>📡 Сеть / Wireless</b></summary>

| Команда | Описание |
|---|---|
| `network` | Network Analysis меню |
| `wifi` | Wireless Toolkit меню |
| `wifi-scan` | Wi-Fi scan |
| `wifi-full` | Wi-Fi полный анализ |
| `wifi-evil` | Evil twin detector |
| `wifi-open` | Открытые сети |
| `wifi-weak` | WEP / WPA1 |
| `wifi-channels` | Загруженность каналов |
| `wifi-top` | Топ по силе |
| `wifi-export-csv` / `json` / `html` | Экспорт |
| `wl-tools` | Wireless Attack tools |
| `wl-ifaces` | Wireless interfaces |
| `wl-wpa` | WPA workflow |
| `wl-pmkid` | PMKID workflow |
| `wl-wps` | WPS workflow |
| `wl-evil` | Evil-twin lab |
| `wl-deauth` | Deauth workflow |
| `wl-pro` | Wireless Attack Pro меню |
| `wl-pro-tools` | WLPro tools |
| `wl-pro-cheatsheets` | WLPro cheatsheets |
| `wl-pro-cheat <name>` | WLPro cheat |
| `wl-pro-export-all` | WLPro export all |
| `pcap-analyze <path>` | PCAP analysis |
| `pcap-html` / `csv` / `md` / `all` | PCAP export |

</details>

<details>
<summary><b>⚔️ Red Team</b></summary>

| Команда | Описание |
|---|---|
| `pivot` | Pivot меню |
| `pivot-reverse` | Reverse shells |
| `pivot-bind` | Bind shells |
| `pivot-tty` | TTY upgrade |
| `pivot-transfer` | File transfer |
| `pivot-tunnel` | Tunneling |
| `pivot-linux` | Linux privesc |
| `pivot-windows` | Windows privesc |
| `pivot-encode` | Payload encoding |
| `pivot-container` | Container escape |
| `pivot-cloud` | Cloud metadata |
| `pivot-cred-dump` | Credential dump |
| `pivot-persistence` | Persistence |
| `c2` | Red Team C2 меню |
| `c2-sheets` | C2 cheat-sheets |
| `c2-sliver` / `havoc` / `mythic` | C2 фреймворки |
| `c2-msfvenom <lh> <lp>` | MSFVenom payloads |
| `c2-donut` | Donut |
| `c2-opsec` | OpSec |
| `c2-generators` | Payload generators |
| `c2-listeners` | Listeners |
| `c2-infra` | Infrastructure |
| `c2-evasion` | Defense evasion |
| `c2-mitre` | MITRE mapping |
| `shell` | Shell Manager REPL |
| `shell-status` / `list` / `start` / `stop` | Shell controls |
| `shell-pro` | Shell Listener Pro REPL |
| `shell-pro-linux` / `win` / `quiet` | ShellPro variants |
| `shell-pro-help` | ShellPro help |
| `shell-pro-shortcuts` | ShellPro shortcuts |
| `adv` | Adversary Emulation меню |
| `adv-list` | TTPs list |
| `adv-tactic <tactic>` | TTPs по тактике |
| `adv-platform <platform>` | TTPs по платформе |
| `adv-detail <ttp_id>` | TTP детали |
| `adv-tactics` | Покрытие тактик |
| `adv-export-json` / `md` / `navigator` | Экспорт |

</details>

<details>
<summary><b>🎯 Bug Bounty / Reports</b></summary>

| Команда | Описание |
|---|---|
| `bugbounty` | Bug Bounty меню |
| `autoscan` | Auto-Scan меню |
| `autoscan-run <domain> --profile quick/full/deep` | Auto-scan |
| `autoscan-profiles` | Профили |
| `autoscan-past` | История |
| `ap` | Autopilot меню |
| `ap-run <domain> --profile quick/full/deep` | Autopilot |
| `ap-profiles` / `ap-past` | Профили / история |
| `report-pack` | Report Pack меню |
| `rp-new [--platform]` | Новый отчёт |
| `rp-preset <preset>` | Отчёт из пресета |
| `rp-from-finding <id>` | Из finding |
| `rp-bulk [-t target]` | Bulk |
| `rp-platforms` / `presets` / `list` | Списки |
| `rp-cvss "<vector>"` | CVSS калькулятор |
| `rp-timeline` | Timeline |
| `export-html` / `pdf` / `csv` / `md` / `json` | Экспорт истории |
| `report-pro` | Auto-Report Pro меню |
| `report-pro-html` / `pdf` / `json` / `md` / `diff` | Auto-Report |
| `stats` | Текстовая статистика |
| `stats-graphs [--open]` | Графики |

</details>

<details>
<summary><b>🎭 Social / SSRF / Web3 / Mobile / RE / Forensics</b></summary>

| Команда | Описание |
|---|---|
| `se` | Social Engineering меню |
| `se-templates` | Шаблоны |
| `se-phish <template>` | Phish-страница |
| `se-server [-p 8000]` | Telemetry server |
| `se-qr <data>` | QR-код |
| `se-qr-menu` | QR-меню |
| `se-email <template>` | Email шаблон |
| `se-sms <template>` | SMS шаблон |
| `se-voice <name>` | Vishing скрипт |
| `se-clone <url>` | Website clone |
| `se-obfuscate <url>` | URL obfuscation |
| `se-pixel` | Tracking pixel |
| `ssrf` | SSRF Pro меню |
| `ssrf-cloud` | Cloud metadata |
| `ssrf-ip` | IP bypasses |
| `ssrf-schemes` | Scheme payloads |
| `ssrf-parser` | Parser confusion |
| `ssrf-rebind` | DNS rebinding |
| `ssrf-blind` | Blind helpers |
| `ssrf-chains` | SSRF→RCE chains |
| `ssrf-export-all` | Export all |
| `web3` | Web3 Security меню |
| `web3-solidity <path>` | Solidity scan |
| `web3-dir <path>` | Directory scan |
| `web3-pk <path>` | Private keys scan |
| `web3-etherscan <addr>` | Etherscan lookup |
| `web3-honeypot <addr>` | Honeypot check |
| `web3-drainer <path>` | Drainer patterns |
| `mobile` | Mobile Security меню |
| `mobile-analyze <path>` | Auto-detect + scan |
| `mobile-apk <path>` | APK scan |
| `mobile-ipa <path>` | IPA scan |
| `re` | RE меню |
| `re-analyze <path>` | Full RE analysis |
| `re-strings <path>` | Strings + IOC |
| `re-entropy <path>` | Entropy |
| `re-yara <path>` | YARA scan |
| `re-pe` / `elf` / `macho` | PE/ELF/Mach-O |
| `re-shellcode <path>` | Shellcode |
| `re-miner <path>` | Miner |
| `forensics` | Forensics меню |
| `forensics-ioc <path>` | IOC extractor |
| `forensics-timeline <path>` | Timeline |
| `forensics-sysmon <path>` | Sysmon XML |
| `forensics-authlog` | auth.log |
| `forensics-auditd` | auditd |
| `forensics-yara <path>` | YARA |
| `forensics-browser` | Browser history |

</details>

<details>
<summary><b>🔐 Пароли / Vault</b></summary>

| Команда | Описание |
|---|---|
| `hashid <hash>` | Identify hash |
| `crack <hash>` | Dictionary attack |
| `genpass [-l 16]` | Генератор |
| `hs` | Hash Suite меню |
| `hs-tools` | HS tools |
| `hs-identify <hash>` | HS identify |
| `hs-crack <hash>` | HS crack |
| `hs-mask <hash> <mask>` | HS mask |
| `hs-file <file>` | HS file crack |
| `vault` | Vault меню |
| `vault-init` | Создать vault |
| `vault-status` | Статус |
| `vault-add <title>` | Добавить |
| `vault-list` | Список |
| `vault-get <title>` | Показать |
| `vault-search <query>` | Поиск |
| `vault-del <title>` | Удалить |
| `vault-export <path>` | Экспорт |
| `vault-import <path>` | Импорт |
| `vault-change-master` | Смена мастера |

</details>

<details>
<summary><b>🛠️ Инструменты / Автоматизация</b></summary>

| Команда | Описание |
|---|---|
| `proxy` | HTTP/HTTPS Proxy меню |
| `proxy-start [-p 8080]` | MITM-прокси |
| `proxy-status` / `ca` / `rules` | Прокси статус |
| `proxy-rule-add ...` | Добавить правило |
| `stego` | Steganography меню |
| `stego-chi-png <path>` | Chi-square PNG |
| `stego-chi-wav <path>` | Chi-square WAV |
| `stego-rs` / `spa` / `capacity` | RS/SPA/capacity |
| `utils` | Утилиты меню |
| `b64encode` / `b64decode` | Base64 |
| `filehash <path>` | File hashes |
| `revshell <lhost>` | Reverse shell |
| `wordlists-update` | Обновить словари |
| `wordlist-gen <word>` | Генератор словаря |
| `notes` | Notes меню |
| `note-add` / `finding-add` | Добавить |
| `note-list` / `show` / `edit` / `del` / `search` | CRUD |
| `findings-export` | Экспорт findings |
| `stats` | Статистика |
| `scheduler` | Планировщик |
| `scheduler-list` / `run` / `pause` / `resume` / `history` | Управление |
| `notify` | Notifier меню |
| `notify-status` / `test` / `history` | Каналы |
| `bot` / `bot-info` / `bot-start` / `bot-stop` | Telegram Bot |
| `audit` | Compliance меню |
| `audit-cis` / `owasp` / `asvs` / `pci` / `iso` / `nist` / `all` / `live` | Audit |
| `sdk` | Plugin SDK меню |
| `sdk-list` / `validate` / `docs` / `templates` / `generate <name>` | SDK |
| `plugins` / `plugins-menu` / `plugins-reload` / `plugin-run <key>` | Плагины |
| `roadmap` | Roadmap меню |
| `roadmap-show` / `resources` / `certs` / `quiz` / `progress` / `export` / `streak` | Roadmap |

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
NOTIFY_MIN_SEVERITY=info
NOTIFY_MODULES=
NOTIFY_QUIET_HOURS=
NOTIFY_RATE_LIMIT=60
NOTIFY_DEDUP_TTL=300

# ─── Telegram ───
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
BOT_EXTRA_USERS=

# ─── Discord / Slack / Email / ... ───
DISCORD_WEBHOOK_URL=
SLACK_WEBHOOK_URL=
MATTERMOST_WEBHOOK_URL=
ROCKETCHAT_WEBHOOK_URL=
TEAMS_WEBHOOK_URL=
GOTIFY_URL= GOTIFY_TOKEN=
NTFY_URL= NTFY_TOPIC=
PUSHOVER_TOKEN= PUSHOVER_USER=
PAGERDUTY_ROUTING_KEY=
GENERIC_WEBHOOK_URL= GENERIC_WEBHOOK_SECRET=
SYSLOG_HOST= SYSLOG_PORT=514

# ─── SMTP ───
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

В TUI плагины появятся в группе **🧩 Плагины** (кнопка **🔄 Reload plugins** перечитывает их на лету). Шаблон — `plugins/_template.py`.

**Доступные `arg_hint`:** `none`, `target`, `url`, `host`, `domain`, `hash`, `path`, `query`, `username`, `email`, `phone`, `ip`, `sha`, `network`, `word`.

**7 готовых шаблонов:**
- `basic` — hello-world
- `network` — скан портов
- `web` — HTTP/headers/links
- `crypto` — хеширование / кодирование
- `forensics` — IOC analysis
- `recon` — внешний recon (DNS/whois)
- `custom` — пустой скелет

Генерация через Plugin SDK: `python main.py sdk-generate my_plugin --template web`.

---

## 📁 Структура проекта

```text
CyberSec-Toolkit/
├── core/                          # Ядро: БД, конфиг, логгер, баннер
├── modules/                       # 70+ модулей (см. таблицу ниже)
├── plugins/                       # Плагины (hot-reload, шаблон _template.py)
├── tui/                           # Textual TUI (app, runner, widgets)
├── utils/                         # Хелперы (сеть, кодирование, файлы)
├── tests/                         # Тесты
├── wordlists/                     # Словари для брута / фаззинга
├── reports/                       # Генерируемые отчёты (gitignored)
├── logs/                          # Логи (gitignored)
├── .env.example                   # Пример конфига
├── .gitignore
├── CONTRIBUTING.md
├── Dockerfile
├── LICENSE                        # MIT
├── README.md
├── check_files.py                 # Проверка целостности структуры
├── cyber_toolkit.db               # SQLite (сканы, findings, vault, CVE)
├── fix_plugin_actions.py          # Утилита для плагинов
├── main.py                        # Точка входа (CLI / TUI)
├── requirements.txt
├── schedule.yaml                  # Конфиг планировщика
├── start.bat                      # Запуск на Windows (CLI)
└── start_tui.bat                  # Запуск TUI на Windows
```

### Структура `modules/`

| Файл | Назначение |
|---|---|
| `recon.py` | WHOIS / DNS / subdomain / portscan / geoip / tech / dorks |
| `dns_tools.py` | AXFR / DNSSEC / PTR / SPF / DMARC / rebinding |
| `osint.py` | Username (60+) / HIBP / phone / EXIF / GitHub dorks |
| `osint_pro.py` | Username (100+) / Telegram / Gravatar / Wayback / RDAP / DNS dump |
| `censys_lookup.py` | Censys hosts / certificates |
| `cve_feeds.py` | NVD + CISA KEV + EPSS + OSV |
| `threat_intel.py` | 17 источников IOC |
| `threat_hunting.py` | Sigma + playbooks + MITRE |
| `async_engine.py` | Async portscan / HTTP / UDP |
| `subdomain_takeover.py` | Takeover v1 (60 сервисов) |
| `subdomain_takeover_v2.py` | Takeover v2 (150 сервисов) |
| `subdomain_monitor.py` | Watch-list + diff + alerts |
| `web_vuln.py` | SQLi / XSS / LFI / SSTI / CMDi / NoSQLi / XXE / CRLF / CORS / CSRF |
| `wordpress_scanner.py` | WP deep scan |
| `graphql_discovery.py` | GraphQL / Swagger / REST / JS |
| `graphql_security.py` | GQL introspection / batching / DoS |
| `api_fuzzer.py` | OpenAPI / Postman / HAR + advanced tests |
| `js_secrets.py` | 130+ patterns + validation |
| `cache_poisoning.py` | Unkeyed / deception / cloaking / smuggling |
| `web_crawler.py` | Full crawler (12+ sources) |
| `web_fuzzer.py` | ffuf-like async fuzzer |
| `payload_factory.py` | 250+ payloads + encoding + WAF bypass |
| `cloud_storage.py` | S3 / GCS / Azure / DO / Linode / B2 / ... |
| `cloud_iam.py` | AWS / GCP / Azure IAM audit |
| `cloud_attack_pro.py` | IMDS chains / SSRF / AWS privesc |
| `ad_attack.py` | AD full attack suite |
| `k8s_scanner.py` | Kubernetes scanner |
| `container_escape.py` | Container escape checks |
| `db_attack.py` | MongoDB / Redis / ES / ... |
| `network.py` | ARP / sniff / MITM / Wi-Fi |
| `wireless_toolkit.py` | Wi-Fi analyzer |
| `wireless_attack.py` | WPA / PMKID / WPS workflows |
| `wireless_attack_pro.py` | WPA3 / KARMA / FragAttacks |
| `pcap_analysis.py` | PCAP parser + credentials + DNS tunnel |
| `pivot_helper.py` | Reverse shells + privesc + tunneling |
| `redteam_c2.py` | 15 C2 frameworks + evasion |
| `shell_manager.py` | Shell listener + REPL |
| `shell_listener_pro.py` | Multi-session shell listener |
| `adversary_emulation.py` | MITRE ATT&CK TTPs |
| `bugbounty.py` | CVSS / reports / templates |
| `bugbounty_autoscan.py` | Auto-scan pipeline |
| `bugbounty_autopilot.py` | 13-stage autopilot |
| `report_pack.py` | Platform templates pack |
| `report_export.py` | HTML / PDF / CSV / MD export |
| `auto_report.py` | Auto-Report Pro |
| `social_engineer.py` | Phishing / email / SMS / voice / QR / clone |
| `ssrf_pro.py` | SSRF payloads + RCE chains |
| `web3_security.py` | Solidity + private keys + drainers |
| `mobile_security.py` | APK / IPA analysis |
| `re_suite.py` | Reverse engineering toolkit |
| `forensics_ir.py` | IOC / timeline / Sysmon / auth.log |
| `passwords.py` | Hash ID / crack / strength / gen |
| `hash_suite.py` | 90+ hash types + rules |
| `vault.py` | Encrypted password vault |
| `http_proxy.py` | MITM HTTP/HTTPS proxy |
| `stego_pro.py` | PNG/WAV stego + steganalysis |
| `utils_tools.py` | Encoder / AES / XOR / ciphers |
| `screenshot.py` | Playwright screenshots |
| `wordlist_updater.py` | SecLists downloader |
| `wordlist_tools.py` | Wordlist generator |
| `notes.py` | Notes & Findings |
| `stats.py` | Statistics + graphs |
| `scheduler.py` | Cron-like scheduler |
| `notifier.py` | 14 notification channels |
| `telegram_bot.py` | Telegram control bot |
| `compliance_audit.py` | CIS / OWASP / PCI / ISO / NIST |
| `plugin_sdk.py` | Plugin generator |
| `roadmap.py` | Learning path / quiz |
| `jwt_suite.py` | JWT attacks |

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

**Wireless-модули не работают на Windows**
- Большинство wireless-инструментов работают только на Linux (Kali/Parrot)
- Используй WSL2 или Kali VM с проброшенным USB Wi-Fi адаптером
- Нужен адаптер с поддержкой monitor mode + injection

---

## 📜 License

MIT © [QwixxTwix](https://github.com/QwixxTwix)

См. [LICENSE](LICENSE).

---

<div align="center">

**Хакинг — это ответственность.**

_Если проект оказался полезен — поставь ⭐ на GitHub._

</div>
