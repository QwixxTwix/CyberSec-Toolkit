"""
Главное Textual-приложение CyberSec Toolkit.
Author: idqwixxa
"""
import os
import sys

# ─── Расширяем ширину Rich-консолей до импорта модулей ───
# Иначе Console определяет width=80 (т.к. stdout не TTY) и таблицы ломаются.
os.environ.setdefault("COLUMNS", "150")
os.environ.setdefault("LINES", "60")

import importlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import (
    Container, Horizontal, Vertical, ScrollableContainer,
)
from textual.widgets import (
    Header, Footer, Button, RichLog, Label, Input, Select,
)
from textual.reactive import reactive
from rich.text import Text

from core.banner import TUI_BANNER, DISCLAIMER, AUTHOR, VERSION
from core.config import config
from core.database import db
from core.logger import get_logger
from tui.runner import run_module_async

log = get_logger(__name__)


# ============================================================================
# _LazyModule
# ============================================================================

class _LazyModule:
    def __init__(self, module_name: str) -> None:
        self._module_name = module_name
        self._module = None

    def _load(self):
        if self._module is None:
            self._module = importlib.import_module(self._module_name)
        return self._module

    def __getattr__(self, name: str):
        return getattr(self._load(), name)


# ============================================================================
# Lazy-модули (все)
# ============================================================================

recon               = _LazyModule("modules.recon")
web_vuln            = _LazyModule("modules.web_vuln")
passwords           = _LazyModule("modules.passwords")
osint               = _LazyModule("modules.osint")
network             = _LazyModule("modules.network")
bugbounty           = _LazyModule("modules.bugbounty")
roadmap             = _LazyModule("modules.roadmap")
utils_tools         = _LazyModule("modules.utils_tools")
censys_lookup       = _LazyModule("modules.censys_lookup")
async_engine        = _LazyModule("modules.async_engine")
wordlist_updater    = _LazyModule("modules.wordlist_updater")
screenshot          = _LazyModule("modules.screenshot")
report_export       = _LazyModule("modules.report_export")
scheduler           = _LazyModule("modules.scheduler")
notifier            = _LazyModule("modules.notifier")
stego_pro           = _LazyModule("modules.stego_pro")
wordlist_tools      = _LazyModule("modules.wordlist_tools")
payload_factory     = _LazyModule("modules.payload_factory")
web_crawler         = _LazyModule("modules.web_crawler")
telegram_bot        = _LazyModule("modules.telegram_bot")
web_fuzzer          = _LazyModule("modules.web_fuzzer")
stats               = _LazyModule("modules.stats")
vault               = _LazyModule("modules.vault")
notes               = _LazyModule("modules.notes")
auto_report         = _LazyModule("modules.auto_report")
http_proxy          = _LazyModule("modules.http_proxy")
shell_manager       = _LazyModule("modules.shell_manager")
dns_tools           = _LazyModule("modules.dns_tools")
subdomain_takeover  = _LazyModule("modules.subdomain_takeover")
subdomain_takeover_v2 = _LazyModule("modules.subdomain_takeover_v2")
subdomain_monitor   = _LazyModule("modules.subdomain_monitor")
osint_pro           = _LazyModule("modules.osint_pro")
cve_feeds           = _LazyModule("modules.cve_feeds")
threat_intel        = _LazyModule("modules.threat_intel")
threat_hunting      = _LazyModule("modules.threat_hunting")
wordpress_scanner   = _LazyModule("modules.wordpress_scanner")
graphql_discovery   = _LazyModule("modules.graphql_discovery")
graphql_security    = _LazyModule("modules.graphql_security")
api_fuzzer          = _LazyModule("modules.api_fuzzer")
js_secrets          = _LazyModule("modules.js_secrets")
cache_poisoning     = _LazyModule("modules.cache_poisoning")
cloud_storage       = _LazyModule("modules.cloud_storage")
cloud_iam           = _LazyModule("modules.cloud_iam")
cloud_attack_pro    = _LazyModule("modules.cloud_attack_pro")
ad_attack           = _LazyModule("modules.ad_attack")
k8s_scanner         = _LazyModule("modules.k8s_scanner")
container_escape    = _LazyModule("modules.container_escape")
db_attack           = _LazyModule("modules.db_attack")
wireless_toolkit    = _LazyModule("modules.wireless_toolkit")
wireless_attack     = _LazyModule("modules.wireless_attack")
wireless_attack_pro = _LazyModule("modules.wireless_attack_pro")
pivot_helper        = _LazyModule("modules.pivot_helper")
redteam_c2          = _LazyModule("modules.redteam_c2")
shell_listener_pro  = _LazyModule("modules.shell_listener_pro")
adversary_emulation = _LazyModule("modules.adversary_emulation")
bugbounty_autoscan  = _LazyModule("modules.bugbounty_autoscan")
bugbounty_autopilot = _LazyModule("modules.bugbounty_autopilot")
report_pack         = _LazyModule("modules.report_pack")
social_engineer     = _LazyModule("modules.social_engineer")
ssrf_pro            = _LazyModule("modules.ssrf_pro")
hash_suite          = _LazyModule("modules.hash_suite")
pcap_analysis       = _LazyModule("modules.pcap_analysis")
forensics_ir        = _LazyModule("modules.forensics_ir")
re_suite            = _LazyModule("modules.re_suite")
mobile_security     = _LazyModule("modules.mobile_security")
web3_security       = _LazyModule("modules.web3_security")
compliance_audit    = _LazyModule("modules.compliance_audit")
plugin_sdk          = _LazyModule("modules.plugin_sdk")
plugin_loader       = _LazyModule("core.plugin_loader")


# ============================================================================
# ПРОКСИ-КЛАССЫ
# ============================================================================

class _ActionProxy:
    def __init__(self, func):
        self.run = func

    def __getattr__(self, name):
        if name == "run":
            return self.run
        raise AttributeError(name)


def _tui_findings_view() -> None:
    from rich.console import Console
    from rich.table import Table
    c = Console()
    try:
        findings = notes.list_notes(kind="finding")
    except Exception as exc:  # noqa: BLE001
        c.print(f"[red]Ошибка: {exc}[/red]")
        return
    if not findings:
        c.print("[yellow]Находок нет.[/yellow]")
        return
    t = Table(title=f"🔴 Findings ({len(findings)})")
    t.add_column("ID", style="cyan", width=5)
    t.add_column("Sev", style="red", width=9)
    t.add_column("Status", style="magenta", width=12)
    t.add_column("Target", style="green", max_width=30)
    t.add_column("Title", style="white", max_width=50)
    for f in findings:
        t.add_row(str(f["id"]),
                  (f.get("severity") or "—").upper(),
                  f.get("status") or "—",
                  (f.get("target") or "—")[:30],
                  (f.get("title") or "")[:50])
    c.print(t)


class _FindingsProxy:
    def __init__(self):
        self.run = _tui_findings_view


# ============================================================================
# MODULE_GROUPS (все модули)
# ============================================================================

MODULE_GROUPS = [
    ("🔎 Разведка", [
        ("recon",           "Reconnaissance"),
        ("dns_tools",       "DNS Tools"),
        ("osint",           "OSINT"),
        ("osint_pro",       "OSINT Pro (100+ платформ)"),
        ("censys",          "Censys"),
        ("cve_feeds",       "CVE Feeds"),
        ("threat_intel",    "Threat Intel"),
        ("threat_hunting",  "Threat Hunting"),
        ("async",           "Async Engine"),
        ("takeover",        "Subdomain Takeover"),
        ("takeover_v2",     "Subdomain Takeover v2"),
        ("monitor",         "Subdomain Monitor"),
        ("cloud_storage",   "Cloud Storage (S3/GCS/Azure)"),
    ]),
    ("🌐 Web / API", [
        ("web",             "Web Vulnerabilities"),
        ("wordpress",       "WordPress Scanner"),
        ("gql",             "GraphQL / API Discovery"),
        ("gql_sec",         "GraphQL Security Suite"),
        ("api_fuzzer",      "API Fuzzing Suite"),
        ("secrets",         "JS Secrets Scanner"),
        ("cache_poison",    "Web Cache Poisoning"),
        ("crawler",         "Web Crawler"),
        ("fuzzer",          "Web Fuzzer"),
        ("payloads",        "Payload Factory"),
    ]),
    ("☁  Cloud", [
        ("cloud_iam",       "Cloud IAM Analyzer"),
        ("cloud_attack",    "Cloud Attack Pro"),
    ]),
    ("🏢 AD / K8s / DB", [
        ("ad_attack",       "Active Directory Attack"),
        ("k8s_scan",        "Kubernetes Scanner"),
        ("container",       "Container Escape"),
        ("db_attack",       "Database Attack Helper"),
    ]),
    ("📡 Сеть / Wireless", [
        ("network",         "Network (ARP/WiFi)"),
        ("wireless",        "Wireless Toolkit"),
        ("wl_attack",       "Wireless Attack Helper"),
        ("wl_pro",          "Wireless Attack Pro"),
        ("pcap",            "Packet Analysis"),
    ]),
    ("⚔  Red Team", [
        ("pivot",           "Pivot / Post-Exploit"),
        ("c2",              "Red Team C2"),
        ("shell",           "Shell Manager"),
        ("shell_pro",       "Reverse Shell Listener Pro"),
        ("adv_emul",        "Adversary Emulation (ATT&CK)"),
    ]),
    ("🎯 Bug Bounty / Reports", [
        ("bugbounty",       "Bug Bounty (CVSS, отчёты)"),
        ("autoscan",        "Auto-Scan (пайплайн)"),
        ("autopilot",       "Bug Bounty Autopilot"),
        ("reportpack",      "Report Templates Pack"),
        ("report",          "Report Export"),
        ("autoreport",      "Auto-Report Pro"),
    ]),
    ("🎭 Social / SSRF / Web3", [
        ("se",              "Social Engineering (CTF)"),
        ("ssrf",            "SSRF Pro"),
        ("web3",            "Web3 / Blockchain"),
        ("mobile",          "Mobile App Security"),
        ("re",              "Reverse Engineering"),
        ("forensics",       "Forensics & IR"),
    ]),
    ("🔐 Пароли / Хранилище", [
        ("passwords",       "Passwords & Hashes"),
        ("hash_suite",      "Hash Cracking Suite"),
        ("vault",           "Password Vault"),
    ]),
    ("🛠  Инструменты", [
        ("http_proxy",      "HTTP/HTTPS Proxy"),
        ("stego",           "Steganography Pro"),
        ("utils",           "Утилиты"),
        ("screenshot",      "Screenshot"),
        ("wordlists",       "Wordlist Updater"),
        ("wordtools",       "Wordlist Tools"),
    ]),
    ("📊 Notes / Авто", [
        ("notes",           "Notes & Findings"),
        ("stats",           "Graph & Statistics"),
        ("scheduler",       "Scheduler"),
        ("notifier",        "Notifier"),
        ("bot",             "Telegram Bot"),
    ]),
    ("📋 Compliance / SDK", [
        ("compliance",      "Compliance & Audit"),
        ("sdk",             "Plugin SDK"),
    ]),
    ("🧩 Плагины", []),
    ("🎓 Обучение", [
        ("roadmap",         "Roadmap"),
    ]),
]


# ============================================================================
# PREFIX_MAP
# ============================================================================

PREFIX_MAP = {
    "recon": "recon.",
    "dns_tools": "dns_tools.",
    "osint": "osint.",
    "osint_pro": "op.",
    "censys": "censys.",
    "cve_feeds": "cve.",
    "threat_intel": "ti.",
    "threat_hunting": "threat_hunting.",
    "async": "async.",
    "takeover": "takeover.",
    "takeover_v2": "takeover_v2.",
    "monitor": "monitor.",
    "cloud_storage": "cloud_storage.",
    "web": "web.",
    "wordpress": "wordpress.",
    "gql": "gql.",
    "gql_sec": "gql_sec.",
    "api_fuzzer": "api_fuzzer.",
    "secrets": "secrets.",
    "cache_poison": "cache_poison.",
    "crawler": "crawler.",
    "fuzzer": "fuzzer.",
    "payloads": "payloads.",
    "cloud_iam": "cloud_iam.",
    "cloud_attack": "cloud_attack.",
    "ad_attack": "ad_attack.",
    "k8s_scan": "k8s_scan.",
    "container": "container.",
    "db_attack": "db_attack.",
    "network": "network.",
    "wireless": "wireless.",
    "wl_attack": "wl_attack.",
    "wl_pro": "wl_pro.",
    "pcap": "pcap.",
    "pivot": "pivot.",
    "c2": "c2.",
    "shell": "shell.",
    "shell_pro": "shell_pro.",
    "adv_emul": "adv_emul.",
    "bugbounty": "bugbounty.",
    "autoscan": "autoscan.",
    "autopilot": "autopilot.",
    "reportpack": "reportpack.",
    "report": "report.",
    "autoreport": "autoreport.",
    "se": "se.",
    "ssrf": "ssrf.",
    "web3": "web3.",
    "mobile": "mobile.",
    "re": "re.",
    "forensics": "forensics.",
    "passwords": "passwords.",
    "hash_suite": "hash_suite.",
    "vault": "vault.",
    "http_proxy": "http_proxy.",
    "stego": "stego.",
    "utils": "utils.",
    "screenshot": "screenshot.",
    "wordlists": "wordlists.",
    "wordtools": "wordtools.",
    "notes": "notes.",
    "stats": "stats.",
    "scheduler": "scheduler.",
    "notifier": "notifier.",
    "bot": "bot.",
    "compliance": "compliance.",
    "sdk": "sdk.",
    "plugins": "plugins.",
    "roadmap": "roadmap.",
}


# ============================================================================
# INFO_CARDS
# ============================================================================

INFO_CARDS = {
    "recon": (
        "🔎 Reconnaissance",
        "WHOIS (RDAP fallback + age), DNS enum (A/AAAA/MX/NS/TXT/CAA/"
        "SPF/DMARC/DKIM/BIMI), subdomain scan (wordlist + crt.sh + "
        "wildcard), port scan с баннерами, geoip+ASN, tech fingerprint "
        "(40+ techs), google dorks (50+), shodan/InternetDB, reverse IP, "
        "SSL info, robots/security.txt, HTTP headers.",
        "recon",
    ),
    "dns_tools": (
        "🌍 DNS Tools",
        "AXFR zone transfer, DNSSEC (DS/DNSKEY/RRSIG), wildcard, "
        "PTR-скан, cache snooping, CNAME chain, SRV, SPF/DMARC/DKIM, "
        "DNS rebinding.",
        "dns-tools",
    ),
    "osint": (
        "🔎 OSINT (базовый)",
        "Username check (60+ сервисов), HIBP email breach, phone lookup, "
        "EXIF extractor (+GPS), GitHub dorks (17 шаблонов).",
        "username",
    ),
    "osint_pro": (
        "🕵  OSINT Pro",
        "Username (100+ платформ по категориям), Telegram, Gravatar "
        "(+linked accounts), Wayback (sensitive URLs), domain age (RDAP), "
        "DNS dump (DNSSEC/DMARC/BIMI), GitHub/GitLab user info, "
        "email intel, phone intel, reverse image search.",
        "osint-pro",
    ),
    "censys": (
        "🔍 Censys Lookup",
        "Поиск хостов, сервисов и сертификатов через Censys API. "
        "Требует CENSYS_API_ID + CENSYS_API_SECRET в .env.",
        "censys",
    ),
    "cve_feeds": (
        "📡 CVE Feeds",
        "NVD API 2.0 (download + search), CISA KEV, EPSS enrichment, "
        "OSV query, статистика, фильтры (severity/KEV/ransomware/EPSS), "
        "Google dorks под CVE, watch-list, экспорт JSON/CSV/HTML/MD.",
        "cve",
    ),
    "threat_intel": (
        "🟡 Threat Intelligence",
        "Мульти-API IOC (IP/domain/hash/URL): Shodan IDB, GreyNoise, "
        "AbuseIPDB, VirusTotal, OTX, IPQS, URLhaus, MalwareBazaar, "
        "ThreatFox, PhishTank, urlscan. Авто-детект типа IOC, кэш, "
        "risk-score, malware families, экспорт JSON/CSV/MD/HTML.",
        "ti",
    ),
    "threat_hunting": (
        "🎯 Threat Hunting",
        "Sigma rules (20+), hunt playbooks (12 тактик с KQL/PowerShell/"
        "Sysmon), MITRE ATT&CK mapping (37 TTPs), экспорт в Sigma YAML, "
        "Markdown, HTML dashboard, Navigator layer.",
        "hunting",
    ),
    "async": (
        "⚡ Async Engine",
        "Быстрый TCP-портскан (asyncio) с баннерами, UDP-скан, HTTP-скан "
        "URL-списка с методами. Резолв IPv4/IPv6, batch-хосты, "
        "JSON/CSV экспорт.",
        "asyncscan",
    ),
    "takeover": (
        "🎯 Subdomain Takeover",
        "Проверка dangling CNAME + 60 fingerprints SaaS-сервисов "
        "(GitHub/Heroku/AWS/Azure/GCP/Shopify/Zendesk/...).",
        "takeover",
    ),
    "takeover_v2": (
        "🎯 Subdomain Takeover v2",
        "150+ сервисов (cloud/pages/CMS/support/dev-tools/tunnel), "
        "полный CNAME chain, wildcard filter, sqlite-мониторинг dangling, "
        "экспорт JSON/HTML/CSV/Markdown.",
        "takeover-v2",
    ),
    "monitor": (
        "👁  Subdomain Monitor",
        "Watch-list доменов, ре-скан по интервалам, diff (new/disappeared/"
        "changed IP/takeover), алерты, история снапшотов, экспорт.",
        "monitor",
    ),
    "cloud_storage": (
        "☁  Cloud Storage Enum",
        "Автогенерация имён бакетов из домена + проверка S3/GCS/Azure/"
        "DO/Linode/B2/Wasabi/Alibaba/R2/Firebase на public-list/read/"
        "write/ACL/policy.",
        "cloud",
    ),

    "web": (
        "🌐 Web Vulnerabilities",
        "Security headers (9), SSL/TLS, cookies flags, SQLi (error + "
        "time-based), XSS (reflected), LFI/RFI, SSTI, CMDi, NoSQLi, "
        "XXE, CRLF, Host-header, open redirect, CORS, CSRF, dir-brute, "
        "CMS detect, JWT decode/attacks.",
        "web",
    ),
    "wordpress": (
        "🔍 WordPress Scanner",
        "Детект WP + версия, users (REST + ?author=N + author-sitemap), "
        "plugins (+readme.txt версии), themes, xmlrpc, REST API probes, "
        "CVE база для 40+ плагинов + core, sensitive files (60+), "
        "directory listing, pingback SSRF.",
        "wp",
    ),
    "gql": (
        "🔎 GraphQL / API Discovery",
        "Поиск GraphQL (60+ путей), introspection, schema analysis, "
        "Swagger/OpenAPI (25+), REST endpoints, API-URL из JS, WebSocket, "
        "Apollo/Relay detection.",
        "gql",
    ),
    "gql_sec": (
        "🔎 GraphQL Security Suite",
        "Introspection, suggestions attack, batch (rate-limit bypass), "
        "alias bomb (DoS), depth attack, directive abuse, CSRF via GET, "
        "rate-limit test, mutation fuzz.",
        "gql-sec",
    ),
    "api_fuzzer": (
        "🌐 API Fuzzing Suite",
        "OpenAPI/Swagger 2.0+3.x (с $ref), Postman, HAR, auto-discovery. "
        "Auth-bypass matrix, method confusion, Content-Type confusion, "
        "mass assignment, SSRF params, ReDoS, idempotency, BOLA/IDOR, "
        "rate-limit, JWT, GraphQL.",
        "api-fuzz",
    ),
    "secrets": (
        "🔐 JS Secrets Scanner",
        "130+ паттернов (AWS/GCP/Azure/Stripe/GitHub/Slack/Discord/"
        "OpenAI/Anthropic/HuggingFace/...), entropy detection, "
        "валидация (GitHub/GitLab/Slack/Stripe/SendGrid/OpenAI/"
        "Anthropic/HuggingFace/Discord), source maps.",
        "secrets",
    ),
    "cache_poison": (
        "💾 Web Cache Poisoning",
        "Unkeyed headers (40+), cache deception, parameter cloaking, "
        "vary/cache-control, fat GET, method override, host header, "
        "smuggling hints, HTTP/2 vectors.",
        "cache-poison",
    ),
    "crawler": (
        "🕷  Web Crawler",
        "HTML/JS/robots/sitemap, sensitive paths, forms, JS endpoints, "
        "extract secrets (30+ patterns), cloud buckets, admin paths, "
        "authentication (Basic/Cookies).",
        "crawl",
    ),
    "fuzzer": (
        "🔎 Web Fuzzer",
        "Paths, params, headers, cookies, methods, subdomains, vhosts, "
        "JSON body. Matchers/filters (status/size/words/regex/time), "
        "recursion, delay/retry.",
        "fuzz",
    ),
    "payloads": (
        "💉 Payload Factory",
        "XSS (33), SQLi (30), NoSQLi (14), LFI (30), SSRF (37), CMDi "
        "(33), SSTI (33), LDAP, XPath, XXE, Prototype Pollution, Open "
        "Redirect, CRLF, Log Injection, GraphQL. Кодирование (19), "
        "обфускация WAF, полиглоты.",
        "payload",
    ),

    "cloud_iam": (
        "☁  Cloud IAM Analyzer",
        "AWS STS/IAM (25+ permissions, privesc paths, assume-role, S3), "
        "GCP service account (10 permissions), Azure CLI (subscriptions/"
        "roles/KeyVault), env vars scan, credential files scan.",
        "cloud-iam",
    ),
    "cloud_attack": (
        "☁  Cloud Attack Pro",
        "IMDS chains (AWS/GCP/Azure/DO/Alibaba/OCI/Linode/Vultr/Hetzner/"
        "K8s/Docker/Vault/etcd), 16 AWS IAM privesc, SSRF bypass headers, "
        "live AWS cred chain, SSRF→metadata, cloud dorks, Lambda dump.",
        "cap",
    ),

    "ad_attack": (
        "🏢 Active Directory Attack",
        "LDAP anon, LDAP enum (users/groups/computers/SPN/AS-REP), "
        "password policy, SMB signing, null session, GPP cpassword "
        "(decrypt), Zerologon, PetitPotam, delegation enum, ADCS "
        "(ESC1-ESC8), Kerberoasting, AS-REP, DCSync, spray, BloodHound.",
        "ad",
    ),
    "k8s_scan": (
        "☸  Kubernetes Scanner",
        "K8s порты (30+) + PaaS (ArgoCD/Rancher/Harbor/Vault/Consul), "
        "kube-apiserver anon (full RBAC enum), kubelet, etcd, Docker API, "
        "dashboard/grafana/prometheus, container escape checks, CVE KB.",
        "k8s",
    ),
    "container": (
        "🔓 Container Escape",
        "Runtime detect (docker/containerd/CRI-O/podman/K8s/LXC), "
        "capabilities (41), namespaces, seccomp, AppArmor/SELinux, "
        "docker/containerd/CRI-O/podman sockets, host mounts, "
        "/proc/1/root, cgroup, eBPF, kubelet, hostPID, 14 kernel CVE.",
        "escape",
    ),
    "db_attack": (
        "🗄  Database Attack",
        "MongoDB, Redis, Elasticsearch, Memcached, CouchDB, Cassandra, "
        "Neo4j, InfluxDB, ClickHouse, ArangoDB, Solr, RabbitMQ no-auth "
        "checks. SQLMap launcher (9 пресетов), NoSQL payloads, "
        "hydra bruteforce.",
        "db",
    ),

    "network": (
        "🌐 Network",
        "Интерфейсы (детально), ARP-скан (vendor lookup), SYN/FIN/XMAS/"
        "NULL/ACK/connect scan, packet sniffer (HTTP/DNS/creds), "
        "MITM detector, DNS-spoof detector, Wi-Fi analyzer (evil-twin), "
        "MITM simulator.",
        "network",
    ),
    "wireless": (
        "📶 Wireless Toolkit",
        "Кроссплатформенный анализ Wi-Fi (Windows netsh / Linux nmcli+iw): "
        "SSID/BSSID/channel/signal/vendor, evil-twin, открытые сети, "
        "слабые шифры (WEP/WPA1), каналы (2.4/5/6), karma, "
        "multi-scan + timeline, JSON/CSV/MD/HTML.",
        "wifi",
    ),
    "wl_attack": (
        "📶 Wireless Attack Helper",
        "18 инструментов, WPA handshake workflow, PMKID capture, WPS-PIN "
        "(reaver/bully/Pixie Dust), WPA3-Transition, evil-twin lab "
        "(hostapd + dnsmasq + captive portal + telemetry), deauth-detector. "
        "Только Linux.",
        "wl-tools",
    ),
    "wl_pro": (
        "📶 Wireless Attack Pro",
        "WPA3 SAE (Dragonblood/downgrade), PMKID v2 (hcxdumptool), "
        "KARMA/MANA (hostapd-mana), Pixie Dust, deauth + beacon flood "
        "(mdk4), EAPHammer (WPA2-Enterprise), FragAttacks "
        "(CVE-2020-24586..24588), Wifite. Экспорт bash-скриптов.",
        "wl-pro",
    ),
    "pcap": (
        "📦 Packet Analysis",
        "PCAP/PCAPNG: credentials (HTTP Basic/FTP/Telnet/SMTP/POP3/IMAP/"
        "SNMP), HTTP request/response, DNS + tunneling detection, TLS SNI, "
        "ARP-spoof, beaconing, top talkers. JSON/CSV/MD/HTML.",
        "pcap",
    ),

    "pivot": (
        "🔀 Pivot / Post-Exploitation",
        "40+ reverse/bind shells, TTY stabilization, file transfer (25+), "
        "pivoting (SSH/socat/chisel/ligolo/sshuttle/netsh/dnscat2/ptunnel/"
        "rpivot/gost/nginx), Linux privesc (60+), Windows privesc (40+), "
        "container escape, cloud metadata, cred dump, persistence, "
        "payload encoding. Экспорт MD/TXT/JSON/SH.",
        "pivot",
    ),
    "c2": (
        "🎯 Red Team C2",
        "15 фреймворков (Sliver/Havoc/Mythic/Cobalt Strike/Metasploit/"
        "Empire/Covenant/PoshC2/Merlin/NimPlant/Villain/Caldera/...), "
        "MSFVenom (15 категорий), 12 payload generators (Donut/Shellter/"
        "Veil/Unicorn/HoaxShell/...), 6 listeners, infrastructure "
        "(nginx/socat redirectors, domain fronting), defense evasion "
        "(AMSI/ETW/injection), OpSec, MITRE mapping.",
        "c2",
    ),
    "shell": (
        "🐚 Shell Manager",
        "Multi-session TCP listener + REPL, autorecon, автопарсинг "
        "артефактов (users/hostname/IPs/sudo/SUID/kernels/AV), "
        "asciinema-запись, upload/download (base64), broadcast, "
        "шорткаты (25+). Экспорт JSON/HTML/MD/CSV.",
        "shell",
    ),
    "shell_pro": (
        "🐚 Reverse Shell Listener Pro",
        "Multi-session + auto-reconnect, persistence (JSON), payload "
        "generator (bash/nc/socat/python/php/powershell), labels+tags, "
        "TTY auto-upgrade (10+), upload/download, broadcast, asciinema, "
        "as-you-go findings. Linux/Windows auto-commands.",
        "shell-pro",
    ),
    "adv_emul": (
        "⚔  Adversary Emulation",
        "60+ TTPs по 14 тактикам MITRE ATT&CK (recon/exec/persist/privesc/"
        "evasion/cred/lateral/collection/c2/exfil/impact), atomic-style "
        "проверки, detection advice (Sysmon/EDR). Экспорт JSON/MD/"
        "Navigator layer.",
        "adv",
    ),

    "bugbounty": (
        "🎯 Bug Bounty Toolkit",
        "CVSS v3.1 (base+temporal+env), 13 пресетов уязвимостей, 6 "
        "шаблонов платформ (H1/Bugcrowd/Intigriti/YesWeHack/Immunefi/"
        "CVE), quality-checker (10+), export MD/HTML/PDF/JSON, "
        "история CSV/JSON/HTML/MD.",
        "bugbounty",
    ),
    "autoscan": (
        "🟢 Bug Bounty Auto-Scan",
        "Subs (crt.sh + hackertarget + OTX + RapidDNS + AnubisDB + brute "
        "+ wildcard), DNS resolve, port scan (top-100/1000) + banner, "
        "HTTP probe, tech fingerprint, sensitive files, screenshots, "
        "takeover, wayback. Checkpoint/resume. HTML/JSON/CSV/MD.",
        "autoscan",
    ),
    "autopilot": (
        "🎯 Bug Bounty Autopilot",
        "13 стадий: subs → live → tech → ports → takeover → dir brute → "
        "wayback → JS secrets → JS endpoints → CORS → GraphQL → findings "
        "→ report. Профили quick/full/deep. Findings → notes, notify, "
        "HTML+JSON.",
        "ap",
    ),
    "reportpack": (
        "📝 Report Templates Pack",
        "12 шаблонов платформ, 35+ пресетов уязвимостей (XSS/SQLi/SSRF/"
        "RCE/IDOR/CSRF/XXE/HTTP smuggling/cache poisoning/Web3/...), "
        "CVSS v3.1 full, wizard, quality-check, bulk export, timeline.",
        "report-pack",
    ),
    "report": (
        "📄 Report Export",
        "История сканов → HTML (TOC, фильтры, timeline), PDF (reportlab), "
        "CSV, MD, JSON. Конкретный скан → MD. Auto-notify.",
        "export-html",
    ),
    "autoreport": (
        "📊 Auto-Report Pro",
        "Сбор: scans + findings + notes + CVEs + takeovers + screenshots "
        "+ stats-images. Executive summary, timeline, methodology, TOC. "
        "HTML/PDF/JSON/MD. 4 шаблона (default/hackerone/bugcrowd/pentest). "
        "Incremental diff.",
        "report-pro",
    ),

    "se": (
        "🎭 Social Engineering (CTF)",
        "15+ phishing-шаблонов (employee-portal/webmail/vpn/mfa/sharepoint/"
        "docusign/...), telemetry server с JS fingerprint, 15+ email-"
        "шаблонов (.eml + SMTP send), 11 SMS, 5 vishing-скриптов, "
        "QR (12 типов), website clone, URL obfuscation (20+), "
        "tracking pixel.",
        "se",
    ),
    "ssrf": (
        "🌐 SSRF Pro",
        "Cloud metadata (20+ провайдеров: AWS/GCP/Azure/DO/Alibaba/OCI/"
        "IBM/Linode/Vultr/Hetzner/Scaleway/K8s/Docker/Consul/etcd/Vault/"
        "ES/Rancher/Jenkins), IP bypass (decimal/octal/hex/IPv6/NAT64/6to4/"
        "nip.io), scheme payloads (gopher/dict/file/ftp/ldap/jar/netdoc), "
        "parser confusion (@/backslash/CRLF/unicode), DNS rebinding, "
        "blind helpers, SSRF→RCE chains.",
        "ssrf",
    ),
    "web3": (
        "⛓  Blockchain Security",
        "Solidity static analysis (35+ паттернов: reentrancy, tx.origin, "
        "delegatecall, overflow, weak randomness, oracle manipulation, "
        "flash loan, unchecked, selfdestruct, access control, assembly, "
        "sig replay, storage collision, initializer, donation attack...), "
        "ERC20/721/1155 detect, proxy (EIP-1967/1822/UUPS), multi-chain "
        "(10 сетей), private keys (12 типов), honeypot heuristics, "
        "drainer patterns.",
        "web3",
    ),
    "mobile": (
        "📱 Mobile App Security",
        "APK (manifest, permissions 80+, exported components, deeplinks, "
        "DEX IOC, 130+ secret patterns, NSC, pinning, allowBackup, "
        "debuggable) / IPA (Info.plist, ATS, entitlements, embedded "
        "provision, frameworks, strings). JSON/HTML/CSV.",
        "mobile",
    ),
    "re": (
        "🔬 Reverse Engineering",
        "Magic-детект (60+), Shannon entropy (+graph), strings (ASCII + "
        "UTF-16LE + UTF-16BE) + 25+ IOC patterns + base64-decode, PE "
        "parser (sections+entropy, DLLs, imphash, PDB, packer detect), "
        "ELF, Mach-O, YARA (18 built-in rules), shellcode detect, "
        "crypto miner, ransomware. JSON/HTML/MD.",
        "re",
    ),
    "forensics": (
        "🔬 Forensics & IR",
        "IOC extractor (40+ паттернов: IP/domain/URL/email/hashes/CVE/"
        "MITRE/crypto-wallets/API-keys/JWT/PEM/tool-names/LOLBins/"
        "ransom-ext), timeline (mtime/ctime/atime + suspicious paths), "
        "Sysmon XML (26 EventIDs + suspicious chains), auth.log, auditd, "
        "browser history (Chrome/Firefox), hash verification (hashdeep), "
        "YARA.",
        "forensics",
    ),

    "passwords": (
        "🔑 Passwords & Hashes",
        "Hash identifier (65+), cracker (wordlist + rules), mask cracker "
        "(brute), strength analyzer (score 0-10 + zxcvbn + entropy + "
        "crack-time), password generator, passphrase (XKCD), memorable, "
        "L33t, wordlist generator (crunch), rules-wordlist.",
        "hashid",
    ),
    "hash_suite": (
        "🔨 Hash Cracking Suite",
        "90+ типов хешей (все hashcat modes), built-in cracker (MD5/SHA*/"
        "NTLM/MySQL5/SHA-crypt/...), wordlist, mask (?l?u?d?s?a?h?H?b), "
        "combinator, rules (16 типов: best64/dive/leet/capitalize/append/"
        "prepend/toggle/reverse/duplicate/reflect/swap/rotate), hashcat, "
        "john, hcxpcapngtool, aircrack. Potfile import/export.",
        "hs",
    ),
    "vault": (
        "🔐 Password Vault",
        "Шифрованное (AES-256 + PBKDF2 200k) хранилище: title/username/"
        "password/url/notes/tags/totp/extra. Auto-lock, история паролей, "
        "audit log, health-check (weak/reused/old/no-2FA/dupe), "
        "password generator (6 пресетов + passphrase), экспорт "
        "encrypted/JSON/CSV/HTML (masked), смена мастера.",
        "vault",
    ),

    "http_proxy": (
        "🌐 HTTP/HTTPS Proxy",
        "MITM-прокси с собственным CA + dynamic signing, HTTP/1.1 "
        "keep-alive, chunked, gzip/deflate/br. Правила (replace/"
        "add-header/remove-header/drop/inject-body), фильтры (host/"
        "method/status), SQLite logging, metrics, sensitive detection "
        "(auth/cookies). Экспорт HAR/JSON/CSV/HTML.",
        "proxy",
    ),
    "stego": (
        "🖼  Steganography Pro",
        "Скрытие текста/файлов в PNG (LSB 1/2/4) / WAV (16-bit PCM) / "
        "FLAC. AES-256-GCM + PBKDF2-200k. zlib/lzma сжатие. Random LSB "
        "(seed от пароля). Steganalysis: Chi-square, RS-анализ "
        "(Fridrich), Sample-Pair Analysis, гистограмма. Batch.",
        "stego",
    ),
    "utils": (
        "🛠  Утилиты",
        "Encoder/Decoder (30+: base64/base32/base85/hex/url/rot13/rot-n/"
        "binary/octal/unicode-escape/html-entity/gzip/zlib/jwt/url-parse), "
        "AES (Fernet), XOR (1-byte + multi-byte), шифры (Caesar/"
        "Vigenère/Atbash/Rail fence), hashes файлов (5 алгоритмов), "
        "reverse shell (15+), LSB-stego PNG.",
        "utils",
    ),
    "screenshot": (
        "📸 Screenshot Pro",
        "Playwright (chromium/firefox/webkit), viewports (7), full-page/"
        "element/PDF, wait-стратегии (load/domcontentloaded/networkidle), "
        "selector wait, basic auth, cookies, headers, proxy, "
        "console/network capture. Batch, multi-viewport, compare (hash "
        "diff), stealth.",
        "screenshot",
    ),
    "wordlists": (
        "📚 Wordlist Updater",
        "50+ источников (SecLists/PayloadsAllTheThings/fuzzdb/"
        "commonspeak2), категории (dns/web/passwords/usernames/payloads/"
        "fuzzing), параллельная загрузка, retry, resume, ETag skip, "
        "gzip. Integrity check, dedup, custom sources, export MD/JSON/"
        "HTML/CSV.",
        "wordlists-update",
    ),
    "wordtools": (
        "📚 Wordlist Tools",
        "Генерация из 1/2/N слов (leet + регистр + суффиксы/префиксы + "
        "годы), mask (?l?u?d?s?a?h?H), hashcat rules (16), combinator "
        "2 словарей. Анализ: stats (length/charset/entropy), dedup, "
        "crack-time estimation.",
        "wordlist-gen",
    ),

    "notes": (
        "📝 Notes & Findings",
        "Заметки и находки (kind/severity/status/target/tags/body), "
        "FTS5-поиск, теги (rename/delete), related notes, timeline, "
        "bulk-операции, wizard с пресетами, экспорт MD/JSON/CSV/HTML/"
        "Kanban, импорт JSON, auto-notify для critical.",
        "notes",
    ),
    "stats": (
        "📊 Graph & Statistics",
        "Текстовая сводка + аномалии (спайки/редкие модули/критические "
        "findings), PNG-графики (timeline/top modules/targets/hourly/"
        "pie/severity/heatmap/cumulative/dashboard 2×3), HTML-dashboard "
        "self-contained, CSV/MD экспорт.",
        "stats",
    ),
    "scheduler": (
        "📅 Scheduler Pro",
        "40+ actions из всех модулей, расписание (interval/daily/weekly/"
        "cron/one-shot), retry + severity, SQLite job_history, экспорт "
        "JSON/CSV/MD/HTML, dry-run, pause/resume, notify start/finish/"
        "fail.",
        "scheduler-list",
    ),
    "notifier": (
        "📢 Notifier Pro",
        "14 каналов: Telegram, Discord, Slack, Mattermost, Rocket.Chat, "
        "MS Teams, Gotify, ntfy, Pushover, PagerDuty, Email, Webhook "
        "(HMAC), Syslog, Desktop. Severity filter, module filter, quiet "
        "hours, rate-limit, dedup, retry, batch, история + статус, "
        "шаблоны.",
        "notify-status",
    ),
    "bot": (
        "🤖 Telegram Bot",
        "Управление из чата: /dns, /whois, /geoip, /portscan, /headers, "
        "/screenshot, /crawl, /hashid, /crack, /last, /export-html, "
        "/status, /ping, /reload. Whitelist (owner + extra users) через "
        "/allow, /deny, /users.",
        "bot-info",
    ),

    "compliance": (
        "📋 Compliance & Audit",
        "CIS Linux (80+ live checks: fs/services/net/log/access/maintenance/"
        "kernel), CIS Docker (10), OWASP Top 10, ASVS 4.0, PCI-DSS 4.0, "
        "ISO 27001, NIST 800-53. Findings → notes, экспорт MD/JSON/CSV/"
        "HTML.",
        "audit",
    ),
    "sdk": (
        "🧩 Plugin SDK",
        "7 шаблонов (basic/network/web/crypto/forensics/recon/custom), "
        "генерация + валидация (PLUGIN_INFO/ACTIONS/callable/arg_hint), "
        "документация API, export/import через JSON.",
        "sdk",
    ),
    "roadmap": (
        "🎓 Roadmap Pro",
        "7 путей (Junior/Middle/Senior/Expert/Red Team/Blue Team/Web Deep), "
        "40+ ресурсов, 18 сертификаций, квиз (60+ вопросов по 8 "
        "категориям), progress tracker + streak, экспорт JSON/MD/HTML/CSV.",
        "roadmap",
    ),
}


# ============================================================================
# QUICK ACTIONS
# ============================================================================

def _build_quick_actions() -> dict[str, tuple]:
    qa: dict[str, tuple] = {
        # ── Recon ──
        "recon.whois":          (recon, "whois_lookup", "WHOIS", "target"),
        "recon.dns":            (recon, "dns_enum", "DNS enum", "target"),
        "recon.subdomain":      (recon, "subdomain_scan", "Subdomain scan", "target"),
        "recon.portscan":       (recon, "port_scan", "Port scan", "target"),
        "recon.geoip":          (recon, "ip_geolocation", "IP geoip", "target"),
        "recon.fingerprint":    (recon, "tech_fingerprint", "Tech fingerprint", "url"),
        "recon.dork":           (recon, "google_dork", "Google dork", "domain"),
        "recon.shodan":         (recon, "shodan_lookup", "Shodan", "query"),
        "recon.ssl":            (recon, "ssl_info", "SSL/TLS info", "host"),
        "recon.robots":         (recon, "robots_security_txt",
                                 "robots/security.txt", "url"),
        "recon.headers":        (recon, "http_headers", "HTTP headers", "url"),

        # ── OSINT ──
        "osint.username":       (osint, "username_check", "OSINT: username", "username"),
        "osint.email":          (osint, "email_breach", "OSINT: HIBP", "email"),
        "osint.phone":          (osint, "phone_lookup", "OSINT: phone", "phone"),
        "osint.exif":           (osint, "exif_extractor", "OSINT: EXIF", "path"),
        "osint.github":         (osint, "github_dork", "OSINT: GitHub dorks", "query"),

        # ── Censys ──
        "censys.search":        (censys_lookup, "censys_search", "Censys: search", "query"),
        "censys.host":          (censys_lookup, "censys_host", "Censys: host", "ip"),
        "censys.cert":          (censys_lookup, "censys_cert", "Censys: cert", "sha"),

        # ── DNS Tools ──
        "dns_tools.axfr":       (dns_tools, "zone_transfer", "DNS AXFR", "domain"),
        "dns_tools.dnssec":     (dns_tools, "dnssec_check", "DNSSEC", "domain"),
        "dns_tools.wildcard":   (dns_tools, "wildcard_detect", "Wildcard", "domain"),
        "dns_tools.ptr":        (dns_tools, "reverse_scan", "Reverse PTR", "network"),
        "dns_tools.snoop":      (dns_tools, "cache_snooping", "Cache snoop", "domain"),
        "dns_tools.cname":      (dns_tools, "show_cname_chain", "CNAME chain", "domain"),
        "dns_tools.srv":        (dns_tools, "srv_scan", "SRV scan", "domain"),
        "dns_tools.mail":       (dns_tools, "mail_security", "SPF/DMARC/DKIM", "domain"),
        "dns_tools.rebind":     (dns_tools, "rebinding_detect", "Rebinding", "domain"),

        # ── Takeover ──
        "takeover.scan":        (subdomain_takeover, "cli_scan", "Takeover: скан", "domain"),
        "takeover.check":       (subdomain_takeover, "cli_check", "Takeover: 1 sub", "target"),
        "takeover.services":    (subdomain_takeover, "cli_services", "Takeover: база", "none"),

        "takeover_v2.scan":     (subdomain_takeover_v2, "cli_scan",
                                 "Takeover v2: скан", "domain"),
        "takeover_v2.check":    (subdomain_takeover_v2, "cli_check",
                                 "Takeover v2: 1 sub", "target"),
        "takeover_v2.services": (subdomain_takeover_v2, "cli_services",
                                 "Takeover v2: база", "none"),
        "takeover_v2.history":  (subdomain_takeover_v2, "cli_history",
                                 "Takeover v2: история", "none"),

        # ── Monitor ──
        "monitor.list":         (subdomain_monitor, "cli_list", "Monitor: список", "none"),
        "monitor.add":          (subdomain_monitor, "cli_add", "Monitor: добавить", "domain"),
        "monitor.scan":         (subdomain_monitor, "cli_scan", "Monitor: скан", "domain"),
        "monitor.scan_all":     (subdomain_monitor, "cli_scan_all",
                                 "Monitor: скан всех", "none"),
        "monitor.history":      (subdomain_monitor, "cli_history",
                                 "Monitor: история", "domain"),

        # ── Threat Intel ──
        "ti.ip":                (threat_intel, "cli_ip", "TI: IP", "ip"),
        "ti.domain":            (threat_intel, "cli_domain", "TI: домен", "domain"),
        "ti.hash":              (threat_intel, "cli_hash", "TI: hash", "hash"),
        "ti.url":               (threat_intel, "cli_url", "TI: URL", "url"),
        "ti.auto":              (threat_intel, "cli_auto", "TI: авто-IOC", "word"),
        "ti.bulk":              (threat_intel, "cli_bulk", "TI: bulk", "path"),
        "ti.sources":           (threat_intel, "cli_sources", "TI: источники", "none"),
        "ti.cache":             (threat_intel, "cli_cache", "TI: кэш", "none"),

        # ── Threat Hunting ──
        "threat_hunting.sigma":     (threat_hunting, "cli_sigma",
                                     "Hunting: Sigma", "none"),
        "threat_hunting.playbooks": (threat_hunting, "cli_playbooks",
                                     "Hunting: playbooks", "none"),
        "threat_hunting.mitre":     (threat_hunting, "cli_mitre",
                                     "Hunting: MITRE", "none"),
        "threat_hunting.export_nav": (threat_hunting,
                                       "export_mitre_navigator",
                                       "Hunting: Navigator layer", "none"),
        "threat_hunting.export_dash": (threat_hunting, "export_dashboard",
                                        "Hunting: HTML dashboard", "none"),

        # ── CVE ──
        "cve.top":              (cve_feeds, "cli_top", "CVE: топ", "none"),
        "cve.kev":              (cve_feeds, "cli_kev", "CVE: KEV", "none"),
        "cve.stats":            (cve_feeds, "stats", "CVE: stats", "none"),
        "cve.search":           (cve_feeds, "cli_search", "CVE: поиск", "word"),
        "cve.show":             (cve_feeds, "cli_show", "CVE: показать", "word"),
        "cve.dorks":            (cve_feeds, "cli_dorks", "CVE: dorks", "word"),
        "cve.download":         (cve_feeds, "cli_download", "CVE: download", "none"),
        "cve.kev_update":       (cve_feeds, "download_kev", "CVE: KEV update", "none"),

        # ── OSINT Pro ──
        "op.username":          (osint_pro, "cli_username", "OSINT: username", "username"),
        "op.telegram":          (osint_pro, "cli_telegram", "OSINT: Telegram", "username"),
        "op.gravatar":          (osint_pro, "cli_gravatar", "OSINT: Gravatar", "email"),
        "op.wayback":           (osint_pro, "cli_wayback", "OSINT: Wayback", "domain"),
        "op.age":               (osint_pro, "cli_age", "OSINT: domain age", "domain"),
        "op.dns":               (osint_pro, "cli_dns", "OSINT: DNS dump", "domain"),
        "op.github":            (osint_pro, "cli_github", "OSINT: GitHub", "username"),
        "op.email":             (osint_pro, "cli_email", "OSINT: email", "email"),
        "op.image":             (osint_pro, "cli_image", "OSINT: reverse img", "url"),
        "op.phone":             (osint_pro, "cli_phone", "OSINT: phone", "phone"),

        # ── Cloud Storage ──
        "cloud_storage.s3":     (cloud_storage, "cli_scan", "Cloud: S3", "domain"),
        "cloud_storage.gcs":    (cloud_storage, "cli_scan", "Cloud: GCS", "domain"),
        "cloud_storage.all":    (cloud_storage, "cli_scan_all", "Cloud: все", "domain"),
        "cloud_storage.check":  (cloud_storage, "cli_check", "Cloud: 1 бакет", "word"),
        "cloud_storage.batch":  (cloud_storage, "cli_batch", "Cloud: batch", "path"),
        "cloud_storage.azure":  (cloud_storage, "cli_azure", "Cloud: Azure", "word"),
        "cloud_storage.providers": (cloud_storage, "cli_providers",
                                     "Cloud: список провайдеров", "none"),

        # ── Cloud IAM ──
        "cloud_iam.aws":        (cloud_iam, "cli_aws", "Cloud IAM: AWS", "none"),
        "cloud_iam.gcp":        (cloud_iam, "cli_gcp", "Cloud IAM: GCP", "none"),
        "cloud_iam.azure":      (cloud_iam, "cli_azure", "Cloud IAM: Azure", "none"),
        "cloud_iam.env":        (cloud_iam, "cli_env", "Cloud IAM: env vars", "none"),
        "cloud_iam.files":      (cloud_iam, "cli_files", "Cloud IAM: files", "none"),
        "cloud_iam.full":       (cloud_iam, "full_audit", "Cloud IAM: full", "none"),

        # ── Cloud Attack Pro ──
        "cloud_attack.imds":       (cloud_attack_pro, "cli_imds",
                                     "CAP: IMDS chains", "none"),
        "cloud_attack.privesc":    (cloud_attack_pro, "cli_privesc",
                                     "CAP: AWS privesc", "none"),
        "cloud_attack.ssrf_hdrs":  (cloud_attack_pro, "cli_ssrf_headers",
                                     "CAP: SSRF headers", "none"),
        "cloud_attack.metadata":   (cloud_attack_pro, "cli_metadata_ssrf",
                                     "CAP: SSRF→meta", "url"),
        "cloud_attack.dorks":      (cloud_attack_pro, "cli_dorks",
                                     "CAP: secret dorks", "word"),
        "cloud_attack.lambda":     (cloud_attack_pro, "cli_lambda",
                                     "CAP: Lambda dump", "none"),
        "cloud_attack.ip_bypass":  (cloud_attack_pro, "cli_ip_bypass",
                                     "CAP: IP bypass variants", "none"),

        # ── Web ──
        "web.headers":          (web_vuln, "header_analyzer", "HTTP headers", "url"),
        "web.ssl":              (web_vuln, "ssl_checker", "SSL/TLS", "host"),
        "web.sqli":             (web_vuln, "sqli_scan", "SQLi", "url"),
        "web.xss":              (web_vuln, "xss_scan", "XSS", "url"),
        "web.lfi":              (web_vuln, "lfi_scan", "LFI", "url"),
        "web.dirb":             (web_vuln, "dir_bruteforce", "Dir brute", "url"),
        "web.cms":              (web_vuln, "cms_scanner", "CMS", "url"),
        "web.redirect":         (web_vuln, "open_redirect", "Open redirect", "url"),
        "web.csrf":             (web_vuln, "csrf_checker", "CSRF", "url"),

        # ── WordPress ──
        "wordpress.scan":       (wordpress_scanner, "cli_scan",
                                 "WP: полный скан", "url"),
        "wordpress.detect":     (wordpress_scanner, "cli_detect",
                                 "WP: детект", "url"),
        "wordpress.users":      (wordpress_scanner, "cli_users",
                                 "WP: users", "url"),
        "wordpress.plugins":    (wordpress_scanner, "cli_plugins",
                                 "WP: plugins", "url"),
        "wordpress.xmlrpc":     (wordpress_scanner, "cli_xmlrpc",
                                 "WP: xmlrpc", "url"),
        "wordpress.vulns":      (wordpress_scanner, "cli_vulns",
                                 "WP: CVE", "url"),
        "wordpress.rest":       (wordpress_scanner, "cli_rest",
                                 "WP: REST API", "url"),

        # ── GraphQL / API ──
        "gql.scan":             (graphql_discovery, "cli_full",
                                 "API: full scan", "url"),
        "gql.discover":         (graphql_discovery, "cli_gql",
                                 "API: GQL discover", "url"),
        "gql.introspect":       (graphql_discovery, "cli_gql_introspect",
                                 "API: introspection", "url"),
        "api.swagger":          (graphql_discovery, "cli_swagger",
                                 "API: Swagger", "url"),
        "api.rest":             (graphql_discovery, "cli_rest",
                                 "API: REST", "url"),
        "api.js":               (graphql_discovery, "cli_js",
                                 "API: JS endpoints", "url"),

        # ── GraphQL Security ──
        "gql_sec.scan":         (graphql_security, "cli_scan",
                                 "GQLSec: scan", "url"),
        "gql_sec.introspect":   (graphql_security, "cli_introspect",
                                 "GQLSec: introspection", "url"),
        "gql_sec.suggest":      (graphql_security, "cli_suggestions",
                                 "GQLSec: suggestions", "url"),
        "gql_sec.batch":        (graphql_security, "cli_batch",
                                 "GQLSec: batching", "url"),
        "gql_sec.alias":        (graphql_security, "cli_alias",
                                 "GQLSec: alias bomb", "url"),
        "gql_sec.csrf":         (graphql_security, "cli_csrf",
                                 "GQLSec: CSRF", "url"),

        # ── API Fuzzer ──
        "api_fuzzer.ratelimit": (api_fuzzer, "cli_ratelimit",
                                 "APIFuzz: ratelimit", "url"),
        "api_fuzzer.graphql":   (api_fuzzer, "cli_graphql",
                                 "APIFuzz: GraphQL", "url"),
        "api_fuzzer.bola":      (api_fuzzer, "cli_bola",
                                 "APIFuzz: BOLA", "url"),

        # ── JS Secrets ──
        "secrets.scan":         (js_secrets, "cli_scan",
                                 "Secrets: scan", "url"),
        "secrets.js":           (js_secrets, "cli_js",
                                 "Secrets: one JS", "url"),

        # ── Cache Poisoning ──
        "cache_poison.scan":      (cache_poisoning, "cli_scan",
                                    "Cache: full scan", "url"),
        "cache_poison.unkeyed":   (cache_poisoning, "cli_unkeyed",
                                    "Cache: unkeyed", "url"),
        "cache_poison.deception": (cache_poisoning, "cli_deception",
                                    "Cache: deception", "url"),
        "cache_poison.vary":      (cache_poisoning, "cli_vary",
                                    "Cache: vary", "url"),
        "cache_poison.fat":       (cache_poisoning, "cli_fat",
                                    "Cache: fat GET", "url"),
        "cache_poison.param":     (cache_poisoning, "cli_param_cloaking",
                                    "Cache: param cloaking", "url"),
        "cache_poison.host":      (cache_poisoning, "cli_host_injection",
                                    "Cache: host-header", "url"),

        # ── Crawler / Fuzzer / Payloads ──
        "crawler.crawl":        (web_crawler, "crawl", "Crawl URL", "url"),
        "fuzzer.params":        (web_fuzzer, "fuzz_params",
                                 "Fuzz params", "url"),
        "fuzzer.paths":         (web_fuzzer, "fuzz_paths",
                                 "Fuzz paths", "url"),
        "payloads.xss":         (payload_factory, "generate_payloads",
                                 "Payloads: XSS", "none"),
        "payloads.sqli":        (payload_factory, "generate_payloads",
                                 "Payloads: SQLi", "none"),
        "payloads.lfi":         (payload_factory, "generate_payloads",
                                 "Payloads: LFI", "none"),
        "payloads.ssrf":        (payload_factory, "generate_payloads",
                                 "Payloads: SSRF", "none"),

        # ── Passwords / Hash ──
        "passwords.hashid":     (passwords, "identify_hash",
                                 "Hash ID", "hash"),
        "passwords.crack":      (passwords, "crack_hash",
                                 "Crack hash", "hash"),
        "passwords.genpass":    (passwords, "generate_password",
                                 "Genpass 16", "none"),
        "passwords.genphrase":  (passwords, "generate_passphrase",
                                 "Passphrase (XKCD)", "none"),

        "hash_suite.tools":     (hash_suite, "cli_tools", "HS: tools", "none"),
        "hash_suite.identify":  (hash_suite, "cli_identify", "HS: identify", "hash"),
        "hash_suite.crack":     (hash_suite, "cli_crack", "HS: crack", "hash"),
        "hash_suite.file":      (hash_suite, "cli_file", "HS: file", "path"),

        # ── Vault ──
        "vault.status":         (vault, "cli_status", "Vault: status", "none"),
        "vault.list":           (vault, "cli_list", "Vault: list", "none"),
        "vault.search":         (vault, "cli_search", "Vault: search", "word"),
        "vault.health":         (vault, "cli_health", "Vault: health-check", "none"),
        "vault.gen":            (vault, "cli_generate_preset",
                                 "Vault: генератор паролей", "none"),

        # ── AD Attack ──
        "ad_attack.tools":         (ad_attack, "cli_tools",
                                     "AD: tools", "none"),
        "ad_attack.cheatsheets":   (ad_attack, "cli_cheatsheets",
                                     "AD: cheatsheets", "none"),
        "ad_attack.cheat":         (ad_attack, "cli_cheat",
                                     "AD: cheat-sheet", "word"),
        "ad_attack.smb_signing":   (ad_attack, "cli_smb_signing",
                                     "AD: SMB signing", "target"),
        "ad_attack.ldap_anon":     (ad_attack, "cli_ldap_anon",
                                     "AD: LDAP anon", "target"),
        "ad_attack.null_session":  (ad_attack, "cli_null_session",
                                     "AD: NULL session", "target"),

        # ── K8s ──
        "k8s_scan.scan":        (k8s_scanner, "cli_scan", "K8s: scan", "target"),
        "k8s_scan.api":         (k8s_scanner, "cli_api", "K8s: API", "target"),
        "k8s_scan.etcd":        (k8s_scanner, "cli_etcd", "K8s: etcd", "target"),
        "k8s_scan.docker":      (k8s_scanner, "cli_docker", "K8s: Docker", "target"),
        "k8s_scan.escape":      (k8s_scanner, "cli_escape", "K8s: escape", "none"),
        "k8s_scan.ports":       (k8s_scanner, "cli_ports", "K8s: порты", "none"),
        "k8s_scan.cve_kb":      (k8s_scanner, "cli_cve_kb", "K8s: CVE KB", "none"),

        # ── Container Escape ──
        "container.scan":       (container_escape, "cli_scan",
                                 "Escape: scan", "none"),
        "container.cves":       (container_escape, "cli_cves",
                                 "Escape: CVE list", "none"),
        "container.caps":       (container_escape, "cli_caps",
                                 "Escape: capabilities", "none"),

        # ── DB Attack ──
        "db_attack.scan":       (db_attack, "cli_scan", "DB: scan host", "target"),
        "db_attack.mongo":      (db_attack, "cli_mongo", "DB: MongoDB", "target"),
        "db_attack.redis":      (db_attack, "cli_redis", "DB: Redis", "target"),
        "db_attack.es":         (db_attack, "cli_es", "DB: Elasticsearch", "target"),
        "db_attack.ports":      (db_attack, "cli_ports", "DB: порты", "none"),

        # ── Network ──
        "network.ifaces":       (network, "list_interfaces",
                                 "Net: интерфейсы", "none"),
        "network.arp":          (network, "arp_scan", "Net: ARP scan", "network"),
        "network.wifi":         (network, "wifi_analyzer",
                                 "Net: Wi-Fi список", "none"),

        # ── Wireless Toolkit ──
        "wireless.scan":        (wireless_toolkit, "cli_scan", "WiFi: scan", "none"),
        "wireless.evil":        (wireless_toolkit, "cli_evil_twin",
                                 "WiFi: evil twin", "none"),
        "wireless.open":        (wireless_toolkit, "cli_open", "WiFi: open", "none"),
        "wireless.weak":        (wireless_toolkit, "cli_weak", "WiFi: weak", "none"),
        "wireless.channels":    (wireless_toolkit, "cli_channels",
                                 "WiFi: channels", "none"),
        "wireless.top":         (wireless_toolkit, "cli_top", "WiFi: top", "none"),
        "wireless.export_csv":  (wireless_toolkit, "cli_export_csv",
                                 "WiFi: CSV", "none"),
        "wireless.export_json": (wireless_toolkit, "cli_export_json",
                                 "WiFi: JSON", "none"),
        "wireless.export_html": (wireless_toolkit, "cli_export_html",
                                 "WiFi: HTML", "none"),
        "wireless.full":        (wireless_toolkit, "cli_full",
                                 "WiFi: full", "none"),

        "wl_attack.tools":      (wireless_attack, "_print_tools_table",
                                 "WL: tools", "none"),
        "wl_attack.ifaces":     (wireless_attack, "show_interfaces",
                                 "WL: ifaces", "none"),
        "wl_attack.wpa":        (wireless_attack, "show_wpa_workflow",
                                 "WL: WPA workflow", "none"),
        "wl_attack.pmkid":      (wireless_attack, "show_pmkid_workflow",
                                 "WL: PMKID workflow", "none"),
        "wl_attack.wps":        (wireless_attack, "show_wps_workflow",
                                 "WL: WPS workflow", "none"),
        "wl_attack.evil":       (wireless_attack, "generate_evil_twin",
                                 "WL: evil twin", "none"),

        "wl_pro.tools":         (wireless_attack_pro, "cli_tools",
                                 "WLPro: tools", "none"),
        "wl_pro.cheatsheets":   (wireless_attack_pro, "cli_cheatsheets",
                                 "WLPro: cheatsheets", "none"),
        "wl_pro.cheat":         (wireless_attack_pro, "cli_cheat",
                                 "WLPro: cheat", "word"),
        "wl_pro.export_all":    (wireless_attack_pro, "cli_export_all",
                                 "WLPro: export all", "none"),

        # ── PCAP ──
        "pcap.analyze":         (pcap_analysis, "cli_analyze",
                                 "PCAP: analyze", "path"),
        "pcap.html":            (pcap_analysis, "cli_html", "PCAP: HTML", "path"),
        "pcap.csv":             (pcap_analysis, "cli_csv", "PCAP: CSV", "path"),
        "pcap.md":              (pcap_analysis, "cli_md", "PCAP: MD", "path"),
        "pcap.all":             (pcap_analysis, "cli_all", "PCAP: all", "path"),

        # ── Pivot ──
        "pivot.reverse":        (pivot_helper, "quick_reverse",
                                 "Pivot: reverse", "none"),
        "pivot.bind":           (pivot_helper, "quick_bind", "Pivot: bind", "none"),
        "pivot.tty":            (pivot_helper, "quick_tty", "Pivot: TTY", "none"),
        "pivot.transfer":       (pivot_helper, "quick_transfer",
                                 "Pivot: transfer", "none"),
        "pivot.tunnel":         (pivot_helper, "quick_pivot",
                                 "Pivot: tunnel", "none"),
        "pivot.linux":          (pivot_helper, "quick_linux_privesc",
                                 "Pivot: linux privesc", "none"),
        "pivot.windows":        (pivot_helper, "quick_windows_privesc",
                                 "Pivot: windows privesc", "none"),
        "pivot.encode":         (pivot_helper, "quick_encoding",
                                 "Pivot: encode", "none"),
        "pivot.container":      (pivot_helper, "quick_container_escape",
                                 "Pivot: container escape", "none"),
        "pivot.cloud":          (pivot_helper, "quick_cloud_metadata",
                                 "Pivot: cloud metadata", "none"),
        "pivot.creds":          (pivot_helper, "quick_cred_dump",
                                 "Pivot: credential dump", "none"),
        "pivot.persist":        (pivot_helper, "quick_persistence",
                                 "Pivot: persistence", "none"),

        # ── C2 ──
        "c2.sheets":            (redteam_c2, "cli_sheets", "C2: sheets", "none"),
        "c2.sliver":            (redteam_c2, "cli_sliver", "C2: Sliver", "none"),
        "c2.havoc":             (redteam_c2, "cli_havoc", "C2: Havoc", "none"),
        "c2.mythic":            (redteam_c2, "cli_mythic", "C2: Mythic", "none"),
        "c2.donut":             (redteam_c2, "cli_donut", "C2: Donut", "none"),
        "c2.opsec":             (redteam_c2, "cli_opsec", "C2: OpSec", "none"),
        "c2.generators":        (redteam_c2, "cli_generators",
                                 "C2: generators", "none"),
        "c2.listeners":         (redteam_c2, "cli_listeners",
                                 "C2: listeners", "none"),
        "c2.infra":             (redteam_c2, "cli_infrastructure",
                                 "C2: infrastructure", "none"),
        "c2.evasion":           (redteam_c2, "cli_evasion",
                                 "C2: defense evasion", "none"),
        "c2.mitre":             (redteam_c2, "cli_mitre", "C2: MITRE", "none"),

        # ── Shell ──
        "shell.start":          (shell_manager, "quick_start",
                                 "Shell: start :4444", "none"),
        "shell.stop":           (shell_manager, "quick_stop",
                                 "Shell: stop", "none"),
        "shell.status":         (shell_manager, "quick_status",
                                 "Shell: status", "none"),
        "shell.list":           (shell_manager, "quick_list",
                                 "Shell: list", "none"),

        # ── Shell Listener Pro ──
        "shell_pro.linux":      (shell_listener_pro, "cli_repl",
                                 "ShellPro: Linux", "none"),
        "shell_pro.win":        (shell_listener_pro, "cli_repl_win",
                                 "ShellPro: Windows", "none"),
        "shell_pro.quiet":      (shell_listener_pro, "cli_repl_no_auto",
                                 "ShellPro: quiet", "none"),
        "shell_pro.help":       (shell_listener_pro, "show_listener_help",
                                 "ShellPro: help", "none"),
        "shell_pro.shortcuts":  (shell_listener_pro, "show_shortcuts",
                                 "ShellPro: shortcuts", "none"),

        # ── Adversary Emulation ──
        "adv_emul.list":        (adversary_emulation, "cli_list",
                                 "ATT&CK: list", "none"),
        "adv_emul.tactics":     (adversary_emulation, "cli_tactics",
                                 "ATT&CK: coverage", "none"),
        "adv_emul.tactic":      (adversary_emulation, "cli_by_tactic",
                                 "ATT&CK: tactic", "word"),
        "adv_emul.platform":    (adversary_emulation, "cli_by_platform",
                                 "ATT&CK: platform", "word"),
        "adv_emul.detail":      (adversary_emulation, "cli_detail",
                                 "ATT&CK: detail", "word"),
        "adv_emul.export_json": (adversary_emulation, "cli_list",
                                 "ATT&CK: export JSON", "none"),
        "adv_emul.export_md":   (adversary_emulation, "cli_list",
                                 "ATT&CK: export MD", "none"),
        "adv_emul.export_nav":  (adversary_emulation, "cli_list",
                                 "ATT&CK: Navigator", "none"),

        # ── Bug Bounty ──
        "bugbounty.cvss":       (bugbounty, "cvss_calculator",
                                 "BB: CVSS calculator", "none"),
        "bugbounty.report":     (bugbounty, "generate_report",
                                 "BB: генератор отчёта", "none"),
        "bugbounty.export_csv": (bugbounty, "export_history_csv",
                                 "BB: export CSV", "none"),
        "bugbounty.export_json": (bugbounty, "export_history_json",
                                  "BB: export JSON", "none"),
        "bugbounty.h1_tpl":     (bugbounty, "hackerone_template",
                                 "BB: HackerOne шаблон", "none"),
        "bugbounty.bc_tpl":     (bugbounty, "bugcrowd_template",
                                 "BB: Bugcrowd шаблон", "none"),

        # ── Auto-Scan / Autopilot ──
        "autoscan.quick":       (bugbounty_autoscan, "cli_scan",
                                 "AutoScan: quick", "domain"),
        "autoscan.full":        (bugbounty_autoscan, "cli_scan",
                                 "AutoScan: full", "domain"),
        "autoscan.deep":        (bugbounty_autoscan, "cli_scan",
                                 "AutoScan: deep", "domain"),
        "autoscan.profiles":    (bugbounty_autoscan, "cli_profiles",
                                 "AutoScan: profiles", "none"),
        "autoscan.past":        (bugbounty_autoscan, "cli_past",
                                 "AutoScan: past", "none"),

        "autopilot.quick":      (bugbounty_autopilot, "cli_run",
                                 "AP: quick", "domain"),
        "autopilot.full":       (bugbounty_autopilot, "cli_run",
                                 "AP: full", "domain"),
        "autopilot.deep":       (bugbounty_autopilot, "cli_run",
                                 "AP: deep", "domain"),
        "autopilot.profiles":   (bugbounty_autopilot, "cli_profiles",
                                 "AP: profiles", "none"),
        "autopilot.past":       (bugbounty_autopilot, "cli_past",
                                 "AP: past", "none"),

        # ── Report Pack ──
        "reportpack.platforms": (report_pack, "cli_platforms",
                                 "RPack: platforms", "none"),
        "reportpack.presets":   (report_pack, "cli_presets",
                                 "RPack: presets", "none"),
        "reportpack.list":      (report_pack, "cli_list",
                                 "RPack: list", "none"),
        "reportpack.new_h1":    (report_pack, "cli_wizard",
                                 "RPack: new (H1)", "none"),
        "reportpack.cvss":      (report_pack, "cli_cvss",
                                 "RPack: CVSS", "word"),
        "reportpack.timeline":  (report_pack, "cli_timeline",
                                 "RPack: timeline", "none"),

        # ── Reports / Auto-Report ──
        "report.html":          (report_export, "export_html",
                                 "History → HTML", "none"),
        "report.pdf":           (report_export, "export_pdf",
                                 "History → PDF", "none"),
        "report.csv":           (report_export, "export_csv",
                                 "History → CSV", "none"),
        "report.md":            (report_export, "export_markdown",
                                 "History → MD", "none"),
        "report.json":          (report_export, "export_json",
                                 "History → JSON", "none"),
        "autoreport.html":      (auto_report, "quick_html",
                                 "AutoReport: HTML", "none"),
        "autoreport.pdf":       (auto_report, "quick_pdf",
                                 "AutoReport: PDF", "none"),
        "autoreport.json":      (auto_report, "quick_json",
                                 "AutoReport: JSON", "none"),
        "autoreport.md":        (auto_report, "quick_markdown",
                                 "AutoReport: Markdown", "none"),
        "autoreport.diff":      (auto_report, "incremental_diff",
                                 "AutoReport: diff", "none"),

        # ── Social Engineering ──
        "se.templates":         (social_engineer, "cli_templates",
                                 "SE: templates", "none"),
        "se.qr":                (social_engineer, "cli_qr",
                                 "SE: QR", "word"),
        "se.email":             (social_engineer, "cli_email",
                                 "SE: email", "word"),
        "se.sms":               (social_engineer, "cli_sms",
                                 "SE: SMS", "word"),
        "se.voice":             (social_engineer, "cli_voice",
                                 "SE: voice script", "word"),
        "se.clone":             (social_engineer, "cli_clone",
                                 "SE: clone", "url"),
        "se.obfuscate":         (social_engineer, "cli_obfuscate",
                                 "SE: obfuscate URL", "url"),
        "se.pixel":             (social_engineer, "cli_pixel",
                                 "SE: tracking pixel", "none"),

        # ── SSRF Pro ──
        "ssrf.cloud":           (ssrf_pro, "cli_cloud",
                                 "SSRF: cloud metadata", "none"),
        "ssrf.ip":              (ssrf_pro, "cli_ip",
                                 "SSRF: IP bypasses", "none"),
        "ssrf.schemes":         (ssrf_pro, "cli_schemes",
                                 "SSRF: scheme payloads", "none"),
        "ssrf.parser":          (ssrf_pro, "cli_parser",
                                 "SSRF: parser confusion", "none"),
        "ssrf.rebind":          (ssrf_pro, "cli_rebind",
                                 "SSRF: DNS rebinding", "word"),
        "ssrf.blind":           (ssrf_pro, "cli_blind",
                                 "SSRF: blind helpers", "none"),
        "ssrf.chains":          (ssrf_pro, "cli_chains",
                                 "SSRF: RCE chains", "none"),
        "ssrf.export_all":      (ssrf_pro, "cli_export_all",
                                 "SSRF: export all", "none"),

        # ── Web3 ──
        "web3.solidity":        (web3_security, "cli_solidity",
                                 "Web3: .sol scan", "path"),
        "web3.dir":             (web3_security, "cli_dir",
                                 "Web3: dir scan", "path"),
        "web3.pk":              (web3_security, "cli_pk",
                                 "Web3: private keys", "path"),
        "web3.etherscan":       (web3_security, "cli_etherscan",
                                 "Web3: Etherscan", "word"),
        "web3.honeypot":        (web3_security, "cli_honeypot",
                                 "Web3: honeypot", "word"),
        "web3.drainer":         (web3_security, "cli_drainer",
                                 "Web3: drainer patterns", "path"),

        # ── Mobile ──
        "mobile.analyze":       (mobile_security, "cli_analyze",
                                 "Mobile: analyze", "path"),
        "mobile.apk":           (mobile_security, "cli_apk",
                                 "Mobile: APK", "path"),
        "mobile.ipa":           (mobile_security, "cli_ipa",
                                 "Mobile: IPA", "path"),

        # ── RE ──
        "re.analyze":           (re_suite, "cli_analyze", "RE: analyze", "path"),
        "re.strings":           (re_suite, "cli_strings", "RE: strings", "path"),
        "re.entropy":           (re_suite, "cli_entropy", "RE: entropy", "path"),
        "re.yara":              (re_suite, "cli_yara", "RE: YARA", "path"),
        "re.pe":                (re_suite, "cli_pe", "RE: PE", "path"),
        "re.elf":               (re_suite, "cli_elf", "RE: ELF", "path"),
        "re.macho":             (re_suite, "cli_macho", "RE: Mach-O", "path"),
        "re.shellcode":         (re_suite, "cli_shellcode", "RE: shellcode", "path"),
        "re.miner":             (re_suite, "cli_miner", "RE: miner", "path"),

        # ── Forensics ──
        "forensics.ioc":        (forensics_ir, "cli_ioc", "Forensics: IOC", "path"),
        "forensics.timeline":   (forensics_ir, "cli_timeline",
                                 "Forensics: timeline", "path"),
        "forensics.sysmon":     (forensics_ir, "cli_sysmon",
                                 "Forensics: Sysmon", "path"),
        "forensics.authlog":    (forensics_ir, "cli_authlog",
                                 "Forensics: auth.log", "path"),
        "forensics.auditd":     (forensics_ir, "cli_auditd",
                                 "Forensics: auditd", "path"),
        "forensics.yara":       (forensics_ir, "cli_yara",
                                 "Forensics: YARA", "path"),

        # ── HTTP Proxy ──
        "http_proxy.start":     (http_proxy, "quick_start",
                                 "Proxy: start :8080", "none"),
        "http_proxy.stop":      (http_proxy, "quick_stop", "Proxy: stop", "none"),
        "http_proxy.status":    (http_proxy, "quick_status",
                                 "Proxy: status", "none"),
        "http_proxy.ca":        (http_proxy, "quick_ca_info",
                                 "Proxy: CA info", "none"),
        "http_proxy.rules":     (http_proxy, "quick_rules",
                                 "Proxy: rules", "none"),

        # ── Stego / Utils / Screenshot ──
        "stego.chi_png":        (stego_pro, "chi_square_png",
                                 "Stego: chi PNG", "path"),
        "stego.chi_wav":        (stego_pro, "chi_square_wav",
                                 "Stego: chi WAV", "path"),
        "stego.rs":             (stego_pro, "cli_rs",
                                 "Stego: RS-analysis", "path"),
        "stego.spa":            (stego_pro, "cli_spa",
                                 "Stego: SPA", "path"),
        "stego.capacity":       (stego_pro, "cli_capacity",
                                 "Stego: capacity", "path"),
        "utils.filehash":       (utils_tools, "file_hashes",
                                 "File hashes", "path"),
        "screenshot.one":       (screenshot, "screenshot_one",
                                 "Screenshot", "url"),

        # ── Wordlists ──
        "wordlists.list":       (wordlist_updater, "list_local_wordlists",
                                 "WL: list", "none"),
        "wordlists.check":      (wordlist_updater, "check_updates",
                                 "WL: check", "none"),
        "wordlists.updateall":  (wordlist_updater, "update_all",
                                 "WL: update all", "none"),
        "wordlists.categories": (wordlist_updater, "show_categories",
                                 "WL: categories", "none"),
        "wordtools.gen":        (wordlist_tools, "generate_wordlist",
                                 "WLTools: gen", "word"),

        # ── Notes / Stats ──
        "notes.stats":          (notes, "cli_stats", "Notes: stats", "none"),
        "notes.list":           (notes, "cli_list", "Notes: list", "none"),
        "notes.findings":       (_FindingsProxy(), "run",
                                 "Notes: findings", "none"),
        "notes.by_target":      (notes, "cli_by_target",
                                 "Notes: findings by target", "none"),
        "notes.timeline":       (notes, "cli_timeline",
                                 "Notes: timeline", "none"),
        "stats.summary":        (stats, "text_summary",
                                 "Stats: summary", "none"),
        "stats.graphs":         (stats, "generate_all", "Stats: graphs", "none"),

        # ── Scheduler / Notifier / Bot ──
        "scheduler.list":       (scheduler, "list_jobs",
                                 "Scheduler: list", "none"),
        "scheduler.history":    (scheduler, "show_history",
                                 "Scheduler: history", "none"),
        "scheduler.pause":      (scheduler, "pause_scheduler",
                                 "Scheduler: pause", "none"),
        "scheduler.resume":     (scheduler, "resume_scheduler",
                                 "Scheduler: resume", "none"),
        "notifier.status":      (notifier, "status",
                                 "Notifier: status", "none"),
        "notifier.testall":     (notifier, "test_all",
                                 "Notifier: test all", "none"),
        "notifier.history":     (notifier, "show_history",
                                 "Notifier: history", "none"),
        "bot.info":             (telegram_bot, "info", "Bot: info", "none"),

        # ── Compliance / SDK ──
        "compliance.cis":       (compliance_audit, "cli_cis",
                                 "Audit: CIS", "none"),
        "compliance.owasp":     (compliance_audit, "cli_owasp_top10",
                                 "Audit: OWASP", "none"),
        "compliance.asvs":      (compliance_audit, "cli_asvs",
                                 "Audit: ASVS", "none"),
        "compliance.pci":       (compliance_audit, "cli_pci",
                                 "Audit: PCI-DSS", "none"),
        "compliance.iso":       (compliance_audit, "cli_iso",
                                 "Audit: ISO 27001", "none"),
        "compliance.nist":      (compliance_audit, "cli_nist",
                                 "Audit: NIST 800-53", "none"),
        "compliance.all":       (compliance_audit, "cli_all",
                                 "Audit: всё", "none"),

        "sdk.list":             (plugin_sdk, "list_plugins_detailed",
                                 "SDK: list", "none"),
        "sdk.validate":         (plugin_sdk, "validate_all_plugins",
                                 "SDK: validate", "none"),
        "sdk.docs":             (plugin_sdk, "print_docs",
                                 "SDK: docs", "none"),
        "sdk.templates":        (plugin_sdk, "print_templates",
                                 "SDK: templates", "none"),
        "sdk.generate":         (plugin_sdk, "generate_plugin",
                                 "SDK: generate", "word"),

        # ── Plugins ──
        "plugins.list":         (plugin_loader, "list_plugins_cli",
                                 "Plugins: list", "none"),
        "plugins.reload":       (plugin_loader, "reload_plugins",
                                 "Plugins: reload", "none"),

        # ── Roadmap ──
        "roadmap.roadmap":      (roadmap, "show_roadmap",
                                 "Roadmap: показать", "none"),
        "roadmap.resources":    (roadmap, "show_resources",
                                 "Roadmap: ресурсы", "none"),
        "roadmap.certs":        (roadmap, "show_certifications",
                                 "Roadmap: сертификации", "none"),
        "roadmap.quiz":         (roadmap, "run_quiz",
                                 "Roadmap: квиз", "none"),
        "roadmap.progress":     (roadmap, "show_progress",
                                 "Roadmap: прогресс", "none"),
        "roadmap.streak":       (roadmap, "cli_streak",
                                 "Roadmap: streak", "none"),

        # ── Async ──
        "async.portscan":       (async_engine, "async_port_scan",
                                 "Async: портскан", "target"),
        "async.http":           (async_engine, "async_http_scan",
                                 "Async: HTTP-скан", "url"),
        "async.udp":            (async_engine, "async_udp_scan",
                                 "Async: UDP-скан", "target"),
    }

    # Динамические плагины
    try:
        for act in plugin_loader.get_all_actions():
            key = act["key"]
            qa[key] = (
                _ActionProxy(act["func"]),
                "run",
                f"[{act['plugin']}] {act['description']}",
                act["arg_hint"],
            )
    except Exception as exc:  # noqa: BLE001
        log.warning("Плагины не загружены: %s", exc)

    return qa


QUICK_ACTIONS: dict = _build_quick_actions()


def _rebuild_quick_actions() -> dict:
    """Пересобрать QUICK_ACTIONS (включая плагины)."""
    global QUICK_ACTIONS
    QUICK_ACTIONS = _build_quick_actions()
    return QUICK_ACTIONS


def _get_plugin_group_entries() -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    try:
        for pname, pdata in plugin_loader.get_registry().items():
            entries.append((f"plugin-{pname}",
                            f"{pname} ({len(pdata['actions'])})"))
    except Exception:  # noqa: BLE001
        pass
    return entries


# ============================================================================
# TEXTUAL APP
# ============================================================================

class CyberToolkitApp(App):
    """TUI CyberSec Toolkit. Author: idqwixxa."""

    CSS = """
    Screen { background: #050505; color: #c8c8c8; }
    #topbar {
        height: 3; background: #0a0a0a; color: #00ff9c;
        content-align: center middle; border-bottom: solid #00ff9c;
    }
    #body { height: 1fr; }
    #left_panel {
        width: 44; border: round #00ff9c; background: #080808; padding: 0 1;
    }
    #menu_scroll {
        height: 1fr; scrollbar-color: #00ff9c; scrollbar-background: #0a0a0a;
        scrollbar-size-vertical: 1;
    }
    .group_title {
        color: #00ff9c; text-style: bold; padding: 1 0 0 0;
        background: #080808;
    }
    #left_panel Button {
        width: 100%; height: 2; min-height: 2; margin: 0; border: none;
        background: #0d0d0d; color: #a0a0a0; padding-left: 2;
    }
    #left_panel Button:hover { background: #003322; color: #00ff9c; }
    #left_panel Button:focus {
        background: #005533; color: #ffffff; text-style: bold;
    }
    #sys_buttons {
        height: auto; border-top: solid #003322; padding-top: 1; margin-top: 1;
    }
    #right_panel { border: round #00ff9c; padding: 1 1; background: #080808; }
    #result_log {
        height: 1fr; border: round #003322; background: #030303; padding: 0 1;
        scrollbar-color: #00ff9c; scrollbar-background: #050505;
    }
    #bottom_bar {
        height: 9; border: round #00ff9c; padding: 0 1; background: #080808;
    }
    #action_hint { height: 1; color: #00ff9c; }
    #arg_input { height: 3; border: round #003322; background: #050505; }
    #arg_input:focus { border: round #00ff9c; }
    #action_row { height: 3; }
    #action_select { width: 1fr; }
    #run_action { width: 18; height: 3; margin: 0 0 0 1; }
    #clear_log { width: 5; height: 3; margin: 0 0 0 1; }
    #statusbar { height: 1; background: #0a0a0a; color: #666; padding: 0 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Выход"),
        Binding("r", "refresh_history", "История"),
        Binding("c", "clear_log", "Очистить"),
        Binding("ctrl+r", "run_selected", "Запустить", priority=True),
        Binding("ctrl+l", "focus_arg", "К аргументу", priority=True),
        Binding("escape", "focus_arg", "Аргумент"),
        Binding("ctrl+p", "command_palette", "Команды"),
    ]

    current_module: reactive[str] = reactive("")

    def on_resize(self, event) -> None:
        try:
            self.refresh(layout=True)
        except Exception:  # noqa: BLE001
            pass

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="topbar"):
            yield Label(Text.from_markup(
                "[bold green]╔══ CYBERSEC TOOLKIT ══╗[/bold green]  "
                "[cyan]TermuxVoid-style[/cyan]  "
                f"[magenta]by {AUTHOR}[/magenta]  "
                f"[dim]v{VERSION}[/dim]  "
                "[yellow]⚠ ethical use only[/yellow]"
            ))
        with Horizontal(id="body"):
            with Vertical(id="left_panel"):
                yield Label("[bold cyan]📂 МОДУЛИ[/bold cyan]")
                with ScrollableContainer(id="menu_scroll"):
                    for group_name, modules in MODULE_GROUPS:
                        yield Label(
                            f"[bold green]{group_name}[/bold green]",
                            classes="group_title",
                        )
                        if group_name == "🧩 Плагины":
                            with Vertical(id="plugin_buttons"):
                                yield Label("[dim]  загрузка…[/dim]")
                        else:
                            for key, title in modules:
                                yield Button(title, id=f"module-{key}")
                with Vertical(id="sys_buttons"):
                    yield Button("🔄  Reload plugins",
                                  id="reload_plugins")
                    yield Button("📜  История", id="history")
                    yield Button("ℹ  О программе", id="about")
                    yield Button("❌  Выход", id="quit")
            with Vertical(id="right_panel"):
                yield RichLog(highlight=True, markup=True,
                              wrap=True, id="result_log")
        with Vertical(id="bottom_bar"):
            yield Label(
                "[cyan]▶ Быстрое действие:[/cyan] сначала кликни модуль "
                "слева, потом выбери команду и жми [green]Ctrl+R[/green] "
                "(или Enter в поле аргумента).",
                id="action_hint",
            )
            yield Input(
                placeholder="Аргумент (домен / URL / IP / hash / путь)…",
                id="arg_input",
            )
            with Horizontal(id="action_row"):
                yield Select(
                    options=[("— сначала выбери модуль слева —",
                              "__empty__")],
                    prompt="выбери действие…",
                    id="action_select",
                    allow_blank=False,
                )
                yield Button("▶ Запустить", id="run_action",
                              variant="success")
                yield Button("🧹", id="clear_log", variant="warning")
        with Container(id="statusbar"):
            yield Label("", id="status_text")
        yield Footer()

    def on_mount(self) -> None:
        self._write("[bold cyan]╔══ Добро пожаловать в CyberSec "
                    "Toolkit ══╗[/bold cyan]")
        self._write(f"[magenta]by {AUTHOR}  •  v{VERSION}[/magenta]")
        self._write("")
        self._write("[yellow]⚠ Только для этичного использования."
                    "[/yellow]")
        self._write("")
        self._write("[dim]Как пользоваться:[/dim]")
        self._write("[dim]  1. Кликни модуль слева (например "
                    "[cyan]Network[/cyan] или [cyan]Censys[/cyan])."
                    "[/dim]")
        self._write("[dim]  2. Внизу появится список действий этого "
                    "модуля.[/dim]")
        self._write("[dim]  3. Выбери действие → введи аргумент → "
                    "[green]Ctrl+R[/green] или Enter.[/dim]")
        self._write("")
        try:
            n_plugins = len(plugin_loader.get_registry())
            self._write(f"[dim]🧩 Загружено плагинов: {n_plugins}[/dim]")
        except Exception:  # noqa: BLE001
            pass
        self._refresh_status()
        self.set_timer(0.3, lambda: self.refresh(layout=True))
        self.set_timer(0.1, self._populate_plugin_buttons)

    def _populate_plugin_buttons(self) -> None:
        """Пересобрать секцию плагинов в левой панели."""
        try:
            container = self.query_one("#plugin_buttons")
        except Exception:  # noqa: BLE001
            return

        async def _rebuild() -> None:
            try:
                await container.remove_children()
            except Exception:  # noqa: BLE001
                pass
            entries = _get_plugin_group_entries()
            if not entries:
                try:
                    await container.mount(
                        Label("[dim]  плагинов нет[/dim]")
                    )
                except Exception:  # noqa: BLE001
                    pass
                return
            for key, title in entries:
                try:
                    await container.mount(
                        Button(title, id=f"module-{key}")
                    )
                except Exception as exc:  # noqa: BLE001
                    log.debug("mount plugin button: %s", exc)

        try:
            self.run_worker(_rebuild(), exclusive=False)
        except Exception:  # noqa: BLE001
            pass

    def _refresh_status(self) -> None:
        try:
            rows = db.history(1)
            total = 0
            if rows:
                cur = db.conn.cursor()
                cur.execute("SELECT COUNT(*) as c FROM scans")
                total = cur.fetchone()["c"]

            vault_status = "—"
            try:
                v = vault.get_vault()
                if not v.exists():
                    vault_status = "—"
                elif v.unlocked:
                    vault_status = "🔓"
                else:
                    vault_status = "🔐"
            except Exception:  # noqa: BLE001
                pass

            notes_count = 0
            findings_count = 0
            cves_count = 0
            try:
                cur = db.conn.cursor()
                cur.execute("SELECT COUNT(*) as c FROM notes")
                notes_count = cur.fetchone()["c"]
                cur.execute("SELECT COUNT(*) as c FROM notes "
                            "WHERE kind='finding'")
                findings_count = cur.fetchone()["c"]
                cur.execute("SELECT COUNT(*) as c FROM cves")
                cves_count = cur.fetchone()["c"]
            except Exception:  # noqa: BLE001
                pass

            proxy_status = "—"
            try:
                if http_proxy._server_thread and \
                        http_proxy._server_thread.is_alive():
                    proxy_status = "🟢:8080"
            except Exception:  # noqa: BLE001
                pass

            shell_status = "—"
            try:
                srv = shell_manager.get_server()
                if srv and srv.running:
                    shell_status = f"🟢:{srv.port}({len(srv.sessions)})"
            except Exception:  # noqa: BLE001
                pass

            try:
                n_plugins = len(plugin_loader.get_registry())
            except Exception:  # noqa: BLE001
                n_plugins = 0

            status = (
                f"[green]●[/green] Сканов: [cyan]{total}[/cyan]   "
                f"[green]●[/green] CVE: [cyan]{cves_count}[/cyan]   "
                f"[green]●[/green] Vault: {vault_status}   "
                f"[green]●[/green] Notes: [cyan]{notes_count}[/cyan]"
                f"[red](F:{findings_count})[/red]   "
                f"[green]●[/green] Plugins: [cyan]{n_plugins}[/cyan]   "
                f"[green]●[/green] Proxy: [cyan]{proxy_status}[/cyan]   "
                f"[green]●[/green] Shell: [cyan]{shell_status}[/cyan]   "
                f"[magenta]by {AUTHOR}[/magenta]"
            )
            self.query_one("#status_text", Label).update(status)
        except Exception:  # noqa: BLE001
            pass

    def _log(self) -> RichLog:
        return self.query_one("#result_log", RichLog)

    def _write(self, text: str) -> None:
        """Для НАШИХ сообщений с Rich markup."""
        try:
            self._log().write(Text.from_markup(text))
        except Exception:  # noqa: BLE001
            self._log().write(Text(text))

    def _write_raw(self, text: str) -> None:
        """Для вывода МОДУЛЕЙ — без парсинга markup."""
        try:
            self._log().write(Text(text))
        except Exception:  # noqa: BLE001
            pass

    def _clear(self) -> None:
        self._log().clear()

    def action_clear_log(self) -> None:
        self._clear()

    def action_refresh_history(self) -> None:
        self.show_history()

    def action_focus_arg(self) -> None:
        try:
            self.query_one("#arg_input", Input).focus()
        except Exception:  # noqa: BLE001
            pass

    def action_run_selected(self) -> None:
        self.run_selected_action()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.run_selected_action()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid == "quit":
            self.exit()
        elif bid == "history":
            self.show_history()
        elif bid == "about":
            self.show_about()
        elif bid == "run_action":
            self.run_selected_action()
        elif bid == "clear_log":
            self._clear()
        elif bid == "reload_plugins":
            self.reload_plugins()
        elif bid.startswith("module-"):
            self.show_module_info(bid.split("-", 1)[1])

    def reload_plugins(self) -> None:
        """Полный reload: реестр + QUICK_ACTIONS + UI + Select."""
        self._clear()
        self._write("[cyan]🔄 Перечитываю плагины…[/cyan]")

        try:
            reg = plugin_loader.reload_plugins()
        except Exception as exc:  # noqa: BLE001
            self._write(f"[red]Ошибка reload: {exc}[/red]")
            return

        self._write(f"[green]✓ Загружено плагинов: {len(reg)}[/green]")
        for name, data in reg.items():
            self._write(f"  [cyan]{name}[/cyan] "
                        f"[dim]v{data['version']} — "
                        f"{len(data['actions'])} действий[/dim]")

        try:
            qa = _rebuild_quick_actions()
            self._write(f"[green]✓ Собрано действий: {len(qa)}[/green]")
        except Exception as exc:  # noqa: BLE001
            self._write(f"[yellow]QuickActions: {exc}[/yellow]")

        self._populate_plugin_buttons()
        if self.current_module:
            self._refresh_action_select(self.current_module)
        self._refresh_status()

    def action_reload_plugins(self) -> None:
        self.reload_plugins()

    def show_about(self) -> None:
        self._clear()
        for line in TUI_BANNER.splitlines():
            if line.strip():
                self._write(f"[cyan]{line}[/cyan]")
        self._write("")
        self._write(f"[magenta]Разработчик: {AUTHOR}[/magenta]")
        self._write(f"[magenta]Версия: {VERSION}[/magenta]")
        self._write("")
        self._write(f"[red]{DISCLAIMER}[/red]")

    def _refresh_action_select(self, module_key: str | None = None) -> None:
        """Пересобрать Select с быстрыми действиями для модуля/плагина."""
        try:
            sel = self.query_one("#action_select", Select)
        except Exception:  # noqa: BLE001
            return

        if not module_key:
            options = [("— сначала выбери модуль слева —", "__empty__")]
        elif module_key.startswith("plugin-"):
            pname = module_key[len("plugin-"):]
            prefix = f"plugin.{pname}."
            filtered = [
                (f"{k}  —  {v[2]}", k)
                for k, v in QUICK_ACTIONS.items()
                if k.startswith(prefix)
            ]
            if not filtered:
                options = [(f"⚠ У плагина '{pname}' нет действий",
                            "__empty__")]
            else:
                options = filtered
        else:
            prefix = PREFIX_MAP.get(module_key, f"{module_key}.")
            filtered = [
                (f"{k}  —  {v[2]}", k)
                for k, v in QUICK_ACTIONS.items()
                if k.startswith(prefix)
            ]
            if not filtered:
                options = [(f"⚠ Нет быстрых действий для '{module_key}'",
                            "__empty__")]
            else:
                options = filtered

        async def _apply() -> None:
            try:
                sel.set_options(options)
                try:
                    sel.value = "__empty__"
                except Exception:
                    pass
            except Exception as exc:  # noqa: BLE001
                log.debug("set_options: %s", exc)

        try:
            self.run_worker(_apply(), exclusive=False)
        except Exception:
            try:
                sel.set_options(options)
                try:
                    sel.value = "__empty__"
                except Exception:
                    pass
            except Exception as exc:  # noqa: BLE001
                log.debug("set_options sync fallback: %s", exc)

    def show_module_info(self, key: str) -> None:
        self._clear()
        self.current_module = key

        if key.startswith("plugin-"):
            pname = key[len("plugin-"):]
            plugin = plugin_loader.get_plugin(pname)
            if plugin:
                self._write(f"[bold cyan]🧩 Плагин: "
                            f"{plugin['name']}[/bold cyan]")
                self._write(f"[dim]v{plugin['version']} by "
                            f"{plugin['author']}[/dim]")
                self._write(f"[white]{plugin['description']}[/white]")
                self._write("")
                for i, a in enumerate(plugin["actions"], 1):
                    self._write(f"  [green]{i}. {a['name']}[/green]  — "
                                f"{a['description']}  "
                                f"[dim]({a['arg_hint']})[/dim]")
                self._refresh_action_select(key)
            return

        title = key
        for _group, modules in MODULE_GROUPS:
            for mkey, mtitle in modules:
                if mkey == key:
                    title = mtitle
                    break

        if key in INFO_CARDS:
            icon_title, desc, cli = INFO_CARDS[key]
            self._write(f"[bold cyan]{icon_title}[/bold cyan]")
            self._write(f"[dim]CLI: python main.py {cli}[/dim]")
            self._write("[dim]─────────────────────────────[/dim]")
            self._write("")
            self._write(f"[white]{desc}[/white]")
            self._write("")
            self._write("[bold yellow]Быстрые действия:[/bold yellow]")
        else:
            self._write(f"[bold cyan]📦 Модуль: {title}[/bold cyan]")
            self._write("[dim]─────────────────────────────[/dim]")
            self._write("")
            self._write("[bold yellow]Быстрые действия:[/bold yellow]")

        prefix = PREFIX_MAP.get(key, f"{key}.")
        found = False
        for action_key, (_m, _fn, desc, arg) in QUICK_ACTIONS.items():
            if action_key.startswith(prefix):
                found = True
                arg_hint = {
                    "none": "[dim]без аргумента[/dim]",
                    "target": "[cyan]домен/IP[/cyan]",
                    "url": "[cyan]URL[/cyan]",
                    "host": "[cyan]host[/cyan]",
                    "domain": "[cyan]домен[/cyan]",
                    "hash": "[cyan]hash[/cyan]",
                    "path": "[cyan]путь[/cyan]",
                    "query": "[cyan]запрос[/cyan]",
                    "username": "[cyan]username[/cyan]",
                    "email": "[cyan]email[/cyan]",
                    "phone": "[cyan]телефон[/cyan]",
                    "ip": "[cyan]IP[/cyan]",
                    "sha": "[cyan]SHA-256[/cyan]",
                    "network": "[cyan]CIDR[/cyan]",
                    "word": "[cyan]слово[/cyan]",
                    "number": "[cyan]число[/cyan]",
                }.get(arg, f"[dim]{arg}[/dim]")
                self._write(f"  [green]{action_key:<30}[/green] "
                            f"{desc:<32} {arg_hint}")

        if not found:
            self._write("[yellow]У модуля нет быстрых действий — "
                        "используй CLI-меню.[/yellow]")
        self._write("")
        self._write("[dim]Выбери действие в списке внизу и нажми "
                    "Ctrl+R (или Enter в поле аргумента).[/dim]")

        self._refresh_action_select(key)
        self.set_timer(0.1, self.action_focus_arg)

    def show_history(self) -> None:
        self._clear()
        self._write("[bold cyan]📜 Последние 25 сканов[/bold cyan]")
        self._write("[dim]─────────────────────────────[/dim]")
        rows = db.history(25)
        if not rows:
            self._write("[yellow]История пуста.[/yellow]")
            return
        for r in rows:
            self._write(
                f"[green]#{r['id']:<5}[/green] "
                f"[magenta]{r['module']:<20}[/magenta] "
                f"[cyan]{r['target']:<40}[/cyan] "
                f"[dim]{r['created_at']}[/dim]"
            )
        self._refresh_status()

    def run_selected_action(self) -> None:
        sel = self.query_one("#action_select", Select)
        arg_input = self.query_one("#arg_input", Input)
        action_key = sel.value if isinstance(sel.value, str) else None

        if not action_key or action_key == "__empty__" \
                or action_key not in QUICK_ACTIONS:
            self._write("[red]Сначала выбери действие в списке внизу "
                        "(кликни модуль слева).[/red]")
            return

        mod, fn_name, desc, arg_kind = QUICK_ACTIONS[action_key]
        is_plugin = action_key.startswith("plugin.")
        try:
            fn = getattr(mod, fn_name)
        except Exception as exc:  # noqa: BLE001
            self._write(f"[red]Ошибка загрузки: {exc}[/red]")
            return

        arg_value = arg_input.value.strip()

        self._clear()
        self._write(f"[bold cyan]▶ {desc}[/bold cyan]")
        self._write(f"[dim]action: {action_key}[/dim]")
        self._write("[dim]─────────────────────────────[/dim]")

        if arg_kind != "none":
            if arg_value:
                self._write(f"[yellow]Аргумент:[/yellow] {arg_value}")
            else:
                self._write("[red]✗ Нужен аргумент.[/red]")
                return
        self._write("")

        if is_plugin:
            if arg_kind == "none":
                run_module_async(fn, on_line=self._write_raw)
            else:
                run_module_async(fn, arg_value, on_line=self._write_raw)
            self.set_timer(2.0, self._refresh_status)
            return

        if self._handle_special(action_key, fn, arg_value):
            self.set_timer(2.0, self._refresh_status)
            return

        if arg_kind == "none":
            run_module_async(fn, on_line=self._write_raw)
        else:
            run_module_async(fn, arg_value, on_line=self._write_raw)

        self.set_timer(2.0, self._refresh_status)

    def _handle_special(self, key: str, fn, arg_value: str) -> bool:
        W = self._write_raw

        # Payload presets
        if key == "payloads.xss":
            run_module_async(fn, "xss", on_line=W); return True
        if key == "payloads.sqli":
            run_module_async(fn, "sqli", on_line=W); return True
        if key == "payloads.lfi":
            run_module_async(fn, "lfi", on_line=W); return True
        if key == "payloads.ssrf":
            run_module_async(fn, "ssrf", on_line=W); return True

        if key == "stats.graphs":
            run_module_async(fn, False, on_line=W); return True

        if key == "wordtools.gen":
            run_module_async(fn, arg_value, f"wl_{arg_value}.txt",
                             True, True, True, "", on_line=W)
            return True

        # Recon
        if key == "recon.portscan":
            run_module_async(fn, arg_value, "1-1024", on_line=W)
            return True
        if key == "recon.robots":
            run_module_async(fn, arg_value, on_line=W); return True
        if key == "recon.headers":
            run_module_async(fn, arg_value, on_line=W); return True
        if key == "recon.ssl":
            run_module_async(fn, arg_value, on_line=W); return True

        # Web
        if key == "web.dirb":
            run_module_async(fn, arg_value, 30, on_line=W)
            return True

        # Async
        if key == "async.portscan":
            run_module_async(fn, arg_value, "1-1024", 500, 1.0, on_line=W)
            return True
        if key == "async.http":
            run_module_async(fn, arg_value,
                             "admin,login,api,robots.txt,.env",
                             50, 5.0, on_line=W); return True
        if key == "async.udp":
            run_module_async(fn, arg_value, "53,123,161,1900",
                             2.0, 100, on_line=W); return True

        # Passwords
        if key == "passwords.genpass":
            run_module_async(fn, 16, on_line=W); return True
        if key == "passwords.genphrase":
            run_module_async(fn, 4, "-", on_line=W); return True

        # Network
        if key == "network.arp":
            run_module_async(fn, None, arg_value, on_line=W)
            return True

        # Crawler
        if key == "crawler.crawl":
            run_module_async(fn, arg_value, 1, 50, on_line=W)
            return True

        # Screenshot
        if key == "screenshot.one":
            run_module_async(fn, arg_value, True, on_line=W)
            return True

        # DNS tools
        if key == "dns_tools.ptr":
            run_module_async(fn, arg_value, 50, on_line=W)
            return True
        if key == "dns_tools.snoop":
            run_module_async(fn, arg_value, None, on_line=W)
            return True

        # Takeover
        if key in ("takeover.scan", "takeover_v2.scan",
                   "takeover.check", "takeover_v2.check"):
            run_module_async(fn, arg_value, on_line=W); return True
        if key in ("takeover.batch", "takeover_v2.batch"):
            run_module_async(fn, arg_value, 20, on_line=W); return True

        # Monitor
        if key == "monitor.add":
            run_module_async(fn, arg_value, 360, on_line=W); return True
        if key == "monitor.scan":
            run_module_async(fn, arg_value, False, on_line=W)
            return True

        # Stego
        if key == "stego.chi_png" or key == "stego.chi_wav" \
                or key == "stego.rs" or key == "stego.spa":
            from pathlib import Path as _P
            run_module_async(fn, _P(arg_value), on_line=W)
            return True
        if key == "stego.capacity":
            run_module_async(fn, arg_value, on_line=W); return True

        # Cloud storage
        if key == "cloud_storage.s3":
            run_module_async(fn, arg_value, "s3", 30, False, on_line=W)
            return True
        if key == "cloud_storage.gcs":
            run_module_async(fn, arg_value, "gcs", 30, False, on_line=W)
            return True
        if key == "cloud_storage.all":
            run_module_async(fn, arg_value, 30, False, on_line=W)
            return True
        if key == "cloud_storage.check":
            run_module_async(fn, arg_value, "s3", False, on_line=W)
            return True
        if key == "cloud_storage.batch":
            run_module_async(fn, arg_value, "s3", 20, False, on_line=W)
            return True

        if key == "cloud_attack.imds":
            run_module_async(fn, None, on_line=W); return True

        # K8s
        if key == "k8s_scan.scan":
            run_module_async(fn, arg_value, None, on_line=W)
            return True

        # AD
        if key == "ad_attack.cheat":
            run_module_async(fn, arg_value, on_line=W); return True

        # Wireless Attack
        if key == "wl_attack.wpa":
            run_module_async(fn, arg_value or "wlan0", on_line=W)
            return True
        if key == "wl_attack.pmkid":
            run_module_async(fn, arg_value or "wlan0", on_line=W)
            return True
        if key == "wl_attack.wps":
            run_module_async(fn, arg_value or "wlan0",
                             on_line=W); return True
        if key == "wl_attack.evil":
            run_module_async(fn, "Free WiFi", arg_value or "wlan0",
                             on_line=W); return True
        if key == "wl_pro.cheat":
            run_module_async(fn, arg_value, on_line=W); return True

        # SSRF
        if key == "ssrf.rebind":
            run_module_async(fn, arg_value, on_line=W); return True

        # Shell pro
        if key in ("shell_pro.linux", "shell_pro.win",
                   "shell_pro.quiet"):
            run_module_async(fn, on_line=W); return True

        # Report pack
        if key == "reportpack.new_h1":
            run_module_async(fn, "hackerone", on_line=W); return True
        if key == "reportpack.cvss":
            run_module_async(fn, arg_value, on_line=W); return True

        # Auto-Scan / Autopilot
        if key.startswith("autoscan."):
            profile = key.split(".", 1)[1]
            if profile in ("quick", "full", "deep"):
                run_module_async(fn, arg_value, profile, on_line=W)
                return True
        if key.startswith("autopilot."):
            profile = key.split(".", 1)[1]
            if profile in ("quick", "full", "deep"):
                run_module_async(fn, arg_value, profile, on_line=W)
                return True

        # Threat Hunting
        if key == "threat_hunting.playbook":
            run_module_async(fn, arg_value, on_line=W); return True
        if key == "threat_hunting.export_nav":
            run_module_async(fn, on_line=W); return True
        if key == "threat_hunting.export_dash":
            run_module_async(fn, on_line=W); return True

        # Threat Intel
        if key == "ti.bulk":
            run_module_async(fn, arg_value, 4, on_line=W); return True

        # API Fuzzer
        if key == "api_fuzzer.ratelimit":
            run_module_async(fn, arg_value, 50, on_line=W)
            return True
        if key == "api_fuzzer.bola":
            run_module_async(fn, arg_value, "/api/v1/users", "id",
                             on_line=W); return True

        # SDK
        if key == "sdk.generate":
            run_module_async(fn, arg_value, "basic", on_line=W)
            return True

        # Compliance
        if key == "compliance.cis":
            run_module_async(fn, on_line=W); return True
        if key == "compliance.all":
            run_module_async(fn, on_line=W); return True

        # Hash suite
        if key == "hash_suite.crack":
            run_module_async(fn, arg_value, None, None, on_line=W)
            return True
        if key == "hash_suite.file":
            run_module_async(fn, arg_value, None, None, on_line=W)
            return True

        # PCAP
        if key in ("pcap.analyze", "pcap.html", "pcap.csv",
                   "pcap.md", "pcap.all"):
            run_module_async(fn, arg_value, on_line=W); return True

        # Wireless toolkit
        if key == "wireless.full":
            run_module_async(fn, on_line=W); return True

        # Vault
        if key == "vault.health":
            run_module_async(fn, on_line=W); return True
        if key == "vault.gen":
            run_module_async(fn, on_line=W); return True

        return False


# ============================================================================
# run_tui
# ============================================================================

def run_tui() -> None:
    try:
        CyberToolkitApp().run()
    except Exception:  # noqa: BLE001
        print("=" * 60)
        print("ОШИБКА TUI:")
        print("=" * 60)
        import traceback
        traceback.print_exc()
        try:
            input("Enter — выход…")
        except Exception:
            pass


if __name__ == "__main__":
    run_tui()