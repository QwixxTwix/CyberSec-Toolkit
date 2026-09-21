"""
Главное Textual-приложение CyberSec Toolkit.
Author: idqwixxa
"""
import sys
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


MODULE_GROUPS = [
    ("🔎 Разведка", [
        ("recon",      "Reconnaissance"),
        ("dns_tools",  "DNS Tools"),
        ("osint",      "OSINT"),
        ("censys",     "Censys"),
        ("cve_feeds",  "CVE Feeds"),
        ("threat_intel", "Threat Intel"),
        ("async",      "Async Engine"),
    ]),
    ("⚔  Атаки", [
        ("web",        "Web Vulnerabilities"),
        ("wordpress",  "WordPress Scanner"),
        ("gql",        "GraphQL / API Discovery"),
        ("pivot",      "Pivot / Post-Exploit"),
        ("se",         "Social Engineering (CTF)"),
        ("passwords",  "Passwords & Hashes"),
        ("network",    "Network (ARP/WiFi)"),
        ("payloads",   "Payload Factory"),
        ("crawler",    "Web Crawler"),
        ("fuzzer",     "Web Fuzzer"),
        ("takeover",   "Subdomain Takeover"),
        ("proxy",      "HTTP/HTTPS Proxy"),
        ("shell",      "Shell Manager"),
    ]),
    ("🛠  Инструменты", [
        ("wireless",   "Wireless Toolkit"),
        ("wordlists",  "Wordlist Updater"),
        ("wordtools",  "Wordlist Tools"),
        ("screenshot", "Screenshot"),
        ("stego",      "Steganography Pro"),
    ]),
    ("🔐 Хранилище", [
        ("vault",      "Password Vault"),
    ]),
    ("📊 Отчёты и авто", [
        ("bugbounty",  "Bug Bounty"),
        ("autoscan",   "Auto-Scan (пайплайн)"),
        ("reportpack", "Report Templates Pack"),
        ("report",     "Report Export"),
        ("stats",      "Graph & Statistics"),
        ("notes",      "Notes & Findings"),
        ("autoreport", "Auto-Report Pro"),
        ("scheduler",  "Scheduler"),
        ("notifier",   "Notifier"),
        ("bot",        "Telegram Bot"),
    ]),
    ("🧩 Плагины", []),
    ("🎓 Обучение", [
        ("roadmap",    "Roadmap"),
        ("utils",      "Утилиты"),
    ]),
]


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


def _build_quick_actions() -> dict[str, tuple]:
    qa: dict[str, tuple] = {
        # Recon
        "recon.whois":        (recon, "whois_lookup", "WHOIS lookup", "target"),
        "recon.dns":          (recon, "dns_enum", "DNS enumeration", "target"),
        "recon.subdomain":    (recon, "subdomain_scan", "Subdomain scan", "target"),
        "recon.portscan":     (recon, "port_scan", "Port scan (1-1024)", "target"),
        "recon.geoip":        (recon, "ip_geolocation", "IP geolocation", "target"),
        "recon.fingerprint":  (recon, "tech_fingerprint", "Tech fingerprint", "url"),
        "recon.dork":         (recon, "google_dork", "Google dork", "domain"),
        "recon.shodan":       (recon, "shodan_lookup", "Shodan lookup", "query"),
        # DNS Tools
        "dns_tools.axfr":     (dns_tools, "zone_transfer", "DNS AXFR", "domain"),
        "dns_tools.dnssec":   (dns_tools, "dnssec_check", "DNSSEC check", "domain"),
        "dns_tools.wildcard": (dns_tools, "wildcard_detect", "Wildcard detect", "domain"),
        "dns_tools.ptr":      (dns_tools, "reverse_scan", "Reverse PTR scan", "network"),
        "dns_tools.snoop":    (dns_tools, "cache_snooping", "Cache snooping", "domain"),
        "dns_tools.cname":    (dns_tools, "show_cname_chain", "CNAME chain", "domain"),
        "dns_tools.srv":      (dns_tools, "srv_scan", "SRV scan", "domain"),
        "dns_tools.mail":     (dns_tools, "mail_security", "SPF/DMARC/DKIM", "domain"),
        "dns_tools.rebind":   (dns_tools, "rebinding_detect", "Rebinding check", "domain"),
        # Subdomain Takeover
        "takeover.scan":      (subdomain_takeover, "cli_scan", "Takeover: скан домена", "domain"),
        "takeover.check":     (subdomain_takeover, "cli_check", "Takeover: 1 поддомен", "target"),
        "takeover.services":  (subdomain_takeover, "cli_services", "Takeover: сервисы", "none"),
        # Threat Intel
        "ti.ip":              (threat_intel, "cli_ip", "TI: проверить IP", "ip"),
        "ti.domain":          (threat_intel, "cli_domain", "TI: проверить домен", "domain"),
        "ti.hash":            (threat_intel, "cli_hash", "TI: проверить hash", "hash"),
        "ti.url":             (threat_intel, "cli_url", "TI: проверить URL", "url"),
        "ti.auto":            (threat_intel, "cli_auto", "TI: авто-детект IOC", "word"),
        "ti.bulk":            (threat_intel, "cli_bulk", "TI: bulk из файла", "path"),
        "ti.sources":         (threat_intel, "cli_sources", "TI: статус источников", "none"),
        # CVE Feeds
        "cve.top":            (cve_feeds, "cli_top", "CVE: топ свежих", "none"),
        "cve.kev":            (cve_feeds, "cli_kev", "CVE: CISA KEV", "none"),
        "cve.stats":          (cve_feeds, "stats", "CVE: статистика", "none"),
        "cve.search":         (cve_feeds, "cli_search", "CVE: поиск", "word"),
        "cve.show":           (cve_feeds, "cli_show", "CVE: показать", "word"),
        "cve.dorks":          (cve_feeds, "cli_dorks", "CVE: dorks для продукта", "word"),
        "cve.download":       (cve_feeds, "cli_download", "CVE: скачать из NVD (все)", "none"),
        "cve.kev_update":     (cve_feeds, "download_kev", "CVE: скачать KEV", "none"),
        # Wireless Toolkit
        "wifi.scan":          (wireless_toolkit, "cli_scan", "Wi-Fi: сканировать", "none"),
        "wifi.evil":          (wireless_toolkit, "cli_evil_twin", "Wi-Fi: evil twin", "none"),
        "wifi.open":          (wireless_toolkit, "cli_open", "Wi-Fi: открытые", "none"),
        "wifi.weak":          (wireless_toolkit, "cli_weak", "Wi-Fi: слабые шифры", "none"),
        "wifi.channels":      (wireless_toolkit, "cli_channels", "Wi-Fi: каналы", "none"),
        "wifi.top":           (wireless_toolkit, "cli_top", "Wi-Fi: топ по сигналу", "none"),
        "wifi.export_csv":    (wireless_toolkit, "cli_export_csv", "Wi-Fi: экспорт CSV", "none"),
        "wifi.export_json":   (wireless_toolkit, "cli_export_json", "Wi-Fi: экспорт JSON", "none"),
        "wifi.full":          (wireless_toolkit, "cli_full", "Wi-Fi: полный анализ", "none"),
        # WordPress
        "wordpress.scan":     (wordpress_scanner, "cli_scan", "WP: полный скан", "url"),
        "wordpress.detect":   (wordpress_scanner, "cli_detect", "WP: детект версии", "url"),
        "wordpress.users":    (wordpress_scanner, "cli_users", "WP: пользователи", "url"),
        "wordpress.plugins":  (wordpress_scanner, "cli_plugins", "WP: плагины", "url"),
        "wordpress.xmlrpc":   (wordpress_scanner, "cli_xmlrpc", "WP: xmlrpc", "url"),
        "wordpress.vulns":    (wordpress_scanner, "cli_vulns", "WP: уязвимости", "url"),
        # GraphQL / API Discovery
        "gql.scan":           (graphql_discovery, "cli_full", "API: полный скан", "url"),
        "gql.discover":       (graphql_discovery, "cli_gql", "API: GraphQL endpoints", "url"),
        "gql.introspect":     (graphql_discovery, "cli_gql_introspect", "API: introspection", "url"),
        "api.swagger":        (graphql_discovery, "cli_swagger", "API: Swagger/OpenAPI", "url"),
        "api.rest":           (graphql_discovery, "cli_rest", "API: REST endpoints", "url"),
        "api.js":             (graphql_discovery, "cli_js", "API: JS endpoints", "url"),
        # Pivot / Post-Exploitation
        "pivot.reverse":      (pivot_helper, "quick_reverse", "Pivot: reverse shells", "none"),
        "pivot.bind":         (pivot_helper, "quick_bind", "Pivot: bind shells", "none"),
        "pivot.tty":          (pivot_helper, "quick_tty", "Pivot: TTY upgrade", "none"),
        "pivot.transfer":     (pivot_helper, "quick_transfer", "Pivot: file transfer", "none"),
        "pivot.tunnel":       (pivot_helper, "quick_pivot", "Pivot: tunneling", "none"),
        "pivot.linux":        (pivot_helper, "quick_linux_privesc", "Pivot: Linux privesc", "none"),
        "pivot.windows":      (pivot_helper, "quick_windows_privesc", "Pivot: Windows privesc", "none"),
        "pivot.encode":       (pivot_helper, "quick_encoding", "Pivot: payload encoding", "none"),
        # Social Engineering (CTF)
        "se.templates":       (social_engineer, "cli_templates", "SE: список шаблонов", "none"),
        "se.phish":           (social_engineer, "generate_phish_page", "SE: HTML фишинг-страница", "word"),
        "se.qr":              (social_engineer, "cli_qr", "SE: QR-код", "word"),
        "se.email":           (social_engineer, "cli_email", "SE: email шаблон", "word"),
        "se.sms":             (social_engineer, "cli_sms", "SE: SMS шаблон", "word"),
        "se.clone":           (social_engineer, "cli_clone", "SE: клонировать страницу", "url"),
        "se.obfuscate":       (social_engineer, "cli_obfuscate", "SE: обфускация URL", "url"),
        "se.pixel":           (social_engineer, "cli_pixel", "SE: tracking pixel", "none"),
        # Web
        "web.headers":        (web_vuln, "header_analyzer", "HTTP headers", "url"),
        "web.ssl":            (web_vuln, "ssl_checker", "SSL/TLS check", "host"),
        "web.sqli":           (web_vuln, "sqli_scan", "SQLi scan", "url"),
        "web.xss":            (web_vuln, "xss_scan", "XSS scan", "url"),
        "web.lfi":            (web_vuln, "lfi_scan", "LFI scan", "url"),
        "web.dirb":           (web_vuln, "dir_bruteforce", "Dir brute-force", "url"),
        "web.cms":            (web_vuln, "cms_scanner", "CMS scanner", "url"),
        "web.redirect":       (web_vuln, "open_redirect", "Open redirect", "url"),
        "web.csrf":           (web_vuln, "csrf_checker", "CSRF check", "url"),
        # Passwords
        "passwords.hashid":   (passwords, "identify_hash", "Identify hash", "hash"),
        "passwords.crack":    (passwords, "crack_hash", "Crack hash (wordlist)", "hash"),
        "passwords.genpass":  (passwords, "generate_password", "Generate password (16)", "none"),
        # OSINT
        "osint.username":     (osint, "username_check", "Username check", "username"),
        "osint.email":        (osint, "email_breach", "Email breach (HIBP)", "email"),
        "osint.phone":        (osint, "phone_lookup", "Phone lookup", "phone"),
        "osint.exif":         (osint, "exif_extractor", "EXIF extractor", "path"),
        "osint.github":       (osint, "github_dork", "GitHub dorks", "query"),
        # Network
        "network.ifaces":     (network, "list_interfaces", "List interfaces", "none"),
        "network.arp":        (network, "arp_scan", "ARP scan (192.168.1.0/24)", "network"),
        "network.wifi":       (network, "wifi_analyzer", "Wi-Fi analyzer", "none"),
        # Censys
        "censys.search":      (censys_lookup, "censys_search", "Censys search (query)", "query"),
        "censys.host":        (censys_lookup, "censys_host", "Censys host (IP)", "ip"),
        "censys.cert":        (censys_lookup, "censys_cert", "Censys cert (SHA-256)", "sha"),
        # Async
        "async.portscan":     (async_engine, "async_port_scan", "Async portscan (1-1024)", "target"),
        "async.http":         (async_engine, "async_http_scan", "Async HTTP scan", "url"),
        # Wordlists
        "wordlists.list":     (wordlist_updater, "list_local_wordlists", "Список словарей", "none"),
        "wordlists.check":    (wordlist_updater, "check_updates", "Проверка источников", "none"),
        "wordlists.updateall": (wordlist_updater, "update_all", "Обновить словари", "none"),
        # Wordlist Tools
        "wordtools.gen":      (wordlist_tools, "generate_wordlist", "Словарь из слова", "word"),
        # Payloads
        "payloads.xss":       (payload_factory, "generate_payloads", "XSS payloads", "none"),
        "payloads.sqli":      (payload_factory, "generate_payloads", "SQLi payloads", "none"),
        "payloads.lfi":       (payload_factory, "generate_payloads", "LFI payloads", "none"),
        # Crawler
        "crawler.crawl":      (web_crawler, "crawl", "Краулить URL", "url"),
        # Fuzzer
        "fuzzer.params":      (web_fuzzer, "fuzz_params", "Fuzz параметров URL", "url"),
        "fuzzer.paths":       (web_fuzzer, "fuzz_paths", "Fuzz директорий", "url"),
        # Proxy
        "proxy.start":        (http_proxy, "quick_start", "Запустить прокси (8080)", "none"),
        "proxy.stop":         (http_proxy, "quick_stop", "Остановить прокси", "none"),
        "proxy.status":       (http_proxy, "quick_status", "Статус прокси", "none"),
        "proxy.ca":           (http_proxy, "quick_ca_info", "Инфо о CA", "none"),
        "proxy.rules":        (http_proxy, "quick_rules", "Список правил", "none"),
        # Shell
        "shell.start":        (shell_manager, "quick_start", "Запустить shell listener :4444", "none"),
        "shell.stop":         (shell_manager, "quick_stop", "Остановить shell listener", "none"),
        "shell.status":       (shell_manager, "quick_status", "Статус shell listener", "none"),
        "shell.list":         (shell_manager, "quick_list", "Список shell-сессий", "none"),
        # Screenshot
        "screenshot.one":     (screenshot, "screenshot_one", "Скриншот URL", "url"),
        # Bug Bounty Auto-Scan
        "autoscan.quick":     (bugbounty_autoscan, "cli_scan", "AutoScan: quick профиль", "domain"),
        "autoscan.full":      (bugbounty_autoscan, "cli_scan", "AutoScan: full профиль", "domain"),
        "autoscan.deep":      (bugbounty_autoscan, "cli_scan", "AutoScan: deep профиль", "domain"),
        "autoscan.profiles":  (bugbounty_autoscan, "cli_profiles", "AutoScan: профили", "none"),
        "autoscan.past":      (bugbounty_autoscan, "cli_past", "AutoScan: прошлые сканы", "none"),
        # Report Templates Pack
        "rp.platforms":       (report_pack, "cli_platforms", "RPack: платформы", "none"),
        "rp.presets":         (report_pack, "cli_presets", "RPack: пресеты уязвимостей", "none"),
        "rp.list":            (report_pack, "cli_list", "RPack: сохранённые отчёты", "none"),
        "rp.new-h1":          (report_pack, "cli_wizard", "RPack: новый отчёт HackerOne", "none"),
        "rp.from-finding":    (report_pack, "cli_from_finding", "RPack: отчёт из finding #", "number"),
        "rp.cvss":            (report_pack, "cli_cvss", "RPack: CVSS вектор → score", "word"),
        # Report Export
        "report.html":        (report_export, "export_html", "История → HTML", "none"),
        "report.pdf":         (report_export, "export_pdf", "История → PDF", "none"),
        # Stats
        "stats.summary":      (stats, "text_summary", "Текстовая статистика", "none"),
        "stats.graphs":       (stats, "generate_all", "Построить все графики", "none"),
        # Vault
        "vault.status":       (vault, "cli_status", "Статус Vault", "none"),
        "vault.list":         (vault, "cli_list", "Список записей (нужен unlock)", "none"),
        # Notes
        "notes.stats":        (notes, "cli_stats", "Notes — статистика", "none"),
        "notes.list":         (notes, "cli_list", "Notes — список", "none"),
        "notes.findings":     (_FindingsProxy(), "run", "Notes — находки", "none"),
        # Auto-Report Pro
        "autoreport.html":    (auto_report, "quick_html", "Auto-Report: HTML", "none"),
        "autoreport.pdf":     (auto_report, "quick_pdf", "Auto-Report: PDF", "none"),
        "autoreport.json":    (auto_report, "quick_json", "Auto-Report: JSON", "none"),
        # Scheduler
        "scheduler.list":     (scheduler, "list_jobs", "Показать задачи", "none"),
        # Notifier
        "notifier.status":    (notifier, "status", "Статус каналов", "none"),
        "notifier.testall":   (notifier, "test_all", "Тест всех каналов", "none"),
        # Bot
        "bot.info":           (telegram_bot, "info", "Статус Telegram-бота", "none"),
        # Stego
        "stego.chi_png":      (stego_pro, "chi_square_png", "Chi-square PNG", "path"),
        "stego.chi_wav":      (stego_pro, "chi_square_wav", "Chi-square WAV", "path"),
        # Utils
        "utils.filehash":     (utils_tools, "file_hashes", "File hashes", "path"),
        # Plugins
        "plugins.list":       (plugin_loader, "list_plugins_cli", "Список плагинов", "none"),
        "plugins.reload":     (plugin_loader, "reload_plugins", "Перечитать плагины", "none"),
    }

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
        log.warning("Не удалось загрузить плагины: %s", exc)

    return qa


class _ActionProxy:
    def __init__(self, func):
        self.run = func

    def __getattr__(self, name):
        if name == "run":
            return self.run
        raise AttributeError(name)


class _FindingsProxy:
    def __init__(self):
        self.run = _tui_findings_view


QUICK_ACTIONS = _build_quick_actions()


def _get_plugin_group_entries() -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    try:
        for pname, pdata in plugin_loader.get_registry().items():
            entries.append((f"plugin-{pname}",
                            f"{pname} ({len(pdata['actions'])})"))
    except Exception:  # noqa: BLE001
        pass
    return entries


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
        width: 42; border: round #00ff9c; background: #080808; padding: 0 1;
    }
    #menu_scroll {
        height: 1fr; scrollbar-color: #00ff9c; scrollbar-background: #0a0a0a;
        scrollbar-size-vertical: 1;
    }
    .group_title {
        color: #00ff9c; text-style: bold; padding: 1 0 0 0; background: #080808;
    }
    #left_panel Button {
        width: 100%; height: 2; min-height: 2; margin: 0; border: none;
        background: #0d0d0d; color: #a0a0a0; padding-left: 2;
    }
    #left_panel Button:hover { background: #003322; color: #00ff9c; }
    #left_panel Button:focus { background: #005533; color: #ffffff; text-style: bold; }
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
        Binding("ctrl+r", "run_selected", "Запустить"),
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
                        yield Label(f"[bold green]{group_name}[/bold green]",
                                    classes="group_title")
                        if group_name == "🧩 Плагины":
                            plugin_entries = _get_plugin_group_entries()
                            if plugin_entries:
                                for key, title in plugin_entries:
                                    yield Button(title, id=f"module-{key}")
                            else:
                                yield Label("[dim]  плагинов нет[/dim]")
                        else:
                            for key, title in modules:
                                yield Button(title, id=f"module-{key}")
                with Vertical(id="sys_buttons"):
                    yield Button("🔄  Reload plugins", id="reload_plugins")
                    yield Button("📜  История", id="history")
                    yield Button("ℹ  О программе", id="about")
                    yield Button("❌  Выход", id="quit")
            with Vertical(id="right_panel"):
                yield RichLog(highlight=True, markup=True,
                              wrap=True, id="result_log")
        with Vertical(id="bottom_bar"):
            yield Label(
                "[cyan]▶ Быстрое действие:[/cyan] выбери, введи "
                "аргумент, нажми [green]Ctrl+R[/green].",
                id="action_hint",
            )
            yield Input(placeholder="Аргумент (домен / URL / IP / hash / путь)…",
                        id="arg_input")
            with Horizontal(id="action_row"):
                yield Select(
                    options=[(f"{k}  —  {v[2]}", k) for k, v in QUICK_ACTIONS.items()],
                    prompt="— выбери действие —",
                    id="action_select",
                )
                yield Button("▶ Запустить", id="run_action", variant="success")
                yield Button("🧹", id="clear_log", variant="warning")
        with Container(id="statusbar"):
            yield Label("", id="status_text")
        yield Footer()

    def on_mount(self) -> None:
        self._write("[bold cyan]╔══ Добро пожаловать в CyberSec Toolkit ══╗[/bold cyan]")
        self._write(f"[magenta]by {AUTHOR}  •  v{VERSION}[/magenta]")
        self._write("")
        self._write("[yellow]⚠ Используй только на своих системах или с письменным разрешением.[/yellow]")
        self._write("")
        self._write("[dim]• Слева — модули по категориям.[/dim]")
        self._write("[dim]• Кликни модуль — увидишь список команд.[/dim]")
        self._write("[dim]• Внизу: выбери действие → введи аргумент → Ctrl+R.[/dim]")
        self._write("[dim]• 🔍 WordPress Scanner — версия, плагины, users, CVE.[/dim]")
        self._write("")
        try:
            n_plugins = len(plugin_loader.get_registry())
            self._write(f"[dim]🧩 Загружено плагинов: {n_plugins}[/dim]")
        except Exception:  # noqa: BLE001
            pass
        self._refresh_status()
        self.set_timer(0.3, lambda: self.refresh(layout=True))

    def _refresh_status(self) -> None:
        try:
            rows = db.history(1)
            total = 0
            last = "—"
            if rows:
                cur = db.conn.cursor()
                cur.execute("SELECT COUNT(*) as c FROM scans")
                total = cur.fetchone()["c"]
                last = f"{rows[0]['module']} → {rows[0]['target']}"
            notif = "🟢 ON" if config.NOTIFY_ENABLED else "⚪ OFF"
            try:
                n_plugins = len(plugin_loader.get_registry())
            except Exception:  # noqa: BLE001
                n_plugins = 0

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
                cur.execute("SELECT COUNT(*) as c FROM notes WHERE kind='finding'")
                findings_count = cur.fetchone()["c"]
                cur.execute("SELECT COUNT(*) as c FROM cves")
                cves_count = cur.fetchone()["c"]
            except Exception:  # noqa: BLE001
                pass

            proxy_status = "—"
            try:
                if http_proxy._server_thread and http_proxy._server_thread.is_alive():
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

            status = (
                f"[green]●[/green] Модулей: [cyan]{len(MODULE_GROUPS)}[/cyan]   "
                f"[green]●[/green] Сканов: [cyan]{total}[/cyan]   "
                f"[green]●[/green] CVE: [cyan]{cves_count}[/cyan]   "
                f"[green]●[/green] Vault: {vault_status}   "
                f"[green]●[/green] Notes: [cyan]{notes_count}[/cyan]"
                f"[red](F:{findings_count})[/red]   "
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
        try:
            self._log().write(Text.from_markup(text))
        except Exception:  # noqa: BLE001
            self._log().write(Text(text))

    def _clear(self) -> None:
        self._log().clear()

    def action_clear_log(self) -> None:
        self._clear()

    def action_refresh_history(self) -> None:
        self.show_history()

    def action_focus_arg(self) -> None:
        self.query_one("#arg_input", Input).focus()

    def action_run_selected(self) -> None:
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
        self._clear()
        self._write("[cyan]🔄 Перечитываю плагины…[/cyan]")
        try:
            reg = plugin_loader.reload_plugins()
            self._write(f"[green]✓ Загружено: {len(reg)}[/green]")
            for name, data in reg.items():
                self._write(f"  [cyan]{name}[/cyan] "
                            f"[dim]v{data['version']} — "
                            f"{len(data['actions'])} действий[/dim]")
        except Exception as exc:  # noqa: BLE001
            self._write(f"[red]Ошибка: {exc}[/red]")

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

    def show_module_info(self, key: str) -> None:
        title = key
        for _group, modules in MODULE_GROUPS:
            for mkey, mtitle in modules:
                if mkey == key:
                    title = mtitle
                    break

        if key.startswith("plugin-"):
            pname = key[len("plugin-"):]
            plugin = plugin_loader.get_plugin(pname)
            if plugin:
                self._clear()
                self._write(f"[bold cyan]🧩 Плагин: {plugin['name']}[/bold cyan]")
                self._write(f"[dim]v{plugin['version']} by {plugin['author']}[/dim]")
                self._write(f"[white]{plugin['description']}[/white]")
                self._write("")
                for i, a in enumerate(plugin["actions"], 1):
                    self._write(f"  [green]{i}. {a['name']}[/green]  — "
                                f"{a['description']}  [dim]({a['arg_hint']})[/dim]")
            return

        if key == "wordpress":
            self._clear()
            self._write("[bold cyan]🔍 WordPress Scanner[/bold cyan]")
            self._write("[dim]─────────────────────────────[/dim]")
            self._write("")
            self._write("[yellow]Что делает:[/yellow]")
            self._write("  • Детект WP (meta generator, readme.html, feed, wp-json)")
            self._write("  • Версия через meta/readme/feed")
            self._write("  • Users enumeration (?author=N, /wp-json/wp/v2/users)")
            self._write("  • Plugins и Themes из HTML")
            self._write("  • xmlrpc.php + system.listMethods")
            self._write("  • REST API namespace enumeration")
            self._write("  • Мини-база CVE (WP core + 15 популярных плагинов)")
            self._write("  • Агрессивный режим: проверка wp-config.bak, .env, debug.log")
            self._write("")
            self._write("[yellow]CLI:[/yellow]")
            self._write("  [green]python main.py wp[/green]                — меню")
            self._write("  [green]python main.py wp-scan URL[/green]        — полный скан")
            self._write("  [green]python main.py wp-scan URL --aggressive[/green]")
            self._write("  [green]python main.py wp-detect URL[/green]      — только версия")
            self._write("  [green]python main.py wp-users URL[/green]")
            self._write("  [green]python main.py wp-plugins URL[/green]")
            self._write("  [green]python main.py wp-xmlrpc URL[/green]")
            self._write("  [green]python main.py wp-vulns URL[/green]")
            self._write("")
            self._write("[yellow]TUI (селект внизу):[/yellow]")
            self._write("  wordpress.scan / wordpress.detect / wordpress.users")
            self._write("  wordpress.plugins / wordpress.xmlrpc / wordpress.vulns")
            return

        if key == "wireless":
            self._clear()
            self._write("[bold cyan]📶 Wireless Toolkit[/bold cyan]")
            self._write("[dim]─────────────────────────────[/dim]")
            self._write("")
            self._write("[yellow]CLI:[/yellow] python main.py wifi")
            return

        if key == "cve_feeds":
            self._clear()
            self._write("[bold cyan]📡 CVE Feeds[/bold cyan]")
            self._write("[dim]─────────────────────────────[/dim]")
            self._write("")
            self._write("[yellow]CLI:[/yellow] python main.py cve")
            return

        if key == "vault":
            self._clear()
            self._write("[bold cyan]🔐 Password Vault[/bold cyan]")
            self._write("[dim]─────────────────────────────[/dim]")
            self._write("")
            self._write("[yellow]CLI:[/yellow] python main.py vault")
            return

        if key == "notes":
            self._clear()
            self._write("[bold cyan]📝 Notes & Findings[/bold cyan]")
            self._write("[dim]─────────────────────────────[/dim]")
            self._write("")
            self._write("[yellow]CLI:[/yellow] python main.py notes")
            return

        if key == "autoreport":
            self._clear()
            self._write("[bold cyan]📄 Auto-Report Pro[/bold cyan]")
            self._write("[dim]─────────────────────────────[/dim]")
            self._write("")
            self._write("[yellow]CLI:[/yellow] python main.py report-pro")
            return

        if key == "proxy":
            self._clear()
            self._write("[bold cyan]🌐 HTTP/HTTPS Proxy[/bold cyan]")
            self._write("[dim]─────────────────────────────[/dim]")
            self._write("")
            self._write("[yellow]CLI:[/yellow] python main.py proxy")
            return

        if key == "shell":
            self._clear()
            self._write("[bold cyan]🐚 Shell Manager[/bold cyan]")
            self._write("[dim]─────────────────────────────[/dim]")
            self._write("")
            self._write("[yellow]CLI:[/yellow] python main.py shell")
            return

        if key == "dns_tools":
            self._clear()
            self._write("[bold cyan]🌍 DNS Tools[/bold cyan]")
            self._write("[dim]─────────────────────────────[/dim]")
            self._write("")
            self._write("[yellow]CLI:[/yellow] python main.py dns-tools")
            return

        if key == "takeover":
            self._clear()
            self._write("[bold cyan]🎯 Subdomain Takeover[/bold cyan]")
            self._write("[dim]─────────────────────────────[/dim]")
            self._write("")
            self._write("[yellow]CLI:[/yellow] python main.py takeover")
            return

        self._clear()
        self._write(f"[bold cyan]📦 Модуль: {title}[/bold cyan]")
        self._write("[dim]─────────────────────────────[/dim]")
        found = False
        for action_key, (_m, _fn, desc, arg) in QUICK_ACTIONS.items():
            if action_key.startswith(f"{key}."):
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
                }.get(arg, f"[dim]{arg}[/dim]")
                self._write(f"  [green]{action_key:<26}[/green] "
                            f"{desc:<32} {arg_hint}")
        if not found:
            self._write("[yellow]У модуля нет быстрых действий.[/yellow]")
        self._write("")
        self._write("[dim]Выбери действие в списке внизу и нажми Ctrl+R.[/dim]")

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
                f"[magenta]{r['module']:<18}[/magenta] "
                f"[cyan]{r['target']:<38}[/cyan] "
                f"[dim]{r['created_at']}[/dim]"
            )
        self._refresh_status()

    def run_selected_action(self) -> None:
        sel = self.query_one("#action_select", Select)
        arg_input = self.query_one("#arg_input", Input)
        action_key = sel.value if isinstance(sel.value, str) else None
        if not action_key or action_key not in QUICK_ACTIONS:
            self._write("[red]Сначала выбери действие в списке внизу.[/red]")
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
                run_module_async(fn, on_line=self._write)
            else:
                run_module_async(fn, arg_value, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return

        if arg_kind == "none":
            if action_key == "payloads.xss":
                run_module_async(fn, "xss", on_line=self._write)
            elif action_key == "payloads.sqli":
                run_module_async(fn, "sqli", on_line=self._write)
            elif action_key == "payloads.lfi":
                run_module_async(fn, "lfi", on_line=self._write)
            elif action_key == "stats.graphs":
                run_module_async(fn, False, on_line=self._write)
            else:
                run_module_async(fn, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return

        # WordPress
        if action_key.startswith("wordpress."):
            run_module_async(fn, arg_value, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return

        # GraphQL / API
        if action_key.startswith("gql.") or action_key.startswith("api."):
            run_module_async(fn, arg_value, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        
        # Pivot Helpers
        if action_key.startswith("pivot."):
            run_module_async(fn, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return

        # Social Engineering (CTF)
        if action_key == "se.templates" or action_key == "se.pixel":
            run_module_async(fn, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        if action_key == "se.qr":
            run_module_async(fn, arg_value, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        if action_key == "se.phish":
            run_module_async(fn, arg_value, None, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        if action_key == "se.email":
            run_module_async(fn, arg_value, "https://example.com/login",
                            "John", None, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        if action_key == "se.sms":
            run_module_async(fn, arg_value, "https://example.com",
                            on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        if action_key == "se.clone" or action_key == "se.obfuscate":
            run_module_async(fn, arg_value, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        # Bug Bounty Auto-Scan
        if action_key == "autoscan.profiles" or action_key == "autoscan.past":
            run_module_async(fn, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        if action_key == "autoscan.quick":
            run_module_async(fn, arg_value, "quick", None, None,
                            on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        if action_key == "autoscan.full":
            run_module_async(fn, arg_value, "full", None, None,
                            on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        if action_key == "autoscan.deep":
            run_module_async(fn, arg_value, "deep", None, None,
                            on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return

        # Report Templates Pack
        if action_key in ("rp.platforms", "rp.presets", "rp.list"):
            run_module_async(fn, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        if action_key == "rp.new-h1":
            run_module_async(fn, "hackerone", on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        if action_key == "rp.from-finding":
            try:
                fid = int(arg_value)
            except ValueError:
                self._write("[red]Нужен числовой finding_id.[/red]")
                return
            run_module_async(fn, fid, "hackerone", None,
                            on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        if action_key == "rp.cvss":
            run_module_async(fn, arg_value, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        
        # Threat Intel
        if action_key == "ti.sources":
            run_module_async(fn, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        if action_key in ("ti.ip", "ti.domain", "ti.hash",
                        "ti.url", "ti.auto"):
            run_module_async(fn, arg_value, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        if action_key == "ti.bulk":
            run_module_async(fn, arg_value, 4, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        
        # Wireless
        if action_key.startswith("wifi."):
            run_module_async(fn, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return

        # CVE Feeds
        if action_key == "cve.search":
            run_module_async(fn, arg_value, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        if action_key == "cve.show":
            run_module_async(fn, arg_value, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        if action_key == "cve.dorks":
            run_module_async(fn, arg_value, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return

        # Takeover
        if action_key == "takeover.scan":
            run_module_async(fn, arg_value, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        if action_key == "takeover.check":
            run_module_async(fn, arg_value, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return

        # DNS Tools
        if action_key == "dns_tools.ptr":
            run_module_async(fn, arg_value, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return
        if action_key == "dns_tools.snoop":
            run_module_async(fn, arg_value, None, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return

        one_arg = {
            "recon.whois", "recon.dns", "recon.subdomain",
            "recon.geoip", "recon.fingerprint", "recon.dork",
            "recon.shodan",
            "dns_tools.axfr", "dns_tools.dnssec", "dns_tools.wildcard",
            "dns_tools.cname", "dns_tools.srv", "dns_tools.mail",
            "dns_tools.rebind",
            "web.headers", "web.ssl", "web.sqli", "web.xss",
            "web.lfi", "web.cms", "web.redirect", "web.csrf",
            "passwords.hashid", "passwords.crack",
            "osint.username", "osint.email", "osint.phone",
            "osint.exif", "osint.github",
            "censys.search", "censys.host", "censys.cert",
            "screenshot.one",
            "utils.filehash",
        }
        if action_key in one_arg:
            run_module_async(fn, arg_value, on_line=self._write)
            self.set_timer(2.0, self._refresh_status)
            return

        if action_key == "crawler.crawl":
            run_module_async(fn, arg_value, 1, 50, on_line=self._write)
        elif action_key == "fuzzer.params":
            run_module_async(fn, arg_value, on_line=self._write)
        elif action_key == "fuzzer.paths":
            run_module_async(fn, arg_value, on_line=self._write)
        elif action_key == "wordtools.gen":
            run_module_async(fn, arg_value, f"wl_{arg_value}.txt",
                             True, True, True, "", on_line=self._write)
        elif action_key in ("stego.chi_png", "stego.chi_wav"):
            from pathlib import Path as _P
            run_module_async(fn, _P(arg_value), on_line=self._write)
        elif action_key == "recon.portscan":
            run_module_async(fn, arg_value, "1-1024", on_line=self._write)
        elif action_key == "web.dirb":
            run_module_async(fn, arg_value, 30, on_line=self._write)
        elif action_key == "async.portscan":
            run_module_async(fn, arg_value, "1-1024", 500, 1.0,
                             on_line=self._write)
        elif action_key == "async.http":
            run_module_async(fn, arg_value,
                             "admin,login,api,robots.txt,.env",
                             50, 5.0, on_line=self._write)
        elif action_key == "passwords.genpass":
            try:
                length = int(arg_value) if arg_value else 16
            except ValueError:
                length = 16
            run_module_async(fn, length, on_line=self._write)
        elif action_key == "network.arp":
            run_module_async(fn, None, arg_value, on_line=self._write)
        else:
            self._write(f"[yellow]Не знаю, как вызвать {action_key}.[/yellow]")
            return
        self.set_timer(2.0, self._refresh_status)


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