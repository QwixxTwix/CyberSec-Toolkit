"""Проверка наличия всех файлов проекта CyberSec Toolkit."""
import os

REQUIRED = [
    # --- корень ---
    "main.py",
    "requirements.txt",
    ".env",
    "schedule.yaml",
    # --- core ---
    "core/__init__.py",
    "core/banner.py",
    "core/config.py",
    "core/database.py",
    "core/logger.py",
    # --- utils ---
    "utils/__init__.py",
    "utils/helpers.py",
    # --- modules ---
    "modules/__init__.py",
    "modules/recon.py",
    "modules/web_vuln.py",
    "modules/passwords.py",
    "modules/osint.py",
    "modules/network.py",
    "modules/bugbounty.py",
    "modules/roadmap.py",
    "modules/utils_tools.py",
    "modules/censys_lookup.py",
    "modules/async_engine.py",
    "modules/wordlist_updater.py",
    "modules/screenshot.py",
    "modules/report_export.py",
    "modules/scheduler.py",
    "modules/notifier.py",
    "modules/stego_pro.py",
    # --- tui ---
    "tui/__init__.py",
    "tui/app.py",
    "tui/runner.py",
    # --- wordlists ---
    "wordlists/subdomains.txt",
    "wordlists/dirs.txt",
    "wordlists/rockyou-mini.txt",
    # --- tests ---
    "tests/test_core.py",
    "modules/wordlist_tools.py",
    "modules/payload_factory.py",
    "modules/web_crawler.py",
]

missing = [f for f in REQUIRED if not os.path.exists(f)]

print("=" * 60)
if missing:
    print(f"❌ НАЙДЕНО ОТСУТСТВУЮЩИХ ФАЙЛОВ: {len(missing)}")
    print("=" * 60)
    for f in missing:
        print("  " + f)
    print("=" * 60)
    print("Скопируй этот список целиком и пришли мне — я дам все файлы.")
else:
    print("✅ ВСЕ ФАЙЛЫ НА МЕСТЕ")
print("=" * 60)