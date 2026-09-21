"""Загрузка конфигурации из .env."""
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
REPORT_DIR = BASE_DIR / "reports"
WORDLIST_DIR = BASE_DIR / "wordlists"
DB_PATH = BASE_DIR / "cyber_toolkit.db"

for _d in (LOG_DIR, REPORT_DIR, WORDLIST_DIR):
    _d.mkdir(exist_ok=True)

load_dotenv(BASE_DIR / ".env")


def _parse_int_list(value: str) -> list[int]:
    """'111,222,333' → [111, 222, 333]."""
    result = []
    for chunk in (value or "").split(","):
        chunk = chunk.strip()
        if chunk:
            try:
                result.append(int(chunk))
            except ValueError:
                pass
    return result


class Config:
    """Глобальная конфигурация."""

    # --- API-ключи (базовые) ---
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    HIBP_API_KEY: str = os.getenv("HIBP_API_KEY", "")
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
    CENSYS_API_ID: str = os.getenv("CENSYS_API_ID", "")
    CENSYS_API_SECRET: str = os.getenv("CENSYS_API_SECRET", "")

    # --- Threat Intelligence API-ключи ---
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    IPQS_API_KEY: str = os.getenv("IPQS_API_KEY", "")
    GREYNOISE_API_KEY: str = os.getenv("GREYNOISE_API_KEY", "")
    OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")
    URLSCAN_API_KEY: str = os.getenv("URLSCAN_API_KEY", "")
    PHISHTANK_APP_KEY: str = os.getenv("PHISHTANK_APP_KEY", "")

    # --- Сеть ---
    REQUEST_TIMEOUT: int = int(os.getenv("REQUEST_TIMEOUT", "10"))
    MAX_THREADS: int = int(os.getenv("MAX_THREADS", "100"))
    USER_AGENT: str = os.getenv(
        "USER_AGENT",
        "Mozilla/5.0 (X11; Linux x86_64) CyberSecToolkit/1.0",
    )

    # --- Уведомления ---
    NOTIFY_ENABLED: bool = os.getenv("NOTIFY_ENABLED", "false").lower() == "true"

    TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID: str = os.getenv("TELEGRAM_CHAT_ID", "")
    BOT_EXTRA_USERS: list[int] = _parse_int_list(os.getenv("BOT_EXTRA_USERS", ""))

    DISCORD_WEBHOOK_URL: str = os.getenv("DISCORD_WEBHOOK_URL", "")

    SMTP_HOST: str = os.getenv("SMTP_HOST", "")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: str = os.getenv("SMTP_USER", "")
    SMTP_PASS: str = os.getenv("SMTP_PASS", "")
    SMTP_FROM: str = os.getenv("SMTP_FROM", "")
    SMTP_TO: str = os.getenv("SMTP_TO", "")

    # --- TUI ---
    TUI_COLS: int = int(os.getenv("TUI_COLS", "200"))
    TUI_LINES: int = int(os.getenv("TUI_LINES", "55"))


config = Config()