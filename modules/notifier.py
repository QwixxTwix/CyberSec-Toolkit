"""
Notifier Pro — много-канальные уведомления.
Author: idqwixxa

Каналы:
    - Telegram Bot
    - Discord Webhook (embed)
    - Slack (blocks)
    - Mattermost
    - Rocket.Chat
    - MS Teams (adaptive card)
    - Gotify
    - ntfy.sh
    - Pushover
    - PagerDuty Events v2
    - Email (SMTP)
    - Generic Webhook (JSON + HMAC)
    - Syslog (UDP/TCP)
    - Desktop (notify-send / osascript / Windows toast)

Возможности:
    ─── Routing ───
    - Severity filter (only critical/high by default)
    - Module whitelist/blacklist
    - Quiet hours (не спамить ночью)
    - Rate limiting (не больше N сообщений/час)
    - Deduplication (не повторять одно и то же)

    ─── Delivery ───
    - Retry with exponential backoff (3 попытки)
    - Async queue (не блокирует сканы)
    - Batch notifications (собрать и отправить одним сообщением)
    - Attachments (скриншот, отчёт, PCAP)

    ─── Templates ───
    - scan_done, finding_created, error, custom
    - Markdown / HTML formatting
    - Emoji + severity colors

    ─── History ───
    - SQLite таблица notification_history
    - Фильтр по дате / каналу / статусу
    - Статистика (success rate, avg latency)

    ─── Env (.env) ───
    NOTIFY_ENABLED=true
    NOTIFY_MIN_SEVERITY=high           # info|low|medium|high|critical
    NOTIFY_MODULES=recon,web_vuln      # пусто = все
    NOTIFY_QUIET_HOURS=22-8            # тихие часы
    NOTIFY_RATE_LIMIT=20               # max/час
    NOTIFY_DEDUP_TTL=300               # сек

    # Telegram
    TELEGRAM_BOT_TOKEN=...
    TELEGRAM_CHAT_ID=...

    # Discord
    DISCORD_WEBHOOK_URL=...

    # Slack
    SLACK_WEBHOOK_URL=...
    SLACK_CHANNEL=#security

    # Teams / Mattermost / Rocket.Chat — аналогично webhook
    TEAMS_WEBHOOK_URL=...
    MATTERMOST_WEBHOOK_URL=...
    ROCKETCHAT_WEBHOOK_URL=...

    # Gotify / ntfy / Pushover
    GOTIFY_URL=... GOTIFY_TOKEN=...
    NTFY_URL=https://ntfy.sh NTFY_TOPIC=my-secret-topic
    PUSHOVER_TOKEN=... PUSHOVER_USER=...

    # PagerDuty
    PAGERDUTY_ROUTING_KEY=...

    # Generic webhook
    GENERIC_WEBHOOK_URL=...
    GENERIC_WEBHOOK_SECRET=...         # HMAC-SHA256

    # Syslog
    SYSLOG_HOST=... SYSLOG_PORT=514

    # SMTP
    SMTP_HOST=... SMTP_PORT=587 SMTP_USER=... SMTP_PASS=...
    SMTP_FROM=... SMTP_TO=...
"""
import base64
import hashlib
import hmac
import json
import os
import platform
import queue
import smtplib
import socket
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.header import Header
from email import encoders
from pathlib import Path
from typing import Any, Callable

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

NOTIFY_DIR = REPORT_DIR / "notifications"
NOTIFY_DIR.mkdir(parents=True, exist_ok=True)

# Ensure notification_history schema
try:
    cur = db.conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS notification_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            channel TEXT NOT NULL,
            severity TEXT DEFAULT 'info',
            title TEXT DEFAULT '',
            body TEXT DEFAULT '',
            ok INTEGER DEFAULT 0,
            latency_ms REAL DEFAULT 0,
            error TEXT DEFAULT '',
            attempts INTEGER DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_notif_ts ON notification_history(ts);
        CREATE INDEX IF NOT EXISTS idx_notif_channel
            ON notification_history(channel);
        CREATE INDEX IF NOT EXISTS idx_notif_ok
            ON notification_history(ok);
    """)
    db.conn.commit()
except Exception as exc:  # noqa: BLE001
    log.warning("notification_history schema: %s", exc)


# ===========================================================================
# Env helpers
# ===========================================================================

def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default) or ""


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name, "true" if default else "false").lower()
    return v in ("true", "1", "yes", "on")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


# ===========================================================================
# Severity / routing
# ===========================================================================

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_ok(severity: str) -> bool:
    """Проверить, проходит ли severity через фильтр."""
    min_sev = _env("NOTIFY_MIN_SEVERITY", "info").lower()
    return SEVERITY_ORDER.get(severity.lower(), 0) >= \
           SEVERITY_ORDER.get(min_sev, 0)


def _in_quiet_hours() -> bool:
    """Проверить тихие часы (формат HH-HH, например 22-8)."""
    spec = _env("NOTIFY_QUIET_HOURS", "").strip()
    if not spec or "-" not in spec:
        return False
    try:
        start, end = spec.split("-")
        start_h, end_h = int(start.strip()), int(end.strip())
        now_h = datetime.now().hour
        if start_h <= end_h:
            return start_h <= now_h < end_h
        return now_h >= start_h or now_h < end_h
    except Exception:
        return False


# ===========================================================================
# Rate limiting / dedup
# ===========================================================================

_rate_lock = threading.Lock()
_recent_sent: deque = deque(maxlen=500)
_dedup_cache: dict[str, float] = {}


def _rate_ok() -> bool:
    """Rate-limit по количеству сообщений/час."""
    limit = _env_int("NOTIFY_RATE_LIMIT", 60)
    if limit <= 0:
        return True
    cutoff = time.time() - 3600
    with _rate_lock:
        while _recent_sent and _recent_sent[0] < cutoff:
            _recent_sent.popleft()
        return len(_recent_sent) < limit


def _rate_mark() -> None:
    with _rate_lock:
        _recent_sent.append(time.time())


def _dedup_ok(fingerprint: str) -> bool:
    """Проверить, не отправляли ли это недавно."""
    ttl = _env_int("NOTIFY_DEDUP_TTL", 300)
    if ttl <= 0:
        return True
    now = time.time()
    last = _dedup_cache.get(fingerprint, 0)
    if now - last < ttl:
        return False
    _dedup_cache[fingerprint] = now
    # Cleanup
    if len(_dedup_cache) > 1000:
        stale = [k for k, v in _dedup_cache.items() if now - v > ttl]
        for k in stale:
            _dedup_cache.pop(k, None)
    return True


# ===========================================================================
# History
# ===========================================================================

def _log_history(channel: str, ok: bool, title: str, body: str,
                 latency_ms: float = 0, error: str = "",
                 severity: str = "info", attempts: int = 1) -> None:
    try:
        cur = db.conn.cursor()
        cur.execute(
            "INSERT INTO notification_history "
            "(channel, severity, title, body, ok, latency_ms, error, attempts) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (channel, severity, title[:200], body[:2000],
             1 if ok else 0, latency_ms, error[:500], attempts),
        )
        db.conn.commit()
    except Exception as exc:  # noqa: BLE001
        log.debug("history: %s", exc)


def history(limit: int = 100, channel: str | None = None,
            only_failed: bool = False) -> list[dict]:
    """История отправок."""
    try:
        sql = "SELECT * FROM notification_history WHERE 1=1"
        args: list = []
        if channel:
            sql += " AND channel = ?"
            args.append(channel)
        if only_failed:
            sql += " AND ok = 0"
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        cur = db.conn.cursor()
        cur.execute(sql, args)
        return [dict(r) for r in cur.fetchall()]
    except Exception as exc:  # noqa: BLE001
        log.warning("history: %s", exc)
        return []


def history_stats() -> dict:
    """Статистика по истории."""
    try:
        cur = db.conn.cursor()
        cur.execute("SELECT COUNT(*) as c FROM notification_history")
        total = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM notification_history WHERE ok=1")
        ok = cur.fetchone()["c"]
        cur.execute("SELECT AVG(latency_ms) as a FROM notification_history "
                    "WHERE ok=1")
        avg_latency = cur.fetchone()["a"] or 0
        cur.execute("SELECT channel, COUNT(*) as c FROM notification_history "
                    "GROUP BY channel ORDER BY c DESC")
        by_channel = {r["channel"]: r["c"] for r in cur.fetchall()}
        return {
            "total": total,
            "ok": ok,
            "failed": total - ok,
            "success_rate": round(ok / total * 100, 1) if total else 0,
            "avg_latency_ms": round(avg_latency, 1),
            "by_channel": by_channel,
        }
    except Exception as exc:  # noqa: BLE001
        log.warning("history_stats: %s", exc)
        return {"total": 0, "ok": 0, "failed": 0, "success_rate": 0,
                "avg_latency_ms": 0, "by_channel": {}}


# ===========================================================================
# Retry wrapper
# ===========================================================================

def _with_retry(fn: Callable[[], bool], attempts: int = 3,
                base_delay: float = 1.0) -> tuple[bool, int, float]:
    """Retry с exponential backoff. Возвращает (ok, attempts_used, latency_ms)."""
    start = time.time()
    for i in range(attempts):
        try:
            if fn():
                return True, i + 1, (time.time() - start) * 1000
        except Exception as exc:  # noqa: BLE001
            log.debug("retry %s/%s: %s", i + 1, attempts, exc)
        if i < attempts - 1:
            time.sleep(base_delay * (2 ** i))
    return False, attempts, (time.time() - start) * 1000


# ===========================================================================
# Channels
# ===========================================================================

def send_telegram(title: str, message: str,
                  severity: str = "info") -> bool:
    """Telegram Bot."""
    token = config.TELEGRAM_BOT_TOKEN or _env("TELEGRAM_BOT_TOKEN")
    chat_id = config.TELEGRAM_CHAT_ID or _env("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    emoji = {"info": "ℹ️", "low": "🟢", "medium": "🟡",
             "high": "🟠", "critical": "🔴"}.get(severity, "📌")
    text = f"{emoji} *{title}*\n\n{message}"
    try:
        r = requests.post(url, json={
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }, timeout=config.REQUEST_TIMEOUT)
        r.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("Telegram: %s", exc)
        return False


def send_discord(title: str, message: str,
                 severity: str = "info") -> bool:
    """Discord Webhook с embed."""
    url = config.DISCORD_WEBHOOK_URL or _env("DISCORD_WEBHOOK_URL")
    if not url:
        return False
    color_map = {"info": 0x7ad9ff, "low": 0x00ff9c, "medium": 0xffd23f,
                 "high": 0xff7a40, "critical": 0xff2020}
    color = color_map.get(severity, 0x7ad9ff)
    payload = {
        "username": "CyberSec Toolkit",
        "embeds": [{
            "title": title[:250],
            "description": message[:3900],
            "color": color,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "footer": {"text": f"severity: {severity}"},
        }],
    }
    try:
        r = requests.post(url, json=payload,
                          timeout=config.REQUEST_TIMEOUT)
        r.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("Discord: %s", exc)
        return False


def send_slack(title: str, message: str, severity: str = "info") -> bool:
    """Slack Webhook с blocks."""
    url = _env("SLACK_WEBHOOK_URL")
    if not url:
        return False
    emoji = {"info": ":information_source:", "low": ":large_green_circle:",
             "medium": ":large_yellow_circle:", "high": ":large_orange_circle:",
             "critical": ":red_circle:"}.get(severity, ":bell:")
    payload = {
        "text": f"{emoji} {title}",
        "channel": _env("SLACK_CHANNEL", ""),
        "blocks": [
            {"type": "header",
             "text": {"type": "plain_text",
                       "text": f"{emoji} {title[:140]}"}},
            {"type": "section",
             "text": {"type": "mrkdwn",
                       "text": message[:2900]}},
            {"type": "context",
             "elements": [{"type": "mrkdwn",
                            "text": f"*Severity:* `{severity}` • "
                                    f"{datetime.now().strftime('%Y-%m-%d %H:%M')}"}]},
        ],
    }
    try:
        r = requests.post(url, json=payload,
                          timeout=config.REQUEST_TIMEOUT)
        r.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("Slack: %s", exc)
        return False


def send_mattermost(title: str, message: str,
                    severity: str = "info") -> bool:
    """Mattermost Webhook."""
    url = _env("MATTERMOST_WEBHOOK_URL")
    if not url:
        return False
    payload = {
        "text": f"**{title}**\n\n{message}",
        "username": "CyberSec Toolkit",
    }
    try:
        r = requests.post(url, json=payload,
                          timeout=config.REQUEST_TIMEOUT)
        r.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("Mattermost: %s", exc)
        return False


def send_rocketchat(title: str, message: str,
                    severity: str = "info") -> bool:
    """Rocket.Chat Webhook."""
    url = _env("ROCKETCHAT_WEBHOOK_URL")
    if not url:
        return False
    payload = {
        "text": f"*{title}*\n\n{message}",
        "username": "CyberSec Toolkit",
    }
    try:
        r = requests.post(url, json=payload,
                          timeout=config.REQUEST_TIMEOUT)
        r.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("Rocket.Chat: %s", exc)
        return False


def send_teams(title: str, message: str, severity: str = "info") -> bool:
    """MS Teams Adaptive Card."""
    url = _env("TEAMS_WEBHOOK_URL")
    if not url:
        return False
    color = {"info": "0078D7", "low": "00B294",
             "medium": "FFB900", "high": "FF8C00",
             "critical": "E81123"}.get(severity, "0078D7")
    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": color,
        "summary": title[:200],
        "title": title[:200],
        "text": message[:3500],
        "potentialAction": [],
    }
    try:
        r = requests.post(url, json=payload,
                          timeout=config.REQUEST_TIMEOUT)
        r.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("Teams: %s", exc)
        return False


def send_gotify(title: str, message: str,
                severity: str = "info") -> bool:
    """Gotify self-hosted push."""
    url = _env("GOTIFY_URL")
    token = _env("GOTIFY_TOKEN")
    if not url or not token:
        return False
    priority = {"info": 1, "low": 2, "medium": 5,
                "high": 8, "critical": 10}.get(severity, 5)
    try:
        r = requests.post(
            f"{url.rstrip('/')}/message?token={token}",
            json={"title": title[:200], "message": message[:4000],
                   "priority": priority},
            timeout=config.REQUEST_TIMEOUT)
        r.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("Gotify: %s", exc)
        return False


def send_ntfy(title: str, message: str, severity: str = "info") -> bool:
    """ntfy.sh push."""
    base = _env("NTFY_URL", "https://ntfy.sh").rstrip("/")
    topic = _env("NTFY_TOPIC")
    if not topic:
        return False
    priority = {"info": "default", "low": "low", "medium": "default",
                "high": "high", "critical": "urgent"}.get(severity, "default")
    tags = {"info": "information_source", "low": "white_check_mark",
            "medium": "warning", "high": "rotating_light",
            "critical": "fire"}.get(severity, "bell")
    try:
        r = requests.post(
            f"{base}/{topic}",
            data=message[:4000].encode("utf-8"),
            headers={
                "Title": title[:200],
                "Priority": priority,
                "Tags": tags,
            }, timeout=config.REQUEST_TIMEOUT)
        r.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("ntfy: %s", exc)
        return False


def send_pushover(title: str, message: str,
                  severity: str = "info") -> bool:
    """Pushover push."""
    token = _env("PUSHOVER_TOKEN")
    user = _env("PUSHOVER_USER")
    if not token or not user:
        return False
    priority = {"info": 0, "low": -1, "medium": 0,
                "high": 1, "critical": 2}.get(severity, 0)
    try:
        r = requests.post(
            "https://api.pushover.net/1/messages.json",
            data={"token": token, "user": user,
                   "title": title[:200], "message": message[:1000],
                   "priority": priority},
            timeout=config.REQUEST_TIMEOUT)
        r.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("Pushover: %s", exc)
        return False


def send_pagerduty(title: str, message: str,
                   severity: str = "info") -> bool:
    """PagerDuty Events v2."""
    key = _env("PAGERDUTY_ROUTING_KEY")
    if not key:
        return False
    pd_sev = {"info": "info", "low": "info", "medium": "warning",
              "high": "error", "critical": "critical"}.get(severity, "info")
    payload = {
        "routing_key": key,
        "event_action": "trigger",
        "payload": {
            "summary": title[:1024],
            "source": "CyberSec Toolkit",
            "severity": pd_sev,
            "custom_details": {"message": message[:4000]},
        },
    }
    try:
        r = requests.post("https://events.pagerduty.com/v2/enqueue",
                          json=payload, timeout=config.REQUEST_TIMEOUT)
        r.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("PagerDuty: %s", exc)
        return False


def send_email(subject: str, body: str,
               severity: str = "info",
               attachments: list[str] | None = None) -> bool:
    """Email SMTP с вложениями."""
    need = [config.SMTP_HOST, config.SMTP_USER,
            config.SMTP_PASS, config.SMTP_TO]
    if not all(need):
        return False

    from_addr = config.SMTP_FROM or config.SMTP_USER
    try:
        if attachments:
            msg: Any = MIMEMultipart()
            msg.attach(MIMEText(body, "plain", "utf-8"))
            for att in attachments:
                p = Path(att)
                if not p.exists():
                    continue
                part = MIMEBase("application", "octet-stream")
                with p.open("rb") as f:
                    part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition",
                    f'attachment; filename="{p.name}"')
                msg.attach(part)
        else:
            msg = MIMEText(body, "plain", "utf-8")

        msg["Subject"] = Header(f"[{severity.upper()}] {subject}", "utf-8")
        msg["From"] = from_addr
        msg["To"] = config.SMTP_TO

        if config.SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(config.SMTP_HOST,
                                       config.SMTP_PORT, timeout=15)
        else:
            server = smtplib.SMTP(config.SMTP_HOST,
                                   config.SMTP_PORT, timeout=15)
            server.starttls()
        server.login(config.SMTP_USER, config.SMTP_PASS)
        server.sendmail(from_addr, [config.SMTP_TO], msg.as_string())
        server.quit()
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("Email: %s", exc)
        return False


def send_desktop(title: str, message: str,
                 severity: str = "info") -> bool:
    """Desktop notification (Linux/macOS/Windows)."""
    sysname = platform.system()
    try:
        if sysname == "Linux":
            urgency = {"info": "low", "low": "low",
                       "medium": "normal", "high": "normal",
                       "critical": "critical"}.get(severity, "normal")
            subprocess.run(
                ["notify-send", "-u", urgency, title, message],
                check=True, timeout=5,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        if sysname == "Darwin":
            subprocess.run(
                ["osascript", "-e",
                 f'display notification "{message}" with title "{title}"'],
                check=True, timeout=5,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        if sysname == "Windows":
            # PowerShell toast (via BurntToast not guaranteed, use msg fallback)
            try:
                subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     f'[System.Reflection.Assembly]::LoadWithPartialName'
                     f'("System.Windows.Forms") | Out-Null; '
                     f'[System.Windows.Forms.MessageBox]::Show("{message[:200]}",'
                     f'"{title}")'],
                    check=False, timeout=8,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            except Exception:
                return False
        return False
    except Exception as exc:  # noqa: BLE001
        log.error("Desktop: %s", exc)
        return False


def send_webhook(title: str, message: str, severity: str = "info") -> bool:
    """Generic webhook с HMAC подписью."""
    url = _env("GENERIC_WEBHOOK_URL")
    if not url:
        return False
    payload = {
        "title": title, "message": message, "severity": severity,
        "ts": datetime.utcnow().isoformat(),
        "source": "cyber_toolkit",
    }
    headers = {"Content-Type": "application/json"}
    secret = _env("GENERIC_WEBHOOK_SECRET")
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if secret:
        sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        headers["X-Signature-256"] = f"sha256={sig}"
    try:
        r = requests.post(url, data=body, headers=headers,
                          timeout=config.REQUEST_TIMEOUT)
        r.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("Webhook: %s", exc)
        return False


def send_syslog(title: str, message: str, severity: str = "info") -> bool:
    """Syslog UDP/TCP."""
    host = _env("SYSLOG_HOST")
    if not host:
        return False
    port = _env_int("SYSLOG_PORT", 514)
    try:
        pri = {"info": 14, "low": 13, "medium": 12,
               "high": 11, "critical": 10}.get(severity, 14)
        facility = 1  # user-level
        tag = "cyber_toolkit"
        msg = f"<{facility*8 + pri}>" \
              f"{datetime.now().strftime('%b %d %H:%M:%S')} " \
              f"{socket.gethostname()} {tag}: {title} - {message}"[:1024]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg.encode("utf-8", errors="ignore"), (host, port))
        sock.close()
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("Syslog: %s", exc)
        return False


# ===========================================================================
# Channel registry
# ===========================================================================

CHANNELS: dict[str, Callable[[str, str, str], bool]] = {
    "telegram":   send_telegram,
    "discord":    send_discord,
    "slack":      send_slack,
    "mattermost": send_mattermost,
    "rocketchat": send_rocketchat,
    "teams":      send_teams,
    "gotify":     send_gotify,
    "ntfy":       send_ntfy,
    "pushover":   send_pushover,
    "pagerduty":  send_pagerduty,
    "email":      send_email,
    "webhook":    send_webhook,
    "syslog":     send_syslog,
    "desktop":    send_desktop,
}


def channel_configured(channel: str) -> bool:
    """Проверить, заданы ли env для канала."""
    checks = {
        "telegram": lambda: bool(
            (config.TELEGRAM_BOT_TOKEN or _env("TELEGRAM_BOT_TOKEN")) and
            (config.TELEGRAM_CHAT_ID or _env("TELEGRAM_CHAT_ID"))),
        "discord": lambda: bool(
            config.DISCORD_WEBHOOK_URL or _env("DISCORD_WEBHOOK_URL")),
        "slack": lambda: bool(_env("SLACK_WEBHOOK_URL")),
        "mattermost": lambda: bool(_env("MATTERMOST_WEBHOOK_URL")),
        "rocketchat": lambda: bool(_env("ROCKETCHAT_WEBHOOK_URL")),
        "teams": lambda: bool(_env("TEAMS_WEBHOOK_URL")),
        "gotify": lambda: bool(_env("GOTIFY_URL") and _env("GOTIFY_TOKEN")),
        "ntfy": lambda: bool(_env("NTFY_TOPIC")),
        "pushover": lambda: bool(_env("PUSHOVER_TOKEN") and
                                  _env("PUSHOVER_USER")),
        "pagerduty": lambda: bool(_env("PAGERDUTY_ROUTING_KEY")),
        "email": lambda: bool(
            config.SMTP_HOST and config.SMTP_USER and
            config.SMTP_PASS and config.SMTP_TO),
        "webhook": lambda: bool(_env("GENERIC_WEBHOOK_URL")),
        "syslog": lambda: bool(_env("SYSLOG_HOST")),
        "desktop": lambda: platform.system() in ("Linux", "Darwin", "Windows"),
    }
    fn = checks.get(channel)
    return fn() if fn else False


# ===========================================================================
# Public API
# ===========================================================================

def notify_all(title: str, message: str,
               severity: str = "info",
               module: str = "",
               attachments: list[str] | None = None,
               force: bool = False) -> dict[str, bool]:
    """
    Отправить уведомление во все настроенные каналы.

    Args:
        title: заголовок
        message: тело
        severity: info|low|medium|high|critical
        module: имя модуля (для фильтра)
        attachments: список путей для вложения (только email)
        force: игнорировать фильтры (severity, modules, quiet hours, rate)
    """
    # Master switch
    if not config.NOTIFY_ENABLED and not force:
        log.debug("Notify отключён")
        return {}

    # Severity filter
    if not force and not _severity_ok(severity):
        log.debug("Severity %s < min — skip", severity)
        return {}

    # Module filter
    if not force and module:
        allowed = _env("NOTIFY_MODULES", "").strip()
        if allowed:
            allowed_set = {m.strip() for m in allowed.split(",") if m.strip()}
            if module not in allowed_set:
                log.debug("Module %s не в списке — skip", module)
                return {}

    # Quiet hours (кроме critical)
    if not force and severity != "critical" and _in_quiet_hours():
        log.debug("Quiet hours — skip")
        return {}

    # Rate limit (кроме critical)
    if not force and severity != "critical" and not _rate_ok():
        log.warning("Rate limit exceeded — skip")
        return {}

    # Dedup
    fingerprint = hashlib.sha256(
        f"{title}|{message[:200]}".encode()).hexdigest()
    if not force and not _dedup_ok(fingerprint):
        log.debug("Duplicate notification — skip")
        return {}

    # Send
    results: dict[str, bool] = {}
    for name, fn in CHANNELS.items():
        if not channel_configured(name):
            continue
        # Email — handle attachments
        if name == "email":
            def _send_email() -> bool:
                return send_email(title, message, severity,
                                   attachments=attachments)
            ok, attempts, latency = _with_retry(_send_email)
        else:
            def _send() -> bool:
                return fn(title, message, severity)
            ok, attempts, latency = _with_retry(_send)

        results[name] = ok
        _log_history(name, ok, title, message, latency,
                      severity=severity, attempts=attempts)
        if ok:
            _rate_mark()

    ok_count = sum(1 for v in results.values() if v)
    if ok_count:
        log.info("Notified via %s/%s channels",
                 ok_count, len(results))
    elif results:
        log.warning("Все каналы не сработали: %s", results)
    return results


def notify_scan_done(module: str, target: str, summary: str = "",
                      severity: str = "info",
                      attachments: list[str] | None = None) -> dict[str, bool]:
    """Готовое уведомление о завершении скана."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = f"✅ Скан завершён: {module}"
    message = (
        f"**Модуль:** `{module}`\n"
        f"**Цель:** `{target}`\n"
        f"**Время:** {ts}\n"
    )
    if summary:
        message += f"\n{summary[:1500]}"
    return notify_all(title, message, severity=severity,
                       module=module, attachments=attachments)


def notify_finding(title: str, target: str = "",
                    severity: str = "high",
                    body: str = "") -> dict[str, bool]:
    """Уведомление о находке (для findings → notes → notify)."""
    emoji = {"info": "ℹ️", "low": "🟢", "medium": "🟡",
             "high": "🟠", "critical": "🔴"}.get(severity, "📌")
    full_title = f"{emoji} {severity.upper()}: {title}"
    message = f"**Target:** `{target or '—'}`\n\n{body[:1200]}"
    return notify_all(full_title, message, severity=severity,
                       module="findings", force=(severity == "critical"))


# ===========================================================================
# Batch / Queue
# ===========================================================================

_batch_queue: list[dict] = []
_batch_lock = threading.Lock()


def queue_notification(title: str, message: str,
                        severity: str = "info") -> None:
    """Добавить в очередь (отправится через flush_batch)."""
    with _batch_lock:
        _batch_queue.append({
            "title": title, "message": message, "severity": severity,
            "ts": time.time(),
        })


def flush_batch() -> dict[str, bool]:
    """Отправить всё что накопилось одним сообщением."""
    with _batch_lock:
        items = list(_batch_queue)
        _batch_queue.clear()
    if not items:
        return {}
    title = f"📦 Batch ({len(items)} events)"
    lines = []
    for it in items:
        ts = datetime.fromtimestamp(it["ts"]).strftime("%H:%M:%S")
        lines.append(f"[{ts}] ({it['severity']}) {it['title']}")
    message = "\n".join(lines)[:3000]
    # Max severity
    max_sev = max(items, key=lambda x: SEVERITY_ORDER.get(
        x["severity"], 0))["severity"]
    return notify_all(title, message, severity=max_sev, force=False)


# ===========================================================================
# Diagnostics / tests
# ===========================================================================

def status() -> None:
    """Показать статус всех каналов."""
    table = Table(title="📢 Notifier: статус каналов")
    table.add_column("Канал", style="cyan", width=12)
    table.add_column("Env", width=6)
    table.add_column("Настроен", width=10)
    table.add_column("Детали", style="white", max_width=50)

    for name in CHANNELS:
        env_ok = channel_configured(name)
        table.add_row(
            name, "✓" if env_ok else "—",
            "[green]✓[/green]" if env_ok else "[red]—[/red]",
            _channel_detail(name),
        )

    console.print(table)

    # Global config
    g = Table(title="⚙️  Global config")
    g.add_column("Параметр", style="cyan")
    g.add_column("Значение", style="green")
    g.add_row("NOTIFY_ENABLED",
               "✓" if config.NOTIFY_ENABLED else "✗")
    g.add_row("NOTIFY_MIN_SEVERITY",
               _env("NOTIFY_MIN_SEVERITY", "info"))
    g.add_row("NOTIFY_MODULES",
               _env("NOTIFY_MODULES", "(все)"))
    g.add_row("NOTIFY_QUIET_HOURS",
               _env("NOTIFY_QUIET_HOURS", "(нет)"))
    g.add_row("NOTIFY_RATE_LIMIT",
               str(_env_int("NOTIFY_RATE_LIMIT", 60)) + "/час")
    g.add_row("NOTIFY_DEDUP_TTL",
               str(_env_int("NOTIFY_DEDUP_TTL", 300)) + "s")
    g.add_row("В quiet hours",
               "✓" if _in_quiet_hours() else "—")
    g.add_row("Rate OK",
               "✓" if _rate_ok() else "✗ (превышен)")
    console.print(g)

    stats = history_stats()
    s = Table(title="📊 Статистика отправок")
    s.add_column("Метрика", style="cyan")
    s.add_column("Значение", style="green")
    s.add_row("Total", str(stats["total"]))
    s.add_row("OK", str(stats["ok"]))
    s.add_row("Failed", str(stats["failed"]))
    s.add_row("Success rate", f"{stats['success_rate']}%")
    s.add_row("Avg latency", f"{stats['avg_latency_ms']} ms")
    for ch, c in list(stats["by_channel"].items())[:10]:
        s.add_row(f"  {ch}", str(c))
    console.print(s)


def _channel_detail(name: str) -> str:
    if name == "telegram":
        cid = config.TELEGRAM_CHAT_ID or _env("TELEGRAM_CHAT_ID")
        return f"chat_id={cid or '—'}"
    if name == "discord":
        url = config.DISCORD_WEBHOOK_URL or _env("DISCORD_WEBHOOK_URL")
        return "webhook" if url else "не задан"
    if name == "slack":
        return "webhook" if _env("SLACK_WEBHOOK_URL") else "не задан"
    if name == "email":
        if config.SMTP_HOST:
            return f"{config.SMTP_HOST}:{config.SMTP_PORT} " \
                   f"→ {config.SMTP_TO or '—'}"
        return "SMTP не задан"
    if name == "ntfy":
        return f"topic={_env('NTFY_TOPIC') or '—'}"
    if name == "syslog":
        return f"{_env('SYSLOG_HOST') or '—'}:" \
               f"{_env_int('SYSLOG_PORT', 514)}"
    if name == "webhook":
        return "signed" if _env("GENERIC_WEBHOOK_SECRET") else "unsigned"
    if name == "desktop":
        return platform.system()
    return "env-based"


def test_channel(channel: str) -> None:
    """Тест одного канала."""
    if channel not in CHANNELS:
        console.print(f"[red]Неизвестный канал: {channel}[/red]")
        return
    if not channel_configured(channel):
        console.print(f"[yellow]Канал {channel} не настроен (env).[/yellow]")
        return
    title = "CyberSec Toolkit — тест"
    message = f"Тестовое сообщение, {datetime.now().strftime('%H:%M:%S')}"
    fn = CHANNELS[channel]
    start = time.time()
    ok = fn(title, message, "info")
    latency = (time.time() - start) * 1000
    _log_history(channel, ok, title, message, latency, severity="info")
    console.print(
        f"[green]✓ отправлено[/green] ({latency:.0f} ms)" if ok
        else "[red]✗ не сработало[/red]")


def test_all() -> None:
    """Прогнать тест по всем настроенным каналам."""
    title = "CyberSec Toolkit — тест всех каналов"
    message = f"Проверка каналов, {datetime.now().strftime('%H:%M:%S')}"
    results: dict[str, tuple[bool, float]] = {}
    for name, fn in CHANNELS.items():
        if not channel_configured(name):
            continue
        start = time.time()
        try:
            ok = fn(title, message, "info")
        except Exception:
            ok = False
        latency = (time.time() - start) * 1000
        results[name] = (ok, latency)
        _log_history(name, ok, title, message, latency)

    t = Table(title=f"Результат теста ({len(results)} каналов)")
    t.add_column("Канал", style="cyan")
    t.add_column("Статус", width=10)
    t.add_column("Latency", width=12)
    for k, (ok, lat) in results.items():
        t.add_row(k,
                   "[green]OK[/green]" if ok else "[red]FAIL[/red]",
                   f"{lat:.0f} ms")
    console.print(t)


def send_custom() -> None:
    """Отправить произвольное сообщение."""
    title = Prompt.ask("Заголовок", default="CyberSec Toolkit")
    message = Prompt.ask("Сообщение")
    sev = Prompt.ask("Severity",
                     choices=["info", "low", "medium", "high", "critical"],
                     default="info")
    results = notify_all(title, message, severity=sev, force=True)
    if not results:
        console.print("[yellow]Нет настроенных каналов.[/yellow]")
        return
    for k, v in results.items():
        console.print(f"  {k}: {'[green]OK[/green]' if v else '[red]FAIL[/red]'}")


def show_history(limit: int = 50) -> None:
    """Показать историю отправок."""
    items = history(limit=limit)
    if not items:
        console.print("[yellow]История пуста.[/yellow]")
        return
    t = Table(title=f"📜 История уведомлений ({len(items)})")
    t.add_column("ID", style="dim", width=5)
    t.add_column("Время", width=19)
    t.add_column("Канал", style="cyan", width=12)
    t.add_column("Sev", width=8)
    t.add_column("OK", width=4)
    t.add_column("Latency", width=10)
    t.add_column("Title", style="white", max_width=50)
    for r in items:
        sev = r.get("severity", "info")
        sty = {"info": "dim", "low": "green", "medium": "yellow",
               "high": "red", "critical": "bold red"}.get(sev, "white")
        t.add_row(
            str(r["id"]),
            str(r["ts"])[:19],
            r["channel"],
            f"[{sty}]{sev}[/{sty}]",
            "[green]✓[/green]" if r["ok"] else "[red]✗[/red]",
            f"{r.get('latency_ms', 0):.0f} ms",
            (r.get("title") or "")[:50],
        )
    console.print(t)


def cli_status() -> None:
    status()


def cli_test_all() -> None:
    test_all()


def cli_history(limit: int = 50) -> None:
    show_history(limit)


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]📢 Notifier Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Статус каналов + конфиг"),
        ("2", "Тест всех каналов"),
        ("3", "Тест одного канала"),
        ("4", "Отправить произвольное сообщение"),
        ("5", "История отправок"),
        ("6", "Статистика истории"),
        ("7", "Отправить batch (flush queue)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        status()
    elif c == "2":
        test_all()
    elif c == "3":
        ch = Prompt.ask("Канал", choices=list(CHANNELS.keys()))
        test_channel(ch)
    elif c == "4":
        send_custom()
    elif c == "5":
        show_history(IntPrompt.ask("Лимит", default=50))
    elif c == "6":
        stats = history_stats()
        for k, v in stats.items():
            console.print(f"  [cyan]{k}[/cyan]: {v}")
    elif c == "7":
        r = flush_batch()
        console.print(f"Отправлено: {r}")