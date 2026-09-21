"""
Уведомления по завершении скана:
Telegram Bot, Discord Webhook, Email (SMTP), Desktop (notify-send/osascript).
Включается через NOTIFY_ENABLED=true в .env.
"""
import os
import sys
import smtplib
import subprocess
import platform
from email.mime.text import MIMEText
from email.header import Header
from datetime import datetime

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from core.config import config
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Каналы
# ---------------------------------------------------------------------------

def send_telegram(title: str, message: str) -> bool:
    """Отправить сообщение в Telegram через Bot API."""
    if not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID:
        log.debug("Telegram: не заданы токен/чат")
        return False
    url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
    text = f"*{title}*\n\n{message}"
    try:
        r = requests.post(
            url,
            json={
                "chat_id": config.TELEGRAM_CHAT_ID,
                "text": text,
                "parse_mode": "Markdown",
                "disable_web_page_preview": True,
            },
            timeout=config.REQUEST_TIMEOUT,
        )
        r.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("Telegram: %s", exc)
        return False


def send_discord(title: str, message: str) -> bool:
    """Отправить сообщение в Discord Webhook."""
    if not config.DISCORD_WEBHOOK_URL:
        log.debug("Discord: URL не задан")
        return False
    try:
        r = requests.post(
            config.DISCORD_WEBHOOK_URL,
            json={
                "content": f"**{title}**\n```\n{message[:1900]}\n```",
                "username": "CyberSec Toolkit",
            },
            timeout=config.REQUEST_TIMEOUT,
        )
        r.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("Discord: %s", exc)
        return False


def send_email(subject: str, body: str) -> bool:
    """Отправить email через SMTP."""
    need = [config.SMTP_HOST, config.SMTP_USER, config.SMTP_PASS, config.SMTP_TO]
    if not all(need):
        log.debug("Email: не все SMTP-переменные заданы")
        return False

    from_addr = config.SMTP_FROM or config.SMTP_USER
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = Header(subject, "utf-8")
        msg["From"] = from_addr
        msg["To"] = config.SMTP_TO

        if config.SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, timeout=15)
        else:
            server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15)
            server.starttls()

        server.login(config.SMTP_USER, config.SMTP_PASS)
        server.sendmail(from_addr, [config.SMTP_TO], msg.as_string())
        server.quit()
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("Email: %s", exc)
        return False


def send_desktop(title: str, message: str) -> bool:
    """Системное уведомление (Linux notify-send / macOS osascript)."""
    sysname = platform.system()
    try:
        if sysname == "Linux":
            subprocess.run(
                ["notify-send", title, message],
                check=True, timeout=5,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            return True
        if sysname == "Darwin":
            subprocess.run(
                ["osascript", "-e",
                 f'display notification "{message}" with title "{title}"'],
                check=True, timeout=5,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            return True
        log.debug("Desktop: не поддерживается на %s", sysname)
        return False
    except Exception as exc:  # noqa: BLE001
        log.error("Desktop: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Общая точка входа
# ---------------------------------------------------------------------------

def notify_all(title: str, message: str) -> dict[str, bool]:
    """
    Разослать уведомление во все доступные каналы.
    Возвращает словарь {channel: ok}. Ничего не делает, если
    NOTIFY_ENABLED != true.
    """
    if not config.NOTIFY_ENABLED:
        log.debug("Notify отключён (NOTIFY_ENABLED!=true)")
        return {}

    results = {
        "telegram": send_telegram(title, message),
        "discord": send_discord(title, message),
        "email": send_email(title, message),
        "desktop": send_desktop(title, message),
    }
    ok_any = any(results.values())
    if ok_any:
        log.info("Уведомление отправлено: %s", results)
    else:
        log.warning("Ни один канал не сработал: %s", results)
    return results


def notify_scan_done(module: str, target: str, summary: str = "") -> dict[str, bool]:
    """Готовое уведомление о завершении скана."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = f"CyberSec Toolkit — скан завершён"
    message = (
        f"Модуль: {module}\n"
        f"Цель:   {target}\n"
        f"Время:  {ts}\n"
    )
    if summary:
        message += f"\n{summary[:1500]}"
    return notify_all(title, message)


# ---------------------------------------------------------------------------
# Диагностика / тесты
# ---------------------------------------------------------------------------

def status() -> None:
    """Показать, какие каналы настроены."""
    table = Table(title="Notifier: статус каналов")
    table.add_column("Канал", style="cyan")
    table.add_column("Настроен", style="green")
    table.add_column("Детали", style="white")

    tg = bool(config.TELEGRAM_BOT_TOKEN and config.TELEGRAM_CHAT_ID)
    dc = bool(config.DISCORD_WEBHOOK_URL)
    em = bool(config.SMTP_HOST and config.SMTP_USER
              and config.SMTP_PASS and config.SMTP_TO)
    dt = platform.system() in ("Linux", "Darwin")

    table.add_row("NOTIFY_ENABLED", "да" if config.NOTIFY_ENABLED else "нет",
                  "глобальный тумблер")
    table.add_row("Telegram", "✓" if tg else "—",
                  f"chat_id={config.TELEGRAM_CHAT_ID or '—'}")
    table.add_row("Discord", "✓" if dc else "—",
                  "webhook" if dc else "webhook не задан")
    table.add_row("Email", "✓" if em else "—",
                  f"{config.SMTP_HOST or '—'}:{config.SMTP_PORT}"
                  f" → {config.SMTP_TO or '—'}")
    table.add_row("Desktop", "✓" if dt else "—",
                  platform.system())
    console.print(table)


def test_channel(channel: str) -> None:
    """Протестировать один канал."""
    title = "CyberSec Toolkit — тест"
    message = f"Тестовое уведомление, {datetime.now().strftime('%H:%M:%S')}"
    dispatch = {
        "telegram": send_telegram,
        "discord": send_discord,
        "email": send_email,
        "desktop": send_desktop,
    }
    fn = dispatch.get(channel)
    if not fn:
        console.print(f"[red]Неизвестный канал: {channel}[/red]")
        return
    ok = fn(title, message)
    console.print("[green]✓ отправлено[/green]" if ok else "[red]✗ не сработало[/red]")


def test_all() -> None:
    """Прогнать тест по всем каналам."""
    title = "CyberSec Toolkit — тест всех каналов"
    message = f"Проверка каналов уведомлений, {datetime.now().strftime('%H:%M:%S')}"
    results = {
        "telegram": send_telegram(title, message),
        "discord": send_discord(title, message),
        "email": send_email(title, message),
        "desktop": send_desktop(title, message),
    }
    table = Table(title="Результат теста")
    table.add_column("Канал", style="cyan")
    table.add_column("Статус", style="green")
    for k, v in results.items():
        table.add_row(k, "[green]OK[/green]" if v else "[red]FAIL[/red]")
    console.print(table)


def send_custom() -> None:
    """Отправить произвольное сообщение во все каналы."""
    title = Prompt.ask("Заголовок", default="CyberSec Toolkit")
    message = Prompt.ask("Сообщение")
    results = notify_all(title, message)
    if not results:
        console.print("[yellow]NOTIFY_ENABLED=false — сообщение не отправлено.[/yellow]")
        console.print("[yellow]Включи NOTIFY_ENABLED=true в .env[/yellow]")
        return
    for k, v in results.items():
        console.print(f"  {k}: {'[green]OK[/green]' if v else '[red]FAIL[/red]'}")


def menu() -> None:
    """Меню notifier."""
    table = Table(title="[bold]Notifier[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Статус каналов"),
        ("2", "Тест всех каналов"),
        ("3", "Тест одного канала"),
        ("4", "Отправить произвольное сообщение"),
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
        ch = Prompt.ask("Канал",
                        choices=["telegram", "discord", "email", "desktop"])
        test_channel(ch)
    elif c == "4":
        send_custom()