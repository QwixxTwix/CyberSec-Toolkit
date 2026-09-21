"""Вспомогательные функции."""
import re
import ipaddress
import socket
from urllib.parse import urlparse
from rich.console import Console
from rich.prompt import Confirm

console = Console()

URL_RE = re.compile(r"^https?://", re.IGNORECASE)

# Глобальный флаг: если True — confirm_external всегда возвращает True.
# Используется в неинтерактивных контекстах: Telegram-бот, scheduler.
AUTO_CONFIRM: bool = False


def set_auto_confirm(value: bool) -> None:
    """Установить режим авто-подтверждения."""
    global AUTO_CONFIRM
    AUTO_CONFIRM = value


def normalize_url(target: str) -> str:
    """Добавляет http:// если схема отсутствует."""
    if not URL_RE.match(target):
        return "http://" + target
    return target


def extract_host(target: str) -> str:
    """Из URL/строки достаёт hostname."""
    if URL_RE.match(target):
        return urlparse(target).hostname or target
    return target.split("/")[0].split(":")[0]


def is_ip(value: str) -> bool:
    """True, если value — корректный IP."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def resolve_host(host: str) -> str | None:
    """Резолв host -> IP или None."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def confirm_external(target: str) -> bool:
    """Запрос подтверждения для внешних целей (приватные — сразу True)."""
    if AUTO_CONFIRM:
        return True
    host = extract_host(target)
    if is_ip(host):
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback:
                return True
        except ValueError:
            pass
    try:
        return Confirm.ask(
            f"[yellow]Цель {target} выглядит внешней. "
            f"Подтверждаешь, что у тебя есть разрешение?[/yellow]",
            default=False,
        )
    except Exception:
        # Если нет TTY (например в потоке) — отказываем
        return False


def print_kv(data: dict) -> None:
    """Красивый вывод словаря."""
    for k, v in data.items():
        console.print(f"  [cyan]{k:<22}[/cyan] → {v}")