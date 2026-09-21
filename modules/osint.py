"""Модуль OSINT: username, HIBP, phone, EXIF, GitHub dorks."""
import json
import re
from pathlib import Path

import requests
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from core.config import config
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


# Сайты для проверки username. {username} подставляется.
USERNAME_SITES = {
    "GitHub": "https://github.com/{}",
    "Twitter/X": "https://x.com/{}",
    "Instagram": "https://instagram.com/{}",
    "Reddit": "https://reddit.com/user/{}",
    "Medium": "https://medium.com/@{}",
    "Telegram": "https://t.me/{}",
    "TikTok": "https://tiktok.com/@{}",
    "Pinterest": "https://pinterest.com/{}",
    "Keybase": "https://keybase.io/{}",
    "About.me": "https://about.me/{}",
    "VK": "https://vk.com/{}",
    "Patreon": "https://patreon.com/{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Twitch": "https://twitch.tv/{}",
}


def username_check(username: str) -> None:
    """Проверка username на популярных площадках."""
    username = username.strip()
    if not username:
        console.print("[red]Пустой username.[/red]")
        return
    table = Table(title=f"Username: {username}")
    table.add_column("Сервис", style="cyan")
    table.add_column("URL")
    table.add_column("Статус")
    found: list[str] = []
    for name, tmpl in USERNAME_SITES.items():
        url = tmpl.format(username)
        try:
            r = requests.get(
                url,
                timeout=config.REQUEST_TIMEOUT,
                headers={"User-Agent": config.USER_AGENT},
                allow_redirects=True,
            )
            if r.status_code == 200:
                status = "[green]есть[/green]"
                found.append(url)
            elif r.status_code == 404:
                status = "[red]нет[/red]"
            else:
                status = f"[yellow]{r.status_code}[/yellow]"
        except Exception:  # noqa: BLE001
            status = "[yellow]err[/yellow]"
        table.add_row(name, url, status)
    console.print(table)
    db.save_scan("username", username, found)


def email_breach(email: str) -> None:
    """Проверка утечек через HaveIBeenPwned API v3."""
    email = email.strip()
    if not config.HIBP_API_KEY:
        console.print("[yellow]HIBP_API_KEY не задан в .env.[/yellow]")
        console.print(f"[cyan]Проверить вручную: "
                      f"https://haveibeenpwned.com/account/{email}[/cyan]")
        return
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    try:
        r = requests.get(
            url,
            headers={
                "hibp-api-key": config.HIBP_API_KEY,
                "User-Agent": config.USER_AGENT,
            },
            timeout=config.REQUEST_TIMEOUT,
        )
        if r.status_code == 404:
            console.print("[green]Утечек не найдено.[/green]")
            return
        r.raise_for_status()
        data = r.json()
        for b in data:
            console.print(
                f"[red]⚠ {b['Name']}[/red] — "
                f"{b.get('BreachDate')} | {b.get('Description', '')[:100]}"
            )
        db.save_scan("hibp", email, [b["Name"] for b in data])
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка HIBP: {exc}[/red]")
        log.error("HIBP %s: %s", email, exc)


def phone_lookup(phone: str) -> None:
    """Базовая информация о номере (страна, код, длина)."""
    digits = re.sub(r"\D", "", phone)
    if len(digits) < 7:
        console.print("[red]Неверный номер.[/red]")
        return

    info = {
        "raw": phone,
        "digits": digits,
        "length": len(digits),
        "country_code": None,
        "country": None,
    }

    prefixes = [
        ("7", "RU/KZ (+7)"),
        ("1", "US/CA (+1)"),
        ("44", "UK (+44)"),
        ("49", "DE (+49)"),
        ("380", "UA (+380)"),
        ("375", "BY (+375)"),
        ("48", "PL (+48)"),
        ("33", "FR (+33)"),
        ("39", "IT (+39)"),
        ("34", "ES (+34)"),
        ("86", "CN (+86)"),
        ("81", "JP (+81)"),
        ("91", "IN (+91)"),
        ("55", "BR (+55)"),
    ]
    # Проверяем префиксы от длинных к коротким
    for prefix, country in sorted(prefixes, key=lambda x: -len(x[0])):
        if digits.startswith(prefix):
            info["country_code"] = country
            info["country"] = country
            break

    for k, v in info.items():
        console.print(f"  [cyan]{k}[/cyan]: {v}")
    db.save_scan("phone", phone, info)


def exif_extractor(path: str) -> None:
    """Извлечение EXIF из изображения."""
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
    except ImportError:
        console.print("[red]Pillow не установлен.[/red]")
        return

    p = Path(path)
    if not p.exists():
        console.print("[red]Файл не найден.[/red]")
        return

    try:
        img = Image.open(p)
        exif = img.getexif()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка открытия: {exc}[/red]")
        return

    if not exif:
        console.print("[yellow]EXIF отсутствует.[/yellow]")
        return

    result: dict[str, str] = {}
    for tag_id, value in exif.items():
        tag = TAGS.get(tag_id, tag_id)
        result[str(tag)] = str(value)

    # GPS-блок
    try:
        gps_info = exif.get_ifd(0x8825)
    except Exception:  # noqa: BLE001
        gps_info = {}
    if gps_info:
        gps = {GPSTAGS.get(k, k): v for k, v in gps_info.items()}
        result["GPS"] = json.dumps(gps, default=str)

    for k, v in result.items():
        console.print(f"  [cyan]{k}[/cyan]: {str(v)[:160]}")
    db.save_scan("exif", str(p), result)


def github_dork(query: str) -> None:
    """GitHub-поиск (веб-ссылки)."""
    base = "https://github.com/search?q="
    queries = [
        f'{query} password',
        f'{query} api_key',
        f'{query} secret',
        f'org:{query} filename:.env',
        f'user:{query} filename:config.json',
        f'{query} filename:id_rsa',
    ]
    for q in queries:
        url = base + requests.utils.quote(q) + "&type=code"
        console.print(f"[cyan]{url}[/cyan]")
    db.save_scan("github_dork", query, queries)


def menu() -> None:
    """Меню модуля OSINT."""
    table = Table(title="[bold]OSINT[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Username check"),
        ("2", "Email breach (HIBP)"),
        ("3", "Phone lookup"),
        ("4", "EXIF extractor"),
        ("5", "GitHub dorking"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])
    {
        "1": lambda: username_check(Prompt.ask("Username")),
        "2": lambda: email_breach(Prompt.ask("Email")),
        "3": lambda: phone_lookup(Prompt.ask("Телефон")),
        "4": lambda: exif_extractor(Prompt.ask("Путь к фото")),
        "5": lambda: github_dork(Prompt.ask("Запрос")),
    }[c]()