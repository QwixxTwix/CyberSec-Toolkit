"""
Telegram Bot Control Panel: запуск сканов прямо из чата.
Author: idqwixxa

Команды:
    /start, /help              — справка
    /status                    — статус бота и БД
    /ping                      — проверка живости
    /reload                    — перечитать .env
    /dns <domain>              — DNS enumeration
    /whois <domain>            — WHOIS
    /geoip <ip>                — геолокация
    /portscan <host> [ports]   — скан портов (по умолчанию 1-1024)
    /headers <url>             — HTTP-заголовки
    /screenshot <url>          — скриншот
    /crawl <url>               — краулер
    /hashid <hash>             — идентификация хеша
    /crack <hash>              — крэк хеша словарём
    /last [N]                  — последние N сканов
    /export-html               — экспорт истории в HTML

Владелец (TELEGRAM_CHAT_ID):
    /users                     — список разрешённых
    /allow <chat_id>           — добавить пользователя
    /deny <chat_id>            — удалить пользователя
"""
import sys
import os
import json
import time
import threading
import io
import contextlib
import re
from datetime import datetime
from pathlib import Path
from typing import Callable

import requests
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from core.config import config, BASE_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import set_auto_confirm

console = Console()
log = get_logger(__name__)

API = "https://api.telegram.org/bot{token}/{method}"
USERS_FILE = BASE_DIR / "bot_users.json"

_bot_thread: threading.Thread | None = None
_stop_event = threading.Event()
_offset = 0
_users_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Whitelist (файл bot_users.json)
# ---------------------------------------------------------------------------

def _load_extra_users() -> set[int]:
    """Прочитать дополнительных пользователей из файла."""
    users: set[int] = set(config.BOT_EXTRA_USERS)
    if USERS_FILE.exists():
        try:
            data = json.loads(USERS_FILE.read_text(encoding="utf-8"))
            for x in data.get("allowed", []):
                try:
                    users.add(int(x))
                except (TypeError, ValueError):
                    pass
        except Exception as exc:  # noqa: BLE001
            log.warning("bot_users.json: %s", exc)
    return users


def _save_extra_users(users: set[int]) -> None:
    try:
        USERS_FILE.write_text(
            json.dumps({"allowed": sorted(users)}, indent=2),
            encoding="utf-8",
        )
    except Exception as exc:  # noqa: BLE001
        log.error("save bot_users.json: %s", exc)


def _owner_id() -> int | None:
    try:
        return int(config.TELEGRAM_CHAT_ID) if config.TELEGRAM_CHAT_ID else None
    except ValueError:
        return None


def _is_allowed(chat_id: str) -> bool:
    """Проверить, разрешён ли доступ пользователю."""
    try:
        cid = int(chat_id)
    except ValueError:
        return False
    owner = _owner_id()
    if owner is not None and cid == owner:
        return True
    with _users_lock:
        extra = _load_extra_users()
    return cid in extra


def _is_owner(chat_id: str) -> bool:
    owner = _owner_id()
    if owner is None:
        return False
    try:
        return int(chat_id) == owner
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Telegram API
# ---------------------------------------------------------------------------

def _api_url(method: str) -> str:
    return API.format(token=config.TELEGRAM_BOT_TOKEN, method=method)


def _api_get(method: str, **params) -> dict | None:
    """GET-запрос к Bot API."""
    if not config.TELEGRAM_BOT_TOKEN:
        return None
    try:
        r = requests.get(_api_url(method), params=params, timeout=35)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ReadTimeout:
        return {"ok": True, "result": []}
    except Exception as exc:  # noqa: BLE001
        log.warning("Bot API GET %s: %s", method, exc)
        return None


def _api_post(method: str, **data) -> dict | None:
    """POST JSON к Bot API."""
    if not config.TELEGRAM_BOT_TOKEN:
        return None
    try:
        r = requests.post(_api_url(method), json=data, timeout=20)
        r.raise_for_status()
        return r.json()
    except Exception as exc:  # noqa: BLE001
        log.warning("Bot API POST %s: %s", method, exc)
        return None


def _api_post_photo(photo_path: Path, chat_id: str,
                    caption: str = "") -> dict | None:
    """Отправка фото через multipart (JSON не поддерживает бинарь)."""
    if not config.TELEGRAM_BOT_TOKEN:
        return None
    try:
        with photo_path.open("rb") as f:
            r = requests.post(
                _api_url("sendPhoto"),
                data={"chat_id": chat_id, "caption": caption[:1024]},
                files={"photo": (photo_path.name, f, "image/png")},
                timeout=60,
            )
        r.raise_for_status()
        return r.json()
    except Exception as exc:  # noqa: BLE001
        log.warning("sendPhoto: %s", exc)
        return None


def send_message(text: str, chat_id: str | None = None,
                 parse_mode: str = "Markdown") -> bool:
    """Отправить сообщение (обрезает по 4000 символов)."""
    cid = chat_id or config.TELEGRAM_CHAT_ID
    if not cid:
        return False
    if len(text) > 4000:
        text = text[:4000] + "\n… (обрезано)"
    resp = _api_post("sendMessage", chat_id=cid, text=text,
                     parse_mode=parse_mode,
                     disable_web_page_preview=True)
    return bool(resp and resp.get("ok"))


def send_typing(chat_id: str | None = None) -> None:
    cid = chat_id or config.TELEGRAM_CHAT_ID
    if cid:
        _api_post("sendChatAction", chat_id=cid, action="typing")


# ---------------------------------------------------------------------------
# Захват вывода
# ---------------------------------------------------------------------------

def _capture_output(fn: Callable, *args, **kwargs) -> str:
    """Выполнить функцию, перехватить stdout/stderr, вычистить ANSI."""
    buf = io.StringIO()
    set_auto_confirm(True)
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            try:
                fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001
                buf.write(f"\n[Ошибка] {exc}\n")
    finally:
        set_auto_confirm(False)

    raw = buf.getvalue()
    raw = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw)
    raw = re.sub(r"\[/?[a-zA-Z][^\]]*\]", "", raw)
    raw = re.sub(r"\n{3,}", "\n\n", raw)
    return raw.strip() or "(пусто)"


# ---------------------------------------------------------------------------
# Команды
# ---------------------------------------------------------------------------

HELP_TEXT = """*CyberSec Toolkit — Telegram Control Panel*
_by idqwixxa_

*Разведка:*
`/dns <domain>` — DNS enumeration
`/whois <domain>` — WHOIS
`/geoip <ip>` — геолокация
`/portscan <host> [ports]` — скан портов

*Web:*
`/headers <url>` — HTTP-заголовки
`/screenshot <url>` — скриншот
`/crawl <url>` — краулер

*Пароли:*
`/hashid <hash>` — определить тип
`/crack <hash>` — крэк словарём

*Утилиты:*
`/last [N]` — последние N сканов (по умолчанию 5)
`/export-html` — экспорт истории в HTML
`/status` — статус бота
`/ping` — проверка
`/reload` — перечитать .env

_Только для этичного использования._
"""


def _cmd_start(chat_id: str, args: list[str]) -> None:
    send_message(
        "🛡️ *CyberSec Toolkit Bot*\n\n"
        "Готов к работе. Отправь /help — список команд.\n\n"
        "⚠ Только для этичного использования и CTF.",
        chat_id=chat_id,
    )


def _cmd_help(chat_id: str, args: list[str]) -> None:
    send_message(HELP_TEXT, chat_id=chat_id)


def _cmd_ping(chat_id: str, args: list[str]) -> None:
    send_message(
        f"🏓 pong\n🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        chat_id=chat_id,
    )


def _cmd_reload(chat_id: str, args: list[str]) -> None:
    """Перечитать .env (без перезапуска)."""
    try:
        from dotenv import load_dotenv
        load_dotenv(BASE_DIR / ".env", override=True)
        send_message("🔄 .env перечитан (некоторые поля требуют "
                     "перезапуска процесса).", chat_id=chat_id)
    except Exception as exc:  # noqa: BLE001
        send_message(f"❌ Ошибка reload: {exc}", chat_id=chat_id)


def _cmd_status(chat_id: str, args: list[str]) -> None:
    cur = db.conn.cursor()
    cur.execute("SELECT COUNT(*) as c FROM scans")
    total = cur.fetchone()["c"]
    rows = db.history(1)
    last = "—"
    if rows:
        last = f"{rows[0]['module']} → {rows[0]['target']}"
    notif = "🟢 ON" if config.NOTIFY_ENABLED else "⚪ OFF"
    extra = _load_extra_users()
    send_message(
        f"*📊 Статус CyberSec Toolkit*\n\n"
        f"• Сканов в БД: `{total}`\n"
        f"• Последний: `{last[:60]}`\n"
        f"• Уведомления: {notif}\n"
        f"• Доп. пользователей: `{len(extra)}`\n"
        f"• Время: `{datetime.now().strftime('%Y-%m-%d %H:%M')}`",
        chat_id=chat_id,
    )


def _cmd_dns(chat_id: str, args: list[str]) -> None:
    if not args:
        send_message("❌ `/dns example.com`", chat_id=chat_id); return
    send_typing(chat_id)
    from modules import recon
    out = _capture_output(recon.dns_enum, args[0])
    send_message(f"```\n{out[:3500]}\n```", chat_id=chat_id)


def _cmd_whois(chat_id: str, args: list[str]) -> None:
    if not args:
        send_message("❌ `/whois example.com`", chat_id=chat_id); return
    send_typing(chat_id)
    from modules import recon
    out = _capture_output(recon.whois_lookup, args[0])
    send_message(f"```\n{out[:3500]}\n```", chat_id=chat_id)


def _cmd_geoip(chat_id: str, args: list[str]) -> None:
    if not args:
        send_message("❌ `/geoip 8.8.8.8`", chat_id=chat_id); return
    send_typing(chat_id)
    from modules import recon
    out = _capture_output(recon.ip_geolocation, args[0])
    send_message(f"```\n{out[:3500]}\n```", chat_id=chat_id)


def _cmd_portscan(chat_id: str, args: list[str]) -> None:
    if not args:
        send_message("❌ `/portscan 1.2.3.4 [1-1024]`", chat_id=chat_id); return
    host = args[0]
    ports = args[1] if len(args) > 1 else "1-1024"
    send_message(f"🔍 Скан `{host}` порты `{ports}`…\n"
                 f"_Это займёт 30–90 секунд._", chat_id=chat_id)
    send_typing(chat_id)
    from modules import recon
    out = _capture_output(recon.port_scan, host, ports)
    send_message(f"```\n{out[:3500]}\n```", chat_id=chat_id)


def _cmd_headers(chat_id: str, args: list[str]) -> None:
    if not args:
        send_message("❌ `/headers https://example.com`", chat_id=chat_id); return
    send_typing(chat_id)
    from modules import web_vuln
    out = _capture_output(web_vuln.header_analyzer, args[0])
    send_message(f"```\n{out[:3500]}\n```", chat_id=chat_id)


def _cmd_screenshot(chat_id: str, args: list[str]) -> None:
    if not args:
        send_message("❌ `/screenshot https://example.com`", chat_id=chat_id); return
    url = args[0]
    send_message(f"📸 Делаю скриншот `{url}`…", chat_id=chat_id)
    send_typing(chat_id)
    try:
        from modules import screenshot
        from core.config import REPORT_DIR
        before = set(REPORT_DIR.glob("shot_*.png"))
        _capture_output(screenshot.screenshot_one, url, True)
        after = set(REPORT_DIR.glob("shot_*.png"))
        new_files = list(after - before)
        if not new_files:
            send_message("⚠ Скриншот не создан. Проверь playwright.",
                         chat_id=chat_id)
            return
        p = max(new_files, key=lambda x: x.stat().st_mtime)
        resp = _api_post_photo(p, chat_id, caption=f"📸 {url}")
        if not resp or not resp.get("ok"):
            send_message(f"✅ Сохранён: `{p.name}` (не удалось отправить фото)",
                         chat_id=chat_id)
    except Exception as exc:  # noqa: BLE001
        send_message(f"❌ Ошибка скриншота: {exc}", chat_id=chat_id)


def _cmd_crawl(chat_id: str, args: list[str]) -> None:
    if not args:
        send_message("❌ `/crawl https://example.com`", chat_id=chat_id); return
    send_message(f"🕷 Краулю `{args[0]}` (depth=1, max=30)…", chat_id=chat_id)
    send_typing(chat_id)
    from modules import web_crawler
    out = _capture_output(web_crawler.crawl, args[0], 1, 30)
    send_message(f"```\n{out[:3500]}\n```", chat_id=chat_id)


def _cmd_hashid(chat_id: str, args: list[str]) -> None:
    if not args:
        send_message("❌ `/hashid <hash>`", chat_id=chat_id); return
    from modules import passwords
    out = _capture_output(passwords.identify_hash, args[0])
    send_message(f"```\n{out[:3500]}\n```", chat_id=chat_id)


def _cmd_crack(chat_id: str, args: list[str]) -> None:
    if not args:
        send_message("❌ `/crack <hash>`", chat_id=chat_id); return
    send_message("🔨 Крэк словарём…", chat_id=chat_id)
    send_typing(chat_id)
    from modules import passwords
    out = _capture_output(passwords.crack_hash, args[0])
    send_message(f"```\n{out[:3500]}\n```", chat_id=chat_id)


def _cmd_last(chat_id: str, args: list[str]) -> None:
    n = 5
    if args:
        try:
            n = min(int(args[0]), 30)
        except ValueError:
            pass
    rows = db.history(n)
    if not rows:
        send_message("📭 История пуста.", chat_id=chat_id); return
    lines = ["*📜 Последние сканы:*", ""]
    for r in rows:
        lines.append(f"`#{r['id']:<4}` {r['module']:<14} `{r['target'][:30]}`")
    send_message("\n".join(lines), chat_id=chat_id)


def _cmd_export_html(chat_id: str, args: list[str]) -> None:
    send_message("📄 Экспорт в HTML…", chat_id=chat_id)
    send_typing(chat_id)
    from modules import report_export
    out = _capture_output(report_export.export_html, 500)
    send_message(f"```\n{out[:3500]}\n```", chat_id=chat_id)


# ---- Whitelist-команды (только владелец) ----

def _cmd_users(chat_id: str, args: list[str]) -> None:
    owner = _owner_id()
    with _users_lock:
        extra = _load_extra_users()
    lines = ["*👥 Разрешённые пользователи:*", ""]
    lines.append(f"👑 Владелец: `{owner}`")
    if extra:
        for u in sorted(extra):
            lines.append(f"• `{u}`")
    else:
        lines.append("_Дополнительных нет._")
    lines.append("")
    lines.append("Добавить: `/allow <chat_id>`")
    lines.append("Удалить: `/deny <chat_id>`")
    send_message("\n".join(lines), chat_id=chat_id)


def _cmd_allow(chat_id: str, args: list[str]) -> None:
    if not args:
        send_message("❌ `/allow <chat_id>`", chat_id=chat_id); return
    try:
        new_id = int(args[0])
    except ValueError:
        send_message("❌ chat_id — целое число.", chat_id=chat_id); return
    with _users_lock:
        extra = _load_extra_users()
        extra.add(new_id)
        _save_extra_users(extra)
    send_message(f"✅ Добавлен `{new_id}` в разрешённые.", chat_id=chat_id)


def _cmd_deny(chat_id: str, args: list[str]) -> None:
    if not args:
        send_message("❌ `/deny <chat_id>`", chat_id=chat_id); return
    try:
        rm_id = int(args[0])
    except ValueError:
        send_message("❌ chat_id — целое число.", chat_id=chat_id); return
    if rm_id == _owner_id():
        send_message("❌ Нельзя удалить владельца.", chat_id=chat_id); return
    with _users_lock:
        extra = _load_extra_users()
        extra.discard(rm_id)
        _save_extra_users(extra)
    send_message(f"✅ Удалён `{rm_id}`.", chat_id=chat_id)


COMMANDS: dict[str, Callable[[str, list[str]], None]] = {
    "/start":         _cmd_start,
    "/help":          _cmd_help,
    "/ping":          _cmd_ping,
    "/status":        _cmd_status,
    "/reload":        _cmd_reload,
    "/dns":           _cmd_dns,
    "/whois":         _cmd_whois,
    "/geoip":         _cmd_geoip,
    "/portscan":      _cmd_portscan,
    "/headers":       _cmd_headers,
    "/screenshot":    _cmd_screenshot,
    "/crawl":         _cmd_crawl,
    "/hashid":        _cmd_hashid,
    "/crack":         _cmd_crack,
    "/last":          _cmd_last,
    "/export-html":   _cmd_export_html,
    # whitelist (только владелец)
    "/users":         _cmd_users,
    "/allow":         _cmd_allow,
    "/deny":          _cmd_deny,
}

OWNER_ONLY = {"/users", "/allow", "/deny", "/reload"}


# ---------------------------------------------------------------------------
# Обработка update (в отдельном потоке на каждую команду)
# ---------------------------------------------------------------------------

def _run_handler(handler: Callable[[str, list[str]], None],
                 chat_id: str, args: list[str],
                 cmd: str) -> None:
    """Обёртка для запуска в фоновом потоке."""
    try:
        handler(chat_id, args)
    except Exception as exc:  # noqa: BLE001
        log.exception("bot handler %s", cmd)
        try:
            send_message(f"❌ Ошибка: {exc}", chat_id=chat_id)
        except Exception:  # noqa: BLE001
            pass


def _handle_update(update: dict) -> None:
    msg = update.get("message") or update.get("edited_message")
    if not msg:
        return
    chat = msg.get("chat") or {}
    chat_id = str(chat.get("id", ""))
    text = (msg.get("text") or "").strip()

    if not text.startswith("/"):
        if _is_allowed(chat_id):
            send_message("🤔 Не понимаю. /help", chat_id=chat_id)
        else:
            send_message("⛔ Нет доступа. Попроси владельца добавить твой "
                         "chat_id командой `/allow`.", chat_id=chat_id)
        return

    parts = text.split()
    cmd = parts[0].split("@")[0].lower()
    args = parts[1:]

    if not _is_allowed(chat_id):
        send_message(
            "⛔ Доступ запрещён.\n"
            f"Твой chat_id: `{chat_id}`\n"
            "Попроси владельца добавить: `/allow " + chat_id + "`",
            chat_id=chat_id,
        )
        log.warning("denied user %s tried %s", chat_id, cmd)
        return

    if cmd in OWNER_ONLY and not _is_owner(chat_id):
        send_message("⛔ Только владелец может использовать эту команду.",
                     chat_id=chat_id)
        return

    handler = COMMANDS.get(cmd)
    if not handler:
        send_message(f"❓ Неизвестная: `{cmd}`. /help", chat_id=chat_id)
        return

    log.info("Bot cmd: %s %s (from %s)", cmd, " ".join(args), chat_id)
    # Запускаем в отдельном потоке, чтобы не блокировать polling
    threading.Thread(
        target=_run_handler, args=(handler, chat_id, args, cmd),
        daemon=True,
    ).start()


# ---------------------------------------------------------------------------
# Long-polling
# ---------------------------------------------------------------------------

def _poll_loop() -> None:
    global _offset
    log.info("Telegram bot polling started")
    console.print("[green]✓ Telegram-бот запущен (long-polling)[/green]")
    console.print(f"[dim]  Владелец: {config.TELEGRAM_CHAT_ID}[/dim]")
    extra = _load_extra_users()
    if extra:
        console.print(f"[dim]  Доп. пользователей: {len(extra)}[/dim]")

    while not _stop_event.is_set():
        try:
            data = _api_get(
                "getUpdates",
                offset=_offset + 1,
                timeout=30,
                allowed_updates='["message"]',
            )
            if not data or not data.get("ok"):
                time.sleep(2)
                continue
            for upd in data.get("result", []):
                _offset = max(_offset, upd.get("update_id", 0))
                try:
                    _handle_update(upd)
                except Exception as exc:  # noqa: BLE001
                    log.exception("update handler: %s", exc)
        except KeyboardInterrupt:
            break
        except Exception as exc:  # noqa: BLE001
            log.warning("poll loop: %s", exc)
            time.sleep(3)

    log.info("Telegram bot stopped")


# ---------------------------------------------------------------------------
# Публичный API
# ---------------------------------------------------------------------------

def start_bot_background() -> bool:
    global _bot_thread
    if not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID:
        console.print("[red]Не заданы TELEGRAM_BOT_TOKEN / CHAT_ID[/red]")
        return False
    if _bot_thread and _bot_thread.is_alive():
        console.print("[yellow]Бот уже запущен.[/yellow]")
        return True
    _stop_event.clear()
    _bot_thread = threading.Thread(target=_poll_loop, daemon=True,
                                   name="telegram-bot")
    _bot_thread.start()
    return True


def stop_bot() -> None:
    global _bot_thread
    _stop_event.set()
    if _bot_thread:
        _bot_thread.join(timeout=3)
    _bot_thread = None
    console.print("[yellow]Бот остановлен.[/yellow]")


def _get_me() -> dict | None:
    resp = _api_get("getMe")
    if resp and resp.get("ok"):
        return resp["result"]
    return None


def info() -> None:
    """Инфо о боте (для CLI/TUI)."""
    if not config.TELEGRAM_BOT_TOKEN:
        console.print("[red]TELEGRAM_BOT_TOKEN не задан[/red]")
        return

    table = Table(title="Telegram Bot Info")
    table.add_column("Параметр", style="cyan")
    table.add_column("Значение", style="green")

    table.add_row("Token", config.TELEGRAM_BOT_TOKEN[:20] + "…")
    table.add_row("Owner", config.TELEGRAM_CHAT_ID or "—")
    extra = _load_extra_users()
    table.add_row("Доп. users", str(len(extra)) + (
        f" ({', '.join(str(x) for x in sorted(extra))})" if extra else ""
    ))
    table.add_row("Running", "✓" if (_bot_thread and _bot_thread.is_alive())
                  else "—")

    me = _get_me()
    if me:
        table.add_row("Name", me.get("first_name", "?"))
        table.add_row("Username", "@" + me.get("username", "?"))
        table.add_row("ID", str(me.get("id", "?")))
    else:
        table.add_row("API", "[red]getMe failed — проверь токен[/red]")
    console.print(table)


def run_bot_forever() -> None:
    """Запустить и держать в foreground."""
    if not config.TELEGRAM_BOT_TOKEN:
        console.print("[red]TELEGRAM_BOT_TOKEN не задан[/red]")
        return
    console.print("[bold cyan]▶ Telegram-бот запущен. Ctrl+C — остановить.[/bold cyan]")

    me = _get_me()
    if me:
        console.print(f"[green]✓ @{me.get('username', '?')} "
                      f"({me.get('first_name', '?')})[/green]")
    else:
        console.print("[red]✗ getMe failed. Проверь токен.[/red]")
        return

    send_message("🟢 *CyberSec Toolkit Bot* запущен.\n/help — команды.")

    try:
        _poll_loop()
    except KeyboardInterrupt:
        console.print("\n[yellow]Остановка…[/yellow]")
        send_message("🔴 Бот остановлен.")
        stop_bot()


def menu() -> None:
    """Меню Telegram-бота."""
    table = Table(title="[bold]Telegram Bot[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Информация о боте (getMe)"),
        ("2", "Запустить бота (foreground, Ctrl+C — стоп)"),
        ("3", "Отправить тестовое сообщение"),
        ("4", "Показать разрешённых пользователей"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        info()
    elif c == "2":
        run_bot_forever()
    elif c == "3":
        ok = send_message(
            f"🟢 Тест от CyberSec Toolkit\n"
            f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        console.print("[green]✓ отправлено[/green]" if ok
                      else "[red]✗ ошибка[/red]")
    elif c == "4":
        with _users_lock:
            extra = _load_extra_users()
        console.print(f"[cyan]Владелец:[/cyan] {_owner_id()}")
        if extra:
            for u in sorted(extra):
                console.print(f"  • {u}")
        else:
            console.print("[yellow]Доп. пользователей нет.[/yellow]")