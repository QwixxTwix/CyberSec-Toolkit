"""
Password Vault — шифрованное хранилище паролей.
Author: idqwixxa

Формат файла vault.enc:
    MAGIC(4) = b"CSVT"
    VERSION(1) = 1
    salt(16)
    Fernet-token(JSON)

Ключ: PBKDF2-HMAC-SHA256(master_password, salt, 200_000 iterations)
      → 32 байта → base64 → Fernet key.
"""
import base64
import getpass
import json
import os
import secrets
import string
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table

from core.config import BASE_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

VAULT_FILE = BASE_DIR / "vault.enc"
MAGIC = b"CSVT"
VERSION = 1
SALT_LEN = 16
PBKDF2_ITER = 200_000
DEFAULT_PWD_LEN = 20

# Сессионный ключ (in-memory)
_session_key: bytes | None = None
_session_data: dict | None = None


# ---------------------------------------------------------------------------
# Крипто
# ---------------------------------------------------------------------------

def _derive_key(password: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 → base64-ключ для Fernet."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITER,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def _encrypt(data: dict, password: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    key = _derive_key(password, salt)
    token = Fernet(key).encrypt(
        json.dumps(data, ensure_ascii=False).encode("utf-8")
    )
    return MAGIC + bytes([VERSION]) + salt + token


def _decrypt(raw: bytes, password: str) -> dict:
    if not raw.startswith(MAGIC):
        raise ValueError("Файл не является CyberSec Vault")
    ver = raw[4]
    if ver != VERSION:
        raise ValueError(f"Версия vault {ver} не поддерживается")
    salt = raw[5:5 + SALT_LEN]
    token = raw[5 + SALT_LEN:]
    key = _derive_key(password, salt)
    try:
        blob = Fernet(key).decrypt(token)
    except InvalidToken:
        raise ValueError("Неверный мастер-пароль или файл повреждён")
    return json.loads(blob.decode("utf-8"))


# ---------------------------------------------------------------------------
# Класс Vault
# ---------------------------------------------------------------------------

class Vault:
    def __init__(self, path: Path = VAULT_FILE) -> None:
        self.path = path

    # --- статус ---
    def exists(self) -> bool:
        return self.path.exists()

    def size_kb(self) -> float:
        return self.path.stat().st_size / 1024 if self.path.exists() else 0.0

    def created_at(self) -> str | None:
        if not self.path.exists():
            return None
        return datetime.fromtimestamp(
            self.path.stat().st_ctime
        ).strftime("%Y-%m-%d %H:%M:%S")

    # --- unlock / lock ---
    def create(self, master_password: str) -> None:
        """Создать новый vault."""
        if self.exists():
            raise FileExistsError(f"{self.path} уже существует")
        data = {
            "version": VERSION,
            "created_at": datetime.utcnow().isoformat(),
            "entries": {},
        }
        raw = _encrypt(data, master_password)
        self.path.write_bytes(raw)
        try:
            os.chmod(self.path, 0o600)
        except Exception:  # noqa: BLE001
            pass
        log.info("Vault создан: %s", self.path)

    def unlock(self, master_password: str) -> bool:
        global _session_key, _session_data
        if not self.exists():
            raise FileNotFoundError("Vault не существует")
        raw = self.path.read_bytes()
        try:
            data = _decrypt(raw, master_password)
        except Exception as exc:  # noqa: BLE001
            log.warning("Vault unlock failed: %s", exc)
            return False
        _session_data = data
        # Ключ не храним отдельно — расшифровка уже прошла
        _session_key = b"unlocked"
        return True

    def lock(self) -> None:
        global _session_key, _session_data
        _session_key = None
        _session_data = None

    @property
    def unlocked(self) -> bool:
        return _session_data is not None

    # --- save / load ---
    def _save(self, master_password: str) -> None:
        if _session_data is None:
            raise RuntimeError("Vault заблокирован")
        raw = _encrypt(_session_data, master_password)
        self.path.write_bytes(raw)
        try:
            os.chmod(self.path, 0o600)
        except Exception:  # noqa: BLE001
            pass

    # --- CRUD ---
    def add(self, title: str, username: str, password: str,
            url: str = "", notes: str = "", tags: list[str] | None = None,
            master_password: str | None = None) -> bool:
        if _session_data is None:
            raise RuntimeError("Vault заблокирован")
        entries = _session_data.setdefault("entries", {})
        if title in entries:
            raise ValueError(f"Запись '{title}' уже существует")
        now = datetime.utcnow().isoformat()
        entries[title] = {
            "title": title,
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
            "tags": tags or [],
            "created_at": now,
            "updated_at": now,
        }
        if master_password:
            self._save(master_password)
        db.save_scan("vault", f"add:{title}", {"username": username})
        return True

    def get(self, title: str) -> dict | None:
        if _session_data is None:
            raise RuntimeError("Vault заблокирован")
        return _session_data.get("entries", {}).get(title)

    def list_all(self) -> list[dict]:
        if _session_data is None:
            raise RuntimeError("Vault заблокирован")
        return list(_session_data.get("entries", {}).values())

    def search(self, query: str) -> list[dict]:
        q = query.lower()
        results = []
        for e in self.list_all():
            blob = " ".join([
                e.get("title", ""), e.get("username", ""),
                e.get("url", ""), e.get("notes", ""),
                " ".join(e.get("tags", [])),
            ]).lower()
            if q in blob:
                results.append(e)
        return results

    def update(self, title: str, master_password: str, **kwargs) -> bool:
        if _session_data is None:
            raise RuntimeError("Vault заблокирован")
        entries = _session_data.get("entries", {})
        if title not in entries:
            return False
        entry = entries[title]
        for k, v in kwargs.items():
            if v is not None:
                entry[k] = v
        entry["updated_at"] = datetime.utcnow().isoformat()
        self._save(master_password)
        db.save_scan("vault", f"update:{title}", {})
        return True

    def delete(self, title: str, master_password: str) -> bool:
        if _session_data is None:
            raise RuntimeError("Vault заблокирован")
        entries = _session_data.get("entries", {})
        if title not in entries:
            return False
        del entries[title]
        self._save(master_password)
        db.save_scan("vault", f"delete:{title}", {})
        return True

    def change_master(self, old_password: str, new_password: str) -> bool:
        """Сменить мастер-пароль (заново шифрует весь файл)."""
        if not self.exists():
            return False
        if not self.unlock(old_password):
            return False
        # _session_data уже расшифрован
        self._save(new_password)
        log.info("Vault: мастер-пароль изменён")
        return True

    def export_encrypted(self, out_path: str) -> None:
        """Экспорт (копия зашифрованного файла)."""
        if not self.exists():
            raise FileNotFoundError("Vault не существует")
        Path(out_path).write_bytes(self.path.read_bytes())
        db.save_scan("vault", "export", {"to": out_path})

    def import_encrypted(self, in_path: str) -> None:
        """Импорт (перезаписывает текущий файл — с бэкапом)."""
        src = Path(in_path)
        if not src.exists():
            raise FileNotFoundError(f"Файл {in_path} не найден")
        # Проверим, что это vault
        raw = src.read_bytes()
        if not raw.startswith(MAGIC):
            raise ValueError("Импортируемый файл — не CyberSec Vault")
        if self.exists():
            backup = self.path.with_suffix(".enc.bak")
            backup.write_bytes(self.path.read_bytes())
            console.print(f"[yellow]Старый vault сохранён как: {backup}[/yellow]")
        self.path.write_bytes(raw)
        db.save_scan("vault", "import", {"from": in_path})


# Глобальный singleton
_vault: Vault | None = None


def get_vault() -> Vault:
    global _vault
    if _vault is None:
        _vault = Vault()
    return _vault


# ---------------------------------------------------------------------------
# Генератор паролей
# ---------------------------------------------------------------------------

def generate_password(length: int = DEFAULT_PWD_LEN,
                      symbols: bool = True) -> str:
    alphabet = string.ascii_letters + string.digits
    if symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?/|~"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ---------------------------------------------------------------------------
# Хелперы ввода
# ---------------------------------------------------------------------------

def _prompt_master(confirm: bool = False) -> str:
    """Запросить мастер-пароль (без эха)."""
    pwd = getpass.getpass("Master password: ")
    if confirm:
        pwd2 = getpass.getpass("Повтори master password: ")
        if pwd != pwd2:
            raise ValueError("Пароли не совпадают")
    return pwd


def _ensure_unlocked(cli_password: str | None = None) -> str | None:
    """
    Разблокировать vault (если не разблокирован).
    Возвращает master password (для последующей записи) или None.
    """
    v = get_vault()
    if not v.exists():
        console.print("[red]Vault не создан.[/red]")
        console.print("[cyan]Создай: python main.py vault-init[/cyan]")
        return None
    if v.unlocked:
        # Уже разблокирован в текущем процессе
        return cli_password or ""
    pwd = cli_password or _prompt_master()
    if not v.unlock(pwd):
        console.print("[red]Неверный мастер-пароль.[/red]")
        return None
    return pwd


# ---------------------------------------------------------------------------
# CLI-команды (вызываются из main.py)
# ---------------------------------------------------------------------------

def cli_status() -> None:
    v = get_vault()
    table = Table(title="🔐 Password Vault — статус")
    table.add_column("Параметр", style="cyan")
    table.add_column("Значение", style="green")
    table.add_row("Файл", str(v.path))
    if v.exists():
        table.add_row("Размер", f"{v.size_kb():.2f} KB")
        table.add_row("Создан", v.created_at() or "—")
        table.add_row("Статус", "🔓 unlocked" if v.unlocked else "🔒 locked")
    else:
        table.add_row("Размер", "—")
        table.add_row("Создан", "—")
        table.add_row("Статус", "[red]не существует[/red]")
    console.print(table)
    if not v.exists():
        console.print("\n[yellow]Создать:[/yellow] python main.py vault-init")


def cli_init() -> None:
    v = get_vault()
    if v.exists():
        console.print(f"[yellow]Vault уже существует: {v.path}[/yellow]")
        if not Confirm.ask("Перезаписать (все записи будут потеряны!)",
                           default=False):
            return
        try:
            v.path.unlink()
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Не удалось удалить: {exc}[/red]")
            return
    try:
        pwd = _prompt_master(confirm=True)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return
    if len(pwd) < 8:
        console.print("[red]Мастер-пароль должен быть ≥ 8 символов.[/red]")
        return
    try:
        v.create(pwd)
        console.print(f"[green]✓ Vault создан: {v.path}[/green]")
        console.print("[yellow]⚠ Запомни мастер-пароль — восстановить нельзя![/yellow]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")


def cli_add(title: str | None = None, username: str | None = None,
            password: str | None = None, url: str | None = None,
            notes: str | None = None,
            generate: bool = False, gen_len: int = DEFAULT_PWD_LEN) -> None:
    master = _ensure_unlocked()
    if master is None:
        return
    v = get_vault()

    if not title:
        title = Prompt.ask("Заголовок (например 'github')").strip()
    if not title:
        console.print("[red]Пустой заголовок.[/red]")
        return

    if not username:
        username = Prompt.ask("Username", default="").strip()
    if generate and not password:
        password = generate_password(gen_len)
        console.print(f"[green]Сгенерирован пароль:[/green] {password}")
    if not password:
        password = Prompt.ask("Пароль", password=True).strip()
    if not url:
        url = Prompt.ask("URL (необязательно)", default="").strip()
    if not notes:
        notes = Prompt.ask("Заметки (необязательно)", default="").strip()
    tags_raw = Prompt.ask("Теги через запятую", default="").strip()
    tags = [t.strip() for t in tags_raw.split(",") if t.strip()]

    try:
        v.add(title, username, password, url, notes, tags,
              master_password=master)
        console.print(f"[green]✓ Добавлено: {title}[/green]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")


def cli_get(title: str) -> None:
    master = _ensure_unlocked()
    if master is None:
        return
    v = get_vault()
    e = v.get(title)
    if not e:
        console.print(f"[red]Запись не найдена: {title}[/red]")
        return
    table = Table(title=f"🔐 {e['title']}")
    table.add_column("Поле", style="cyan")
    table.add_column("Значение", style="green")
    for k in ("username", "password", "url", "notes"):
        table.add_row(k, e.get(k, "") or "—")
    table.add_row("tags", ", ".join(e.get("tags", [])) or "—")
    table.add_row("created_at", e.get("created_at", "—"))
    table.add_row("updated_at", e.get("updated_at", "—"))
    console.print(table)


def cli_list() -> None:
    master = _ensure_unlocked()
    if master is None:
        return
    v = get_vault()
    entries = v.list_all()
    if not entries:
        console.print("[yellow]Vault пуст.[/yellow]")
        return
    table = Table(title=f"🔐 Записей: {len(entries)}")
    table.add_column("#", style="yellow", width=4)
    table.add_column("Заголовок", style="cyan")
    table.add_column("Username", style="green")
    table.add_column("URL", style="white")
    table.add_column("Теги", style="magenta")
    for i, e in enumerate(sorted(entries, key=lambda x: x["title"]), 1):
        table.add_row(
            str(i),
            e.get("title", ""),
            e.get("username", "") or "—",
            (e.get("url", "") or "—")[:40],
            ", ".join(e.get("tags", [])) or "—",
        )
    console.print(table)


def cli_search(query: str) -> None:
    master = _ensure_unlocked()
    if master is None:
        return
    v = get_vault()
    results = v.search(query)
    if not results:
        console.print(f"[yellow]Ничего не найдено по '{query}'.[/yellow]")
        return
    table = Table(title=f"🔎 Найдено: {len(results)}")
    table.add_column("Заголовок", style="cyan")
    table.add_column("Username", style="green")
    table.add_column("URL", style="white")
    for e in results:
        table.add_row(
            e.get("title", ""),
            e.get("username", "") or "—",
            (e.get("url", "") or "—")[:50],
        )
    console.print(table)


def cli_delete(title: str) -> None:
    master = _ensure_unlocked()
    if master is None:
        return
    v = get_vault()
    e = v.get(title)
    if not e:
        console.print(f"[red]Запись не найдена: {title}[/red]")
        return
    if not Confirm.ask(f"Удалить '{title}'?", default=False):
        return
    if v.delete(title, master):
        console.print(f"[green]✓ Удалено: {title}[/green]")


def cli_export(out_path: str) -> None:
    v = get_vault()
    try:
        v.export_encrypted(out_path)
        console.print(f"[green]✓ Экспортировано в: {out_path}[/green]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")


def cli_import(in_path: str) -> None:
    v = get_vault()
    try:
        v.import_encrypted(in_path)
        console.print(f"[green]✓ Импортировано из: {in_path}[/green]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")


def cli_change_master() -> None:
    v = get_vault()
    if not v.exists():
        console.print("[red]Vault не создан.[/red]")
        return
    try:
        old = _prompt_master()
        new = _prompt_master(confirm=True)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return
    if len(new) < 8:
        console.print("[red]Новый пароль должен быть ≥ 8 символов.[/red]")
        return
    if v.change_master(old, new):
        console.print("[green]✓ Мастер-пароль изменён.[/green]")
    else:
        console.print("[red]Старый пароль неверен.[/red]")


# ---------------------------------------------------------------------------
# Интерактивное меню (для CLI)
# ---------------------------------------------------------------------------

def menu() -> None:
    table = Table(title="[bold]🔐 Password Vault[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Статус"),
        ("2", "Создать vault"),
        ("3", "Добавить запись"),
        ("4", "Показать запись"),
        ("5", "Список всех записей"),
        ("6", "Поиск"),
        ("7", "Удалить запись"),
        ("8", "Экспорт"),
        ("9", "Импорт"),
        ("10", "Сменить мастер-пароль"),
        ("11", "Сгенерировать пароль"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        cli_status()
    elif c == "2":
        cli_init()
    elif c == "3":
        gen = Confirm.ask("Сгенерировать пароль?", default=True)
        cli_add(generate=gen)
    elif c == "4":
        cli_get(Prompt.ask("Заголовок"))
    elif c == "5":
        cli_list()
    elif c == "6":
        cli_search(Prompt.ask("Поисковый запрос"))
    elif c == "7":
        cli_delete(Prompt.ask("Заголовок"))
    elif c == "8":
        cli_export(Prompt.ask("Путь для экспорта",
                              default="vault_backup.enc"))
    elif c == "9":
        cli_import(Prompt.ask("Путь к файлу"))
    elif c == "10":
        cli_change_master()
    elif c == "11":
        n = IntPrompt.ask("Длина", default=DEFAULT_PWD_LEN)
        p = generate_password(n)
        console.print(f"[bold green]{p}[/bold green]")