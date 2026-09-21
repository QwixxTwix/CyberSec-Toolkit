"""
Password Vault (extended) — шифрованное хранилище паролей.
Author: idqwixxa

Формат файла vault.enc:
    MAGIC(4) = b"CSVT"
    VERSION(1) = 2
    salt(16)
    Fernet-token(JSON)

Ключ: PBKDF2-HMAC-SHA256(master_password, salt, 200_000 iterations)
      → 32 байта → base64 → Fernet key.

Возможности:
    ─── Core ───
    - AES (Fernet) + PBKDF2-SHA256 (200k итераций)
    - Авто-lock по таймауту
    - История паролей (audit log)

    ─── Записи ───
    - title / username / password / url / notes / tags
    - TOTP secret (для 2FA)
    - Привязанные поля (extra key-value)
    - Категории (custom)

    ─── Качество ───
    - Strength-check при добавлении
    - Auto-detect reused passwords
    - Auto-detect old passwords (>90 дней)
    - Weak-hash check

    ─── Утилиты ───
    - Password generator (5 пресетов)
    - Clipboard copy (через pyperclip, если установлен)
    - Search (regex / по тегам)
    - Filter by tag / by url domain

    ─── Экспорт ───
    - Encrypted (полная копия)
    - JSON / CSV (расшифрованный — с подтверждением)
    - HTML (с маскированными паролями)

    ─── Интеграция ───
    - Findings → notes (при weak/reused паролях)
    - Notify при экспорте чувствительных данных
"""
import base64
import csv
import getpass
import html as html_mod
import json
import os
import re
import secrets
import string
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table

from core.config import BASE_DIR, REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

VAULT_FILE = BASE_DIR / "vault.enc"
VAULT_DIR = REPORT_DIR / "vault"
VAULT_DIR.mkdir(parents=True, exist_ok=True)

MAGIC = b"CSVT"
VERSION = 2          # v2: extra fields, totp, history, audit
SALT_LEN = 16
PBKDF2_ITER = 200_000
DEFAULT_PWD_LEN = 20

# Сессионный ключ (in-memory)
_session_key: bytes | None = None
_session_data: dict | None = None
_last_activity: float = 0.0
_auto_lock_min: int = 15


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class VaultFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: VaultFinding) -> int:
    if f.severity not in ("critical", "high"):
        return -1
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f.title,
            target=f.target,
            severity=f.severity,
            status="open",
            tags=["vault", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


def _notify(title: str, msg: str, severity: str = "high") -> None:
    try:
        from modules import notifier
        notifier.notify_all(title, msg, severity=severity)
    except Exception:
        pass


# ===========================================================================
# Крипто
# ===========================================================================

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
    if ver not in (1, 2):
        raise ValueError(f"Версия vault {ver} не поддерживается")
    salt = raw[5:5 + SALT_LEN]
    token = raw[5 + SALT_LEN:]
    key = _derive_key(password, salt)
    try:
        blob = Fernet(key).decrypt(token)
    except InvalidToken:
        raise ValueError("Неверный мастер-пароль или файл повреждён")
    data = json.loads(blob.decode("utf-8"))
    # Миграция v1 → v2
    if ver == 1 or data.get("version") == 1:
        data["version"] = VERSION
        data.setdefault("history", [])
        data.setdefault("audit", [])
    return data


# ===========================================================================
# Класс Vault
# ===========================================================================

class Vault:
    def __init__(self, path: Path = VAULT_FILE) -> None:
        self.path = path

    # --- статус ---
    def exists(self) -> bool:
        return self.path.exists()

    def size_kb(self) -> float:
        return (self.path.stat().st_size / 1024
                if self.path.exists() else 0.0)

    def created_at(self) -> str | None:
        if not self.path.exists():
            return None
        return datetime.fromtimestamp(
            self.path.stat().st_ctime
        ).strftime("%Y-%m-%d %H:%M:%S")

    # --- unlock / lock ---
    def create(self, master_password: str) -> None:
        if self.exists():
            raise FileExistsError(f"{self.path} уже существует")
        data = {
            "version": VERSION,
            "created_at": datetime.utcnow().isoformat(),
            "entries": {},
            "history": [],       # audit log: add/update/delete
            "audit": [],         # открытия / смены мастера
        }
        raw = _encrypt(data, master_password)
        self.path.write_bytes(raw)
        try:
            os.chmod(self.path, 0o600)
        except Exception:  # noqa: BLE001
            pass
        log.info("Vault создан: %s", self.path)

    def unlock(self, master_password: str) -> bool:
        global _session_key, _session_data, _last_activity
        if not self.exists():
            raise FileNotFoundError("Vault не существует")
        raw = self.path.read_bytes()
        try:
            data = _decrypt(raw, master_password)
        except Exception as exc:  # noqa: BLE001
            log.warning("Vault unlock failed: %s", exc)
            return False
        _session_data = data
        _session_key = b"unlocked"
        _last_activity = time.time()
        # audit
        _session_data.setdefault("audit", []).append({
            "ts": datetime.utcnow().isoformat(),
            "action": "unlock",
        })
        _trim_audit(_session_data)
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
            url: str = "", notes: str = "",
            tags: list[str] | None = None,
            totp_secret: str = "",
            extra: dict | None = None,
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
            "totp_secret": totp_secret,
            "extra": extra or {},
            "created_at": now,
            "updated_at": now,
            "history": [],
        }
        _audit(_session_data, "add", title)

        # Auto strength check
        strength = _quick_strength(password)
        if strength["score"] <= 3:
            _save_finding(VaultFinding(
                kind="weak_stored_password",
                severity="high",
                title=f"Слабый пароль в vault: {title}",
                target=title,
                evidence=f"Score: {strength['score']}/10\n"
                         f"Reasons: {', '.join(strength['reasons'][:5])}",
                data={"title": title, "strength": strength},
            ))

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

    def search(self, query: str, regex: bool = False) -> list[dict]:
        results = []
        if regex:
            try:
                pat = re.compile(query, re.IGNORECASE)
            except re.error as exc:
                log.warning("bad regex: %s", exc)
                return []
            for e in self.list_all():
                blob = " ".join([
                    e.get("title", ""), e.get("username", ""),
                    e.get("url", ""), e.get("notes", ""),
                    " ".join(e.get("tags", [])),
                ])
                if pat.search(blob):
                    results.append(e)
            return results

        q = query.lower()
        for e in self.list_all():
            blob = " ".join([
                e.get("title", ""), e.get("username", ""),
                e.get("url", ""), e.get("notes", ""),
                " ".join(e.get("tags", [])),
            ]).lower()
            if q in blob:
                results.append(e)
        return results

    def filter_by_tag(self, tag: str) -> list[dict]:
        tag = tag.lower()
        return [e for e in self.list_all()
                if tag in [t.lower() for t in e.get("tags", [])]]

    def update(self, title: str, master_password: str, **kwargs) -> bool:
        if _session_data is None:
            raise RuntimeError("Vault заблокирован")
        entries = _session_data.get("entries", {})
        if title not in entries:
            return False
        entry = entries[title]
        # History
        if "password" in kwargs and kwargs["password"]:
            old_pwd = entry.get("password")
            if old_pwd and old_pwd != kwargs["password"]:
                entry.setdefault("history", []).append({
                    "password_hash": _pwd_hash(old_pwd),
                    "changed_at": datetime.utcnow().isoformat(),
                })
                # Ограничим историю 10
                entry["history"] = entry["history"][-10:]
        for k, v in kwargs.items():
            if v is not None:
                entry[k] = v
        entry["updated_at"] = datetime.utcnow().isoformat()
        _audit(_session_data, "update", title)
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
        _audit(_session_data, "delete", title)
        self._save(master_password)
        db.save_scan("vault", f"delete:{title}", {})
        return True

    def change_master(self, old_password: str, new_password: str) -> bool:
        if not self.exists():
            return False
        if not self.unlock(old_password):
            return False
        _audit(_session_data, "change_master", "")
        self._save(new_password)
        log.info("Vault: мастер-пароль изменён")
        return True

    # --- health ---
    def health_check(self) -> dict:
        if _session_data is None:
            raise RuntimeError("Vault заблокирован")
        entries = self.list_all()
        report = {
            "total": len(entries),
            "weak": [],
            "reused": [],
            "old": [],
            "no_totp": [],
            "duplicate_username": [],
            "score": 100,
        }
        # Weak
        for e in entries:
            s = _quick_strength(e.get("password", ""))
            if s["score"] <= 3:
                report["weak"].append({
                    "title": e["title"], "score": s["score"],
                })
        # Reused
        pwd_groups: dict[str, list[str]] = {}
        for e in entries:
            p = e.get("password", "")
            if not p:
                continue
            h = _pwd_hash(p)
            pwd_groups.setdefault(h, []).append(e["title"])
        for h, titles in pwd_groups.items():
            if len(titles) > 1:
                report["reused"].append(titles)
        # Old (>90 дней)
        cutoff = datetime.utcnow() - timedelta(days=90)
        for e in entries:
            upd = e.get("updated_at", "")
            if upd:
                try:
                    dt = datetime.fromisoformat(upd)
                    if dt < cutoff:
                        report["old"].append({
                            "title": e["title"],
                            "days": (datetime.utcnow() - dt).days,
                        })
                except Exception:
                    pass
        # No TOTP
        for e in entries:
            if not e.get("totp_secret"):
                report["no_totp"].append(e["title"])
        # Duplicate username
        user_groups: dict[str, list[str]] = {}
        for e in entries:
            u = (e.get("username") or "").lower()
            if u:
                user_groups.setdefault(u, []).append(e["title"])
        for u, titles in user_groups.items():
            if len(titles) > 1:
                report["duplicate_username"].append({
                    "username": u, "titles": titles,
                })

        # Score
        score = 100
        score -= len(report["weak"]) * 5
        score -= len(report["reused"]) * 10
        score -= max(0, len(report["old"]) - 5) * 2
        score -= len(report["duplicate_username"]) * 3
        report["score"] = max(0, min(100, score))

        # Findings
        if len(report["reused"]) >= 3:
            _save_finding(VaultFinding(
                kind="reused_passwords",
                severity="high",
                title=f"Много переиспользуемых паролей: "
                      f"{len(report['reused'])} групп",
                target="vault",
                evidence=json.dumps(report["reused"][:5],
                                     ensure_ascii=False),
                data={"groups": report["reused"][:5]},
            ))
        if len(report["weak"]) >= 3:
            _save_finding(VaultFinding(
                kind="weak_passwords_mass",
                severity="high",
                title=f"Слабых паролей в vault: "
                      f"{len(report['weak'])}",
                target="vault",
                evidence=json.dumps(report["weak"][:10],
                                     ensure_ascii=False),
                data={"weak": report["weak"][:10]},
            ))
        return report

    # --- export / import ---
    def export_encrypted(self, out_path: str) -> None:
        if not self.exists():
            raise FileNotFoundError("Vault не существует")
        Path(out_path).write_bytes(self.path.read_bytes())
        db.save_scan("vault", "export", {"to": out_path})

    def export_json(self, out_path: str,
                     master_password: str) -> None:
        """Расшифрованный JSON-экспорт."""
        if _session_data is None:
            raise RuntimeError("Vault заблокирован")
        Path(out_path).write_text(
            json.dumps(_session_data, indent=2,
                       ensure_ascii=False),
            encoding="utf-8",
        )
        _audit(_session_data, "export_json", out_path)
        _notify("🔓 Vault → JSON",
                f"Расшифрованный экспорт: {out_path}",
                severity="high")
        db.save_scan("vault", "export_json", {"to": out_path})

    def export_csv(self, out_path: str) -> None:
        if _session_data is None:
            raise RuntimeError("Vault заблокирован")
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["title", "username", "password", "url",
                        "notes", "tags", "totp", "updated_at"])
            for e in self.list_all():
                w.writerow([
                    e.get("title"), e.get("username"),
                    e.get("password"), e.get("url"),
                    e.get("notes"),
                    ",".join(e.get("tags", [])),
                    "yes" if e.get("totp_secret") else "no",
                    e.get("updated_at", ""),
                ])
        _audit(_session_data, "export_csv", out_path)
        _notify("🔓 Vault → CSV",
                f"Расшифрованный экспорт: {out_path}",
                severity="high")
        db.save_scan("vault", "export_csv", {"to": out_path})

    def import_encrypted(self, in_path: str) -> None:
        src = Path(in_path)
        if not src.exists():
            raise FileNotFoundError(f"Файл {in_path} не найден")
        raw = src.read_bytes()
        if not raw.startswith(MAGIC):
            raise ValueError("Импортируемый файл — не CyberSec Vault")
        if self.exists():
            backup = self.path.with_suffix(".enc.bak")
            backup.write_bytes(self.path.read_bytes())
            console.print(f"[yellow]Старый vault сохранён как: "
                          f"{backup}[/yellow]")
        self.path.write_bytes(raw)
        db.save_scan("vault", "import", {"from": in_path})


def _pwd_hash(p: str) -> str:
    import hashlib
    return hashlib.sha256(p.encode()).hexdigest()[:16]


def _audit(data: dict, action: str, target: str) -> None:
    data.setdefault("audit", []).append({
        "ts": datetime.utcnow().isoformat(),
        "action": action,
        "target": target,
    })
    _trim_audit(data)


def _trim_audit(data: dict, keep: int = 500) -> None:
    data["audit"] = data.get("audit", [])[-keep:]


def _quick_strength(pwd: str) -> dict:
    """Локальный quick-strength (без zxcvbn)."""
    score = 0
    reasons = []
    if not pwd:
        return {"score": 0, "reasons": ["пусто"]}
    if len(pwd) >= 8:
        score += 1
    else:
        reasons.append("<8 символов")
    if len(pwd) >= 12:
        score += 1
    if len(pwd) >= 16:
        score += 1
    if len(pwd) >= 20:
        score += 1
    if re.search(r"[a-z]", pwd):
        score += 1
    else:
        reasons.append("нет строчных")
    if re.search(r"[A-Z]", pwd):
        score += 1
    else:
        reasons.append("нет заглавных")
    if re.search(r"\d", pwd):
        score += 1
    else:
        reasons.append("нет цифр")
    if re.search(r"[^A-Za-z0-9]", pwd):
        score += 1
    else:
        reasons.append("нет спецсимволов")

    # Penalties
    common = {"password", "123456", "qwerty", "admin", "letmein"}
    if pwd.lower() in common:
        score = max(0, score - 5)
        reasons.append("в топ-common")
    for kw in ("qwerty", "asdf", "1234"):
        if kw in pwd.lower():
            score = max(0, score - 2)
            reasons.append(f"паттерн {kw}")
            break
    if re.search(r"(19|20)\d{2}", pwd):
        score = max(0, score - 1)
        reasons.append("содержит год")

    return {"score": min(10, score), "reasons": reasons}


# Глобальный singleton
_vault: Vault | None = None


def get_vault() -> Vault:
    global _vault
    if _vault is None:
        _vault = Vault()
    return _vault


# ===========================================================================
# Генератор паролей
# ===========================================================================

def generate_password(length: int = DEFAULT_PWD_LEN,
                      symbols: bool = True) -> str:
    alphabet = string.ascii_letters + string.digits
    if symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?/|~"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_preset(preset: str = "strong") -> str:
    """Генератор по пресетам."""
    presets = {
        "pin": "0123456789",
        "alnum": string.ascii_letters + string.digits,
        "strong": string.ascii_letters + string.digits +
                  "!@#$%^&*()-_=+",
        "paranoid": string.ascii_letters + string.digits +
                    "!@#$%^&*()-_=+[]{};:,.?/|~`'\"<>",
        "hex": "0123456789abcdef",
        "base64": string.ascii_letters + string.digits + "+/",
    }
    lens = {
        "pin": 6, "alnum": 20, "strong": 24,
        "paranoid": 40, "hex": 32, "base64": 32,
    }
    alphabet = presets.get(preset, presets["strong"])
    length = lens.get(preset, 24)
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_passphrase(words: int = 4, sep: str = "-") -> str:
    """XKCD-style passphrase."""
    pool = ["correct", "horse", "battery", "staple", "apple",
            "banana", "cobalt", "dragon", "eagle", "falcon",
            "galaxy", "harbor", "island", "jupiter", "kayak",
            "lighthouse", "mango", "nebula", "ocean", "planet",
            "quiet", "rocket", "sunset", "tiger", "umbrella",
            "velvet", "walnut", "xenon", "yellow", "zebra"]
    return sep.join(secrets.choice(pool) for _ in range(words))


def copy_to_clipboard(text: str) -> bool:
    """Скопировать в clipboard (если pyperclip доступен)."""
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except ImportError:
        return False
    except Exception:
        return False


# ===========================================================================
# Хелперы ввода
# ===========================================================================

def _prompt_master(confirm: bool = False) -> str:
    pwd = getpass.getpass("Master password: ")
    if confirm:
        pwd2 = getpass.getpass("Повтори master password: ")
        if pwd != pwd2:
            raise ValueError("Пароли не совпадают")
    return pwd


def _ensure_unlocked(cli_password: str | None = None) -> str | None:
    global _last_activity
    v = get_vault()
    if not v.exists():
        console.print("[red]Vault не создан.[/red]")
        console.print("[cyan]Создай: python main.py vault-init[/cyan]")
        return None
    # Auto-lock
    if v.unlocked and _last_activity:
        if time.time() - _last_activity > _auto_lock_min * 60:
            console.print("[yellow]🔒 Auto-lock сработал.[/yellow]")
            v.lock()
    if v.unlocked:
        _last_activity = time.time()
        return cli_password or ""
    pwd = cli_password or _prompt_master()
    if not v.unlock(pwd):
        console.print("[red]Неверный мастер-пароль.[/red]")
        return None
    _last_activity = time.time()
    return pwd


# ===========================================================================
# CLI-команды
# ===========================================================================

def cli_status() -> None:
    v = get_vault()
    table = Table(title="🔐 Password Vault — статус")
    table.add_column("Параметр", style="cyan")
    table.add_column("Значение", style="green")
    table.add_row("Файл", str(v.path))
    if v.exists():
        table.add_row("Размер", f"{v.size_kb():.2f} KB")
        table.add_row("Создан", v.created_at() or "—")
        status = "🔓 unlocked" if v.unlocked else "🔒 locked"
        table.add_row("Статус", status)
        if v.unlocked:
            entries = v.list_all()
            table.add_row("Записей", str(len(entries)))
            tags = set()
            for e in entries:
                tags.update(e.get("tags", []))
            table.add_row("Уникальных тегов", str(len(tags)))
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
        console.print("[yellow]⚠ Запомни мастер-пароль — "
                      "восстановить нельзя![/yellow]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")


def cli_add(title: str | None = None, username: str | None = None,
            password: str | None = None, url: str | None = None,
            notes: str | None = None,
            generate: bool = False,
            gen_len: int = DEFAULT_PWD_LEN) -> None:
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
        preset = Prompt.ask(
            "Пресет",
            choices=["strong", "paranoid", "alnum", "pin",
                      "hex", "base64", "passphrase"],
            default="strong")
        if preset == "passphrase":
            words = IntPrompt.ask("Слов", default=4)
            password = generate_passphrase(words)
        else:
            password = generate_preset(preset)
        console.print(f"[green]Сгенерирован пароль:[/green] {password}")

    if not password:
        password = Prompt.ask("Пароль", password=True).strip()
    if not url:
        url = Prompt.ask("URL (необязательно)", default="").strip()
    if not notes:
        notes = Prompt.ask("Заметки (необязательно)",
                           default="").strip()
    tags_raw = Prompt.ask("Теги через запятую", default="").strip()
    tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
    totp = Prompt.ask("TOTP secret (опц., base32)",
                       default="").strip()

    try:
        v.add(title, username, password, url, notes, tags,
              totp_secret=totp, master_password=master)
        console.print(f"[green]✓ Добавлено: {title}[/green]")

        # Notify + clipboard
        if Confirm.ask("Скопировать пароль в clipboard?",
                        default=False):
            if copy_to_clipboard(password):
                console.print("[green]✓ Скопировано.[/green]")
            else:
                console.print("[yellow]pyperclip не установлен "
                              "(pip install pyperclip)[/yellow]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")


def cli_get(title: str, show_password: bool = False) -> None:
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
    for k in ("username", "url", "notes"):
        table.add_row(k, e.get(k, "") or "—")
    if show_password or Confirm.ask("Показать пароль?",
                                     default=False):
        table.add_row("password", e.get("password", "") or "—")
        if Confirm.ask("Скопировать в clipboard?", default=False):
            if copy_to_clipboard(e.get("password", "")):
                console.print("[green]✓ Скопировано.[/green]")
    else:
        table.add_row("password",
                      "*" * min(12, len(e.get("password", ""))))
    if e.get("totp_secret"):
        table.add_row("totp", f"[dim]({len(e['totp_secret'])} chars)"
                              f"[/dim]")
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
    table.add_column("2FA", width=4)
    for i, e in enumerate(sorted(entries, key=lambda x: x["title"]), 1):
        table.add_row(
            str(i),
            e.get("title", ""),
            e.get("username", "") or "—",
            (e.get("url", "") or "—")[:40],
            ", ".join(e.get("tags", [])) or "—",
            "✓" if e.get("totp_secret") else "—",
        )
    console.print(table)


def cli_search(query: str, regex: bool = False) -> None:
    master = _ensure_unlocked()
    if master is None:
        return
    v = get_vault()
    results = v.search(query, regex=regex)
    if not results:
        console.print(f"[yellow]Ничего не найдено по '{query}'.[/yellow]")
        return
    table = Table(title=f"🔎 Найдено: {len(results)}")
    table.add_column("Заголовок", style="cyan")
    table.add_column("Username", style="green")
    table.add_column("URL", style="white")
    table.add_column("Теги", style="magenta")
    for e in results:
        table.add_row(
            e.get("title", ""),
            e.get("username", "") or "—",
            (e.get("url", "") or "—")[:50],
            ", ".join(e.get("tags", [])) or "—",
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


# ===========================================================================
# NEW: Health, export decrypted, filter
# ===========================================================================

def cli_health() -> None:
    master = _ensure_unlocked()
    if master is None:
        return
    v = get_vault()
    r = v.health_check()
    console.print(f"\n[bold cyan]🔐 Vault Health — "
                  f"score: {r['score']}/100[/bold cyan]\n")

    t = Table(title=f"Обзор ({r['total']} записей)")
    t.add_column("Метрика", style="cyan")
    t.add_column("Кол-во", style="green", width=8)
    t.add_row("Слабых", f"[red]{len(r['weak'])}[/red]")
    t.add_row("Переиспользуемых групп",
              f"[red]{len(r['reused'])}[/red]")
    t.add_row("Старых (>90 дней)",
              f"[yellow]{len(r['old'])}[/yellow]")
    t.add_row("Без 2FA", f"{len(r['no_totp'])}")
    t.add_row("Дубли username",
              f"{len(r['duplicate_username'])}")
    console.print(t)

    if r["weak"]:
        wt = Table(title="🔴 Слабые пароли")
        wt.add_column("Заголовок", style="cyan")
        wt.add_column("Score", width=8)
        for e in r["weak"][:20]:
            wt.add_row(e["title"], f"{e['score']}/10")
        console.print(wt)

    if r["reused"]:
        rt = Table(title="🔴 Переиспользуемые")
        rt.add_column("Группа", style="cyan")
        for titles in r["reused"][:10]:
            rt.add_row(" | ".join(titles))
        console.print(rt)

    if r["old"]:
        ot = Table(title="🟡 Старые пароли")
        ot.add_column("Заголовок", style="cyan")
        ot.add_column("Дней", width=8)
        for e in sorted(r["old"],
                        key=lambda x: -x["days"])[:20]:
            ot.add_row(e["title"], str(e["days"]))
        console.print(ot)

    if r["duplicate_username"]:
        dt = Table(title="🟡 Дубли username")
        dt.add_column("Username", style="cyan")
        dt.add_column("Записей", style="green")
        for e in r["duplicate_username"][:10]:
            dt.add_row(e["username"], str(len(e["titles"])))
        console.print(dt)


def cli_export_json(out_path: str | None = None) -> None:
    """Расшифрованный JSON-экспорт (с confirm!)."""
    master = _ensure_unlocked()
    if master is None:
        return
    if not Confirm.ask(
        "[bold red]⚠ Расшифрованный экспорт — пароли в открытом виде! "
        "Продолжить?[/bold red]",
        default=False,
    ):
        return
    v = get_vault()
    if not out_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(VAULT_DIR / f"vault_decrypted_{ts}.json")
    try:
        v.export_json(out_path, master)
        console.print(f"[green]✓ JSON: {out_path}[/green]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")


def cli_export_csv(out_path: str | None = None) -> None:
    master = _ensure_unlocked()
    if master is None:
        return
    if not Confirm.ask(
        "[bold red]⚠ Расшифрованный CSV-экспорт! Продолжить?[/bold red]",
        default=False,
    ):
        return
    v = get_vault()
    if not out_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(VAULT_DIR / f"vault_decrypted_{ts}.csv")
    try:
        v.export_csv(out_path)
        console.print(f"[green]✓ CSV: {out_path}[/green]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")


def cli_export_html(out_path: str | None = None) -> None:
    """HTML-экспорт с маскированными паролями (безопасно)."""
    master = _ensure_unlocked()
    if master is None:
        return
    v = get_vault()
    entries = v.list_all()
    if not entries:
        console.print("[yellow]Vault пуст.[/yellow]")
        return
    if not out_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(VAULT_DIR / f"vault_{ts}.html")

    parts = [
        "<!DOCTYPE html><html lang='ru'><head>"
        "<meta charset='utf-8'>",
        "<title>Password Vault (masked)</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;"
        "font-family:monospace;padding:24px;max-width:1200px;"
        "margin:0 auto;line-height:1.5;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
        "table{width:100%;border-collapse:collapse;margin-top:12px;"
        "font-size:13px;}",
        "th{background:#111;color:#00ff9c;padding:6px;"
        "text-align:left;border:1px solid #222;}",
        "td{padding:5px 8px;border:1px solid #222;}"
        "tr:nth-child(even){background:#0d0d0d;}",
        ".pwd{color:#666;letter-spacing:2px;}",
        ".tag{background:#003322;padding:1px 6px;border-radius:8px;"
        "font-size:11px;margin-right:3px;}",
        "</style></head><body>",
        f"<h1>🔐 Password Vault ({len(entries)})</h1>",
        f"<p>Generated: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} — "
        f"passwords masked</p>",
        "<table><tr><th>Title</th><th>Username</th>"
        "<th>Password</th><th>URL</th><th>Tags</th>"
        "<th>2FA</th></tr>",
    ]
    for e in sorted(entries, key=lambda x: x["title"]):
        pwd_masked = "•" * min(12, len(e.get("password", "")))
        tags_html = "".join(
            f"<span class='tag'>{html_mod.escape(t)}</span>"
            for t in e.get("tags", []))
        parts.append(
            f"<tr><td>{html_mod.escape(e.get('title',''))}</td>"
            f"<td>{html_mod.escape(e.get('username',''))}</td>"
            f"<td class='pwd'>{pwd_masked}</td>"
            f"<td>{html_mod.escape((e.get('url','') or '')[:60])}</td>"
            f"<td>{tags_html or '—'}</td>"
            f"<td>{'✓' if e.get('totp_secret') else '—'}</td></tr>")
    parts.append("</table></body></html>")
    try:
        Path(out_path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML (masked): {out_path}[/green]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")


def cli_filter(tag: str) -> None:
    master = _ensure_unlocked()
    if master is None:
        return
    v = get_vault()
    results = v.filter_by_tag(tag)
    if not results:
        console.print(f"[yellow]Тег '{tag}' — пусто.[/yellow]")
        return
    table = Table(title=f"🏷  Tag '{tag}' ({len(results)})")
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


def cli_generate_preset() -> None:
    """Показать пароли по всем пресетам."""
    t = Table(title="🎲 Password presets")
    t.add_column("Preset", style="cyan")
    t.add_column("Password", style="green")
    for p in ("pin", "alnum", "strong", "paranoid", "hex", "base64"):
        t.add_row(p, generate_preset(p))
    console.print(t)
    # Passphrase
    console.print(f"\n[cyan]Passphrase:[/cyan] "
                  f"[green]{generate_passphrase(4)}[/green]")
    console.print(f"[cyan]Passphrase 6:[/cyan] "
                  f"[green]{generate_passphrase(6)}[/green]")


def cli_set_autolock(minutes: int) -> None:
    global _auto_lock_min
    _auto_lock_min = max(1, int(minutes))
    console.print(f"[green]✓ Auto-lock: {_auto_lock_min} мин[/green]")


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🔐 Password Vault (extended)[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Статус"),
        ("2", "Создать vault"),
        ("3", "Добавить запись"),
        ("4", "Показать запись"),
        ("5", "Список всех записей"),
        ("6", "Поиск"),
        ("7", "Поиск (regex)"),
        ("8", "Удалить запись"),
        ("9", "Health-check (weak/reused/old)"),
        ("10", "Фильтр по тегу"),
        ("11", "Экспорт encrypted"),
        ("12", "Экспорт JSON (расшифрованный)"),
        ("13", "Экспорт CSV (расшифрованный)"),
        ("14", "Экспорт HTML (masked)"),
        ("15", "Импорт"),
        ("16", "Сменить мастер-пароль"),
        ("17", "Генератор паролей (все пресеты)"),
        ("18", "Настроить auto-lock"),
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
        cli_search(Prompt.ask("Regex"), regex=True)
    elif c == "8":
        cli_delete(Prompt.ask("Заголовок"))
    elif c == "9":
        cli_health()
    elif c == "10":
        cli_filter(Prompt.ask("Тег"))
    elif c == "11":
        cli_export(Prompt.ask("Путь",
                              default="vault_backup.enc"))
    elif c == "12":
        cli_export_json()
    elif c == "13":
        cli_export_csv()
    elif c == "14":
        cli_export_html()
    elif c == "15":
        cli_import(Prompt.ask("Путь к файлу"))
    elif c == "16":
        cli_change_master()
    elif c == "17":
        cli_generate_preset()
    elif c == "18":
        n = IntPrompt.ask("Минут", default=15)
        cli_set_autolock(n)