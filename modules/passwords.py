"""Модуль паролей и хешей: identify, crack, mask, strength, generator, wordlist."""
import re
import hashlib
import secrets
import string
import itertools
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt, IntPrompt
from rich.table import Table

from core.config import WORDLIST_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


# Регулярки типовых хешей
HASH_PATTERNS = [
    ("MD5", re.compile(r"^[a-f0-9]{32}$")),
    ("NTLM", re.compile(r"^[a-f0-9]{32}$")),
    ("SHA1", re.compile(r"^[a-f0-9]{40}$")),
    ("SHA224", re.compile(r"^[a-f0-9]{56}$")),
    ("SHA256", re.compile(r"^[a-f0-9]{64}$")),
    ("SHA384", re.compile(r"^[a-f0-9]{96}$")),
    ("SHA512", re.compile(r"^[a-f0-9]{128}$")),
    ("bcrypt", re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")),
    ("SHA512-crypt", re.compile(r"^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$")),
    ("SHA256-crypt", re.compile(r"^\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$")),
    ("MySQL5", re.compile(r"^\*[A-F0-9]{40}$")),
]


def identify_hash(hash_value: str) -> None:
    """Определить тип хеша по длине/формату."""
    hash_value = hash_value.strip()
    matches = [name for name, pat in HASH_PATTERNS if pat.match(hash_value)]
    if matches:
        console.print(f"[green]Возможные типы:[/green] {', '.join(matches)}")
    else:
        console.print("[red]Не удалось определить тип.[/red]")
    db.save_scan("hashid", hash_value[:16] + "...", matches)


def _hash_candidates(word: str) -> dict[str, str]:
    """Все популярные хеши для слова."""
    b = word.encode()
    result = {
        "md5": hashlib.md5(b).hexdigest(),
        "sha1": hashlib.sha1(b).hexdigest(),
        "sha256": hashlib.sha256(b).hexdigest(),
        "sha512": hashlib.sha512(b).hexdigest(),
        "sha224": hashlib.sha224(b).hexdigest(),
    }
    try:
        # NTLM = md4(utf-16-le). В openssl это может быть в legacy-провайдере.
        result["ntlm"] = hashlib.new("md4", word.encode("utf-16le")).hexdigest()
    except Exception:  # noqa: BLE001
        result["ntlm"] = ""
    return result


def crack_hash(hash_value: str, wordlist: Path | None = None) -> None:
    """Словарная атака по md5/sha1/sha256/sha512."""
    hash_value = hash_value.strip().lower()
    if wordlist is None:
        wordlist = WORDLIST_DIR / "rockyou-mini.txt"
    if not wordlist.exists():
        console.print(f"[red]Словарь {wordlist} не найден.[/red]")
        return
    console.print(f"[cyan]Атакую {hash_value[:16]}... словарём {wordlist.name}[/cyan]")
    with wordlist.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.rstrip("\n")
            if not w:
                continue
            for algo, h in _hash_candidates(w).items():
                if h and h == hash_value:
                    console.print(f"[green]✓ Найдено: '{w}' ({algo})[/green]")
                    db.save_scan("crack", hash_value[:16], {"plain": w, "algo": algo})
                    return
    console.print("[yellow]Не найдено в словаре.[/yellow]")


def mask_crack(hash_value: str, charset: str, max_len: int, algo: str = "md5") -> None:
    """Brute-force перебор символов до max_len."""
    hash_value = hash_value.strip().lower()
    console.print(f"[cyan]Перебор charset='{charset}' до длины {max_len} ({algo})...[/cyan]")
    try:
        hasher = hashlib.new
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка hashlib: {exc}[/red]")
        return

    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            word = "".join(combo)
            try:
                h = hasher(algo, word.encode()).hexdigest()
            except Exception:  # noqa: BLE001
                continue
            if h == hash_value:
                console.print(f"[green]✓ Найдено: '{word}'[/green]")
                db.save_scan("maskcrack", hash_value[:16], word)
                return
    console.print("[yellow]Не найдено.[/yellow]")


def analyze_strength(password: str) -> None:
    """Анализ стойкости пароля."""
    score = 0
    reasons: list[str] = []

    if len(password) >= 8:
        score += 1
    else:
        reasons.append("короче 8 символов")
    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1

    if re.search(r"[a-z]", password):
        score += 1
    else:
        reasons.append("нет строчных букв")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        reasons.append("нет заглавных букв")

    if re.search(r"\d", password):
        score += 1
    else:
        reasons.append("нет цифр")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        reasons.append("нет спецсимволов")

    weak = {"password", "123456", "qwerty", "admin", "letmein",
            "welcome", "12345678", "1234567890"}
    if password.lower() in weak:
        score = 1
        reasons.append("в списке популярных паролей")

    levels = {
        0: "очень слабый", 1: "слабый", 2: "слабый",
        3: "средний", 4: "средний", 5: "хороший",
        6: "сильный", 7: "очень сильный",
    }
    console.print(f"[cyan]Оценка:[/cyan] {score}/7 ({levels.get(score, '?')})")
    if reasons:
        console.print("[yellow]Замечания:[/yellow] " + ", ".join(reasons))
    db.save_scan("pwd_strength", password[:3] + "***",
                 {"score": score, "notes": reasons})


def generate_password(length: int = 16, use_symbols: bool = True) -> None:
    """Криптостойкий генератор пароля."""
    if length < 4:
        length = 4
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?/|~"
    pwd = "".join(secrets.choice(alphabet) for _ in range(length))
    console.print(f"[bold green]{pwd}[/bold green]")


def wordlist_generator(charset: str, min_len: int, max_len: int, out_file: str) -> None:
    """Генератор словаря (crunch-like)."""
    path = WORDLIST_DIR / out_file
    count = 0
    try:
        with path.open("w", encoding="utf-8") as f:
            for length in range(min_len, max_len + 1):
                for combo in itertools.product(charset, repeat=length):
                    f.write("".join(combo) + "\n")
                    count += 1
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return
    console.print(f"[green]✓ {count} строк → {path}[/green]")
    db.save_scan("wordlist_gen", out_file,
                 {"count": count, "charset": charset,
                  "min": min_len, "max": max_len})


def menu() -> None:
    """Меню модуля."""
    table = Table(title="[bold]Passwords & Hashes[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Hash identifier"),
        ("2", "Hash cracker (словарь)"),
        ("3", "Mask cracker (brute)"),
        ("4", "Password strength analyzer"),
        ("5", "Password generator"),
        ("6", "Wordlist generator"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])
    if c == "1":
        identify_hash(Prompt.ask("Хеш"))
    elif c == "2":
        crack_hash(Prompt.ask("Хеш"))
    elif c == "3":
        h = Prompt.ask("Хеш")
        cs = Prompt.ask("Charset",
                        default="abcdefghijklmnopqrstuvwxyz0123456789")
        ml = IntPrompt.ask("Макс. длина", default=4)
        algo = Prompt.ask("Алгоритм", default="md5")
        mask_crack(h, cs, ml, algo)
    elif c == "4":
        analyze_strength(Prompt.ask("Пароль", password=True))
    elif c == "5":
        generate_password(IntPrompt.ask("Длина", default=16))
    elif c == "6":
        cs = Prompt.ask("Символы", default="abc123")
        mn = IntPrompt.ask("Мин. длина", default=1)
        mx = IntPrompt.ask("Макс. длина", default=3)
        fn = Prompt.ask("Имя файла", default="custom.txt")
        wordlist_generator(cs, mn, mx, fn)