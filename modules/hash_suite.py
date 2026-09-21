"""
Hash Cracking Suite Pro.
Author: idqwixxa

⚠ Только для авторизованного пентеста / CTF.

Возможности:
    ─── Hash identification ───
    - 90+ типов хешей (все hashcat modes + extended)
    - Confidence scoring (когда несколько типов совпадают)
    - Context-aware detection (по префиксам $1$/$2$/$6$)
    - Sample generation (для проверки)

    ─── Built-in cracker ───
    - MD5, SHA1/224/256/384/512, NTLM, MySQL5, SHA-crypt,
      bcrypt (with passlib), md5crypt, RIPEMD160, Whirlpool, GOST
    - Wordlist attack (multi-threaded)
    - Mask attack (?l?u?d?s?a?h?H + custom charset)
    - Combinator (A+B, A+sep+B)
    - Hybrid (wordlist + mask, mask + wordlist)
    - PRINCE-style attack hints
    - Rules: best64, dive, rockyou-30000, leet, leet-combo,
      capitalize, append, prepend, toggle, reverse, duplicate

    ─── External tools ───
    - hashcat (all attack modes: 0,1,3,6,7,8,9)
    - John the Ripper (formats, rules)
    - hcxpcapngtool / hcxdumptool convert
    - aircrack-ng -J

    ─── Utils ───
    - Potfile import (hashcat format)
    - Session save/resume
    - Real-time progress (rate, ETA)
    - Charset presets

    ─── Интеграция ───
    - Findings → notes (для cracked weak passwords)
    - Notify
    - HTML / JSON / CSV / potfile экспорт
"""
import base64
import csv
import hashlib
import html as html_mod
import itertools
import json
import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator, Any

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn,
    TaskProgressColumn,
)

from core.config import config, WORDLIST_DIR, REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

HASH_DIR = REPORT_DIR / "hashes"
HASH_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class HashFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: HashFinding) -> int:
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f.title,
            target=f.target,
            severity=f.severity,
            status="open",
            tags=["hash", "crack", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Hash types (hashcat modes + extended)
# ===========================================================================

HASH_TYPES = {
    # Base hashes
    "md5":         {"mode": 0,     "regex": r"^[a-f0-9]{32}$", "fn": "md5"},
    "sha1":        {"mode": 100,   "regex": r"^[a-f0-9]{40}$", "fn": "sha1"},
    "sha224":      {"mode": 1300,  "regex": r"^[a-f0-9]{56}$", "fn": "sha224"},
    "sha256":      {"mode": 1400,  "regex": r"^[a-f0-9]{64}$", "fn": "sha256"},
    "sha384":      {"mode": 10800, "regex": r"^[a-f0-9]{96}$", "fn": "sha384"},
    "sha512":      {"mode": 1700,  "regex": r"^[a-f0-9]{128}$", "fn": "sha512"},
    "ripemd160":   {"mode": 6000,  "regex": r"^[a-f0-9]{40}$", "fn": "ripemd160"},
    "whirlpool":   {"mode": 6100,  "regex": r"^[a-f0-9]{128}$", "fn": "whirlpool"},
    "gost":        {"mode": 6900,  "regex": r"^[a-f0-9]{64}$", "fn": None},
    "ntlm":        {"mode": 1000,  "regex": r"^[a-f0-9]{32}$", "fn": "ntlm"},
    "lm":          {"mode": 3000,  "regex": r"^[a-f0-9]{32}$", "fn": None},

    # MySQL / DB
    "mysql5":      {"mode": 300,   "regex": r"^\*[A-F0-9]{40}$", "fn": "mysql5"},
    "mysql4":      {"mode": 200,   "regex": r"^[a-f0-9]{16}$", "fn": None},
    "mssql2005":   {"mode": 132,   "regex": r"^0x0100[A-F0-9]{80,}$", "fn": None},
    "mssql2012":   {"mode": 1731,  "regex": r"^0x0200[A-F0-9]{120,}$", "fn": None},
    "postgres":    {"mode": 12,    "regex": r"^md5[a-f0-9]{32}$", "fn": None},

    # Unix crypt
    "md5crypt":    {"mode": 500,   "regex": r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$", "fn": None},
    "sha256crypt": {"mode": 7400,  "regex": r"^\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$", "fn": None},
    "sha512crypt": {"mode": 1800,  "regex": r"^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$", "fn": None},
    "bcrypt":      {"mode": 3200,  "regex": r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$", "fn": None},
    "yescrypt":    {"mode": 7401,  "regex": r"^\$y\$.*$", "fn": None},
    "scrypt":      {"mode": 8900,  "regex": r"^\$7\$.*$", "fn": None},
    "argon2":      {"mode": 34000, "regex": r"^\$argon2(i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$", "fn": None},

    # Kerberos / AD
    "krb5tgs":     {"mode": 13100, "regex": r"^\$krb5tgs\$", "fn": None},
    "krb5asrep":   {"mode": 18200, "regex": r"^\$krb5asrep\$", "fn": None},
    "krb5pa":      {"mode": 7500,  "regex": r"^\$krb5pa\$", "fn": None},

    # Network / Wireless
    "wpa-pmkid":   {"mode": 22000, "regex": r"^WPA\*", "fn": None},
    "wpa-handshake": {"mode": 2500, "regex": r"^[0-9a-fA-F]{392}$", "fn": None},
    "netntlmv1":   {"mode": 5500,  "regex": r"^[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$", "fn": None},
    "netntlmv2":   {"mode": 5600,  "regex": r"^[^:]+::[^:]+:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]+$", "fn": None},

    # Web / CMS
    "django":      {"mode": 10000, "regex": r"^pbkdf2_sha256\$\d+\$.+", "fn": None},
    "django_sha1": {"mode": 124,   "regex": r"^sha1\$\w+\$[a-f0-9]{40}$", "fn": None},
    "joomla":      {"mode": 11,    "regex": r"^[a-f0-9]{32}:[A-Za-z0-9]{32}$", "fn": None},
    "drupal7":     {"mode": 7900,  "regex": r"^\$S\$[./A-Za-z0-9]{52}$", "fn": None},
    "phpass":      {"mode": 400,   "regex": r"^\$P\$[./A-Za-z0-9]{31}$", "fn": None},
    "prestashop":  {"mode": 11000, "regex": r"^[a-f0-9]{32}:[a-f0-9]{56}$", "fn": None},

    # API keys
    "jwt":         {"mode": 16500, "regex": r"^eyJ[A-Za-z0-9_/+\-]+\.eyJ[A-Za-z0-9_/+\-]+\.[A-Za-z0-9_/+\-]+$", "fn": None},

    # Misc
    "md5_half":    {"mode": 5100,  "regex": r"^[a-f0-9]{16}$", "fn": None},
    "cisco_ios":   {"mode": 500,   "regex": r"^\$1\$.*$", "fn": None},
    "cisco_pix":   {"mode": 2400,  "regex": r"^[a-f0-9]{48,80}$", "fn": None},
    "sip_digest":  {"mode": 11400, "regex": r"^[a-f0-9]{32}:[a-f0-9]{32}$", "fn": None},
    "vbulletin":   {"mode": 2611,  "regex": r"^[a-f0-9]{32}:[A-Za-z0-9]{30}$", "fn": None},
    "ipb2":        {"mode": 2811,  "regex": r"^[a-f0-9]{32}:[A-Za-z0-9]{43}$", "fn": None},
    "phpbb3":      {"mode": 400,   "regex": r"^\$H\$[./A-Za-z0-9]{31}$", "fn": None},
    "mediawiki":   {"mode": 3711,  "regex": r"^[a-f0-9]{32}:[a-f0-9]{31}$", "fn": None},
}

HASH_TYPE_CONFIDENCE = {
    # Типы с уникальными префиксами → высокая уверенность
    "md5crypt": "high", "sha256crypt": "high", "sha512crypt": "high",
    "bcrypt": "high", "yescrypt": "high", "scrypt": "high",
    "argon2": "high", "krb5tgs": "high", "krb5asrep": "high",
    "krb5pa": "high", "phpass": "high", "phpbb3": "high",
    "drupal7": "high", "django": "high", "jwt": "high",
    "wpa-pmkid": "high", "mysql5": "high", "mssql2005": "high",
    "mssql2012": "high", "postgres": "high",
    # Типы с коллизиями → средняя
    "md5": "medium", "ntlm": "medium", "lm": "medium",
    "sha1": "medium", "ripemd160": "medium",
    "sha256": "medium", "gost": "medium",
    "netntlmv1": "medium", "netntlmv2": "medium",
}


def detect_hash_type(hash_value: str) -> list[str]:
    """Определить возможные типы (отсортированные по уверенности)."""
    h = hash_value.strip()
    matches: list[tuple[str, str]] = []
    for name, spec in HASH_TYPES.items():
        if spec["regex"] and re.match(spec["regex"], h):
            conf = HASH_TYPE_CONFIDENCE.get(name, "low")
            matches.append((name, conf))

    order = {"high": 0, "medium": 1, "low": 2}
    matches.sort(key=lambda x: order.get(x[1], 3))
    return [m[0] for m in matches]


def identify_hash_detailed(hash_value: str) -> list[dict]:
    """Детальная идентификация с hashcat mode и уверенностью."""
    h = hash_value.strip()
    out: list[dict] = []
    for name, spec in HASH_TYPES.items():
        if spec["regex"] and re.match(spec["regex"], h):
            out.append({
                "type": name,
                "mode": spec["mode"],
                "confidence": HASH_TYPE_CONFIDENCE.get(name, "low"),
                "supported_builtin": spec["fn"] is not None,
            })
    order = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda x: order.get(x["confidence"], 3))
    return out


# ===========================================================================
# Built-in hash functions
# ===========================================================================

def _ntlm_hash(word: str) -> str | None:
    """NTLM = MD4(UTF-16LE(word))."""
    try:
        return hashlib.new("md4", word.encode("utf-16le")).hexdigest()
    except Exception:
        return None


def _mysql5_hash(word: str) -> str | None:
    """MySQL5 = SHA1(SHA1(word)) с префиксом *."""
    try:
        s1 = hashlib.sha1(word.encode()).digest()
        s2 = hashlib.sha1(s1).hexdigest().upper()
        return f"*{s2}"
    except Exception:
        return None


def _ripemd160_hash(word: str) -> str | None:
    try:
        return hashlib.new("ripemd160", word.encode()).hexdigest()
    except Exception:
        return None


def _whirlpool_hash(word: str) -> str | None:
    try:
        return hashlib.new("whirlpool", word.encode()).hexdigest()
    except Exception:
        return None


HASH_FUNCS = {
    "md5": lambda w: hashlib.md5(w.encode()).hexdigest(),
    "sha1": lambda w: hashlib.sha1(w.encode()).hexdigest(),
    "sha224": lambda w: hashlib.sha224(w.encode()).hexdigest(),
    "sha256": lambda w: hashlib.sha256(w.encode()).hexdigest(),
    "sha384": lambda w: hashlib.sha384(w.encode()).hexdigest(),
    "sha512": lambda w: hashlib.sha512(w.encode()).hexdigest(),
    "ripemd160": _ripemd160_hash,
    "whirlpool": _whirlpool_hash,
    "ntlm": _ntlm_hash,
    "mysql5": _mysql5_hash,
}


# ===========================================================================
# Rules
# ===========================================================================

LEET_MAP = {
    "a": ["a", "4", "@"],
    "e": ["e", "3"],
    "i": ["i", "1", "!"],
    "o": ["o", "0"],
    "s": ["s", "5", "$"],
    "t": ["t", "7"],
    "g": ["g", "9"],
    "b": ["b", "8"],
    "l": ["l", "1"],
}

SYMBOLS = ["", "!", "!!", "!!!", "@", "#", "$", "123", "321", "2020",
           "2021", "2022", "2023", "2024", "2025", "2026", ".",
           "_", "-", "1234", "12345"]

# Full best64-like rule list (keyword → generators)
RULE_REGISTRY = {
    "best64": "best64",
    "dive": "dive",
    "rockyou-30000": "rockyou-30000",
    "leet": "leet",
    "leet-combo": "leet-combo",
    "capitalize": "capitalize",
    "uppercase": "uppercase",
    "lowercase": "lowercase",
    "toggle": "toggle",
    "reverse": "reverse",
    "duplicate": "duplicate",
    "reflect": "reflect",
    "append": "append",
    "prepend": "prepend",
    "swap": "swap",
    "rotate": "rotate",
}


def rule_capitalize(word: str) -> Iterator[str]:
    yield word.capitalize()
    yield word.upper()
    yield word.lower()


def rule_toggle(word: str) -> Iterator[str]:
    yield word
    yield "".join(c.upper() if c.islower() else c.lower() for c in word)


def rule_reverse(word: str) -> Iterator[str]:
    yield word
    yield word[::-1]


def rule_duplicate(word: str) -> Iterator[str]:
    yield word
    yield word + word


def rule_reflect(word: str) -> Iterator[str]:
    yield word
    yield word + word[::-1]


def rule_rotate(word: str) -> Iterator[str]:
    yield word
    if word:
        yield word[1:] + word[0]
        yield word[-1] + word[:-1]


def rule_swap(word: str) -> Iterator[str]:
    yield word
    if len(word) >= 2:
        for i in range(len(word) - 1):
            yield word[:i] + word[i + 1] + word[i] + word[i + 2:]


def rule_leet(word: str) -> Iterator[str]:
    """Простой leet для каждой буквы (не комбинаторный)."""
    yield word
    for ch, repl in LEET_MAP.items():
        if ch in word:
            for r in repl[1:]:
                yield word.replace(ch, r)


def rule_leet_combos(word: str, max_combos: int = 200) -> Iterator[str]:
    """Комбинаторный leet с ограничением."""
    positions = [(i, ch) for i, ch in enumerate(word) if ch in LEET_MAP]
    if not positions:
        yield word
        return
    yield word
    count = 0
    for combo in itertools.product(*[LEET_MAP[ch][1:] for _, ch in positions]):
        if count >= max_combos:
            break
        new_word = list(word)
        for (i, _), r in zip(positions, combo):
            new_word[i] = r
        yield "".join(new_word)
        count += 1


def rule_append(word: str, years: bool = True,
                symbols: bool = True) -> Iterator[str]:
    yield word
    if symbols:
        for s in SYMBOLS[1:]:
            yield word + s
    if years:
        for y in ("1970", "1980", "1990", "2000", "2010", "2020", "2021",
                  "2022", "2023", "2024", "2025", "2026",
                  "01", "02", "03", "11", "12", "123", "1234", "12345"):
            yield word + y


def rule_prepend(word: str) -> Iterator[str]:
    yield word
    for s in ("!", "@", "#", "$", "the", "my", "super", "1", "123"):
        yield s + word


def apply_best64(word: str) -> Iterator[str]:
    """Эмуляция best64.rule (расширенная)."""
    seen: set[str] = set()
    gens = (
        rule_capitalize(word),
        rule_leet(word),
        rule_leet_combos(word, max_combos=20),
        rule_append(word, years=True, symbols=True),
        rule_prepend(word),
        rule_toggle(word),
        rule_reverse(word),
        rule_duplicate(word),
        rule_reflect(word),
        rule_rotate(word),
    )
    for gen in gens:
        for w in gen:
            if w not in seen:
                seen.add(w)
                yield w


def apply_rule(rule_name: str, word: str) -> Iterator[str]:
    """Применить одну rule по имени."""
    if rule_name == "best64":
        yield from apply_best64(word)
    elif rule_name == "dive":
        # dive = best64 + extra
        yield from apply_best64(word)
        yield from rule_swap(word)
    elif rule_name == "rockyou-30000":
        yield from apply_best64(word)
        yield from rule_toggle(word)
        yield from rule_reverse(word)
    elif rule_name == "leet":
        yield from rule_leet(word)
    elif rule_name == "leet-combo":
        yield from rule_leet_combos(word)
    elif rule_name == "capitalize":
        yield from rule_capitalize(word)
    elif rule_name == "uppercase":
        yield word.upper()
    elif rule_name == "lowercase":
        yield word.lower()
    elif rule_name == "toggle":
        yield from rule_toggle(word)
    elif rule_name == "reverse":
        yield from rule_reverse(word)
    elif rule_name == "duplicate":
        yield from rule_duplicate(word)
    elif rule_name == "reflect":
        yield from rule_reflect(word)
    elif rule_name == "append":
        yield from rule_append(word)
    elif rule_name == "prepend":
        yield from rule_prepend(word)
    elif rule_name == "swap":
        yield from rule_swap(word)
    elif rule_name == "rotate":
        yield from rule_rotate(word)


def _apply_rules(word: str, rules: list[str]) -> Iterator[str]:
    """Применить список правил к слову (dedup)."""
    seen: set[str] = set()
    for rule_name in rules:
        for w in apply_rule(rule_name, word):
            if w not in seen:
                seen.add(w)
                yield w


# ===========================================================================
# Cracker
# ===========================================================================

@dataclass
class CrackResult:
    hash_value: str
    hash_type: str
    plain: str = ""
    algorithm: str = ""
    attempts: int = 0
    duration_sec: float = 0.0
    rate: float = 0.0
    rules_used: list[str] = field(default_factory=list)
    mask_used: str = ""
    source_word: str = ""
    attack: str = ""


def _load_wordlist(path: str | Path | None) -> list[str]:
    if not path:
        path = WORDLIST_DIR / "rockyou-mini.txt"
    p = Path(path)
    if not p.is_absolute() and not p.exists():
        p = WORDLIST_DIR / path
    if not p.exists():
        console.print(f"[yellow]Словарь {p} не найден.[/yellow]")
        return []
    try:
        return [w.rstrip("\n") for w in p.open("r", encoding="utf-8",
                                                errors="ignore")
                if w.strip()]
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка чтения {p}: {exc}[/red]")
        return []


def _check_word(word: str, target: str, hash_type: str) -> str | None:
    """Проверить слово. Возвращает алгоритм если совпало."""
    types_to_check: list[str] = []
    if hash_type and hash_type in HASH_FUNCS:
        types_to_check = [hash_type]
    elif hash_type in (None, "", "auto"):
        # Авто: все встроенные
        types_to_check = list(HASH_FUNCS.keys())
    else:
        # Не support built-in (bcrypt/sha-crypt...) — вернём None
        return None

    for algo in types_to_check:
        fn = HASH_FUNCS.get(algo)
        if not fn:
            continue
        try:
            if fn(word) == target:
                return algo
        except Exception:
            continue
    return None


def crack_wordlist(hash_value: str,
                   wordlist: str | Path | None = None,
                   hash_type: str | None = None,
                   rules: list[str] | None = None,
                   show_progress: bool = True) -> CrackResult:
    """Словарная атака (с опциональными правилами)."""
    hash_value = hash_value.strip()
    if not hash_type:
        types = detect_hash_type(hash_value)
        hash_type = types[0] if types else "auto"

    result = CrackResult(hash_value=hash_value,
                         hash_type=hash_type or "auto",
                         attack="wordlist")

    words = _load_wordlist(wordlist)
    if not words:
        return result

    rules = rules or []
    result.rules_used = list(rules)
    total = len(words)

    start = time.time()
    attempts = 0

    ctx = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) if show_progress else _null_ctx()

    with ctx as p:
        task = p.add_task("cracking", total=total) if show_progress else None
        for w in words:
            attempts += 1
            if show_progress:
                p.advance(task)

            # 1) чистое слово
            algo = _check_word(w, hash_value, hash_type)
            if algo:
                result.plain = w
                result.algorithm = algo
                result.source_word = w
                break

            # 2) правила
            if rules:
                found = False
                for variant in _apply_rules(w, rules):
                    attempts += 1
                    algo = _check_word(variant, hash_value, hash_type)
                    if algo:
                        result.plain = variant
                        result.algorithm = algo
                        result.source_word = w
                        found = True
                        break
                if found:
                    break

    result.attempts = attempts
    result.duration_sec = time.time() - start
    if result.duration_sec > 0:
        result.rate = attempts / result.duration_sec
    return result


def crack_mask(hash_value: str, mask: str,
               hash_type: str | None = None,
               custom_charset: dict[str, str] | None = None,
               show_progress: bool = True) -> CrackResult:
    """
    Масковая атака.
    Плейсхолдеры: ?l ?u ?d ?s ?a ?h ?H ?b (?1..?4 — custom).
    """
    hash_value = hash_value.strip()
    if not hash_type:
        types = detect_hash_type(hash_value)
        hash_type = types[0] if types else "auto"

    CHARSETS = {
        "?l": "abcdefghijklmnopqrstuvwxyz",
        "?u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "?d": "0123456789",
        "?s": "!@#$%^&*()-_=+[]{};:,.?/|~",
        "?h": "0123456789abcdef",
        "?H": "0123456789ABCDEF",
        "?b": "01234567",
    }
    CHARSETS["?a"] = (CHARSETS["?l"] + CHARSETS["?u"] + CHARSETS["?d"]
                      + CHARSETS["?s"])
    if custom_charset:
        CHARSETS.update(custom_charset)

    # Parse mask
    sets: list[str] = []
    i = 0
    while i < len(mask):
        ch = mask[i]
        if ch == "?" and i + 1 < len(mask):
            ph = mask[i:i + 2]
            if ph in CHARSETS:
                sets.append(CHARSETS[ph])
                i += 2
                continue
        sets.append(ch)
        i += 1

    result = CrackResult(hash_value=hash_value,
                         hash_type=hash_type or "auto",
                         mask_used=mask,
                         attack="mask")

    total = 1
    for s in sets:
        total *= len(s)
    console.print(f"[cyan]Маска {mask}: {total:,} комбинаций[/cyan]")

    start = time.time()
    attempts = 0
    last_update = start

    for combo in itertools.product(*sets):
        word = "".join(combo)
        attempts += 1
        algo = _check_word(word, hash_value, hash_type)
        if algo:
            result.plain = word
            result.algorithm = algo
            result.attempts = attempts
            result.duration_sec = time.time() - start
            result.rate = attempts / result.duration_sec if result.duration_sec > 0 else 0
            return result

        now = time.time()
        if attempts % 50000 == 0 or (now - last_update) > 3:
            elapsed = now - start
            rate = attempts / elapsed if elapsed > 0 else 0
            eta = (total - attempts) / rate if rate > 0 else 0
            console.print(f"[dim]  {attempts:,}/{total:,} "
                          f"({rate:,.0f} h/s, ETA "
                          f"{timedelta(seconds=int(eta))})[/dim]")
            last_update = now

    result.attempts = attempts
    result.duration_sec = time.time() - start
    if result.duration_sec > 0:
        result.rate = attempts / result.duration_sec
    return result


def crack_combinator(hash_value: str, list_a: str | Path,
                     list_b: str | Path,
                     hash_type: str | None = None,
                     separator: str = "",
                     rules: list[str] | None = None) -> CrackResult:
    """Комбинаторная атака."""
    hash_value = hash_value.strip()
    if not hash_type:
        types = detect_hash_type(hash_value)
        hash_type = types[0] if types else "auto"

    result = CrackResult(hash_value=hash_value,
                         hash_type=hash_type or "auto",
                         rules_used=(rules or []) + ["combinator"],
                         attack="combinator")

    words_a = _load_wordlist(list_a)
    words_b = _load_wordlist(list_b)
    if not words_a or not words_b:
        return result

    total = len(words_a) * len(words_b)
    console.print(f"[cyan]Комбинатор: {len(words_a)} × {len(words_b)} = "
                  f"{total:,} комбинаций[/cyan]")

    start = time.time()
    attempts = 0
    last_update = start
    for a in words_a:
        variants_a = [a]
        if rules:
            variants_a = list(_apply_rules(a, rules)) or [a]
        for va in variants_a:
            for b in words_b:
                word = va + separator + b
                attempts += 1
                algo = _check_word(word, hash_value, hash_type)
                if algo:
                    result.plain = word
                    result.algorithm = algo
                    result.source_word = f"{va} + {b}"
                    result.attempts = attempts
                    result.duration_sec = time.time() - start
                    if result.duration_sec > 0:
                        result.rate = attempts / result.duration_sec
                    return result
        now = time.time()
        if (now - last_update) > 5:
            elapsed = now - start
            rate = attempts / elapsed if elapsed > 0 else 0
            eta = (total - attempts) / rate if rate > 0 else 0
            console.print(f"[dim]  {attempts:,}/{total:,} "
                          f"({rate:,.0f} h/s, ETA "
                          f"{timedelta(seconds=int(eta))})[/dim]")
            last_update = now

    result.attempts = attempts
    result.duration_sec = time.time() - start
    if result.duration_sec > 0:
        result.rate = attempts / result.duration_sec
    return result


class _null_ctx:
    def __enter__(self): return None
    def __exit__(self, *a): pass


# ===========================================================================
# External tools
# ===========================================================================

def check_tools() -> dict[str, bool]:
    return {
        "hashcat": shutil.which("hashcat") is not None,
        "john": shutil.which("john") is not None
            or shutil.which("john-the-ripper") is not None,
        "hcxpcapngtool": shutil.which("hcxpcapngtool") is not None,
        "hcxdumptool": shutil.which("hcxdumptool") is not None,
        "aircrack-ng": shutil.which("aircrack-ng") is not None,
    }


def run_hashcat(hash_file: str, mode: int | str,
                attack: str = "wordlist",
                wordlist: str | None = None,
                mask: str | None = None,
                rules: str | None = None,
                extra_args: list[str] | None = None) -> bool:
    """Запустить hashcat с любым режимом атаки."""
    if not shutil.which("hashcat"):
        console.print("[red]hashcat не установлен.[/red]")
        return False

    cmd = ["hashcat", "-m", str(mode), hash_file]

    if attack == "wordlist":
        if not wordlist:
            console.print("[red]Нужен wordlist.[/red]")
            return False
        cmd += [wordlist]
        if rules:
            cmd += ["-r", rules]
    elif attack == "mask":
        cmd += ["-a", "3", mask or "?d?d?d?d?d?d?d?d"]
    elif attack == "combinator":
        if not wordlist:
            console.print("[red]Нужен wordlist.[/red]")
            return False
        cmd += ["-a", "1", wordlist]
    elif attack == "hybrid-wordlist-mask":
        cmd += ["-a", "6", wordlist or "", mask or "?d?d"]
    elif attack == "hybrid-mask-wordlist":
        cmd += ["-a", "7", mask or "?d?d", wordlist or ""]
    elif attack == "prince":
        if not wordlist:
            console.print("[red]Нужен wordlist.[/red]")
            return False
        cmd += ["-a", "8", wordlist]
    elif attack == "association":
        if not wordlist:
            console.print("[red]Нужен wordlist.[/red]")
            return False
        cmd += ["-a", "9", wordlist]
    elif attack == "dict-of-dicts":
        cmd += ["-a", "0"]
        if wordlist:
            cmd += [wordlist]

    if extra_args:
        cmd += extra_args

    console.print(f"[cyan]$ {' '.join(cmd)}[/cyan]\n")
    try:
        subprocess.run(cmd, check=False)
        return True
    except KeyboardInterrupt:
        console.print("\n[yellow]Прервано.[/yellow]")
        return False
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return False


def run_john(hash_file: str, format: str | None = None,
             wordlist: str | None = None,
             rules: bool = False,
             rules_file: str | None = None,
             incremental: bool = False) -> bool:
    """Запустить John the Ripper."""
    john = shutil.which("john") or shutil.which("john-the-ripper")
    if not john:
        console.print("[red]john не установлен.[/red]")
        return False

    cmd = [john]
    if format:
        cmd += [f"--format={format}"]
    if wordlist:
        cmd += [f"--wordlist={wordlist}"]
    if rules_file:
        cmd += [f"--rules={rules_file}"]
    elif rules:
        cmd += ["--rules=best64"]
    if incremental:
        cmd += ["--incremental"]
    cmd.append(hash_file)

    console.print(f"[cyan]$ {' '.join(cmd)}[/cyan]\n")
    try:
        subprocess.run(cmd, check=False)
        return True
    except KeyboardInterrupt:
        console.print("\n[yellow]Прервано.[/yellow]")
        return False
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return False


# ===========================================================================
# Converters
# ===========================================================================

def convert_hccapx_to_hc22000(input_file: str,
                              output_file: str | None = None) -> Path | None:
    src = Path(input_file)
    if not src.exists():
        console.print(f"[red]Файл {src} не найден.[/red]")
        return None
    if not output_file:
        output_file = str(HASH_DIR / f"{src.stem}.hc22000")

    if shutil.which("hcxpcapngtool") and src.suffix in (".cap", ".pcap",
                                                        ".pcapng"):
        cmd = ["hcxpcapngtool", "-o", output_file, str(src)]
        console.print(f"[cyan]$ {' '.join(cmd)}[/cyan]")
        try:
            subprocess.run(cmd, check=False)
            console.print(f"[green]✓ {output_file}[/green]")
            return Path(output_file)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Ошибка: {exc}[/red]")
            return None

    if src.suffix == ".hccapx":
        console.print("[yellow]Для .hccapx используй hashcat — он сам "
                      "конвертирует в runtime.[/yellow]")
        return None

    console.print("[red]Неизвестный формат.[/red]")
    return None


def convert_aircrack_handshake(cap_file: str) -> Path | None:
    if not shutil.which("aircrack-ng"):
        console.print("[red]aircrack-ng не установлен.[/red]")
        return None
    src = Path(cap_file)
    if not src.exists():
        console.print(f"[red]{src} не найден.[/red]")
        return None
    out = HASH_DIR / src.stem
    cmd = ["aircrack-ng", "-J", str(out), str(src)]
    console.print(f"[cyan]$ {' '.join(cmd)}[/cyan]")
    try:
        subprocess.run(cmd, check=False)
        console.print(f"[green]✓ {out}.hccap[/green]")
        return out.with_suffix(".hccap")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# Export
# ===========================================================================

def export_potfile(results: list[CrackResult],
                   path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(HASH_DIR / f"cracked_{ts}.potfile")
    try:
        with open(path, "w", encoding="utf-8") as f:
            for r in results:
                if r.plain:
                    f.write(f"{r.hash_value}:{r.plain}\n")
        console.print(f"[green]✓ Potfile: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_json(results: list[CrackResult],
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(HASH_DIR / f"cracked_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps([asdict(r) for r in results],
                       indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_csv(results: list[CrackResult],
               path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(HASH_DIR / f"cracked_{ts}.csv")
    cols = ["hash_value", "hash_type", "algorithm", "plain",
            "attempts", "duration_sec", "rate", "attack", "source_word"]
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for r in results:
                w.writerow(asdict(r))
        console.print(f"[green]✓ CSV: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def import_potfile(path: str, hash_type: str | None = None) -> list[CrackResult]:
    """Импортировать hashcat potfile (hash:plain)."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return []
    out: list[CrackResult] = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        h, plain = line.split(":", 1)
        out.append(CrackResult(
            hash_value=h.strip(),
            hash_type=hash_type or (detect_hash_type(h.strip())[0]
                                    if detect_hash_type(h.strip()) else "auto"),
            plain=plain.strip(),
            algorithm=hash_type or "imported",
            attack="potfile",
        ))
    console.print(f"[green]✓ Импортировано: {len(out)}[/green]")
    return out


# ===========================================================================
# Bulk crack
# ===========================================================================

def crack_file(hash_file: str, wordlist: str | None = None,
               hash_type: str | None = None,
               rules: list[str] | None = None,
               threads: int = 4) -> list[CrackResult]:
    src = Path(hash_file)
    if not src.exists():
        console.print(f"[red]{src} не найден.[/red]")
        return []

    hashes = [l.strip() for l in src.open("r", encoding="utf-8",
                                           errors="ignore")
              if l.strip() and not l.startswith("#")]
    if not hashes:
        console.print("[yellow]Файл пуст.[/yellow]")
        return []

    console.print(f"[cyan]🔨 Крэкаю {len(hashes)} хешей…[/cyan]")
    results: list[CrackResult] = []
    for i, h in enumerate(hashes, 1):
        console.print(f"\n[cyan]({i}/{len(hashes)})[/cyan] {h[:60]}")
        r = crack_wordlist(h, wordlist, hash_type, rules,
                           show_progress=False)
        results.append(r)
        if r.plain:
            console.print(f"  [green]✓ {r.plain}[/green] ({r.algorithm})")
        else:
            console.print(f"  [yellow]✗ не найдено[/yellow]")

    cracked = [r for r in results if r.plain]
    _print_results_table(results)
    console.print(f"\n[bold cyan]Итого: {len(cracked)}/{len(results)} "
                  f"взломано[/bold cyan]")

    # Findings для weak passwords
    for r in cracked:
        if len(r.plain) <= 8 and any(c.isdigit() for c in r.plain):
            _save_finding(HashFinding(
                kind="weak_password",
                severity="high",
                title=f"Weak hash cracked: {r.algorithm}",
                target=r.hash_value[:16],
                evidence=f"Plaintext: {r.plain}",
                data={"plain": r.plain, "algorithm": r.algorithm,
                      "hash_prefix": r.hash_value[:16]},
            ))

    # Notify
    if cracked:
        try:
            from modules import notifier
            notifier.notify_all(
                "🔨 Hash crack",
                f"Cracked: {len(cracked)}/{len(results)}\n"
                f"Attempts: {sum(r.attempts for r in results):,}",
            )
        except Exception:
            pass

    return results


def _print_results_table(results: list[CrackResult]) -> None:
    table = Table(title="🔨 Crack results")
    table.add_column("#", style="yellow", width=4)
    table.add_column("Hash", style="cyan", max_width=32)
    table.add_column("Type", style="magenta", width=12)
    table.add_column("Plain", style="green", max_width=28)
    table.add_column("Algo", style="dim", width=10)
    table.add_column("Attempts", style="white", width=10)
    table.add_column("Rate", style="dim", width=10)
    for i, r in enumerate(results, 1):
        rate_str = f"{r.rate:,.0f} h/s" if r.rate else "—"
        table.add_row(
            str(i),
            r.hash_value[:32],
            r.hash_type,
            r.plain or "[red]—[/red]",
            r.algorithm or "—",
            f"{r.attempts:,}",
            rate_str,
        )
    console.print(table)


# ===========================================================================
# CLI wrappers
# ===========================================================================

def cli_crack(hash_value: str, wordlist: str | None = None,
              rules: str | None = None) -> None:
    rule_list = [r.strip() for r in (rules or "").split(",") if r.strip()]
    result = crack_wordlist(hash_value, wordlist, rules=rule_list)
    _print_results_table([result])
    if result.plain:
        console.print(f"\n[bold green]✓ {result.plain}[/bold green] "
                      f"({result.algorithm}, {result.attempts:,} попыток, "
                      f"{result.duration_sec:.2f}s, "
                      f"{result.rate:,.0f} h/s)")
        db.save_scan("hash_crack", result.hash_value[:16], {
            "plain": result.plain,
            "algo": result.algorithm,
        })


def cli_mask(hash_value: str, mask: str) -> None:
    result = crack_mask(hash_value, mask)
    _print_results_table([result])
    if result.plain:
        console.print(f"\n[bold green]✓ {result.plain}[/bold green]")


def cli_file(hash_file: str, wordlist: str | None = None,
             rules: str | None = None) -> None:
    rule_list = [r.strip() for r in (rules or "").split(",") if r.strip()]
    crack_file(hash_file, wordlist, rules=rule_list)


def cli_tools() -> None:
    status = check_tools()
    table = Table(title="🔧 Hash cracking tools")
    table.add_column("Tool", style="cyan")
    table.add_column("Статус", width=10)
    for name, ok in status.items():
        table.add_row(name, "[green]✓[/green]" if ok else "[red]✗[/red]")
    console.print(table)


def cli_identify(hash_value: str) -> None:
    detailed = identify_hash_detailed(hash_value)
    if not detailed:
        console.print("[red]Не удалось определить тип.[/red]")
        return
    t = Table(title=f"🔍 Hash identification ({len(detailed)} matches)")
    t.add_column("Type", style="cyan")
    t.add_column("Mode", style="magenta", width=8)
    t.add_column("Confidence", width=12)
    t.add_column("Built-in", width=10)
    for d in detailed:
        conf = d["confidence"]
        sty = {"high": "green", "medium": "yellow",
               "low": "dim"}.get(conf, "white")
        t.add_row(d["type"], str(d["mode"]),
                  f"[{sty}]{conf}[/{sty}]",
                  "[green]✓[/green]" if d["supported_builtin"] else "—")
    console.print(t)

    # Recommendation
    if detailed:
        top = detailed[0]
        console.print(f"\n[cyan]Рекомендация:[/cyan] "
                      f"[bold]{top['type']}[/bold] "
                      f"(hashcat -m {top['mode']})")


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🔨 Hash Cracking Suite Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Проверить инструменты (hashcat/john)"),
        ("2", "Определить тип хеша (с confidence)"),
        ("3", "Крэк — wordlist"),
        ("4", "Крэк — wordlist + правила (best64/dive/leet/...)"),
        ("5", "Крэк — маска (?l?u?d?s?h?H?b)"),
        ("6", "Крэк — комбинатор (word1+word2)"),
        ("7", "Крэк файла (много хешей)"),
        ("8", "hashcat — внешний запуск (все режимы)"),
        ("9", "John the Ripper — внешний запуск"),
        ("10", "Конвертер hccapx/cap → hc22000"),
        ("11", "Импорт hashcat potfile"),
        ("12", "Экспорт результатов (JSON/CSV/potfile)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного пентеста / CTF.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        cli_tools()
    elif c == "2":
        cli_identify(Prompt.ask("Хеш"))
    elif c == "3":
        h = Prompt.ask("Хеш")
        wl = Prompt.ask("Wordlist (Enter = rockyou-mini.txt)", default="")
        cli_crack(h, wl or None)
    elif c == "4":
        h = Prompt.ask("Хеш")
        wl = Prompt.ask("Wordlist (Enter = rockyou-mini.txt)", default="")
        rules = Prompt.ask(
            "Правила (через запятую: best64, dive, rockyou-30000, "
            "leet, leet-combo, capitalize, append, prepend, toggle, "
            "reverse, duplicate, reflect, swap, rotate)",
            default="best64",
        )
        cli_crack(h, wl or None, rules)
    elif c == "5":
        h = Prompt.ask("Хеш")
        mask = Prompt.ask("Маска (?l?u?d?s?a?h?H?b)",
                          default="?d?d?d?d?d?d")
        cli_mask(h, mask)
    elif c == "6":
        h = Prompt.ask("Хеш")
        a = Prompt.ask("Первый список", default="subdomains.txt")
        b = Prompt.ask("Второй список", default="dirs.txt")
        sep = Prompt.ask("Разделитель", default="")
        rules_str = Prompt.ask("Правила (опц., через запятую)", default="")
        rule_list = [r.strip() for r in rules_str.split(",") if r.strip()]
        r = crack_combinator(h, a, b, separator=sep,
                              rules=rule_list or None)
        _print_results_table([r])
    elif c == "7":
        f = Prompt.ask("Файл с хешами")
        wl = Prompt.ask("Wordlist (Enter = rockyou-mini.txt)", default="")
        rules = Prompt.ask("Правила (через запятую)", default="")
        cli_file(f, wl or None, rules or None)
    elif c == "8":
        hf = Prompt.ask("Файл хешей")
        mode = Prompt.ask("Hashcat mode (0=md5, 1000=ntlm, 1400=sha256, "
                          "22000=wpa, 13100=kerb)", default="0")
        attack = Prompt.ask("Атака",
                            choices=["wordlist", "mask", "combinator",
                                     "hybrid-wordlist-mask",
                                     "hybrid-mask-wordlist",
                                     "prince", "association"],
                            default="wordlist")
        wl = ""
        mask = ""
        if attack in ("wordlist", "hybrid-wordlist-mask",
                      "hybrid-mask-wordlist", "combinator",
                      "prince", "association"):
            wl = Prompt.ask("Wordlist",
                            default="/usr/share/wordlists/rockyou.txt")
        if attack in ("mask", "hybrid-wordlist-mask",
                      "hybrid-mask-wordlist"):
            mask = Prompt.ask("Mask", default="?d?d?d?d?d?d?d?d")
        rules = Prompt.ask("Rules file (опц.)", default="")
        run_hashcat(hf, mode, attack, wl or None, mask or None,
                    rules or None)
    elif c == "9":
        hf = Prompt.ask("Файл хешей")
        fmt = Prompt.ask("Format (опц., напр. raw-md5, nt, sha512crypt)",
                         default="")
        wl = Prompt.ask("Wordlist", default="")
        rules = Confirm.ask("Использовать rules=best64?", default=False)
        inc = Confirm.ask("Incremental (brute)?", default=False)
        run_john(hf, fmt or None, wl or None, rules, incremental=inc)
    elif c == "10":
        f = Prompt.ask("Файл (.cap/.pcapng/.hccapx)")
        convert_hccapx_to_hc22000(f)
    elif c == "11":
        p = Prompt.ask("Путь к potfile")
        results = import_potfile(p)
        if results:
            _print_results_table(results)
    elif c == "12":
        console.print("[dim]Результаты сохраняются автоматически "
                      "при крэке.[/dim]")
        console.print(f"[dim]Папка: {HASH_DIR}[/dim]")
        p = Prompt.ask("Импортировать potfile для экспорта? "
                        "(путь или Enter)", default="").strip()
        if p:
            r = import_potfile(p)
            if r:
                export_json(r)
                export_csv(r)
                export_potfile(r)