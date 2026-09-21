"""
Wordlist Tools Pro — генерация словарей + rules engine + mask + анализ.
Author: idqwixxa

⚠ Только для авторизованного пентеста / CTF.

Возможности:
    ─── Генерация ───
    - Из 1 слова: leet + регистр + суффиксы/префиксы + годы
    - Из 2 слов: комбинации (concat, _ , . , -)
    - Из N слов: cartesian N-way
    - Mask-based: ?l ?u ?d ?s ?a + custom charset
    - Common-only: популярные пароли с модификациями
    - Rules engine: полный набор правил (16 типов)

    ─── Комбинирование ───
    - 2 словаря: concat + sep + cap + leet
    - Hashcat-style: word_a[:N] + word_b[:N]
    - Substring combinations

    ─── Анализ ───
    - Stats: длина / charset / entropy distribution
    - Duplicates removal (streaming)
    - Estimated size + time-to-crack (offline 100 GH/s)
    - Top-patterns (dates, keyboard walks, common suffixes)

    ─── Интеграция ───
    - Findings → notes
    - Notify
    - Экспорт: JSON / MD / HTML / CSV
    - Compression (gzip) опционально
"""
import csv
import gzip
import html as html_mod
import itertools
import json
import math
import re
import string
import time
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn,
)

from core.config import WORDLIST_DIR, REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

WL_DIR = REPORT_DIR / "wordlists"
WL_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings
# ===========================================================================

@dataclass
class WLFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: WLFinding) -> int:
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
            tags=["wordlist", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


def _notify(title: str, msg: str, severity: str = "medium") -> None:
    try:
        from modules import notifier
        notifier.notify_all(title, msg, severity=severity)
    except Exception:
        pass


# ===========================================================================
# Rules / mappings
# ===========================================================================

LEET_MAP = [
    ("a", "4"), ("a", "@"),
    ("e", "3"),
    ("i", "1"), ("i", "!"),
    ("o", "0"),
    ("s", "5"), ("s", "$"),
    ("t", "7"),
    ("g", "9"),
    ("b", "8"),
    ("l", "1"),
]

# Расширенная leet-карта (односимвольные + пары)
LEET_EXTENDED = {
    "a": ["4", "@", "a"],
    "b": ["8", "b"],
    "c": ["(", "c"],
    "e": ["3", "e"],
    "g": ["9", "6", "g"],
    "i": ["1", "!", "i"],
    "l": ["1", "|", "l"],
    "o": ["0", "o"],
    "s": ["5", "$", "s"],
    "t": ["7", "t"],
    "z": ["2", "z"],
}

YEARS = [str(y) for y in range(1970, 2031)]

SYMBOLS = ["", "!", "!!", "!!!", "!!!!", "@", "@@", "#", "##", "$",
           "%", "^", "&", "*", ".", ",", "_", "-", "~",
           "123", "321", "1234", "12345", "1", "12", "13", "007",
           "69", "777", "666", "1337", "0", "01"]

# Суффиксы-правила (как в hashcat best64)
SUFFIX_RULES = [
    "", "1", "12", "123", "1234", "12345", "123456",
    "!", "!!", "!!!", "1!", "!1", "@", "#", "$",
    "?", "??", "2024", "2025", "2026", "2023",
    "0", "00", "000", ".", "._", "_",
]

# Префиксы (append в начало)
PREFIX_RULES = [
    "", "1", "!", "@", "#", "the", "The", "my", "My",
]

# Общие правила (из hashcat best64)
HASHCAT_BEST64_RULES = {
    "nothing": lambda w: w,
    "lower": lambda w: w.lower(),
    "upper": lambda w: w.upper(),
    "capital": lambda w: w.capitalize(),
    "c": lambda w: w.capitalize(),
    "C": lambda w: w.lower().capitalize(),
    "invert-capital": lambda w: (w[0].lower() + w[1:].upper()
                                  if len(w) > 1 else w.lower()),
    "reverse": lambda w: w[::-1],
    "duplicate": lambda w: w + w,
    "reflect": lambda w: w + w[::-1],
    "toggle1": lambda w: w[:1].swapcase() + w[1:],
    "toggle2": lambda w: w[:2].swapcase() + w[2:],
    "toggle-all": lambda w: w.swapcase(),
    "leet1": lambda w: w.replace("a", "@").replace("o", "0"),
    "leet2": lambda w: (w.replace("a", "@").replace("e", "3")
                         .replace("i", "1").replace("o", "0")
                         .replace("s", "5").replace("t", "7")),
    "append1": lambda w: w + "1",
    "append!": lambda w: w + "!",
    "append@": lambda w: w + "@",
    "append#": lambda w: w + "#",
    "append$": lambda w: w + "$",
    "append123": lambda w: w + "123",
    "append_year": lambda w: w + "2024",
    "prepend1": lambda w: "1" + w,
    "prepend!": lambda w: "!" + w,
    "prepend@": lambda w: "@" + w,
    "capitalize_reverse": lambda w: w.capitalize()[::-1],
    "append_reverse": lambda w: w + w[::-1],
    "delete_first": lambda w: w[1:] if len(w) > 1 else w,
    "delete_last": lambda w: w[:-1] if len(w) > 1 else w,
    "truncate6": lambda w: w[:6],
    "truncate8": lambda w: w[:8],
    "prefix_2": lambda w: w[:2],
    "suffix_2": lambda w: w[-2:],
}


# ===========================================================================
# Variants
# ===========================================================================

def _leet_variants(word: str, extended: bool = False,
                    max_results: int = 20000) -> set[str]:
    """Все leet-варианты слова (комбинаторно, но с ограничением)."""
    results: set[str] = {word}
    mp = (LEET_MAP if not extended else
          [(k, v) for k, vs in LEET_EXTENDED.items() for v in vs if v != k])
    for ch, repl in mp:
        new_results = set()
        for w in results:
            if ch in w:
                new_results.add(w.replace(ch, repl))
        results |= new_results
        if len(results) > max_results:
            break
    return results


def _case_variants(word: str) -> set[str]:
    """Все варианты регистра."""
    variants = {
        word.lower(),
        word.upper(),
        word.capitalize(),
        word[:1].upper() + word[1:] if word else word,
        word[:1].lower() + word[1:].upper() if word else word,
        "".join(c.upper() if i % 2 == 0 else c.lower()
                for i, c in enumerate(word)),
        "".join(c.lower() if i % 2 == 0 else c.upper()
                for i, c in enumerate(word)),
        word.swapcase(),
    }
    return {v for v in variants if v}


def _all_variants(word: str, leet: bool = True, years: bool = True,
                   symbols: bool = True, extended: bool = False,
                   max_total: int = 200_000) -> set[str]:
    """Все варианты одного слова с суффиксами."""
    base_forms: set[str] = set()
    for case_form in _case_variants(word):
        base_forms.add(case_form)
        if leet:
            base_forms |= _leet_variants(case_form, extended=extended)

    results: set[str] = set(base_forms)

    if symbols:
        for form in base_forms:
            for s in SYMBOLS:
                results.add(form + s)
                if s:
                    results.add(form + s + "!")
            for s in PREFIX_RULES:
                if s:
                    results.add(s + form)
        if len(results) > max_total:
            return results

    if years:
        for form in base_forms:
            for y in YEARS:
                results.add(form + y)
                if symbols:
                    results.add(form + y + "!")
                    results.add(form + "@" + y)
                    results.add(form + y + "!")
        if len(results) > max_total:
            return results

    return results


# ===========================================================================
# Mask
# ===========================================================================

MASK_CHARSETS = {
    "?l": string.ascii_lowercase,
    "?u": string.ascii_uppercase,
    "?d": string.digits,
    "?s": "!@#$%^&*()-_=+[]{};:,.?/|~",
    "?a": (string.ascii_letters + string.digits +
           "!@#$%^&*()-_=+[]{};:,.?/|~"),
    "?h": "0123456789abcdef",
    "?H": "0123456789ABCDEF",
    "?b": "".join(chr(c) for c in range(0x20, 0x7f)),
}


def _expand_mask(mask: str, custom: dict[str, str] | None = None
                  ) -> Iterator[str]:
    """Развернуть hashcat-подобную маску (?l?u?d) в генератор."""
    custom = custom or {}
    charsets: list[str] = []
    i = 0
    while i < len(mask):
        ch = mask[i]
        if ch == "?" and i + 1 < len(mask):
            key = mask[i:i + 2]
            if key in custom:
                charsets.append(custom[key])
            elif key in MASK_CHARSETS:
                charsets.append(MASK_CHARSETS[key])
            else:
                charsets.append(mask[i + 1])
            i += 2
        else:
            charsets.append(ch)
            i += 1
    for combo in itertools.product(*charsets):
        yield "".join(combo)


def mask_generate(mask: str, out_name: str = "mask.txt",
                  custom_charsets: dict[str, str] | None = None,
                  max_lines: int = 5_000_000,
                  gzip_out: bool = False) -> Path | None:
    """Генерация по маске (?l?u?d?d)."""
    # Оценка размера
    size = 1
    i = 0
    while i < len(mask):
        ch = mask[i]
        if ch == "?" and i + 1 < len(mask):
            key = mask[i:i + 2]
            cs = (custom_charsets or {}).get(key) or MASK_CHARSETS.get(key)
            size *= len(cs) if cs else 1
            i += 2
        else:
            i += 1

    console.print(f"[cyan]Маска: {mask} → ~{size:,} вариантов[/cyan]")
    if size > max_lines:
        console.print(f"[red]Слишком много ({size:,}), лимит {max_lines:,}"
                      f"[/red]")
        return None

    out_path = WL_DIR / out_name
    if gzip_out:
        out_path = out_path.with_suffix(out_path.suffix + ".gz")
        open_fn = gzip.open
        mode = "wt"
    else:
        open_fn = open
        mode = "w"

    count = 0
    try:
        with open_fn(out_path, mode, encoding="utf-8") as f:
            for w in _expand_mask(mask, custom_charsets):
                f.write(w + "\n")
                count += 1
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None

    console.print(f"[green]✓ {count:,} → {out_path}[/green]")
    db.save_scan("wl_mask", mask, {"path": str(out_path), "count": count})
    return out_path


# ===========================================================================
# Generation
# ===========================================================================

def _write_streaming(path: Path, gen: Iterable[str], gzip_out: bool = False,
                     dedup: bool = True) -> int:
    """Записать генератор в файл, опционально с дедупликацией."""
    count = 0
    seen: set[str] = set() if dedup else None
    open_fn = gzip.open if gzip_out else open
    try:
        with open_fn(path, "wt" if gzip_out else "w",
                      encoding="utf-8") as f:
            for v in gen:
                if not v:
                    continue
                if seen is not None:
                    if v in seen:
                        continue
                    seen.add(v)
                f.write(v + "\n")
                count += 1
    except Exception as exc:
        console.print(f"[red]Ошибка записи: {exc}[/red]")
        return 0
    return count


def generate_wordlist(base_word: str, out_name: str = "custom_wordlist.txt",
                       leet: bool = True, years: bool = True,
                       symbols: bool = True,
                       second_word: str = "") -> None:
    """Сгенерировать словарь на основе 1–2 базовых слов."""
    base_word = (base_word or "").strip()
    if not base_word:
        console.print("[red]Пустое слово.[/red]")
        return

    console.print(f"[cyan]Генерирую варианты для '{base_word}'…[/cyan]")
    variants = _all_variants(base_word, leet=leet, years=years,
                              symbols=symbols)

    if second_word.strip():
        second_word = second_word.strip()
        second_variants = _all_variants(second_word, leet=False,
                                          years=False, symbols=False)
        combined: set[str] = set()
        for a in variants:
            for b in second_variants:
                combined.add(a + b)
                combined.add(a + "_" + b)
                combined.add(a + "." + b)
                combined.add(a + "-" + b)
                combined.add(a + b.capitalize())
        variants |= combined

    variants = {v for v in variants if v}
    path = WORDLIST_DIR / out_name
    try:
        with path.open("w", encoding="utf-8") as f:
            for v in sorted(variants):
                f.write(v + "\n")
    except Exception as exc:
        console.print(f"[red]Ошибка записи: {exc}[/red]")
        return

    size_kb = path.stat().st_size / 1024
    console.print(
        f"[green]✓ {len(variants)} вариантов → {path} ({size_kb:.1f} KB)[/green]"
    )
    db.save_scan("wordlist_gen_rules", base_word,
                 {"out": str(path), "count": len(variants)})


def generate_multi_word(words: list[str], out_name: str = "multi.txt",
                         separator: str = "", cap_variants: bool = True,
                         max_combos: int = 1_000_000) -> Path | None:
    """N-слов cartesian."""
    words = [w.strip() for w in words if w.strip()]
    if len(words) < 2:
        console.print("[red]Нужно минимум 2 слова.[/red]")
        return None
    total = 1
    for w in words:
        total *= max(1, len(_case_variants(w)) if cap_variants else 1)
    if total > max_combos:
        console.print(f"[red]Слишком много (~{total:,})[/red]")
        return None

    out = WORDLIST_DIR / out_name

    def _gen() -> Iterator[str]:
        word_forms = []
        for w in words:
            if cap_variants:
                word_forms.append(sorted(_case_variants(w)))
            else:
                word_forms.append([w])
        for combo in itertools.product(*word_forms):
            yield separator.join(combo)

    with Progress(SpinnerColumn(),
                   TextColumn("[progress.description]{task.description}"),
                   BarColumn(),
                   TimeElapsedColumn(),
                   console=console) as p:
        task = p.add_task("Запись", total=total)
        count = 0
        seen: set[str] = set()
        with out.open("w", encoding="utf-8") as f:
            for v in _gen():
                if v in seen:
                    continue
                seen.add(v)
                f.write(v + "\n")
                count += 1
                if count % 10_000 == 0:
                    p.update(task, completed=count)
        p.update(task, completed=count)

    console.print(f"[green]✓ {count:,} → {out}[/green]")
    db.save_scan("wl_multi", "+".join(words), {"count": count})
    return out


def apply_hashcat_rules(wordlist_path: Path, out_name: str = "expanded.txt",
                         rules: list[str] | None = None,
                         gzip_out: bool = False) -> Path | None:
    """Применить hashcat-style rules к словарю."""
    src = Path(wordlist_path)
    if not src.exists():
        src = WORDLIST_DIR / wordlist_path
    if not src.exists():
        console.print(f"[red]Словарь {wordlist_path} не найден.[/red]")
        return None

    rule_names = rules or list(HASHCAT_BEST64_RULES.keys())
    rules_fn = [HASHCAT_BEST64_RULES[r] for r in rule_names
                if r in HASHCAT_BEST64_RULES]

    words = [w.strip() for w in src.read_text(encoding="utf-8",
                                                errors="ignore").splitlines()
             if w.strip()]
    out = WL_DIR / out_name
    open_fn = gzip.open if gzip_out else open
    mode = "wt" if gzip_out else "w"

    count = 0
    seen: set[str] = set()
    try:
        with open_fn(out, mode, encoding="utf-8") as f:
            for w in words:
                for fn in rules_fn:
                    try:
                        cand = fn(w)
                        if cand and cand not in seen:
                            seen.add(cand)
                            f.write(cand + "\n")
                            count += 1
                    except Exception:
                        continue
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None

    console.print(f"[green]✓ {count:,} → {out}[/green]")
    db.save_scan("wl_hashcat_rules", src.name,
                 {"out": str(out), "count": count,
                  "rules": rule_names})
    return out


def combine_two_lists(list_a: str, list_b: str, out_name: str = "combo.txt",
                       separator: str = "") -> None:
    """Скомбинировать два словаря (a + sep + b)."""
    path_a = WORDLIST_DIR / list_a
    path_b = WORDLIST_DIR / list_b
    if not path_a.exists() or not path_b.exists():
        console.print("[red]Один из словарей не найден в wordlists/.[/red]")
        return

    words_a = [w.strip() for w in path_a.read_text(
        encoding="utf-8", errors="ignore").splitlines() if w.strip()]
    words_b = [w.strip() for w in path_b.read_text(
        encoding="utf-8", errors="ignore").splitlines() if w.strip()]

    out_path = WORDLIST_DIR / out_name
    total = 0
    try:
        with out_path.open("w", encoding="utf-8") as f:
            for a in words_a:
                for b in words_b:
                    f.write(f"{a}{separator}{b}\n")
                    total += 1
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return

    console.print(f"[green]✓ {total} строк → {out_path}[/green]")
    db.save_scan("wordlist_combo", out_name,
                 {"a": list_a, "b": list_b, "total": total})


# ===========================================================================
# Stats / analysis
# ===========================================================================

def analyze_wordlist(path: Path) -> dict:
    """Статистика словаря."""
    p = Path(path)
    if not p.exists():
        p = WORDLIST_DIR / path
    if not p.exists():
        console.print(f"[red]Файл {path} не найден.[/red]")
        return {}

    total = 0
    chars = Counter()
    lengths = Counter()
    has_digit = has_upper = has_lower = has_sym = 0
    seen: set[str] = set()
    dup_count = 0
    top10: list[tuple[str, int]] = []
    interesting: list[str] = []

    console.print(f"[cyan]Анализ {p.name}…[/cyan]")
    start = time.time()
    try:
        with p.open(encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.rstrip("\n")
                if not w:
                    continue
                total += 1
                if w in seen:
                    dup_count += 1
                    continue
                seen.add(w)
                lengths[len(w)] += 1
                for c in w:
                    chars[c] += 1
                if re.search(r"\d", w):
                    has_digit += 1
                if re.search(r"[A-Z]", w):
                    has_upper += 1
                if re.search(r"[a-z]", w):
                    has_lower += 1
                if re.search(r"[^A-Za-z0-9]", w):
                    has_sym += 1
                if re.search(r"(19|20)\d{2}$", w):
                    interesting.append(w)
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return {}

    elapsed = time.time() - start
    unique = len(seen)

    # Shannon entropy over char distribution
    total_chars = sum(chars.values())
    ent = 0.0
    for c in chars.values():
        if c <= 0:
            continue
        pr = c / total_chars
        ent -= pr * math.log2(pr)

    result = {
        "file": str(p),
        "size_mb": round(p.stat().st_size / 1024 / 1024, 2),
        "total_lines": total,
        "unique": unique,
        "duplicates": dup_count,
        "length_distribution": dict(sorted(lengths.items())),
        "avg_length": round(sum(k * v for k, v in lengths.items())
                            / max(1, unique), 2),
        "min_length": min(lengths.keys()) if lengths else 0,
        "max_length": max(lengths.keys()) if lengths else 0,
        "has_digit_pct": round(has_digit * 100 / max(1, unique), 1),
        "has_upper_pct": round(has_upper * 100 / max(1, unique), 1),
        "has_lower_pct": round(has_lower * 100 / max(1, unique), 1),
        "has_symbol_pct": round(has_sym * 100 / max(1, unique), 1),
        "shannon_entropy": round(ent, 3),
        "top_chars": dict(chars.most_common(15)),
        "year_suffix_samples": interesting[:20],
        "parse_time_sec": round(elapsed, 2),
    }

    table = Table(title=f"📊 Stats: {p.name}")
    table.add_column("Метрика", style="cyan")
    table.add_column("Значение", style="green")
    for k in ("size_mb", "total_lines", "unique", "duplicates",
              "avg_length", "min_length", "max_length",
              "has_digit_pct", "has_upper_pct", "has_lower_pct",
              "has_symbol_pct", "shannon_entropy", "parse_time_sec"):
        table.add_row(k, str(result[k]))
    console.print(table)

    db.save_scan("wl_stats", p.name, result)
    return result


def dedup_wordlist(path: Path, out_name: str | None = None,
                    gzip_out: bool = False) -> Path | None:
    """Удалить дубликаты."""
    p = Path(path)
    if not p.exists():
        p = WORDLIST_DIR / path
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return None
    out_name = out_name or (p.stem + "_dedup.txt")
    out = WL_DIR / out_name

    console.print(f"[cyan]Дедупликация {p.name}…[/cyan]")
    seen: set[str] = set()
    count = 0
    open_fn = gzip.open if gzip_out else open
    mode = "wt" if gzip_out else "w"
    try:
        with open_fn(out, mode, encoding="utf-8") as wf:
            with p.open(encoding="utf-8", errors="ignore") as rf:
                for line in rf:
                    w = line.rstrip("\n")
                    if w and w not in seen:
                        seen.add(w)
                        wf.write(w + "\n")
                        count += 1
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None
    console.print(f"[green]✓ {count:,} → {out}[/green]")
    db.save_scan("wl_dedup", p.name, {"out": str(out), "count": count})
    return out


def estimate_crack_time(unique: int, avg_len: float,
                         hashes_per_sec: float = 1e11) -> str:
    """Оценка времени в секундах для 100 GH/s."""
    if unique <= 0:
        return "0"
    sec = unique / hashes_per_sec
    if sec < 1:
        return f"{sec*1000:.1f} ms"
    if sec < 60:
        return f"{sec:.1f} s"
    if sec < 3600:
        return f"{sec/60:.1f} min"
    if sec < 86400:
        return f"{sec/3600:.1f} h"
    return f"{sec/86400:.2f} d"


# ===========================================================================
# Export
# ===========================================================================

def export_stats(stats: dict, fmt: str = "json",
                  out_path: str | None = None) -> Path | None:
    if not stats:
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = {"json": ".json", "md": ".md",
           "html": ".html", "csv": ".csv"}.get(fmt, ".json")
    if not out_path:
        out_path = str(WL_DIR / f"stats_{ts}{ext}")
    p = Path(out_path)
    try:
        if fmt == "json":
            p.write_text(json.dumps(stats, indent=2, ensure_ascii=False,
                                      default=str), encoding="utf-8")
        elif fmt == "md":
            lines = [f"# Wordlist analysis", "",
                     f"_Generated: {datetime.now().isoformat()}_", ""]
            for k, v in stats.items():
                lines.append(f"- **{k}**: `{v}`")
            p.write_text("\n".join(lines), encoding="utf-8")
        elif fmt == "csv":
            with p.open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(stats.keys())
                w.writerow([str(v) for v in stats.values()])
        elif fmt == "html":
            parts = [
                "<!DOCTYPE html><html><head><meta charset='utf-8'>",
                "<title>Wordlist stats</title>",
                "<style>",
                "body{background:#0a0a0a;color:#c8c8c8;"
                "font-family:monospace;padding:24px;line-height:1.5;}",
                "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
                "table{width:100%;border-collapse:collapse;margin-top:12px;"
                "font-size:13px;}",
                "th{background:#111;color:#00ff9c;padding:8px;"
                "text-align:left;border:1px solid #222;}",
                "td{padding:6px 8px;border:1px solid #222;"
                "word-break:break-all;}",
                "tr:nth-child(even){background:#0d0d0d;}",
                "</style></head><body>",
                "<h1>📊 Wordlist statistics</h1>",
                f"<p>Generated: "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
                "<table><tr><th>Metric</th><th>Value</th></tr>",
            ]
            for k, v in stats.items():
                parts.append(
                    f"<tr><td>{html_mod.escape(str(k))}</td>"
                    f"<td>{html_mod.escape(str(v))}</td></tr>")
            parts.append("</table></body></html>")
            p.write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ {fmt.upper()}: {p}[/green]")
        return p
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    """Меню Wordlist Tools Pro."""
    table = Table(title="[bold]📚 Wordlist Tools Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Генератор из одного слова (leet + регистр + суффиксы)"),
        ("2", "Генератор из двух слов"),
        ("3", "Генератор из N слов (cartesian)"),
        ("4", "Mask generator (?l?u?d?s)"),
        ("5", "Hashcat rules (best64)"),
        ("6", "Комбинация двух словарей"),
        ("7", "Анализ словаря (stats)"),
        ("8", "Дедупликация"),
        ("9", "Экспорт stats (json/md/html/csv)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        word = Prompt.ask("Базовое слово")
        out = Prompt.ask("Имя файла", default=f"wl_{word}.txt")
        leet = Confirm.ask("Leet-варианты?", default=True)
        years = Confirm.ask("Годы?", default=True)
        symbols = Confirm.ask("Символы?", default=True)
        generate_wordlist(word, out, leet, years, symbols)
    elif c == "2":
        w1 = Prompt.ask("Первое слово")
        w2 = Prompt.ask("Второе слово")
        out = Prompt.ask("Имя файла", default=f"wl_{w1}_{w2}.txt")
        generate_wordlist(w1, out, second_word=w2)
    elif c == "3":
        raw = Prompt.ask("Слова через запятую (a,b,c)")
        words = [w.strip() for w in raw.split(",") if w.strip()]
        sep = Prompt.ask("Разделитель", default="")
        out = Prompt.ask("Имя файла", default="multi.txt")
        generate_multi_word(words, out, separator=sep)
    elif c == "4":
        mask = Prompt.ask("Маска (например ?u?l?l?l?d?d)")
        out = Prompt.ask("Имя файла", default="mask.txt")
        gz = Confirm.ask("Gzip?", default=False)
        mask_generate(mask, out, gzip_out=gz)
    elif c == "5":
        src = Prompt.ask("Исходный словарь (в wordlists/)")
        out = Prompt.ask("Выходной", default="expanded.txt")
        apply_hashcat_rules(Path(src), out)
    elif c == "6":
        a = Prompt.ask("Первый словарь (в wordlists/)")
        b = Prompt.ask("Второй словарь")
        out = Prompt.ask("Куда сохранить", default="combo.txt")
        sep = Prompt.ask("Разделитель", default="")
        combine_two_lists(a, b, out, sep)
    elif c == "7":
        path = Prompt.ask("Путь к словарю")
        stats = analyze_wordlist(Path(path))
        if stats:
            unique = stats.get("unique", 0)
            console.print(f"[cyan]Оценка крэка (100 GH/s): "
                          f"{estimate_crack_time(unique, stats.get('avg_length', 0))}"
                          f"[/cyan]")
            if unique > 100_000_000:
                _save_finding(WLFinding(
                    kind="huge_wordlist",
                    severity="high",
                    title=f"Огромный словарь ({unique:,} строк)",
                    target=path,
                    evidence=str(stats)[:1000],
                    data={"unique": unique},
                ))
    elif c == "8":
        path = Prompt.ask("Путь к словарю")
        gz = Confirm.ask("Gzip?", default=False)
        dedup_wordlist(Path(path), gzip_out=gz)
    elif c == "9":
        path = Prompt.ask("Путь к словарю")
        stats = analyze_wordlist(Path(path))
        if stats:
            fmt = Prompt.ask("Формат",
                             choices=["json", "md", "html", "csv"],
                             default="json")
            export_stats(stats, fmt)


# ===========================================================================
# CLI-обёртки (совместимы)
# ===========================================================================

def cli_generate(word: str, out: str = "") -> None:
    generate_wordlist(word, out or f"wl_{word}.txt")


def cli_combo(a: str, b: str, out: str = "combo.txt") -> None:
    combine_two_lists(a, b, out)


def cli_stats(path: str) -> None:
    analyze_wordlist(Path(path))


def cli_mask(mask: str, out: str = "mask.txt") -> None:
    mask_generate(mask, out)


def cli_rules(path: str, out: str = "expanded.txt") -> None:
    apply_hashcat_rules(Path(path), out)


def cli_dedup(path: str) -> None:
    dedup_wordlist(Path(path))