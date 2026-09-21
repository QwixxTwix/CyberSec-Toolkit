"""
Wordlist Tools: генерация словарей по правилам (hashcat-like).
Правила:
  - leet-подстановки (a→4, e→3, o→0, i→1, s→5, t→7)
  - варианты регистра (lower, Capitalized, UPPER, cAmEl)
  - числовые суффиксы (0..9999, годы 1970..2030)
  - символьные суффиксы/префиксы (!, !!, !!!, @, #, $, ., _, -)
  - комбинации двух слов (word1word2, word1_word2, word1.word2)
Сохраняет результат в wordlists/<name>.txt
"""
import itertools
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from core.config import WORDLIST_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


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


YEARS = [str(y) for y in range(1970, 2031)]
SYMBOLS = ["", "!", "!!", "!!!", "@", "#", "$", ".", "_", "-",
           "123", "321", "1", "12", "007", "69", "777"]


def _leet_variants(word: str) -> set[str]:
    """Все leet-варианты слова (комбинаторно, но с ограничением)."""
    results: set[str] = {word}
    for ch, repl in LEET_MAP:
        new_results = set()
        for w in results:
            if ch in w:
                new_results.add(w.replace(ch, repl))
        results |= new_results
        if len(results) > 5000:
            break
    return results


def _case_variants(word: str) -> set[str]:
    """Все варианты регистра."""
    return {
        word.lower(),
        word.upper(),
        word.capitalize(),
        word[:1].upper() + word[1:] if word else word,
        "".join(c.upper() if i % 2 == 0 else c.lower()
                for i, c in enumerate(word)),
    }


def _all_variants(word: str, leet: bool = True, years: bool = True,
                  symbols: bool = True) -> set[str]:
    """Все варианты одного слова с суффиксами."""
    base_forms: set[str] = set()
    for case_form in _case_variants(word):
        base_forms.add(case_form)
        if leet:
            base_forms |= _leet_variants(case_form)

    results: set[str] = set(base_forms)

    if symbols:
        for form in base_forms:
            for s in SYMBOLS:
                results.add(form + s)
                if s:
                    results.add(form + s + "!")

    if years:
        for form in base_forms:
            for y in YEARS:
                results.add(form + y)
                if symbols:
                    results.add(form + y + "!")
                    results.add(form + "@" + y)

    return results


def generate_wordlist(base_word: str, out_name: str = "custom_wordlist.txt",
                      leet: bool = True, years: bool = True,
                      symbols: bool = True,
                      second_word: str = "") -> None:
    """Сгенерировать словарь на основе 1–2 базовых слов."""
    base_word = base_word.strip()
    if not base_word:
        console.print("[red]Пустое слово.[/red]")
        return

    console.print(f"[cyan]Генерирую варианты для '{base_word}'…[/cyan]")
    variants = _all_variants(base_word, leet=leet, years=years, symbols=symbols)

    if second_word.strip():
        second_word = second_word.strip()
        second_variants = _all_variants(second_word, leet=False, years=False,
                                        symbols=False)
        combined: set[str] = set()
        for a in variants:
            for b in second_variants:
                combined.add(a + b)
                combined.add(a + "_" + b)
                combined.add(a + "." + b)
                combined.add(a + "-" + b)
        variants |= combined

    variants = {v for v in variants if v}
    path = WORDLIST_DIR / out_name
    try:
        with path.open("w", encoding="utf-8") as f:
            for v in sorted(variants):
                f.write(v + "\n")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка записи: {exc}[/red]")
        return

    size_kb = path.stat().st_size / 1024
    console.print(
        f"[green]✓ {len(variants)} вариантов → {path} ({size_kb:.1f} KB)[/green]"
    )
    db.save_scan("wordlist_gen_rules", base_word,
                 {"out": str(path), "count": len(variants)})


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
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return

    console.print(f"[green]✓ {total} строк → {out_path}[/green]")
    db.save_scan("wordlist_combo", out_name,
                 {"a": list_a, "b": list_b, "total": total})


def menu() -> None:
    """Меню Wordlist Tools."""
    table = Table(title="[bold]Wordlist Tools[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Генератор из одного слова (leet + регистр + суффиксы)"),
        ("2", "Генератор из двух слов"),
        ("3", "Комбинация двух словарей"),
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
        a = Prompt.ask("Первый словарь (в wordlists/)")
        b = Prompt.ask("Второй словарь")
        out = Prompt.ask("Куда сохранить", default="combo.txt")
        sep = Prompt.ask("Разделитель", default="")
        combine_two_lists(a, b, out, sep)