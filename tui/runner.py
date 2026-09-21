"""
Обёртка запуска модулей с перехватом stdout/stderr.
Модули в проекте пишут через rich.Console(), который выводит в stdout.
Мы перенаправляем sys.stdout/sys.stderr в буфер и отдаём его TUI.

ВАЖНО: корректно обрабатываем:
    - \\n (newline) — новая строка
    - \\r (carriage return) — progress bar overwrite (drop)
    - \\r\\n (CRLF) — как одна новая строка
    - ANSI escape codes — удаляем
    - Progress-bar line noise — пропускаем
"""
import sys
import io
import re
import contextlib
import threading
from typing import Callable


# ANSI escape codes: цвета, движение курсора, очистка строки
_ANSI_RE = re.compile(
    r"\x1b\[[0-9;?]*[A-Za-z]"      # CSI ... letter
    r"|\x1b\][^\x07]*(?:\x07|\x1b\\)"  # OSC ... BEL|ST
    r"|\x1b[()][AB012]"            # charset select
    r"|\x1b[=>]"                   # keypad modes
)

# Символы, из которых состоят progress-бары Rich / tqdm
_BAR_CHARS = set("━─═█▌▐░▒▓▁▂▃▄▅▆▇▉▊▋▍▎▏")

# Regex: длинная последовательность bar-символов → progress bar
_PROGRESS_BAR_RE = re.compile(r"[━─═█▌▐░▒▓▁▂▃▄▅▆▇▉▊▋▍▎▏]{3,}")


def _strip_ansi(text: str) -> str:
    """Удалить ANSI escape sequences."""
    return _ANSI_RE.sub("", text)


def _looks_like_progress(line: str) -> bool:
    """True если строка похожа на progress-bar (Rich Progress/tqdm)."""
    # Много bar-символов подряд
    if _PROGRESS_BAR_RE.search(line):
        return True
    # Паттерн "текст ━━━ N/M" — окончание прогресса
    if re.search(r"\d+\s*/\s*\d+\s*$", line) and \
       any(c in line for c in _BAR_CHARS):
        return True
    # Паттерн "text ... 57%|███"
    if re.search(r"\d+%\|", line):
        return True
    # Паттерн "[####------]"
    if re.search(r"\[#{3,}[-#]{3,}\]", line):
        return True
    # Слишком много bar-символов относительно длины
    if line:
        bar_count = sum(1 for c in line if c in _BAR_CHARS)
        if bar_count >= 6 and bar_count / max(len(line), 1) > 0.25:
            return True
    return False


class _TeeBuffer(io.TextIOBase):
    """Записывает всё в буфер и вызывает callback по строкам.

    Обрабатывает \\r (progress overwrite) и \\r\\n (CRLF).
    """

    def __init__(self, on_line: Callable[[str], None]) -> None:
        self._on_line = on_line
        self._buf = ""

    def write(self, data: str) -> int:
        if not isinstance(data, str):
            data = str(data)
        self._buf += data
        self._process()
        return len(data)

    def _process(self) -> None:
        while self._buf:
            idx_n = self._buf.find("\n")
            idx_r = self._buf.find("\r")
            idxs = [x for x in (idx_n, idx_r) if x >= 0]
            if not idxs:
                break
            idx = min(idxs)

            # CRLF → treat as one newline
            if self._buf[idx] == "\r" and \
               idx + 1 < len(self._buf) and self._buf[idx + 1] == "\n":
                chunk = self._buf[:idx]
                self._buf = self._buf[idx + 2:]
                self._emit(chunk)
                continue

            chunk = self._buf[:idx]
            sep = self._buf[idx]
            self._buf = self._buf[idx + 1:]

            if sep == "\r":
                # Pure CR — progress bar overwrite. Пропускаем chunk.
                continue

            # sep == "\n" — конец строки
            self._emit(chunk)

    def _emit(self, line: str) -> None:
        clean = _strip_ansi(line).rstrip()
        if not clean:
            return
        # Пропускаем прогресс-бары
        if _looks_like_progress(clean):
            return
        # Пропускаем строки с управляющими символами
        clean = "".join(c for c in clean
                        if c == "\t" or ord(c) >= 32 or ord(c) == 0)
        if not clean:
            return
        try:
            self._on_line(clean)
        except Exception:  # noqa: BLE001
            pass

    def flush(self) -> None:
        # Сбрасываем остаток буфера как одну строку
        if self._buf:
            remainder = self._buf
            self._buf = ""
            # Разбиваем на строки по \r/\n для надёжности
            for line in re.split(r"[\r\n]+", remainder):
                if line:
                    self._emit(line)


def run_module(func: Callable, *args,
               on_line: Callable[[str], None], **kwargs) -> None:
    """
    Запустить функцию модуля, перенаправляя stdout/stderr в on_line.
    Модули используют rich.Prompt.ask() / input() — это будет работать
    только в интерактивном режиме. В TUI мы вызываем функции с уже
    переданными аргументами (CLI-стиль), чтобы избежать блокировки на
    input().
    """
    tee = _TeeBuffer(on_line)
    with contextlib.redirect_stdout(tee), contextlib.redirect_stderr(tee):
        try:
            func(*args, **kwargs)
        finally:
            tee.flush()


def run_module_async(func: Callable, *args,
                     on_line: Callable[[str], None],
                     **kwargs) -> threading.Thread:
    """То же, но в отдельном потоке. Возвращает объект Thread."""
    def _target() -> None:
        run_module(func, *args, on_line=on_line, **kwargs)

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    return t