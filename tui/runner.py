"""
Обёртка запуска модулей с перехватом stdout/stderr.
Модули в проекте пишут через rich.Console(), который выводит в stdout.
Мы перенаправляем sys.stdout/sys.stderr в буфер и отдаём его TUI.
"""
import sys
import io
import contextlib
import threading
from typing import Callable


class _TeeBuffer(io.TextIOBase):
    """Записывает всё в буфер и параллельно вызывает callback по строкам."""

    def __init__(self, on_line: Callable[[str], None]) -> None:
        self._on_line = on_line
        self._buf = ""

    def write(self, data: str) -> int:
        self._buf += data
        # Разбиваем по строкам, но не теряем последнюю незавершённую
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            try:
                self._on_line(line)
            except Exception:  # noqa: BLE001
                pass
        return len(data)

    def flush(self) -> None:
        if self._buf:
            try:
                self._on_line(self._buf)
            except Exception:  # noqa: BLE001
                pass
            self._buf = ""


def run_module(func: Callable, *args, on_line: Callable[[str], None], **kwargs) -> None:
    """
    Запустить функцию модуля, перенаправляя stdout/stderr в on_line.
    Модули используют rich.Prompt.ask() / input() — это будет работать только
    в интерактивном режиме. В TUI мы вызываем функции с уже переданными
    аргументами (CLI-стиль), чтобы избежать блокировки на input().
    """
    tee = _TeeBuffer(on_line)
    with contextlib.redirect_stdout(tee), contextlib.redirect_stderr(tee):
        try:
            func(*args, **kwargs)
        finally:
            tee.flush()


def run_module_async(func: Callable, *args,
                     on_line: Callable[[str], None], **kwargs) -> threading.Thread:
    """То же, но в отдельном потоке. Возвращает объект Thread."""
    def _target() -> None:
        run_module(func, *args, on_line=on_line, **kwargs)

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    return t