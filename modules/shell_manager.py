"""
Shell Manager — приём и управление reverse-shell сессиями.
Author: idqwixxa

Возможности:
    - TCP-листенер (по умолчанию 0.0.0.0:4444)
    - Множество одновременных сессий
    - Отправка команд, чтение вывода (буферизация)
    - Логирование каждой сессии в reports/shell_session_*.log
    - REPL-режим (Metasploit-style: use/background/read/send)

⚠ Только для этичного использования и CTF / лабораторий.
"""
import os
import socket
import threading
import time
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, IntPrompt, Confirm

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 4444


# ===========================================================================
# Сессия
# ===========================================================================

class ShellSession:
    """Одно подключение reverse-shell."""

    def __init__(self, sid: int, addr, sock: socket.socket,
                 log_dir: Path) -> None:
        self.sid = sid
        self.addr = addr
        self.sock = sock
        self.connected_at = datetime.now()
        self.last_activity = datetime.now()
        self._buffer = bytearray()
        self.commands_log: list[tuple[datetime, str]] = []
        self.alive = True
        self._lock = threading.Lock()
        self._stop = threading.Event()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_path = log_dir / f"shell_session_{sid}_{ts}.log"
        self._log_handle = None

    # ------------------------------------------------------------------
    # Reader
    # ------------------------------------------------------------------

    def start_reader(self) -> None:
        try:
            self._log_handle = self.log_path.open("ab", buffering=0)
        except Exception:  # noqa: BLE001
            self._log_handle = None
        t = threading.Thread(target=self._reader_loop, daemon=True,
                             name=f"shell-{self.sid}-reader")
        t.start()

    def _reader_loop(self) -> None:
        try:
            self.sock.settimeout(1.0)
        except Exception:  # noqa: BLE001
            pass
        while not self._stop.is_set():
            try:
                data = self.sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            with self._lock:
                self._buffer.extend(data)
                self.last_activity = datetime.now()
            if self._log_handle:
                try:
                    self._log_handle.write(data)
                    self._log_handle.write(b"\n")
                except Exception:  # noqa: BLE001
                    pass
        self.alive = False

    # ------------------------------------------------------------------
    # Отправка / чтение
    # ------------------------------------------------------------------

    def send(self, cmd: str) -> None:
        with self._lock:
            if not self.alive:
                raise RuntimeError("session dead")
            try:
                self.sock.sendall((cmd + "\n").encode("utf-8",
                                                      errors="replace"))
            except OSError as exc:
                self.alive = False
                raise RuntimeError(f"send failed: {exc}")
            self.commands_log.append((datetime.now(), cmd))
            self.last_activity = datetime.now()

    def read_output(self) -> str:
        with self._lock:
            data = bytes(self._buffer)
            self._buffer.clear()
        return data.decode("utf-8", errors="replace")

    def peek_output(self) -> str:
        with self._lock:
            return bytes(self._buffer).decode("utf-8", errors="replace")

    def close(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except Exception:  # noqa: BLE001
            pass
        if self._log_handle:
            try:
                self._log_handle.close()
            except Exception:  # noqa: BLE001
                pass
        self.alive = False


# ===========================================================================
# Сервер
# ===========================================================================

class ShellServer:
    """TCP-листенер с множеством сессий."""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 log_dir: Path | None = None) -> None:
        self.host = host
        self.port = port
        self.log_dir = log_dir or REPORT_DIR
        self.sessions: dict[int, ShellSession] = {}
        self._next_id = 1
        self._stop = threading.Event()
        self._server_sock: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(16)
        self._stop.clear()
        self._accept_thread = threading.Thread(
            target=self._accept_loop, daemon=True, name="shell-accept",
        )
        self._accept_thread.start()
        console.print(
            f"[green]✓ Shell listener: {self.host}:{self.port}[/green]"
        )
        console.print(f"[dim]Логи: {self.log_dir}[/dim]")

    def _accept_loop(self) -> None:
        try:
            self._server_sock.settimeout(1.0)
        except Exception:  # noqa: BLE001
            return
        while not self._stop.is_set():
            try:
                client, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            with self._lock:
                sid = self._next_id
                self._next_id += 1

            sess = ShellSession(sid, addr, client, self.log_dir)
            sess.start_reader()
            with self._lock:
                self.sessions[sid] = sess

            console.print(
                f"\n[bold green]● Новый shell #{sid} от "
                f"{addr[0]}:{addr[1]}[/bold green]"
            )
            try:
                db.save_scan("shell", f"{addr[0]}:{addr[1]}",
                             {"session_id": sid})
            except Exception:  # noqa: BLE001
                pass

    def stop(self) -> None:
        self._stop.set()
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:  # noqa: BLE001
                pass
        with self._lock:
            for sess in self.sessions.values():
                sess.close()

    # ------------------------------------------------------------------
    # Управление
    # ------------------------------------------------------------------

    def list_sessions(self) -> list[ShellSession]:
        with self._lock:
            return list(self.sessions.values())

    def get(self, sid: int) -> ShellSession | None:
        with self._lock:
            return self.sessions.get(sid)

    def remove(self, sid: int) -> bool:
        with self._lock:
            sess = self.sessions.pop(sid, None)
        if sess:
            sess.close()
            return True
        return False

    @property
    def running(self) -> bool:
        return (self._accept_thread is not None
                and self._accept_thread.is_alive())


# ===========================================================================
# Глобальный экземпляр (для TUI)
# ===========================================================================

_server: ShellServer | None = None


def get_server() -> ShellServer | None:
    return _server


def quick_start(host: str = DEFAULT_HOST,
                port: int = DEFAULT_PORT) -> bool:
    """Запустить листенер в фоне (для TUI)."""
    global _server
    if _server and _server.running:
        console.print("[yellow]Shell listener уже запущен.[/yellow]")
        return True
    try:
        srv = ShellServer(host=host, port=port)
        srv.start()
        _server = srv
        return True
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка запуска listener: {exc}[/red]")
        return False


def quick_stop() -> None:
    global _server
    if not _server:
        console.print("[yellow]Listener не запущен.[/yellow]")
        return
    _server.stop()
    _server = None
    console.print("[yellow]Shell listener остановлен.[/yellow]")


def quick_list() -> None:
    """Список сессий (для CLI/TUI)."""
    if not _server:
        console.print("[yellow]Listener не запущен.[/yellow]")
        return
    sessions = _server.list_sessions()
    if not sessions:
        console.print("[yellow]Активных сессий нет.[/yellow]")
        return
    _print_sessions_table(sessions)


def quick_status() -> None:
    """Статус."""
    running = _server is not None and _server.running
    table = Table(title="🐚 Shell Manager")
    table.add_column("Параметр", style="cyan")
    table.add_column("Значение", style="green")
    table.add_row("Запущен", "✓" if running else "—")
    if running and _server:
        table.add_row("Адрес", f"{_server.host}:{_server.port}")
        table.add_row("Сессий", str(len(_server.sessions)))
        table.add_row("Логи", str(_server.log_dir))
    console.print(table)


# ===========================================================================
# Таблица сессий
# ===========================================================================

def _print_sessions_table(sessions: list[ShellSession]) -> None:
    table = Table(title=f"🐚 Сессии ({len(sessions)})")
    table.add_column("ID", style="cyan", width=5)
    table.add_column("Удалённый адрес", style="green")
    table.add_column("Подключён", style="magenta")
    table.add_column("Uptime", style="white")
    table.add_column("Активность", style="yellow")
    table.add_column("Статус", style="red")
    now = datetime.now()
    for s in sessions:
        uptime = str(now - s.connected_at).split(".")[0]
        idle = str(now - s.last_activity).split(".")[0]
        status = "🟢 alive" if s.alive else "⚪ closed"
        table.add_row(
            f"#{s.sid}",
            f"{s.addr[0]}:{s.addr[1]}",
            s.connected_at.strftime("%H:%M:%S"),
            uptime,
            idle,
            status,
        )
    console.print(table)


# ===========================================================================
# REPL (Metasploit-style)
# ===========================================================================

HELP_TEXT = """
[bold cyan]🐚 Команды Shell Manager:[/bold cyan]

  [green]sessions[/green]             — список сессий
  [green]use <id>[/green]             — переключиться на сессию
  [green]read <id>[/green]            — прочитать накопленный вывод
  [green]peek <id>[/green]            — посмотреть без очистки буфера
  [green]send <id> <команда>[/green]  — отправить команду
  [green]kill <id>[/green]            — закрыть сессию
  [green]kill-all[/green]             — закрыть все сессии
  [green]logs <id>[/green]            — путь к логу сессии
  [green]info <id>[/green]            — детальная информация
  [green]clear[/green]                — очистить экран
  [green]help[/green]                 — эта справка
  [green]exit[/green] / Ctrl+C        — выйти (сессии закроются)

[bold cyan]Внутри сессии (после [green]use <id>[/green]):[/bold cyan]
  любой ввод → отправляется как команда
  [green]read[/green]                 — читать вывод
  [green]peek[/green]                 — читать без очистки
  [green]info[/green]                 — информация
  [green]background[/green] / Ctrl+C  — вернуться в главное меню
"""


def _print_banner() -> None:
    console.print("[bold cyan]╔══ CyberSec Shell Manager ══╗[/bold cyan]")
    console.print("[magenta]by idqwixxa[/magenta]")
    console.print("[yellow]⚠ Только для этичного использования и CTF / лабораторий[/yellow]")
    console.print("[dim]Команды: help[/dim]\n")


def repl(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """Интерактивный REPL с листенером."""
    global _server

    srv = ShellServer(host=host, port=port)
    try:
        srv.start()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Не могу запустить листенер: {exc}[/red]")
        return
    _server = srv

    _print_banner()
    current_sid: int | None = None

    def _sessions_list() -> None:
        sessions = srv.list_sessions()
        if not sessions:
            console.print("[yellow]Активных сессий нет.[/yellow]")
            return
        _print_sessions_table(sessions)

    def _read_output(sid: int, peek: bool = False) -> None:
        s = srv.get(sid)
        if not s:
            console.print(f"[red]#{sid} не найдена.[/red]")
            return
        text = s.peek_output() if peek else s.read_output()
        if not text:
            console.print("[dim](пусто)[/dim]")
        else:
            console.print(text, end="" if text.endswith("\n") else "\n")
            if not text.endswith("\n"):
                console.print()

    def _kill(sid: int) -> None:
        if srv.remove(sid):
            console.print(f"[green]✓ Сессия #{sid} закрыта.[/green]")
        else:
            console.print(f"[red]#{sid} не найдена.[/red]")

    def _info(sid: int) -> None:
        s = srv.get(sid)
        if not s:
            console.print(f"[red]#{sid} не найдена.[/red]")
            return
        table = Table(title=f"🐚 Session #{sid}")
        table.add_column("Поле", style="cyan")
        table.add_column("Значение", style="green")
        table.add_row("ID", str(s.sid))
        table.add_row("Addr", f"{s.addr[0]}:{s.addr[1]}")
        table.add_row("Connected", s.connected_at.strftime("%Y-%m-%d %H:%M:%S"))
        table.add_row("Last activity",
                      s.last_activity.strftime("%Y-%m-%d %H:%M:%S"))
        table.add_row("Alive", "✓" if s.alive else "—")
        table.add_row("Commands sent", str(len(s.commands_log)))
        table.add_row("Log file", str(s.log_path))
        console.print(table)
        if s.commands_log:
            console.print("\n[cyan]Последние команды:[/cyan]")
            for ts, cmd in s.commands_log[-10:]:
                console.print(f"  [dim]{ts.strftime('%H:%M:%S')}[/dim] "
                              f"[green]{cmd}[/green]")

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------
    try:
        while True:
            try:
                if current_sid is not None:
                    prompt = f"[bold magenta]session {current_sid}[/bold magenta]> "
                else:
                    prompt = "[bold cyan]shell[/bold cyan]> "
                line = input(prompt if False else "").strip() \
                    if False else input(
                        f"session {current_sid}> "
                        if current_sid is not None else "shell> "
                    ).strip()
            except (EOFError, KeyboardInterrupt):
                console.print()
                if current_sid is not None:
                    current_sid = None
                    console.print("[dim]Возврат в главное меню.[/dim]")
                    continue
                break

            if not line:
                continue

            # --- Внутри сессии ---
            if current_sid is not None:
                low = line.lower()
                if low in ("background", "bg", "back", "exit-session"):
                    current_sid = None
                    console.print("[dim]Возврат в главное меню.[/dim]")
                    continue
                if low == "read":
                    _read_output(current_sid)
                    continue
                if low == "peek":
                    _read_output(current_sid, peek=True)
                    continue
                if low == "info":
                    _info(current_sid)
                    continue
                if low == "help":
                    console.print(HELP_TEXT)
                    continue
                # Всё остальное — команда для шелла
                s = srv.get(current_sid)
                if not s:
                    console.print(f"[red]#{current_sid} потеряна.[/red]")
                    current_sid = None
                    continue
                try:
                    s.send(line)
                    console.print(f"[dim]→ sent[/dim]")
                    # дать немного времени на вывод
                    time.sleep(0.5)
                    _read_output(current_sid)
                except Exception as exc:  # noqa: BLE001
                    console.print(f"[red]Ошибка: {exc}[/red]")
                continue

            # --- Главное меню ---
            parts = line.split(None, 1)
            cmd = parts[0].lower()
            arg = parts[1].strip() if len(parts) > 1 else ""

            if cmd in ("exit", "quit", "q"):
                break
            if cmd == "help" or cmd == "?":
                console.print(HELP_TEXT)
                continue
            if cmd == "sessions" or cmd == "list":
                _sessions_list()
                continue
            if cmd == "use":
                if not arg.isdigit():
                    console.print("[red]use <id>[/red]")
                    continue
                sid = int(arg)
                s = srv.get(sid)
                if not s:
                    console.print(f"[red]#{sid} не найдена.[/red]")
                    continue
                current_sid = sid
                console.print(f"[green]→ session {sid} "
                              f"({s.addr[0]}:{s.addr[1]})[/green]")
                continue
            if cmd == "read":
                if not arg.isdigit():
                    console.print("[red]read <id>[/red]")
                    continue
                _read_output(int(arg))
                continue
            if cmd == "peek":
                if not arg.isdigit():
                    console.print("[red]peek <id>[/red]")
                    continue
                _read_output(int(arg), peek=True)
                continue
            if cmd == "send":
                sp = arg.split(None, 1)
                if len(sp) < 2 or not sp[0].isdigit():
                    console.print("[red]send <id> <команда>[/red]")
                    continue
                sid = int(sp[0])
                s = srv.get(sid)
                if not s:
                    console.print(f"[red]#{sid} не найдена.[/red]")
                    continue
                try:
                    s.send(sp[1])
                    console.print("[dim]→ sent[/dim]")
                    time.sleep(0.5)
                    _read_output(sid)
                except Exception as exc:  # noqa: BLE001
                    console.print(f"[red]Ошибка: {exc}[/red]")
                continue
            if cmd == "kill":
                if not arg.isdigit():
                    console.print("[red]kill <id>[/red]")
                    continue
                _kill(int(arg))
                continue
            if cmd == "kill-all":
                if not Confirm.ask("Закрыть все сессии?", default=False):
                    continue
                for s in srv.list_sessions():
                    srv.remove(s.sid)
                console.print("[green]✓ Все сессии закрыты.[/green]")
                continue
            if cmd == "logs":
                if not arg.isdigit():
                    console.print("[red]logs <id>[/red]")
                    continue
                s = srv.get(int(arg))
                if s:
                    console.print(f"[cyan]{s.log_path}[/cyan]")
                else:
                    console.print(f"[red]#{arg} не найдена.[/red]")
                continue
            if cmd == "info":
                if not arg.isdigit():
                    console.print("[red]info <id>[/red]")
                    continue
                _info(int(arg))
                continue
            if cmd == "clear":
                os.system("cls" if os.name == "nt" else "clear")
                continue

            console.print(f"[red]Неизвестная команда: {cmd}[/red] "
                          f"(help для списка)")
    finally:
        srv.stop()
        _server = None
        console.print("[yellow]Листенер остановлен. Сессии закрыты.[/yellow]")


# ===========================================================================
# CLI-функции
# ===========================================================================

def cli_status() -> None:
    quick_status()


def cli_list() -> None:
    quick_list()


def cli_start(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """Запустить listener в фоне (без REPL)."""
    quick_start(host=host, port=port)
    console.print("[cyan]Листенер работает в фоне. "
                  "Для интерактива используй 'python main.py shell'.[/cyan]")
    console.print("[dim]⚠ Этот процесс завершится и listener умрёт. "
                  "Используй 'shell' для REPL.[/dim]")


def cli_stop() -> None:
    quick_stop()


# ===========================================================================
# Меню (CLI)
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🐚 Shell Manager[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "REPL (запустить listener + интерактив)"),
        ("2", "Статус listener"),
        ("3", "Список сессий (в текущем процессе)"),
        ("4", "Остановить listener"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для этичного использования и CTF.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        host = Prompt.ask("Host", default=DEFAULT_HOST)
        port = IntPrompt.ask("Port", default=DEFAULT_PORT)
        repl(host=host, port=port)
    elif c == "2":
        cli_status()
    elif c == "3":
        cli_list()
    elif c == "4":
        cli_stop()