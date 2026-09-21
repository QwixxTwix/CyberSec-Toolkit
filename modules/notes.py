"""
Notes & Findings — заметки и находки CyberSec Toolkit.
Author: idqwixxa

Две сущности:
    note    — обычная заметка (без severity/status)
    finding — находка (severity + status + target обязательны)

Таблица notes в cyber_toolkit.db:
    id, kind, title, target, severity, status,
    tags (json), body, created_at, updated_at
"""
import json
import sqlite3
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

SEVERITIES = ["info", "low", "medium", "high", "critical"]
STATUSES = ["open", "in-progress", "resolved", "wontfix", "dup", "invalid"]
KINDS = ["note", "finding"]


# ---------------------------------------------------------------------------
# Схема (создаётся при импорте)
# ---------------------------------------------------------------------------

def _init_schema() -> None:
    cur = db.conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL DEFAULT 'note',
            title TEXT NOT NULL,
            target TEXT DEFAULT '',
            severity TEXT DEFAULT '',
            status TEXT DEFAULT '',
            tags TEXT DEFAULT '[]',
            body TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_notes_target ON notes(target);
        CREATE INDEX IF NOT EXISTS idx_notes_kind   ON notes(kind);
        CREATE INDEX IF NOT EXISTS idx_notes_status ON notes(status);
        """
    )
    db.conn.commit()


try:
    _init_schema()
except Exception as exc:  # noqa: BLE001
    log.exception("Не удалось создать таблицу notes: %s", exc)


# ---------------------------------------------------------------------------
# Базовые операции
# ---------------------------------------------------------------------------

def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    try:
        d["tags"] = json.loads(d.get("tags") or "[]")
    except Exception:  # noqa: BLE001
        d["tags"] = []
    return d


def add_note(kind: str, title: str, body: str = "",
             target: str = "", severity: str = "", status: str = "",
             tags: list[str] | None = None) -> int:
    """Добавить заметку/находку. Возвращает id (или -1)."""
    kind = (kind or "note").lower()
    if kind not in KINDS:
        kind = "note"
    title = (title or "").strip()
    if not title:
        raise ValueError("Пустой заголовок")

    if kind == "finding":
        if not target:
            raise ValueError("Для находки обязателен target")
        if severity and severity not in SEVERITIES:
            raise ValueError(f"Severity: {', '.join(SEVERITIES)}")
        if status and status not in STATUSES:
            raise ValueError(f"Status: {', '.join(STATUSES)}")

    tags_json = json.dumps(sorted(set(tags or [])), ensure_ascii=False)
    now = datetime.utcnow().isoformat()

    try:
        cur = db.conn.cursor()
        cur.execute(
            "INSERT INTO notes(kind, title, target, severity, status, tags, "
            "body, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (kind, title, target, severity, status,
             tags_json, body, now, now),
        )
        db.conn.commit()
        nid = cur.lastrowid
        log.info("Note добавлена: #%s (%s)", nid, title)
        db.save_scan("notes", f"{kind}:{title}", {"id": nid})
        return nid
    except Exception as exc:  # noqa: BLE001
        log.exception("add_note: %s", exc)
        return -1


def list_notes(kind: str | None = None, target: str | None = None,
               tag: str | None = None, status: str | None = None,
               severity: str | None = None,
               limit: int = 200) -> list[dict]:
    """Список заметок с фильтрами."""
    sql = "SELECT * FROM notes WHERE 1=1"
    args: list = []
    if kind:
        sql += " AND kind = ?"; args.append(kind)
    if target:
        sql += " AND target LIKE ?"; args.append(f"%{target}%")
    if status:
        sql += " AND status = ?"; args.append(status)
    if severity:
        sql += " AND severity = ?"; args.append(severity)
    if tag:
        # грубый поиск по json-строке
        sql += " AND tags LIKE ?"; args.append(f'%"{tag}"%')
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)

    try:
        cur = db.conn.cursor()
        cur.execute(sql, args)
        return [_row_to_dict(r) for r in cur.fetchall()]
    except Exception as exc:  # noqa: BLE001
        log.exception("list_notes: %s", exc)
        return []


def get_note(nid: int) -> dict | None:
    try:
        cur = db.conn.cursor()
        cur.execute("SELECT * FROM notes WHERE id = ?", (nid,))
        row = cur.fetchone()
        return _row_to_dict(row) if row else None
    except Exception as exc:  # noqa: BLE001
        log.exception("get_note: %s", exc)
        return None


def update_note(nid: int, **kwargs) -> bool:
    allowed = ("title", "target", "severity", "status", "body", "kind")
    sets: list[str] = []
    args: list = []
    for k, v in kwargs.items():
        if k in allowed and v is not None:
            sets.append(f"{k} = ?"); args.append(v)
    if "tags" in kwargs and kwargs["tags"] is not None:
        sets.append("tags = ?")
        args.append(json.dumps(sorted(set(kwargs["tags"])),
                               ensure_ascii=False))
    if not sets:
        return False
    sets.append("updated_at = ?")
    args.append(datetime.utcnow().isoformat())
    args.append(nid)
    try:
        cur = db.conn.cursor()
        cur.execute(f"UPDATE notes SET {', '.join(sets)} WHERE id = ?", args)
        db.conn.commit()
        return cur.rowcount > 0
    except Exception as exc:  # noqa: BLE001
        log.exception("update_note: %s", exc)
        return False


def delete_note(nid: int) -> bool:
    try:
        cur = db.conn.cursor()
        cur.execute("DELETE FROM notes WHERE id = ?", (nid,))
        db.conn.commit()
        return cur.rowcount > 0
    except Exception as exc:  # noqa: BLE001
        log.exception("delete_note: %s", exc)
        return False


def search_notes(query: str) -> list[dict]:
    q = f"%{query}%"
    try:
        cur = db.conn.cursor()
        cur.execute(
            "SELECT * FROM notes WHERE "
            "title LIKE ? OR body LIKE ? OR target LIKE ? OR tags LIKE ? "
            "ORDER BY id DESC LIMIT 100",
            (q, q, q, q),
        )
        return [_row_to_dict(r) for r in cur.fetchall()]
    except Exception as exc:  # noqa: BLE001
        log.exception("search_notes: %s", exc)
        return []


def stats() -> dict:
    """Общая статистика."""
    try:
        cur = db.conn.cursor()
        cur.execute("SELECT COUNT(*) as c FROM notes")
        total = cur.fetchone()["c"]
        cur.execute("SELECT kind, COUNT(*) as c FROM notes GROUP BY kind")
        by_kind = {r["kind"]: r["c"] for r in cur.fetchall()}
        cur.execute("SELECT severity, COUNT(*) as c FROM notes "
                    "WHERE severity != '' GROUP BY severity")
        by_sev = {r["severity"]: r["c"] for r in cur.fetchall()}
        cur.execute("SELECT status, COUNT(*) as c FROM notes "
                    "WHERE status != '' GROUP BY status")
        by_status = {r["status"]: r["c"] for r in cur.fetchall()}
        return {
            "total": total,
            "by_kind": by_kind,
            "by_severity": by_sev,
            "by_status": by_status,
        }
    except Exception as exc:  # noqa: BLE001
        log.exception("stats: %s", exc)
        return {"total": 0, "by_kind": {}, "by_severity": {}, "by_status": {}}


# ---------------------------------------------------------------------------
# Экспорт в Markdown
# ---------------------------------------------------------------------------

def export_markdown(target: str | None = None,
                    out_path: str | None = None) -> Path | None:
    """
    Экспорт заметок/находок в Markdown.
    target — фильтр по цели (если None — экспорт всего).
    """
    notes = list_notes(target=target, limit=1000)
    if not notes:
        console.print("[yellow]Нет заметок для экспорта.[/yellow]")
        return None

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not out_path:
        safe = (target or "all").replace("/", "_").replace(":", "_")[:40]
        out_path = str(REPORT_DIR / f"findings_{safe}_{ts}.md")

    findings = [n for n in notes if n["kind"] == "finding"]
    plain = [n for n in notes if n["kind"] != "finding"]

    lines = [
        "# 🛡️ Findings & Notes",
        "",
        f"**Сгенерировано:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Фильтр по цели:** `{target or 'все цели'}`  ",
        f"**Всего записей:** {len(notes)}  ",
        f"**Находок:** {len(findings)}  •  **Заметок:** {len(plain)}",
        "",
        "---",
        "",
    ]

    if findings:
        # Сортируем по severity
        sev_order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
        findings_sorted = sorted(
            findings,
            key=lambda x: sev_order.get(x.get("severity") or "info", 99),
        )
        lines.append("## 🔴 Findings")
        lines.append("")
        for f in findings_sorted:
            lines.append(_finding_to_md(f))
            lines.append("")

    if plain:
        lines.append("## 📝 Notes")
        lines.append("")
        for n in plain:
            lines.append(_note_to_md(n))
            lines.append("")

    # Сводка по severity
    counts = {}
    for f in findings:
        counts[f.get("severity") or "info"] = \
            counts.get(f.get("severity") or "info", 0) + 1
    if counts:
        lines.append("---")
        lines.append("")
        lines.append("## 📊 Сводка по severity")
        lines.append("")
        lines.append("| Severity | Кол-во |")
        lines.append("|----------|--------|")
        for s in SEVERITIES:
            if s in counts:
                lines.append(f"| {s.upper()} | {counts[s]} |")
        lines.append("")

    path = Path(out_path)
    try:
        path.write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green]✓ Экспортировано: {path}[/green]")
        db.save_scan("notes_export", target or "all",
                     {"path": str(path), "count": len(notes)})
        return path
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка записи: {exc}[/red]")
        return None


def _finding_to_md(f: dict) -> str:
    sev = (f.get("severity") or "info").upper()
    icon = {"INFO": "ℹ️", "LOW": "🟢", "MEDIUM": "🟡",
            "HIGH": "🟠", "CRITICAL": "🔴"}.get(sev, "•")
    status = f.get("status") or "open"
    tags = ", ".join(f"`{t}`" for t in f.get("tags", []))
    return (
        f"### {icon} #{f['id']} — {f['title']}\n\n"
        f"- **Severity:** {sev}\n"
        f"- **Status:** {status}\n"
        f"- **Target:** `{f.get('target', '—')}`\n"
        f"- **Tags:** {tags or '—'}\n"
        f"- **Created:** {f.get('created_at', '—')}\n"
        f"- **Updated:** {f.get('updated_at', '—')}\n\n"
        f"**Описание:**\n\n{f.get('body', '') or '_пусто_'}\n"
    )


def _note_to_md(n: dict) -> str:
    tags = ", ".join(f"`{t}`" for t in n.get("tags", []))
    target = f"\n- **Target:** `{n['target']}`" if n.get("target") else ""
    return (
        f"### 📝 #{n['id']} — {n['title']}\n\n"
        f"- **Tags:** {tags or '—'}"
        f"{target}\n"
        f"- **Created:** {n.get('created_at', '—')}\n\n"
        f"{n.get('body', '') or '_пусто_'}\n"
    )


# ---------------------------------------------------------------------------
# Красивый вывод одной записи
# ---------------------------------------------------------------------------

def _print_note(n: dict) -> None:
    kind = n.get("kind", "note")
    icon = "🔴" if kind == "finding" else "📝"
    header = f"{icon} #{n['id']} — {n['title']}"

    lines = [
        f"[cyan]kind:[/cyan]     {kind}",
        f"[cyan]target:[/cyan]   {n.get('target') or '—'}",
        f"[cyan]severity:[/cyan] {n.get('severity') or '—'}",
        f"[cyan]status:[/cyan]   {n.get('status') or '—'}",
        f"[cyan]tags:[/cyan]     {', '.join(n.get('tags', [])) or '—'}",
        f"[cyan]created:[/cyan]  {n.get('created_at')}",
        f"[cyan]updated:[/cyan]  {n.get('updated_at')}",
        "",
        n.get("body") or "[dim](пусто)[/dim]",
    ]
    console.print(Panel("\n".join(lines), title=header,
                        border_style="cyan"))


def _print_table(notes: list[dict], title: str = "Записи") -> None:
    if not notes:
        console.print("[yellow]Ничего нет.[/yellow]")
        return
    table = Table(title=title)
    table.add_column("ID", style="cyan", width=5)
    table.add_column("Kind", style="yellow", width=8)
    table.add_column("Title", style="white", max_width=40)
    table.add_column("Target", style="green", max_width=30)
    table.add_column("Sev", style="red", width=9)
    table.add_column("Status", style="magenta", width=12)
    table.add_column("Tags", style="dim")
    for n in notes:
        table.add_row(
            str(n["id"]),
            n.get("kind", ""),
            n.get("title", "")[:40],
            (n.get("target") or "—")[:30],
            n.get("severity") or "—",
            n.get("status") or "—",
            ",".join(n.get("tags", []))[:30] or "—",
        )
    console.print(table)


# ---------------------------------------------------------------------------
# CLI-функции (для main.py)
# ---------------------------------------------------------------------------

def cli_stats() -> None:
    s = stats()
    table = Table(title="📊 Notes & Findings — статистика")
    table.add_column("Метрика", style="cyan")
    table.add_column("Значение", style="green")
    table.add_row("Всего записей", str(s["total"]))
    for k, v in s["by_kind"].items():
        table.add_row(f"  {k}", str(v))
    for k, v in s["by_severity"].items():
        table.add_row(f"  severity: {k}", str(v))
    for k, v in s["by_status"].items():
        table.add_row(f"  status: {k}", str(v))
    console.print(table)


def cli_add(kind: str = "note", title: str | None = None,
            body: str | None = None, target: str | None = None,
            severity: str | None = None, status: str | None = None,
            tags: list[str] | None = None) -> None:
    kind = (kind or "note").lower()
    if kind not in KINDS:
        kind = "note"

    if not title:
        title = Prompt.ask("Заголовок").strip()
    if not title:
        console.print("[red]Пустой заголовок.[/red]")
        return

    if kind == "finding":
        if not target:
            target = Prompt.ask("Target (URL/IP/домен)").strip()
        if not severity:
            severity = Prompt.ask("Severity",
                                  choices=SEVERITIES, default="info")
        if not status:
            status = Prompt.ask("Status",
                                choices=STATUSES, default="open")
    else:
        if target is None:
            target = Prompt.ask("Target (необязательно)",
                                default="").strip()

    if body is None:
        console.print("[cyan]Введи описание. Пустая строка = конец.[/cyan]")
        body_lines = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if line == "" and body_lines and body_lines[-1] == "":
                break
            if line == "" and not body_lines:
                break
            body_lines.append(line)
        body = "\n".join(body_lines).strip()

    if tags is None:
        tags_raw = Prompt.ask("Теги через запятую", default="").strip()
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]

    try:
        nid = add_note(kind, title, body, target or "", severity or "",
                       status or "", tags or [])
        if nid > 0:
            console.print(f"[green]✓ Добавлено #{nid}: {title}[/green]")
        else:
            console.print("[red]Не удалось добавить.[/red]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")


def cli_list(kind: str | None = None, target: str | None = None,
             status: str | None = None, severity: str | None = None,
             tag: str | None = None) -> None:
    notes = list_notes(kind=kind, target=target, status=status,
                       severity=severity, tag=tag)
    title = "Записи"
    if kind: title += f" [{kind}]"
    if target: title += f" @ {target}"
    _print_table(notes, title=f"{title} ({len(notes)})")


def cli_show(nid: int) -> None:
    n = get_note(nid)
    if not n:
        console.print(f"[red]#{nid} не найдено.[/red]")
        return
    _print_note(n)


def cli_del(nid: int) -> None:
    n = get_note(nid)
    if not n:
        console.print(f"[red]#{nid} не найдено.[/red]")
        return
    if not Confirm.ask(f"Удалить #{nid} '{n['title']}'?", default=False):
        return
    if delete_note(nid):
        console.print(f"[green]✓ Удалено #{nid}[/green]")
    else:
        console.print("[red]Не удалось удалить.[/red]")


def cli_search(query: str) -> None:
    notes = search_notes(query)
    _print_table(notes, title=f"🔎 По '{query}' ({len(notes)})")


def cli_edit(nid: int) -> None:
    n = get_note(nid)
    if not n:
        console.print(f"[red]#{nid} не найдено.[/red]")
        return
    console.print(f"[cyan]Редактирование #{nid}. Пусто = оставить как есть.[/cyan]")
    new_title = Prompt.ask("Title", default=n.get("title", "")).strip()
    new_target = Prompt.ask("Target", default=n.get("target", "")).strip()
    new_sev = Prompt.ask("Severity", default=n.get("severity", "")).strip()
    new_status = Prompt.ask("Status", default=n.get("status", "")).strip()
    tags_raw = Prompt.ask("Tags (через запятую)",
                          default=",".join(n.get("tags", []))).strip()
    new_tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
    console.print("[cyan]Body (одна строка):[/cyan]")
    new_body = Prompt.ask("Body", default=n.get("body", ""))

    if update_note(nid, title=new_title, target=new_target,
                   severity=new_sev, status=new_status,
                   tags=new_tags, body=new_body):
        console.print(f"[green]✓ Обновлено #{nid}[/green]")
    else:
        console.print("[red]Не удалось обновить.[/red]")


def cli_export(target: str | None = None, out_path: str | None = None) -> None:
    export_markdown(target=target, out_path=out_path)


# ---------------------------------------------------------------------------
# Интерактивное меню
# ---------------------------------------------------------------------------

def menu() -> None:
    table = Table(title="[bold]📝 Notes & Findings[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Статистика"),
        ("2", "Добавить заметку"),
        ("3", "Добавить находку (finding)"),
        ("4", "Список"),
        ("5", "Список находок по цели"),
        ("6", "Показать по ID"),
        ("7", "Редактировать"),
        ("8", "Удалить"),
        ("9", "Поиск"),
        ("10", "Экспорт в Markdown (всё)"),
        ("11", "Экспорт в Markdown (по цели)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        cli_stats()
    elif c == "2":
        cli_add(kind="note")
    elif c == "3":
        cli_add(kind="finding")
    elif c == "4":
        cli_list()
    elif c == "5":
        cli_list(kind="finding", target=Prompt.ask("Target (фильтр)"))
    elif c == "6":
        cli_show(IntPrompt.ask("ID"))
    elif c == "7":
        cli_edit(IntPrompt.ask("ID"))
    elif c == "8":
        cli_del(IntPrompt.ask("ID"))
    elif c == "9":
        cli_search(Prompt.ask("Поиск"))
    elif c == "10":
        cli_export()
    elif c == "11":
        cli_export(target=Prompt.ask("Target (фильтр)"))