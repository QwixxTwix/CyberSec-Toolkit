"""
Notes & Findings Pro — заметки, находки, экспорт.
Author: idqwixxa

Две сущности:
    note    — обычная заметка
    finding — находка (severity + status + target)

Таблица notes:
    id, kind, title, target, severity, status,
    tags (json), body, created_at, updated_at,
    attachments (json), related (json),
    dedup_hash (для авто-дедупликации)

Возможности:
    ─── CRUD ───
    - add, get, update, delete
    - bulk_delete, bulk_update_status, bulk_update_severity
    - duplicate detection (по dedup_hash)
    - clone_note

    ─── Search ───
    - Full-text search (LIKE + FTS5 если доступно)
    - Filters: kind, target, tag, status, severity, date range
    - Sort: by id, created_at, severity
    - Pagination

    ─── Tags ───
    - list_all_tags
    - rename_tag, delete_tag

    ─── Attachments ───
    - attach_file (путь + base64 в БД)
    - get_attachments

    ─── Related ───
    - link_notes (id1 ↔ id2)

    ─── Timeline ───
    - timeline_view: группировка по дням

    ─── Export ───
    - Markdown / HTML / JSON / CSV
    - Export by target / filter
    - Auto-summary по severity
    - Kanban-style status board (HTML)

    ─── Import ───
    - from JSON (с dedup)

    ─── Findings wizard ───
    - Интерактивный мастер с пресетами уязвимостей
    - Автоподсказки из CVSS / OWASP

    ─── Интеграция ───
    - Auto-notify при critical findings (если NOTIFY_ENABLED)
    - report_pack интеграция
"""
import base64
import csv
import hashlib
import html as html_mod
import json
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

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

REPORTS_DIR = REPORT_DIR / "notes"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

SEVERITIES = ["info", "low", "medium", "high", "critical"]
STATUSES = ["open", "in-progress", "resolved", "wontfix", "dup", "invalid"]
KINDS = ["note", "finding"]


# ===========================================================================
# Schema
# ===========================================================================

def _init_schema() -> None:
    cur = db.conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL DEFAULT 'note',
            title TEXT NOT NULL,
            target TEXT DEFAULT '',
            severity TEXT DEFAULT '',
            status TEXT DEFAULT '',
            tags TEXT DEFAULT '[]',
            body TEXT DEFAULT '',
            attachments TEXT DEFAULT '[]',
            related TEXT DEFAULT '[]',
            dedup_hash TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_notes_target ON notes(target);
        CREATE INDEX IF NOT EXISTS idx_notes_kind ON notes(kind);
        CREATE INDEX IF NOT EXISTS idx_notes_status ON notes(status);
        CREATE INDEX IF NOT EXISTS idx_notes_severity ON notes(severity);
        CREATE INDEX IF NOT EXISTS idx_notes_dedup ON notes(dedup_hash);

        -- Audit log (изменения notes)
        CREATE TABLE IF NOT EXISTS notes_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            note_id INTEGER NOT NULL,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL,
            field TEXT DEFAULT '',
            old_value TEXT DEFAULT '',
            new_value TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_audit_note ON notes_audit(note_id);

        -- Tag registry
        CREATE TABLE IF NOT EXISTS notes_tags (
            tag TEXT PRIMARY KEY,
            count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.conn.commit()

    # Try enabling FTS5
    try:
        cur.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts5(
                title, body, target, tags,
                content='notes', content_rowid='id'
            );
        """)
        cur.execute("""
            CREATE TRIGGER IF NOT EXISTS notes_fts_ai
                AFTER INSERT ON notes BEGIN
                INSERT INTO notes_fts(rowid, title, body, target, tags)
                VALUES (new.id, new.title, new.body, new.target, new.tags);
            END;
        """)
        cur.execute("""
            CREATE TRIGGER IF NOT EXISTS notes_fts_ad
                AFTER DELETE ON notes BEGIN
                INSERT INTO notes_fts(notes_fts, rowid, title, body,
                                       target, tags)
                VALUES ('delete', old.id, old.title, old.body,
                        old.target, old.tags);
            END;
        """)
        cur.execute("""
            CREATE TRIGGER IF NOT EXISTS notes_fts_au
                AFTER UPDATE ON notes BEGIN
                INSERT INTO notes_fts(notes_fts, rowid, title, body,
                                       target, tags)
                VALUES ('delete', old.id, old.title, old.body,
                        old.target, old.tags);
                INSERT INTO notes_fts(rowid, title, body, target, tags)
                VALUES (new.id, new.title, new.body, new.target, new.tags);
            END;
        """)
        db.conn.commit()
    except Exception as exc:  # noqa: BLE001
        log.debug("FTS5 недоступен: %s", exc)


try:
    _init_schema()
except Exception as exc:  # noqa: BLE001
    log.exception("Не удалось создать схему notes: %s", exc)


# ===========================================================================
# Helpers
# ===========================================================================

def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    for field in ("tags", "attachments", "related"):
        try:
            d[field] = json.loads(d.get(field) or "[]")
        except Exception:
            d[field] = []
    return d


def _audit(note_id: int, action: str, field: str = "",
            old: str = "", new: str = "") -> None:
    try:
        cur = db.conn.cursor()
        cur.execute(
            "INSERT INTO notes_audit(note_id, action, field, old_value, "
            "new_value) VALUES (?, ?, ?, ?, ?)",
            (note_id, action, field, str(old)[:500], str(new)[:500]),
        )
        db.conn.commit()
    except Exception:
        pass


def _dedup_hash(kind: str, title: str, target: str,
                severity: str) -> str:
    """Hash для детекта дубликатов."""
    blob = f"{kind}|{title.strip().lower()}|{target.strip().lower()}|{severity}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _update_tag_registry(tags: list[str], delta: int = 1) -> None:
    """Обновить счётчики тегов."""
    try:
        cur = db.conn.cursor()
        for t in tags:
            cur.execute("""
                INSERT INTO notes_tags(tag, count) VALUES (?, ?)
                ON CONFLICT(tag) DO UPDATE SET count = count + ?
            """, (t, delta, delta))
        db.conn.commit()
    except Exception:
        pass


# ===========================================================================
# CRUD
# ===========================================================================

def add_note(kind: str, title: str, body: str = "",
             target: str = "", severity: str = "", status: str = "",
             tags: list[str] | None = None,
             attachments: list[str] | None = None,
             dedup_check: bool = True,
             auto_notify: bool = True) -> int:
    """
    Добавить заметку/находку. Возвращает id (или -1).
    Если dedup_check=True и такая запись уже есть (по hash) — вернёт
    существующий id (не создаст дубль).
    """
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

    # Dedup check
    dhash = _dedup_hash(kind, title, target, severity)
    if dedup_check:
        try:
            cur = db.conn.cursor()
            cur.execute("SELECT id FROM notes WHERE dedup_hash = ? LIMIT 1",
                        (dhash,))
            existing = cur.fetchone()
            if existing:
                log.info("Duplicate note skipped: #%s (%s)",
                         existing["id"], title)
                return existing["id"]
        except Exception:
            pass

    tags_json = json.dumps(sorted(set(tags or [])), ensure_ascii=False)
    attach_json = json.dumps(attachments or [], ensure_ascii=False)
    related_json = json.dumps([], ensure_ascii=False)
    now = datetime.utcnow().isoformat()

    try:
        cur = db.conn.cursor()
        cur.execute(
            "INSERT INTO notes(kind, title, target, severity, status, tags, "
            "body, attachments, related, dedup_hash, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (kind, title, target, severity, status,
             tags_json, body, attach_json, related_json, dhash, now, now),
        )
        db.conn.commit()
        nid = cur.lastrowid
        log.info("Note добавлена: #%s (%s)", nid, title)

        _audit(nid, "create", "kind", "", kind)
        if tags:
            _update_tag_registry(tags, 1)

        db.save_scan("notes", f"{kind}:{title}", {"id": nid})

        # Auto-notify для critical findings
        if auto_notify and kind == "finding" and severity == "critical":
            try:
                from modules import notifier
                notifier.notify_finding(title, target, severity, body)
            except Exception:
                pass

        return nid
    except Exception as exc:  # noqa: BLE001
        log.exception("add_note: %s", exc)
        return -1


def get_note(nid: int) -> dict | None:
    try:
        cur = db.conn.cursor()
        cur.execute("SELECT * FROM notes WHERE id = ?", (nid,))
        row = cur.fetchone()
        return _row_to_dict(row) if row else None
    except Exception as exc:  # noqa: BLE001
        log.exception("get_note: %s", exc)
        return None


def list_notes(kind: str | None = None,
                target: str | None = None,
                tag: str | None = None,
                status: str | None = None,
                severity: str | None = None,
                date_from: str | None = None,
                date_to: str | None = None,
                sort: str = "id_desc",
                limit: int = 200,
                offset: int = 0) -> list[dict]:
    """Список с фильтрами и сортировкой."""
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
        sql += " AND tags LIKE ?"; args.append(f'%"{tag}"%')
    if date_from:
        sql += " AND created_at >= ?"; args.append(date_from)
    if date_to:
        sql += " AND created_at <= ?"; args.append(date_to)

    order_map = {
        "id_desc": "id DESC",
        "id_asc": "id ASC",
        "created_desc": "created_at DESC",
        "created_asc": "created_at ASC",
        "severity": ("CASE severity "
                     "WHEN 'critical' THEN 0 "
                     "WHEN 'high' THEN 1 "
                     "WHEN 'medium' THEN 2 "
                     "WHEN 'low' THEN 3 "
                     "ELSE 4 END, id DESC"),
    }
    sql += f" ORDER BY {order_map.get(sort, 'id DESC')} LIMIT ? OFFSET ?"
    args.extend([limit, offset])

    try:
        cur = db.conn.cursor()
        cur.execute(sql, args)
        return [_row_to_dict(r) for r in cur.fetchall()]
    except Exception as exc:  # noqa: BLE001
        log.exception("list_notes: %s", exc)
        return []


def update_note(nid: int, **kwargs) -> bool:
    allowed = ("title", "target", "severity", "status", "body", "kind")
    sets: list[str] = []
    args: list = []
    old = get_note(nid) or {}

    for k, v in kwargs.items():
        if k in allowed and v is not None:
            sets.append(f"{k} = ?"); args.append(v)
            _audit(nid, "update", k, old.get(k, ""), v)
    if "tags" in kwargs and kwargs["tags"] is not None:
        new_tags = sorted(set(kwargs["tags"]))
        sets.append("tags = ?")
        args.append(json.dumps(new_tags, ensure_ascii=False))
        _update_tag_registry(new_tags, 1)
        _audit(nid, "update", "tags",
                json.dumps(old.get("tags", [])), json.dumps(new_tags))

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
    n = get_note(nid)
    try:
        cur = db.conn.cursor()
        cur.execute("DELETE FROM notes WHERE id = ?", (nid,))
        db.conn.commit()
        if n and n.get("tags"):
            _update_tag_registry(n["tags"], -1)
        if n:
            _audit(nid, "delete", "id", str(nid), "")
        return cur.rowcount > 0
    except Exception as exc:  # noqa: BLE001
        log.exception("delete_note: %s", exc)
        return False


# ===========================================================================
# Bulk operations
# ===========================================================================

def bulk_delete(ids: list[int]) -> int:
    """Удалить много записей."""
    if not ids:
        return 0
    placeholders = ",".join("?" * len(ids))
    try:
        cur = db.conn.cursor()
        cur.execute(f"DELETE FROM notes WHERE id IN ({placeholders})", ids)
        db.conn.commit()
        return cur.rowcount
    except Exception as exc:  # noqa: BLE001
        log.exception("bulk_delete: %s", exc)
        return 0


def bulk_update_status(ids: list[int], status: str) -> int:
    """Bulk change status."""
    if status not in STATUSES or not ids:
        return 0
    placeholders = ",".join("?" * len(ids))
    try:
        cur = db.conn.cursor()
        cur.execute(
            f"UPDATE notes SET status = ?, updated_at = ? "
            f"WHERE id IN ({placeholders})",
            [status, datetime.utcnow().isoformat()] + ids,
        )
        db.conn.commit()
        for nid in ids:
            _audit(nid, "bulk_update", "status", "", status)
        return cur.rowcount
    except Exception as exc:  # noqa: BLE001
        log.exception("bulk_update_status: %s", exc)
        return 0


def bulk_update_severity(ids: list[int], severity: str) -> int:
    if severity not in SEVERITIES or not ids:
        return 0
    placeholders = ",".join("?" * len(ids))
    try:
        cur = db.conn.cursor()
        cur.execute(
            f"UPDATE notes SET severity = ?, updated_at = ? "
            f"WHERE id IN ({placeholders})",
            [severity, datetime.utcnow().isoformat()] + ids,
        )
        db.conn.commit()
        for nid in ids:
            _audit(nid, "bulk_update", "severity", "", severity)
        return cur.rowcount
    except Exception as exc:  # noqa: BLE001
        log.exception("bulk_update_severity: %s", exc)
        return 0


def clone_note(nid: int, new_title: str | None = None) -> int:
    """Клонировать заметку (для похожих находок)."""
    n = get_note(nid)
    if not n:
        return -1
    title = new_title or f"{n['title']} (copy)"
    return add_note(
        kind=n["kind"], title=title, body=n.get("body", ""),
        target=n.get("target", ""), severity=n.get("severity", ""),
        status="open", tags=n.get("tags", []),
        dedup_check=False,
    )


# ===========================================================================
# Search
# ===========================================================================

def search_notes(query: str, fts: bool = True) -> list[dict]:
    """Full-text search (FTS5 если доступен, иначе LIKE)."""
    # Try FTS5
    if fts and query.strip():
        try:
            cur = db.conn.cursor()
            # Escape quotes for FTS
            fts_q = query.replace('"', '""')
            cur.execute("""
                SELECT n.* FROM notes n
                JOIN notes_fts fts ON n.id = fts.rowid
                WHERE notes_fts MATCH ?
                LIMIT 100
            """, (fts_q,))
            rows = cur.fetchall()
            if rows:
                return [_row_to_dict(r) for r in rows]
        except Exception as exc:
            log.debug("FTS failed, fallback to LIKE: %s", exc)

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


# ===========================================================================
# Tags
# ===========================================================================

def list_all_tags() -> list[dict]:
    """Все теги с counts (из notes_tags + пересчёт из notes)."""
    try:
        cur = db.conn.cursor()
        cur.execute("SELECT tag, count FROM notes_tags "
                    "WHERE count > 0 ORDER BY count DESC, tag")
        rows = cur.fetchall()
        if rows:
            return [{"tag": r["tag"], "count": r["count"]} for r in rows]
    except Exception:
        pass

    # Fallback: агрегация по notes
    all_notes = list_notes(limit=10000)
    counter: Counter = Counter()
    for n in all_notes:
        for t in n.get("tags", []):
            counter[t] += 1
    return [{"tag": t, "count": c} for t, c in counter.most_common()]


def rename_tag(old: str, new: str) -> int:
    """Переименовать тег во всех записях."""
    if not old or not new:
        return 0
    try:
        cur = db.conn.cursor()
        cur.execute("SELECT id, tags FROM notes WHERE tags LIKE ?",
                    (f'%"{old}"%',))
        rows = cur.fetchall()
        changed = 0
        for r in rows:
            try:
                tags = json.loads(r["tags"] or "[]")
            except Exception:
                continue
            if old in tags:
                tags = [new if t == old else t for t in tags]
                cur.execute("UPDATE notes SET tags = ? WHERE id = ?",
                            (json.dumps(sorted(set(tags)), ensure_ascii=False),
                             r["id"]))
                changed += 1
        db.conn.commit()
        _update_tag_registry([new], changed)
        _update_tag_registry([old], -changed)
        return changed
    except Exception as exc:  # noqa: BLE001
        log.exception("rename_tag: %s", exc)
        return 0


def delete_tag(tag: str) -> int:
    """Удалить тег из всех записей."""
    if not tag:
        return 0
    try:
        cur = db.conn.cursor()
        cur.execute("SELECT id, tags FROM notes WHERE tags LIKE ?",
                    (f'%"{tag}"%',))
        rows = cur.fetchall()
        changed = 0
        for r in rows:
            try:
                tags = json.loads(r["tags"] or "[]")
            except Exception:
                continue
            if tag in tags:
                tags = [t for t in tags if t != tag]
                cur.execute("UPDATE notes SET tags = ? WHERE id = ?",
                            (json.dumps(sorted(set(tags)), ensure_ascii=False),
                             r["id"]))
                changed += 1
        db.conn.commit()
        _update_tag_registry([tag], -changed)
        return changed
    except Exception as exc:  # noqa: BLE001
        log.exception("delete_tag: %s", exc)
        return 0


# ===========================================================================
# Related notes
# ===========================================================================

def link_notes(id1: int, id2: int) -> bool:
    """Связать две заметки."""
    if id1 == id2:
        return False
    try:
        n1 = get_note(id1)
        n2 = get_note(id2)
        if not n1 or not n2:
            return False
        r1 = set(n1.get("related", []))
        r2 = set(n2.get("related", []))
        r1.add(id2)
        r2.add(id1)
        cur = db.conn.cursor()
        cur.execute("UPDATE notes SET related = ? WHERE id = ?",
                    (json.dumps(sorted(r1)), id1))
        cur.execute("UPDATE notes SET related = ? WHERE id = ?",
                    (json.dumps(sorted(r2)), id2))
        db.conn.commit()
        return True
    except Exception as exc:  # noqa: BLE001
        log.exception("link_notes: %s", exc)
        return False


# ===========================================================================
# Timeline
# ===========================================================================

def timeline_view(days_back: int = 30) -> dict[str, list[dict]]:
    """Группировка notes по дням."""
    cutoff = (datetime.utcnow() -
              timedelta(days=days_back)).isoformat()
    try:
        cur = db.conn.cursor()
        cur.execute(
            "SELECT * FROM notes WHERE created_at >= ? "
            "ORDER BY created_at DESC", (cutoff,))
        rows = [_row_to_dict(r) for r in cur.fetchall()]
    except Exception as exc:  # noqa: BLE001
        log.exception("timeline_view: %s", exc)
        return {}

    grouped: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        try:
            day = str(r.get("created_at", ""))[:10]
            if day:
                grouped[day].append(r)
        except Exception:
            continue
    return dict(grouped)


# ===========================================================================
# Stats
# ===========================================================================

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

        cur.execute("SELECT COUNT(DISTINCT target) as c FROM notes "
                    "WHERE target != ''")
        unique_targets = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) as c FROM notes WHERE kind='finding' "
                    "AND status='open'")
        open_findings = cur.fetchone()["c"]

        return {
            "total": total,
            "by_kind": by_kind,
            "by_severity": by_sev,
            "by_status": by_status,
            "unique_targets": unique_targets,
            "open_findings": open_findings,
        }
    except Exception as exc:  # noqa: BLE001
        log.exception("stats: %s", exc)
        return {"total": 0, "by_kind": {}, "by_severity": {},
                "by_status": {}, "unique_targets": 0, "open_findings": 0}


def stats_by_target() -> dict[str, dict]:
    """Статистика по target."""
    try:
        cur = db.conn.cursor()
        cur.execute("""
            SELECT target,
                   COUNT(*) as total,
                   SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END)
                       as critical,
                   SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high,
                   SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) as open
            FROM notes WHERE kind='finding' AND target != ''
            GROUP BY target ORDER BY total DESC LIMIT 50
        """)
        return {r["target"]: dict(r) for r in cur.fetchall()}
    except Exception as exc:  # noqa: BLE001
        log.exception("stats_by_target: %s", exc)
        return {}


# ===========================================================================
# Export
# ===========================================================================

def export_markdown(target: str | None = None,
                     out_path: str | None = None) -> Path | None:
    """Экспорт в Markdown."""
    notes = list_notes(target=target, limit=1000,
                        sort="severity" if not target else "id_desc")
    if not notes:
        console.print("[yellow]Нет записей для экспорта.[/yellow]")
        return None

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not out_path:
        safe = (target or "all").replace("/", "_").replace(":", "_")[:40]
        out_path = str(REPORTS_DIR / f"notes_{safe}_{ts}.md")

    findings = [n for n in notes if n["kind"] == "finding"]
    plain = [n for n in notes if n["kind"] != "finding"]

    lines = [
        "# 🛡️ Findings & Notes",
        "",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Target filter:** `{target or 'all'}`  ",
        f"**Total:** {len(notes)}  ",
        f"**Findings:** {len(findings)}  •  **Notes:** {len(plain)}",
        "",
        "---",
        "",
    ]

    if findings:
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

    counts: Counter = Counter()
    for f in findings:
        counts[f.get("severity") or "info"] += 1
    if counts:
        lines.append("---")
        lines.append("")
        lines.append("## 📊 Severity summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for s in SEVERITIES:
            if s in counts:
                lines.append(f"| {s.upper()} | {counts[s]} |")
        lines.append("")

    path = Path(out_path)
    try:
        path.write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green]✓ {path}[/green]")
        db.save_scan("notes_export_md", target or "all",
                     {"path": str(path), "count": len(notes)})
        return path
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_json(target: str | None = None,
                 out_path: str | None = None) -> Path | None:
    """Экспорт в JSON."""
    notes = list_notes(target=target, limit=10000)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not out_path:
        safe = (target or "all").replace("/", "_").replace(":", "_")[:40]
        out_path = str(REPORTS_DIR / f"notes_{safe}_{ts}.json")
    try:
        Path(out_path).write_text(
            json.dumps(notes, indent=2, ensure_ascii=False,
                        default=str), encoding="utf-8")
        console.print(f"[green]✓ JSON: {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]JSON: {exc}[/red]")
        return None


def export_csv(target: str | None = None,
                out_path: str | None = None) -> Path | None:
    """Экспорт в CSV."""
    notes = list_notes(target=target, limit=10000)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not out_path:
        safe = (target or "all").replace("/", "_").replace(":", "_")[:40]
        out_path = str(REPORTS_DIR / f"notes_{safe}_{ts}.csv")
    cols = ["id", "kind", "title", "target", "severity",
            "status", "tags", "created_at", "updated_at"]
    try:
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for n in notes:
                row = dict(n)
                if isinstance(row.get("tags"), list):
                    row["tags"] = ",".join(row["tags"])
                w.writerow(row)
        console.print(f"[green]✓ CSV: {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]CSV: {exc}[/red]")
        return None


def export_html(target: str | None = None,
                 out_path: str | None = None,
                 kanban: bool = False) -> Path | None:
    """Экспорт в HTML (обычный или Kanban-доска)."""
    notes = list_notes(target=target, limit=1000,
                        sort="severity" if not target else "id_desc")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not out_path:
        safe = (target or "all").replace("/", "_").replace(":", "_")[:40]
        suffix = "_kanban" if kanban else ""
        out_path = str(REPORTS_DIR / f"notes_{safe}_{ts}{suffix}.html")

    try:
        if kanban:
            html = _render_kanban(notes, target)
        else:
            html = _render_html_notes(notes, target)
        Path(out_path).write_text(html, encoding="utf-8")
        console.print(f"[green]✓ HTML: {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]HTML: {exc}[/red]")
        return None


CSS_COMMON = """
body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;
padding:24px;line-height:1.5;}
h1{color:#00ff9c;border-bottom:2px solid #00ff9c;padding-bottom:8px;}
h2{color:#00ff9c;margin-top:32px;}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px;}
th{background:#111;color:#00ff9c;padding:8px;text-align:left;
border:1px solid #222;}
td{padding:6px 8px;border:1px solid #222;word-break:break-word;}
tr:nth-child(even){background:#0d0d0d;}
.critical{color:#ff2020;font-weight:bold;}
.high{color:#ff7a40;font-weight:bold;}
.medium{color:#ffd23f;}
.low{color:#00ff9c;}
.info{color:#7ad9ff;}
code{background:#111;padding:2px 6px;color:#a0ffa0;border-radius:3px;}
.tag{display:inline-block;background:#111;color:#a0ffa0;padding:2px 8px;
border-radius:10px;font-size:11px;margin-right:4px;}
pre{background:#050505;border:1px solid #222;padding:12px;
overflow-x:auto;color:#a0ffa0;font-size:12px;}
"""


def _render_html_notes(notes: list[dict], target: str | None) -> str:
    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>Findings & Notes — {html_mod.escape(target or 'all')}</title>",
        f"<style>{CSS_COMMON}</style></head><body>",
        f"<h1>📝 Findings & Notes ({len(notes)})</h1>",
        f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        f"Filter: <code>{html_mod.escape(target or 'all')}</code></p>",
    ]

    # Group by kind
    findings = [n for n in notes if n["kind"] == "finding"]
    plain = [n for n in notes if n["kind"] != "finding"]

    if findings:
        parts.append(f"<h2>🔴 Findings ({len(findings)})</h2>")
        parts.append("<table><tr><th>ID</th><th>Sev</th><th>Status</th>"
                     "<th>Target</th><th>Title</th><th>Tags</th>"
                     "<th>Body</th></tr>")
        for f in findings:
            tags_html = "".join(
                f"<span class='tag'>{html_mod.escape(t)}</span>"
                for t in f.get("tags", []))
            parts.append(
                f"<tr><td>{f['id']}</td>"
                f"<td class='{f.get('severity', 'info')}'>"
                f"{(f.get('severity') or '—').upper()}</td>"
                f"<td>{html_mod.escape(f.get('status') or '—')}</td>"
                f"<td><code>{html_mod.escape(f.get('target') or '—')}</code></td>"
                f"<td>{html_mod.escape(f.get('title', ''))}</td>"
                f"<td>{tags_html}</td>"
                f"<td><pre>{html_mod.escape((f.get('body') or '')[:400])}</pre></td>"
                f"</tr>")
        parts.append("</table>")

    if plain:
        parts.append(f"<h2>📝 Notes ({len(plain)})</h2>")
        parts.append("<table><tr><th>ID</th><th>Title</th>"
                     "<th>Target</th><th>Tags</th><th>Body</th></tr>")
        for n in plain:
            tags_html = "".join(
                f"<span class='tag'>{html_mod.escape(t)}</span>"
                for t in n.get("tags", []))
            parts.append(
                f"<tr><td>{n['id']}</td>"
                f"<td>{html_mod.escape(n.get('title', ''))}</td>"
                f"<td><code>{html_mod.escape(n.get('target') or '—')}</code></td>"
                f"<td>{tags_html}</td>"
                f"<td><pre>{html_mod.escape((n.get('body') or '')[:400])}</pre></td>"
                f"</tr>")
        parts.append("</table>")

    parts.append("</body></html>")
    return "\n".join(parts)


def _render_kanban(notes: list[dict], target: str | None) -> str:
    """Kanban-доска по статусам."""
    columns: dict[str, list[dict]] = {s: [] for s in STATUSES}
    for n in notes:
        if n["kind"] != "finding":
            continue
        st = n.get("status") or "open"
        if st not in columns:
            st = "open"
        columns[st].append(n)

    cards_css = """
    .kanban{display:flex;gap:16px;overflow-x:auto;padding-bottom:16px;}
    .column{flex:0 0 300px;background:#0d0d0d;border-radius:6px;padding:12px;
    border:1px solid #222;}
    .column h3{margin:0 0 12px 0;color:#00ff9c;text-transform:uppercase;
    font-size:12px;letter-spacing:2px;}
    .card{background:#111;padding:10px;border-radius:4px;margin-bottom:8px;
    border-left:3px solid #7ad9ff;}
    .card.critical{border-left-color:#ff2020;}
    .card.high{border-left-color:#ff7a40;}
    .card.medium{border-left-color:#ffd23f;}
    .card.low{border-left-color:#00ff9c;}
    .card-title{color:#fff;font-weight:bold;font-size:12px;
    margin-bottom:4px;}
    .card-meta{color:#666;font-size:10px;}
    """
    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>Kanban — {html_mod.escape(target or 'all')}</title>",
        f"<style>{CSS_COMMON}{cards_css}</style></head><body>",
        f"<h1>📋 Kanban — {html_mod.escape(target or 'all')}</h1>",
        f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "<div class='kanban'>",
    ]

    for status in STATUSES:
        col_notes = columns.get(status, [])
        parts.append(
            f"<div class='column'><h3>{html_mod.escape(status)} "
            f"({len(col_notes)})</h3>")
        for n in col_notes:
            sev = n.get("severity") or "info"
            parts.append(
                f"<div class='card {sev}'>"
                f"<div class='card-title'>#{n['id']} "
                f"{html_mod.escape(n.get('title', '')[:60])}</div>"
                f"<div class='card-meta'>"
                f"{sev.upper()} · "
                f"{html_mod.escape(n.get('target', '')[:40])}"
                f"</div></div>")
        parts.append("</div>")

    parts.append("</div></body></html>")
    return "\n".join(parts)


# ===========================================================================
# Import
# ===========================================================================

def import_json(path: str, dedup: bool = True) -> dict:
    """Импорт notes из JSON."""
    p = Path(path)
    if not p.exists():
        return {"error": "file not found"}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
    if not isinstance(data, list):
        return {"error": "expected array"}

    imported = 0
    skipped = 0
    for item in data:
        try:
            nid = add_note(
                kind=item.get("kind", "note"),
                title=item.get("title", ""),
                body=item.get("body", ""),
                target=item.get("target", ""),
                severity=item.get("severity", ""),
                status=item.get("status", ""),
                tags=item.get("tags") or [],
                dedup_check=dedup,
            )
            if nid > 0:
                imported += 1
            else:
                skipped += 1
        except Exception:
            skipped += 1
    return {"imported": imported, "skipped": skipped}


# ===========================================================================
# Markdown helpers
# ===========================================================================

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
        f"**Description:**\n\n{f.get('body', '') or '_empty_'}\n"
    )


def _note_to_md(n: dict) -> str:
    tags = ", ".join(f"`{t}`" for t in n.get("tags", []))
    target = f"\n- **Target:** `{n['target']}`" if n.get("target") else ""
    return (
        f"### 📝 #{n['id']} — {n['title']}\n\n"
        f"- **Tags:** {tags or '—'}"
        f"{target}\n"
        f"- **Created:** {n.get('created_at', '—')}\n\n"
        f"{n.get('body', '') or '_empty_'}\n"
    )


# ===========================================================================
# Printing
# ===========================================================================

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
        f"[cyan]related:[/cyan]  {', '.join(str(x) for x in n.get('related', [])) or '—'}",
        f"[cyan]created:[/cyan]  {n.get('created_at')}",
        f"[cyan]updated:[/cyan]  {n.get('updated_at')}",
        "",
        n.get("body") or "[dim](empty)[/dim]",
    ]
    console.print(Panel("\n".join(lines), title=header, border_style="cyan"))


def _print_table(notes: list[dict], title: str = "Notes") -> None:
    if not notes:
        console.print("[yellow]Нет записей.[/yellow]")
        return
    table = Table(title=title)
    table.add_column("ID", style="cyan", width=5)
    table.add_column("Kind", style="yellow", width=8)
    table.add_column("Title", style="white", max_width=40)
    table.add_column("Target", style="green", max_width=30)
    table.add_column("Sev", style="red", width=9)
    table.add_column("Status", style="magenta", width=12)
    table.add_column("Tags", style="dim", max_width=20)
    for n in notes:
        sev = n.get("severity") or "—"
        sty = {"critical": "bold red", "high": "red",
               "medium": "yellow", "low": "green",
               "info": "dim"}.get(sev.lower(), "white")
        table.add_row(
            str(n["id"]),
            n.get("kind", ""),
            n.get("title", "")[:40],
            (n.get("target") or "—")[:30],
            f"[{sty}]{sev}[/{sty}]",
            n.get("status") or "—",
            ",".join(n.get("tags", []))[:20] or "—",
        )
    console.print(table)


# ===========================================================================
# CLI functions
# ===========================================================================

def cli_stats() -> None:
    s = stats()
    table = Table(title="📊 Notes & Findings")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Total", str(s["total"]))
    table.add_row("Unique targets", str(s["unique_targets"]))
    table.add_row("Open findings", str(s["open_findings"]))
    for k, v in s["by_kind"].items():
        table.add_row(f"  kind: {k}", str(v))
    for k, v in s["by_severity"].items():
        table.add_row(f"  sev: {k}", str(v))
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
        title = Prompt.ask("Title").strip()
    if not title:
        console.print("[red]Empty title.[/red]")
        return

    if kind == "finding":
        if not target:
            target = Prompt.ask("Target (URL/IP/domain)").strip()
        if not severity:
            severity = Prompt.ask("Severity", choices=SEVERITIES,
                                    default="info")
        if not status:
            status = Prompt.ask("Status", choices=STATUSES,
                                  default="open")
    else:
        if target is None:
            target = Prompt.ask("Target (optional)", default="").strip()

    if body is None:
        console.print("[cyan]Enter description. Empty line = end.[/cyan]")
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
        tags_raw = Prompt.ask("Tags (comma)", default="").strip()
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]

    try:
        nid = add_note(kind, title, body, target or "", severity or "",
                        status or "", tags or [])
        if nid > 0:
            console.print(f"[green]✓ Added #{nid}: {title}[/green]")
        else:
            console.print("[red]Failed.[/red]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Error: {exc}[/red]")


def cli_list(kind: str | None = None, target: str | None = None,
              status: str | None = None, severity: str | None = None,
              tag: str | None = None) -> None:
    notes = list_notes(kind=kind, target=target, status=status,
                        severity=severity, tag=tag)
    title = "Notes"
    if kind: title += f" [{kind}]"
    if target: title += f" @ {target}"
    _print_table(notes, title=f"{title} ({len(notes)})")


def cli_show(nid: int) -> None:
    n = get_note(nid)
    if not n:
        console.print(f"[red]#{nid} not found.[/red]")
        return
    _print_note(n)


def cli_del(nid: int) -> None:
    n = get_note(nid)
    if not n:
        console.print(f"[red]#{nid} not found.[/red]")
        return
    if not Confirm.ask(f"Delete #{nid} '{n['title']}'?", default=False):
        return
    if delete_note(nid):
        console.print(f"[green]✓ Deleted #{nid}[/green]")
    else:
        console.print("[red]Failed.[/red]")


def cli_search(query: str) -> None:
    notes = search_notes(query)
    _print_table(notes, title=f"🔎 '{query}' ({len(notes)})")


def cli_edit(nid: int) -> None:
    n = get_note(nid)
    if not n:
        console.print(f"[red]#{nid} not found.[/red]")
        return
    console.print(f"[cyan]Edit #{nid}. Empty = keep current.[/cyan]")
    new_title = Prompt.ask("Title", default=n.get("title", "")).strip()
    new_target = Prompt.ask("Target", default=n.get("target", "")).strip()
    new_sev = Prompt.ask("Severity", default=n.get("severity", "")).strip()
    new_status = Prompt.ask("Status", default=n.get("status", "")).strip()
    tags_raw = Prompt.ask("Tags (comma)",
                           default=",".join(n.get("tags", []))).strip()
    new_tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
    console.print("[cyan]Body (single line):[/cyan]")
    new_body = Prompt.ask("Body", default=n.get("body", ""))

    if update_note(nid, title=new_title, target=new_target,
                    severity=new_sev, status=new_status,
                    tags=new_tags, body=new_body):
        console.print(f"[green]✓ Updated #{nid}[/green]")
    else:
        console.print("[red]Failed.[/red]")


def cli_export(target: str | None = None,
                out_path: str | None = None,
                fmt: str = "md") -> None:
    if fmt == "md":
        export_markdown(target=target, out_path=out_path)
    elif fmt == "json":
        export_json(target=target, out_path=out_path)
    elif fmt == "csv":
        export_csv(target=target, out_path=out_path)
    elif fmt == "html":
        export_html(target=target, out_path=out_path)
    elif fmt == "kanban":
        export_html(target=target, out_path=out_path, kanban=True)


def cli_tags() -> None:
    """Показать все теги."""
    tags = list_all_tags()
    if not tags:
        console.print("[yellow]Нет тегов.[/yellow]")
        return
    t = Table(title=f"🏷️  Tags ({len(tags)})")
    t.add_column("Tag", style="cyan")
    t.add_column("Count", style="green", width=8)
    for item in tags[:100]:
        t.add_row(item["tag"], str(item["count"]))
    console.print(t)


def cli_timeline(days: int = 30) -> None:
    """Timeline view."""
    grouped = timeline_view(days)
    if not grouped:
        console.print(f"[yellow]Нет записей за {days} дней.[/yellow]")
        return
    for day in sorted(grouped.keys(), reverse=True):
        items = grouped[day]
        t = Table(title=f"📅 {day} ({len(items)})")
        t.add_column("ID", style="cyan", width=5)
        t.add_column("Kind", style="yellow", width=8)
        t.add_column("Sev", style="red", width=8)
        t.add_column("Title", style="white", max_width=50)
        for n in items[:20]:
            sev = n.get("severity") or "—"
            sty = {"critical": "bold red", "high": "red",
                   "medium": "yellow", "low": "green",
                   "info": "dim"}.get(sev.lower(), "white")
            t.add_row(str(n["id"]), n.get("kind", ""),
                       f"[{sty}]{sev}[/{sty}]",
                       n.get("title", "")[:50])
        console.print(t)


def cli_by_target() -> None:
    """Статистика по target."""
    data = stats_by_target()
    if not data:
        console.print("[yellow]Нет findings.[/yellow]")
        return
    t = Table(title=f"📊 Findings by target ({len(data)})")
    t.add_column("Target", style="cyan", max_width=40)
    t.add_column("Total", width=8)
    t.add_column("Critical", style="red", width=10)
    t.add_column("High", style="red", width=6)
    t.add_column("Open", style="yellow", width=8)
    for target, s in list(data.items())[:30]:
        t.add_row(target[:40], str(s.get("total", 0)),
                   str(s.get("critical", 0)), str(s.get("high", 0)),
                   str(s.get("open", 0)))
    console.print(t)


# ===========================================================================
# Interactive wizard for findings
# ===========================================================================

PRESET_TEMPLATES = {
    "xss": {
        "title_tpl": "XSS in {target}",
        "severity": "high",
        "tags": ["xss", "web"],
        "body_tpl": (
            "**Type:** Cross-Site Scripting\n"
            "**Endpoint:** {target}\n"
            "**Parameter:** {param}\n\n"
            "**Steps to reproduce:**\n"
            "1. Navigate to {target}\n"
            "2. Inject payload in {param}\n"
            "3. Observe execution\n\n"
            "**Impact:** Session hijacking, credential theft, "
            "malicious actions in victim's name\n\n"
            "**Remediation:** Context-aware output encoding + CSP"
        ),
    },
    "sqli": {
        "title_tpl": "SQL Injection in {target}",
        "severity": "critical",
        "tags": ["sqli", "web"],
        "body_tpl": (
            "**Type:** SQL Injection\n"
            "**Endpoint:** {target}\n"
            "**Parameter:** {param}\n\n"
            "**Impact:** Full DB read/write, auth bypass, potential RCE\n\n"
            "**Remediation:** Parameterized queries, least-privilege DB user"
        ),
    },
    "idor": {
        "title_tpl": "IDOR in {target}",
        "severity": "high",
        "tags": ["idor", "access-control"],
        "body_tpl": (
            "**Type:** Insecure Direct Object Reference\n"
            "**Endpoint:** {target}\n\n"
            "**Impact:** Access to other users' data\n\n"
            "**Remediation:** Ownership checks on every request"
        ),
    },
    "ssrf": {
        "title_tpl": "SSRF in {target}",
        "severity": "high",
        "tags": ["ssrf", "web"],
        "body_tpl": (
            "**Type:** Server-Side Request Forgery\n"
            "**Endpoint:** {target}\n"
            "**Parameter:** {param}\n\n"
            "**Impact:** Internal port scan, cloud metadata access\n\n"
            "**Remediation:** Allowlist domains, block internal IPs"
        ),
    },
    "rce": {
        "title_tpl": "Remote Code Execution in {target}",
        "severity": "critical",
        "tags": ["rce", "web"],
        "body_tpl": (
            "**Type:** Remote Code Execution\n"
            "**Endpoint:** {target}\n\n"
            "**Impact:** Full server compromise\n\n"
            "**Remediation:** Never pass user input to eval/exec"
        ),
    },
    "info-disclosure": {
        "title_tpl": "Information Disclosure: {target}",
        "severity": "low",
        "tags": ["info-disclosure"],
        "body_tpl": (
            "**Type:** Information Disclosure\n"
            "**Endpoint:** {target}\n\n"
            "**Impact:** Aids further attacks\n\n"
            "**Remediation:** Disable debug info in production"
        ),
    },
    "subdomain-takeover": {
        "title_tpl": "Subdomain Takeover: {target}",
        "severity": "high",
        "tags": ["takeover", "dns"],
        "body_tpl": (
            "**Type:** Subdomain Takeover\n"
            "**Subdomain:** {target}\n\n"
            "**Impact:** Phishing, cookie theft, CSP bypass\n\n"
            "**Remediation:** Remove dangling DNS records"
        ),
    },
}


def findings_wizard() -> None:
    """Интерактивный мастер для создания finding."""
    console.print("[bold cyan]🐛 Findings Wizard[/bold cyan]\n")

    t = Table(title="Типы находок (presets)")
    t.add_column("#", width=3)
    t.add_column("Ключ", style="cyan")
    t.add_column("Severity", style="red")
    for i, (key, tmpl) in enumerate(PRESET_TEMPLATES.items(), 1):
        t.add_row(str(i), key, tmpl["severity"].upper())
    console.print(t)

    choice = Prompt.ask("Preset (Enter = custom)",
                         default="").strip()

    if choice in PRESET_TEMPLATES:
        tmpl = PRESET_TEMPLATES[choice]
        target = Prompt.ask("Target (URL/endpoint)")
        param = Prompt.ask("Parameter (optional)", default="")
        title = tmpl["title_tpl"].format(target=target, param=param)
        body = tmpl["body_tpl"].format(target=target, param=param)
        severity = Prompt.ask("Severity", choices=SEVERITIES,
                                default=tmpl["severity"])
        status = Prompt.ask("Status", choices=STATUSES,
                              default="open")
        tags = tmpl["tags"] + [choice]
    else:
        title = Prompt.ask("Title")
        target = Prompt.ask("Target")
        severity = Prompt.ask("Severity", choices=SEVERITIES,
                                default="medium")
        status = Prompt.ask("Status", choices=STATUSES,
                              default="open")
        console.print("[cyan]Body (empty line = end):[/cyan]")
        body_lines: list[str] = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if not line:
                break
            body_lines.append(line)
        body = "\n".join(body_lines)
        tags_raw = Prompt.ask("Tags (comma)", default="").strip()
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]

    if not title or not target:
        console.print("[red]Title и target обязательны.[/red]")
        return

    nid = add_note(kind="finding", title=title, body=body,
                    target=target, severity=severity,
                    status=status, tags=tags)
    if nid > 0:
        console.print(f"[green]✓ Finding #{nid} created[/green]")
    else:
        console.print("[red]Failed.[/red]")


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]📝 Notes & Findings Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Статистика"),
        ("2", "Добавить заметку"),
        ("3", "Добавить находку (wizard)"),
        ("4", "Список"),
        ("5", "Список находок по цели"),
        ("6", "Показать по ID"),
        ("7", "Редактировать"),
        ("8", "Удалить"),
        ("9", "Поиск (FTS)"),
        ("10", "Теги (список)"),
        ("11", "Timeline (по дням)"),
        ("12", "Findings по target"),
        ("13", "Экспорт Markdown"),
        ("14", "Экспорт JSON"),
        ("15", "Экспорт CSV"),
        ("16", "Экспорт HTML"),
        ("17", "Экспорт Kanban-доски"),
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
        findings_wizard()
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
        cli_tags()
    elif c == "11":
        cli_timeline(IntPrompt.ask("Дней назад", default=30))
    elif c == "12":
        cli_by_target()
    elif c == "13":
        cli_export(target=Prompt.ask("Target (пусто = всё)", default="")
                    or None, fmt="md")
    elif c == "14":
        cli_export(target=Prompt.ask("Target (пусто = всё)", default="")
                    or None, fmt="json")
    elif c == "15":
        cli_export(target=Prompt.ask("Target (пусто = всё)", default="")
                    or None, fmt="csv")
    elif c == "16":
        cli_export(target=Prompt.ask("Target (пусто = всё)", default="")
                    or None, fmt="html")
    elif c == "17":
        cli_export(target=Prompt.ask("Target (пусто = всё)", default="")
                    or None, fmt="kanban")