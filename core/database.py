"""SQLite-хранилище истории сканов и прогресса."""
import sqlite3
import json
from datetime import datetime
from typing import Any
from core.config import DB_PATH
from core.logger import get_logger

log = get_logger(__name__)


class Database:
    """Обёртка над SQLite."""

    def __init__(self, path: str = str(DB_PATH)) -> None:
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module TEXT NOT NULL,
                target TEXT NOT NULL,
                result TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS progress (
                topic TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        self.conn.commit()

    def save_scan(self, module: str, target: str, result: Any) -> int:
        """Сохранить результат скана."""
        try:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO scans (module, target, result) VALUES (?, ?, ?)",
                (module, target, json.dumps(result, ensure_ascii=False, default=str)),
            )
            self.conn.commit()
            log.info("Скан сохранён: %s -> %s", module, target)
            return cur.lastrowid
        except Exception as exc:  # noqa: BLE001
            log.exception("Ошибка сохранения скана: %s", exc)
            return -1

    def history(self, limit: int = 20) -> list[sqlite3.Row]:
        """Последние сканы."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
        return cur.fetchall()

    def set_progress(self, topic: str, status: str) -> None:
        """Сохранить/обновить прогресс обучения."""
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO progress(topic, status, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(topic) DO UPDATE SET status=excluded.status, "
            "updated_at=excluded.updated_at",
            (topic, status, datetime.utcnow().isoformat()),
        )
        self.conn.commit()

    def get_progress(self) -> dict[str, str]:
        """Вернуть весь прогресс обучения."""
        cur = self.conn.cursor()
        cur.execute("SELECT topic, status FROM progress")
        return {row["topic"]: row["status"] for row in cur.fetchall()}


db = Database()