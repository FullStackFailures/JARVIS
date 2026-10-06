"""Task registry with SQLite history (so ``--tasks`` works across processes)."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any

from jarvis.common.util import utc_iso
from jarvis.core.models import PermissionMode, Task, TaskStatus
from jarvis.security.redact import REDACTOR, Redactor

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY, goal TEXT NOT NULL, status TEXT NOT NULL, outcome TEXT,
    created_at TEXT NOT NULL, finished_at TEXT, snapshot TEXT NOT NULL
);
"""


class TaskManager:
    def __init__(self, db_path: Path | str, redactor: Redactor | None = None) -> None:
        self._redactor = redactor or REDACTOR
        self._tasks: dict[str, Task] = {}
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(db_path), check_same_thread=False, isolation_level=None)
        self._db.executescript(_SCHEMA)

    def create(self, goal: str, source: str, mode: PermissionMode, backend: str) -> Task:
        task = Task(goal=goal, source=source, permission_mode=mode, backend_used=backend)  # type: ignore[arg-type]
        with self._lock:
            self._tasks[task.id] = task
        return task

    def get(self, task_id: str) -> Task | None:
        with self._lock:
            return self._tasks.get(task_id)

    def active(self) -> list[Task]:
        with self._lock:
            return [t for t in self._tasks.values() if not t.status.terminal]

    def session_tasks(self) -> list[Task]:
        with self._lock:
            return sorted(self._tasks.values(), key=lambda t: t.created_at)

    def save(self, task: Task) -> None:
        snapshot = self._redactor.scrub(task.model_dump(mode="json"))
        import json

        with self._lock:
            self._db.execute(
                "INSERT INTO tasks (id, goal, status, outcome, created_at, finished_at, snapshot) "
                "VALUES (?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status, "
                "outcome=excluded.outcome, finished_at=excluded.finished_at, snapshot=excluded.snapshot",
                (task.id, self._redactor.scrub_text(task.goal), task.status.value,
                 task.outcome.value if task.outcome else None, utc_iso(task.created_at),
                 utc_iso(task.finished_at) if task.finished_at else None, json.dumps(snapshot)),
            )

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, goal, status, outcome, created_at, finished_at FROM tasks "
                "ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        keys = ("id", "goal", "status", "outcome", "created_at", "finished_at")
        return [dict(zip(keys, r, strict=True)) for r in rows]

    def close(self) -> None:
        with self._lock:
            self._db.close()


__all__ = ["TaskManager", "TaskStatus"]
