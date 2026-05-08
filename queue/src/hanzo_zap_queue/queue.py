"""SQLite-backed FIFO task queue with checkpointing.

One file, atomic, no daemon. Survives process restarts — claim() finds
the oldest PENDING task and atomically transitions it to RUNNING; the
worker checkpoints progress mid-run and either complete()s or fail()s
when finished. fail() with retries-remaining moves the task back to
PENDING with attempts++; after max_attempts the task ends in FAILED.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterator


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


@dataclass
class Task:
    id: str
    kind: str
    payload: dict[str, Any]
    progress: dict[str, Any]
    status: TaskStatus
    attempts: int
    max_attempts: int
    error: str | None
    result: dict[str, Any] | None
    created_at: float
    updated_at: float


_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    payload      TEXT NOT NULL,
    progress     TEXT NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL DEFAULT 'pending',
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    error        TEXT,
    result       TEXT,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status, created_at);
CREATE INDEX IF NOT EXISTS idx_tasks_kind   ON tasks(kind);
"""


class Queue:
    """Thread-safe (per-process) SQLite-backed task queue."""

    def __init__(self, db_path: str | Path = "~/.hanzo/zap-queue.db") -> None:
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # ``check_same_thread=False`` because asyncio worker may run handlers
        # in different threads via run_in_executor; the queue itself
        # serialises with BEGIN IMMEDIATE.
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA busy_timeout=5000;")
        self._conn.executescript(_SCHEMA)

    # ---- enqueue / lookup ---------------------------------------------------

    def enqueue(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        max_attempts: int = 3,
        task_id: str | None = None,
    ) -> str:
        tid = task_id or f"task-{uuid.uuid4().hex[:12]}"
        now = time.time()
        self._conn.execute(
            "INSERT INTO tasks (id, kind, payload, max_attempts, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (tid, kind, json.dumps(payload), max_attempts, now, now),
        )
        return tid

    def get(self, task_id: str) -> Task | None:
        row = self._conn.execute(
            "SELECT * FROM tasks WHERE id=?", (task_id,)
        ).fetchone()
        return _row_to_task(row) if row else None

    def list(
        self,
        *,
        kind: str | None = None,
        status: TaskStatus | None = None,
        limit: int = 100,
    ) -> list[Task]:
        sql = "SELECT * FROM tasks WHERE 1=1"
        args: list[Any] = []
        if kind:
            sql += " AND kind=?"; args.append(kind)
        if status:
            sql += " AND status=?"; args.append(status.value)
        sql += " ORDER BY created_at ASC LIMIT ?"; args.append(limit)
        rows = self._conn.execute(sql, args).fetchall()
        return [_row_to_task(r) for r in rows]

    # ---- worker lifecycle ---------------------------------------------------

    def claim(self, kind: str | None = None) -> Task | None:
        """Atomically transition the oldest PENDING task to RUNNING."""
        cursor = self._conn.cursor()
        cursor.execute("BEGIN IMMEDIATE;")
        try:
            sql = "SELECT * FROM tasks WHERE status='pending'"
            args: list[Any] = []
            if kind:
                sql += " AND kind=?"; args.append(kind)
            sql += " ORDER BY created_at ASC LIMIT 1"
            row = cursor.execute(sql, args).fetchone()
            if not row:
                cursor.execute("COMMIT;")
                return None
            task = _row_to_task(row)
            cursor.execute(
                "UPDATE tasks SET status='running', attempts=attempts+1, updated_at=?"
                " WHERE id=?",
                (time.time(), task.id),
            )
            cursor.execute("COMMIT;")
            task.status = TaskStatus.RUNNING
            task.attempts += 1
            return task
        except Exception:
            cursor.execute("ROLLBACK;")
            raise

    def checkpoint(self, task_id: str, progress: dict[str, Any]) -> None:
        self._conn.execute(
            "UPDATE tasks SET progress=?, updated_at=? WHERE id=?",
            (json.dumps(progress), time.time(), task_id),
        )

    def complete(self, task_id: str, result: dict[str, Any] | None = None) -> None:
        self._conn.execute(
            "UPDATE tasks SET status='done', result=?, updated_at=? WHERE id=?",
            (json.dumps(result) if result is not None else None, time.time(), task_id),
        )

    def fail(self, task_id: str, error: str, *, retry: bool = True) -> None:
        """Mark FAILED, OR if retries remain, move back to PENDING."""
        row = self._conn.execute(
            "SELECT attempts, max_attempts FROM tasks WHERE id=?", (task_id,)
        ).fetchone()
        if not row:
            return
        attempts, max_attempts = row
        if retry and attempts < max_attempts:
            self._conn.execute(
                "UPDATE tasks SET status='pending', error=?, updated_at=? WHERE id=?",
                (error, time.time(), task_id),
            )
        else:
            self._conn.execute(
                "UPDATE tasks SET status='failed', error=?, updated_at=? WHERE id=?",
                (error, time.time(), task_id),
            )

    def delete(self, task_id: str) -> None:
        self._conn.execute("DELETE FROM tasks WHERE id=?", (task_id,))

    def close(self) -> None:
        self._conn.close()


# ---- helpers -------------------------------------------------------------


def _row_to_task(row: tuple) -> Task:
    (
        tid, kind, payload, progress, status, attempts,
        max_attempts, error, result, created_at, updated_at,
    ) = row
    return Task(
        id=tid,
        kind=kind,
        payload=json.loads(payload),
        progress=json.loads(progress) if progress else {},
        status=TaskStatus(status),
        attempts=attempts,
        max_attempts=max_attempts,
        error=error,
        result=json.loads(result) if result else None,
        created_at=created_at,
        updated_at=updated_at,
    )
