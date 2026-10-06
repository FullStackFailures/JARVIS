"""Append-only, hash-chained audit log (SQLite).

Every entry's hash covers the previous hash, so any in-place edit, deletion or reorder
is detectable by ``verify()``. SQLite triggers additionally reject UPDATE/DELETE through
normal connections. Payloads are redacted *before* hashing and storage.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jarvis.common.util import utc_iso
from jarvis.core.models import AuditEntry
from jarvis.security.redact import REDACTOR, Redactor

GENESIS = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    task_id TEXT,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_task ON audit(task_id);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""


def canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def compute_hash(prev: str, seq: int, ts: str, task_id: str | None, kind: str, payload: str) -> str:
    material = "\x1f".join([prev, str(seq), ts, task_id or "", kind, payload])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass
class VerifyReport:
    ok: bool
    entries: int
    first_bad_seq: int | None = None
    reason: str | None = None


class AuditError(Exception):
    pass


class AuditLog:
    def __init__(self, path: Path | str, redactor: Redactor | None = None) -> None:
        self.path = str(path)
        self._redactor = redactor or REDACTOR
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA busy_timeout=10000")
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        row = self._conn.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        self._last_seq: int = row[0] if row else 0
        self._last_hash: str = row[1] if row else GENESIS

    def append(self, kind: str, task_id: str | None = None, **payload: Any) -> AuditEntry:
        clean = self._redactor.scrub(payload)
        body = canonical(clean)
        with self._lock:
            ts = utc_iso()
            try:
                # The chain head is read INSIDE a write transaction: several processes (jarvisd, CLI one-shots,
                # doctor) share this file, so an in-memory head would fork or collide the chain.
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    row = self._conn.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
                    last_seq, prev = (row[0], row[1]) if row else (0, GENESIS)
                    seq = last_seq + 1
                    digest = compute_hash(prev, seq, ts, task_id, kind, body)
                    self._conn.execute(
                        "INSERT INTO audit (seq, ts, task_id, kind, payload, prev_hash, hash) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (seq, ts, task_id, kind, body, prev, digest),
                    )
                    self._conn.execute("COMMIT")
                except BaseException:
                    self._conn.execute("ROLLBACK")
                    raise
            except sqlite3.Error as exc:
                raise AuditError(f"audit append failed: {exc}") from exc
            self._last_seq, self._last_hash = seq, digest
        return AuditEntry(
            seq=seq, ts=ts, task_id=task_id, kind=kind, payload=json.loads(body),
            prev_hash=prev, hash=digest,
        )

    def verify(self) -> VerifyReport:
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, ts, task_id, kind, payload, prev_hash, hash FROM audit ORDER BY seq"
            ).fetchall()
        prev = GENESIS
        expected_seq = 0
        for seq, ts, task_id, kind, payload, prev_hash, digest in rows:
            expected_seq += 1
            if seq != expected_seq:
                return VerifyReport(False, len(rows), seq, "sequence gap (entry deleted or reordered)")
            if prev_hash != prev:
                return VerifyReport(False, len(rows), seq, "prev_hash does not match previous entry")
            if compute_hash(prev_hash, seq, ts, task_id, kind, payload) != digest:
                return VerifyReport(False, len(rows), seq, "entry content does not match its hash")
            prev = digest
        return VerifyReport(True, len(rows))

    def tail(self, n: int = 20, task_id: str | None = None) -> list[AuditEntry]:
        sql = "SELECT seq, ts, task_id, kind, payload, prev_hash, hash FROM audit"
        args: tuple[Any, ...] = ()
        if task_id:
            sql += " WHERE task_id = ?"
            args = (task_id,)
        sql += " ORDER BY seq DESC LIMIT ?"
        with self._lock:
            rows = self._conn.execute(sql, (*args, n)).fetchall()
        return [
            AuditEntry(seq=r[0], ts=r[1], task_id=r[2], kind=r[3], payload=json.loads(r[4]),
                       prev_hash=r[5], hash=r[6])
            for r in reversed(rows)
        ]

    def count(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0])

    def close(self) -> None:
        with self._lock:
            self._conn.close()
