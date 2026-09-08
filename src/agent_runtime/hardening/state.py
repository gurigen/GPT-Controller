from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .common import ControlError, canonical, identifier


class Ledger:
    """Local durable execution ledger. No expired lease grants execution ownership."""
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.executescript('''
              CREATE TABLE IF NOT EXISTS actions (
                id TEXT PRIMARY KEY COLLATE NOCASE, payload_hash TEXT NOT NULL, state TEXT NOT NULL,
                result TEXT, updated REAL NOT NULL
              );
              CREATE TABLE IF NOT EXISTS steps (
                action_id TEXT NOT NULL COLLATE NOCASE, path TEXT NOT NULL, payload_hash TEXT NOT NULL,
                effect TEXT NOT NULL, state TEXT NOT NULL, result TEXT, updated REAL NOT NULL,
                PRIMARY KEY(action_id,path)
              );
              CREATE TABLE IF NOT EXISTS approvals (
                action_id TEXT PRIMARY KEY COLLATE NOCASE, payload_hash TEXT NOT NULL,
                expires REAL NOT NULL, consumed INTEGER NOT NULL DEFAULT 0
              );
            ''')

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=10000")
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def transaction(self):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def begin(self, action_id: str, payload_hash: str) -> dict | None:
        identifier(action_id)
        with self.transaction() as db:
            row = db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
            if row:
                if row["payload_hash"] != payload_hash:
                    raise ControlError("blocked", "Action ID already belongs to a different payload")
                if row["result"] is not None:
                    return json.loads(row["result"])
                raise ControlError("ambiguous", "Action already started without a final result; inspect before issuing a NEW Action")
            db.execute("INSERT INTO actions VALUES(?,?,?,NULL,?)", (action_id, payload_hash, "started", time.time()))
        return None

    def finish(self, action_id: str, result: dict) -> None:
        with self.transaction() as db:
            changed = db.execute("UPDATE actions SET state=?,result=?,updated=? WHERE id=?", (
                result["status"], canonical(result).decode(), time.time(), action_id,
            )).rowcount
            if changed != 1:
                raise ControlError("ambiguous", "completion has no matching execution record")

    def begin_step(self, action_id: str, path: str, payload_hash: str, effect: str) -> dict | None:
        with self.transaction() as db:
            row = db.execute("SELECT * FROM steps WHERE action_id=? AND path=?", (action_id, path)).fetchone()
            if row:
                if row["payload_hash"] != payload_hash:
                    raise ControlError("blocked", "step payload changed after execution started")
                if row["state"] == "succeeded":
                    return json.loads(row["result"])
                if row["effect"] != "read_only":
                    raise ControlError("ambiguous", "previous side effect has no confirmed result")
                db.execute("UPDATE steps SET state='started',updated=? WHERE action_id=? AND path=?", (time.time(), action_id, path))
            else:
                db.execute("INSERT INTO steps VALUES(?,?,?,?,?,NULL,?)", (action_id, path, payload_hash, effect, "started", time.time()))
        return None

    def finish_step(self, action_id: str, path: str, state: str, result: Any) -> None:
        with self.transaction() as db:
            db.execute("UPDATE steps SET state=?,result=?,updated=? WHERE action_id=? AND path=?", (
                state, canonical(result).decode(), time.time(), action_id, path,
            ))

    def approve(self, action_id: str, payload_hash: str, ttl: float = 300) -> None:
        identifier(action_id)
        if not 1 <= ttl <= 3600:
            raise ValueError("approval TTL out of range")
        with self.transaction() as db:
            db.execute("INSERT OR REPLACE INTO approvals VALUES(?,?,?,0)", (action_id, payload_hash, time.time() + ttl))

    def consume_approval(self, action_id: str, payload_hash: str) -> bool:
        with self.transaction() as db:
            changed = db.execute("UPDATE approvals SET consumed=1 WHERE action_id=? AND payload_hash=? AND expires>? AND consumed=0",
                                 (action_id, payload_hash, time.time())).rowcount
        return changed == 1

    def action(self, action_id: str) -> dict | None:
        with self.connection() as db:
            row = db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
            return dict(row) if row else None
