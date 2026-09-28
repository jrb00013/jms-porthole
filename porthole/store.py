"""
Persistent results store — a small SQLite-backed history of scan/vuln/netmap
runs under ~/.porthole/history.db, so results are diffable over time.

This backs diff.py's `--history` mode: instead of only comparing two files
given at invocation time, a command can diff its current results against
the last stored run of the same kind for the same host/target.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DB_PATH = Path.home() / ".porthole" / "history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    ts TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_kind_target ON runs (kind, target);
"""


def _connect(db_path: Path = None) -> sqlite3.Connection:
    path = db_path or DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.executescript(_SCHEMA)
    return conn


def record_run(kind: str, target: str, data, db_path: Path = None) -> int:
    """Store a snapshot of `data` for (kind, target). Returns the new row id."""
    conn = _connect(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO runs (kind, target, ts, data) VALUES (?, ?, ?, ?)",
            (kind, target, datetime.now(timezone.utc).isoformat(), json.dumps(data, default=str)),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def last_run(kind: str, target: str, db_path: Path = None, before_id: int = None) -> Optional[dict]:
    """Return the most recent stored run for (kind, target), or None."""
    conn = _connect(db_path)
    try:
        query = "SELECT id, ts, data FROM runs WHERE kind = ? AND target = ?"
        params = [kind, target]
        if before_id is not None:
            query += " AND id < ?"
            params.append(before_id)
        query += " ORDER BY id DESC LIMIT 1"
        row = conn.execute(query, params).fetchone()
        if not row:
            return None
        return {"id": row[0], "ts": row[1], "data": json.loads(row[2])}
    finally:
        conn.close()


def history(kind: str, target: str, limit: int = 20, db_path: Path = None) -> list[dict]:
    """Return up to `limit` most recent runs for (kind, target), newest first."""
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, ts, data FROM runs WHERE kind = ? AND target = ? ORDER BY id DESC LIMIT ?",
            (kind, target, limit),
        ).fetchall()
        return [{"id": r[0], "ts": r[1], "data": json.loads(r[2])} for r in rows]
    finally:
        conn.close()


def diff_since_last(kind: str, target: str, data, db_path: Path = None) -> dict:
    """
    Compare `data` against the last stored run for (kind, target) *before*
    this call records the new one. Returns a dict describing what changed;
    always also records the new run as a side effect so history advances.
    """
    previous = last_run(kind, target, db_path=db_path)
    record_run(kind, target, data, db_path=db_path)

    if previous is None:
        return {"has_previous": False, "added": data, "removed": [], "changed": False}

    old_data = previous["data"]

    if isinstance(data, list) and isinstance(old_data, list):
        old_set = {json.dumps(x, sort_keys=True, default=str) for x in old_data}
        new_set = {json.dumps(x, sort_keys=True, default=str) for x in data}
        added = [json.loads(x) for x in (new_set - old_set)]
        removed = [json.loads(x) for x in (old_set - new_set)]
        return {
            "has_previous": True,
            "previous_ts": previous["ts"],
            "added": added,
            "removed": removed,
            "changed": bool(added or removed),
        }

    changed = old_data != data
    return {
        "has_previous": True,
        "previous_ts": previous["ts"],
        "added": data if changed else None,
        "removed": old_data if changed else None,
        "changed": changed,
    }
