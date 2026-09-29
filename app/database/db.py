"""
Phase 3: Database layer.

Stores events, process snapshots, scores, alerts, and incidents in SQLite.

Implementation note: uses stdlib `sqlite3` directly rather than SQLAlchemy.
SQLite itself needs no server - it's just a file at data/rdrs.db. If you'd
rather use SQLAlchemy's ORM, this module is the only place that would need
rewriting; every caller goes through the functions below, never raw SQL.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from app.core.models import FileEvent, ProcessSnapshot, ThreatScore, Incident

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    src_path TEXT NOT NULL,
    dest_path TEXT,
    extension TEXT,
    entropy REAL,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    name TEXT NOT NULL,
    cpu_percent REAL,
    memory_rss_bytes INTEGER,
    exe_path TEXT,
    parent_pid INTEGER,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    score INTEGER NOT NULL,
    band TEXT NOT NULL,
    fired_signals TEXT,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    score INTEGER NOT NULL,
    band TEXT NOT NULL,
    message TEXT,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    score INTEGER NOT NULL,
    band TEXT NOT NULL,
    suspect_process TEXT,
    suspect_pid INTEGER,
    affected_files TEXT,
    quarantine_paths TEXT,
    simulated_response INTEGER NOT NULL
);
"""

_local = threading.local()
_db_path: Optional[str] = None


def init_db(path: str) -> None:
    """Create tables if they don't exist. Call once at startup (or between
    tests) - resets any cached connection on the calling thread so a new
    path takes effect immediately rather than reusing a stale connection."""
    global _db_path
    _db_path = path
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    if hasattr(_local, "conn") and _local.conn is not None:
        _local.conn.close()
        _local.conn = None
    with _connect() as conn:
        conn.executescript(_SCHEMA)


def _connect() -> sqlite3.Connection:
    # One connection per thread (the monitor thread and the API thread both
    # write/read) - sqlite3 connections aren't safe to share across threads.
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(_db_path, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
    return _local.conn


@contextmanager
def _cursor() -> Iterator[sqlite3.Cursor]:
    conn = _connect()
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    finally:
        cur.close()
        # ThreadingHTTPServer may create short-lived worker threads. Closing
        # after each operation prevents those workers from leaking SQLite
        # handles on Windows while retaining the thread-safe connection model.
        conn.close()
        _local.conn = None


def save_event(event: FileEvent) -> None:
    with _cursor() as cur:
        cur.execute(
            "INSERT INTO events (event_type, src_path, dest_path, extension, entropy, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (event.event_type, event.src_path, event.dest_path, event.extension,
             event.entropy, event.timestamp.isoformat()),
        )


def save_process_snapshot(snap: ProcessSnapshot) -> None:
    with _cursor() as cur:
        cur.execute(
            "INSERT INTO processes (pid, name, cpu_percent, memory_rss_bytes, exe_path, parent_pid, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (snap.pid, snap.name, snap.cpu_percent, snap.memory_rss_bytes,
             snap.exe_path, snap.parent_pid, snap.timestamp.isoformat()),
        )


def save_score(score: ThreatScore) -> None:
    with _cursor() as cur:
        cur.execute(
            "INSERT INTO scores (score, band, fired_signals, timestamp) VALUES (?, ?, ?, ?)",
            (score.score, score.band, json.dumps(score.fired_signals), score.timestamp.isoformat()),
        )


def save_alert(score: ThreatScore, message: str) -> int:
    with _cursor() as cur:
        cur.execute(
            "INSERT INTO alerts (score, band, message, timestamp) VALUES (?, ?, ?, ?)",
            (score.score, score.band, message, score.timestamp.isoformat()),
        )
        return cur.lastrowid


def save_incident(incident: Incident) -> int:
    with _cursor() as cur:
        cur.execute(
            "INSERT INTO incidents (created_at, score, band, suspect_process, suspect_pid, "
            "affected_files, quarantine_paths, simulated_response) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (incident.created_at.isoformat(), incident.score, incident.band,
             incident.suspect_process, incident.suspect_pid,
             json.dumps(incident.affected_files), json.dumps(incident.quarantine_paths),
             int(incident.simulated_response)),
        )
        return cur.lastrowid


def recent_events(limit: int = 50) -> list[dict]:
    with _cursor() as cur:
        cur.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]


def recent_alerts(limit: int = 50) -> list[dict]:
    with _cursor() as cur:
        cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]


def recent_incidents(limit: int = 50) -> list[dict]:
    with _cursor() as cur:
        cur.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,))
        rows = [dict(row) for row in cur.fetchall()]
        for row in rows:
            row["affected_files"] = json.loads(row["affected_files"] or "[]")
            row["quarantine_paths"] = json.loads(row["quarantine_paths"] or "[]")
            row["simulated_response"] = bool(row["simulated_response"])
        return rows


def get_incident(incident_id: int) -> Optional[dict]:
    with _cursor() as cur:
        cur.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        d["affected_files"] = json.loads(d["affected_files"] or "[]")
        d["quarantine_paths"] = json.loads(d["quarantine_paths"] or "[]")
        d["simulated_response"] = bool(d["simulated_response"])
        return d


def counts() -> dict:
    with _cursor() as cur:
        out = {}
        for table in ("events", "processes", "scores", "alerts", "incidents"):
            cur.execute(f"SELECT COUNT(*) as c FROM {table}")
            out[table] = cur.fetchone()["c"]
        return out
