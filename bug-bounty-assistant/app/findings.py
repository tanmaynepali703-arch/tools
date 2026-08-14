"""
findings.py – Persist scans and findings to a local SQLite database.

Schema
------
scans      – one row per URL scanned (timestamp, status, error)
findings   – one row per discovered item (type, description, severity, url)
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator


# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------

DDL = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT    NOT NULL,
    scanned_at  TEXT    NOT NULL,
    status_code INTEGER,
    error       TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    finding_type TEXT   NOT NULL,
    description TEXT    NOT NULL,
    severity    TEXT    NOT NULL DEFAULT 'info',
    url         TEXT
);
"""


def init_db(db_path: str) -> None:
    """Create tables if they do not already exist."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with _connect(db_path) as conn:
        conn.executescript(DDL)


@contextmanager
def _connect(db_path: str) -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------

def save_scan(
    db_path: str,
    url: str,
    status_code: int | None = None,
    error: str | None = None,
) -> int:
    """
    Insert a scan record and return its new ``id``.

    Parameters
    ----------
    db_path:
        Path to the SQLite database file.
    url:
        The URL that was scanned.
    status_code:
        HTTP status returned, or None on network error.
    error:
        Error message if the request failed.

    Returns
    -------
    int
        The auto-generated scan ID.
    """
    now = datetime.now(timezone.utc).isoformat()
    with _connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO scans (url, scanned_at, status_code, error) "
            "VALUES (?, ?, ?, ?)",
            (url, now, status_code, error),
        )
        return cur.lastrowid  # type: ignore[return-value]


def save_finding(
    db_path: str,
    scan_id: int,
    finding_type: str,
    description: str,
    severity: str = "info",
    url: str | None = None,
) -> int:
    """
    Insert a finding record linked to *scan_id* and return its new ``id``.

    Parameters
    ----------
    db_path:
        Path to the SQLite database file.
    scan_id:
        FK reference to the parent scan.
    finding_type:
        Short category label (e.g. ``"form"``, ``"link"``, ``"header"``).
    description:
        Human-readable description of the finding.
    severity:
        One of ``"critical"``, ``"high"``, ``"medium"``, ``"low"``,
        ``"info"`` (default).
    url:
        Optional specific URL related to this finding.

    Returns
    -------
    int
        The auto-generated finding ID.
    """
    with _connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO findings "
            "(scan_id, finding_type, description, severity, url) "
            "VALUES (?, ?, ?, ?, ?)",
            (scan_id, finding_type, description, severity, url),
        )
        return cur.lastrowid  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Read helpers
# ---------------------------------------------------------------------------

def get_scan(db_path: str, scan_id: int) -> dict | None:
    """Return a single scan row as a dict, or None if not found."""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        return dict(row) if row else None


def get_findings_for_scan(db_path: str, scan_id: int) -> list[dict]:
    """Return all findings for *scan_id* as a list of dicts."""
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def list_scans(db_path: str) -> list[dict]:
    """Return all scans ordered by most recent first."""
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]
