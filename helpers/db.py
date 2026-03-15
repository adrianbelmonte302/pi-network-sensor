from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "known.db"


def get_connection() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    return con


def _ensure_column(cursor: sqlite3.Cursor, table: str, column: str, definition: str) -> None:
    cursor.execute(f"PRAGMA table_info({table})")
    existing = {row["name"] for row in cursor.fetchall()}
    if column not in existing:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db() -> None:
    con = get_connection()
    cur = con.cursor()

    cur.execute(
        """
    CREATE TABLE IF NOT EXISTS known_devices(
        kind TEXT,
        identifier TEXT,
        alias TEXT,
        category TEXT,
        notes TEXT,
        approved INTEGER DEFAULT 1,
        UNIQUE(kind,identifier)
    )
    """
    )

    cur.execute(
        """
    CREATE TABLE IF NOT EXISTS observations(
        kind TEXT,
        identifier TEXT,
        first_seen TEXT,
        last_seen TEXT,
        last_ip TEXT,
        vendor TEXT DEFAULT '',
        display_name TEXT DEFAULT '',
        UNIQUE(kind,identifier)
    )
    """
    )

    _ensure_column(cur, "observations", "vendor", "TEXT DEFAULT ''")
    _ensure_column(cur, "observations", "display_name", "TEXT DEFAULT ''")

    cur.execute(
        """
    CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        event_type TEXT,
        kind TEXT,
        identifier TEXT,
        detail TEXT
    )
    """
    )

    cur.execute(
        """
    CREATE TABLE IF NOT EXISTS port_scans(
        kind TEXT,
        identifier TEXT,
        ip TEXT,
        mac TEXT,
        ports TEXT,
        services TEXT,
        last_scan TEXT,
        PRIMARY KEY(kind,identifier)
    )
    """
    )

    cur.execute(
        """
    CREATE TABLE IF NOT EXISTS wifi_observations(
        bssid TEXT,
        ssid TEXT,
        first_seen TEXT,
        last_seen TEXT,
        channel TEXT,
        UNIQUE(bssid)
    )
    """
    )

    cur.execute(
        """
    CREATE TABLE IF NOT EXISTS config(
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """
    )

    con.commit()
    con.close()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_event(event_type: str, kind: str, identifier: str, detail: str) -> None:
    con = get_connection()
    cur = con.cursor()
    cur.execute(
        "INSERT INTO events(timestamp,event_type,kind,identifier,detail) VALUES(?,?,?,?,?)",
        (_now_iso(), event_type, kind, identifier, detail),
    )
    con.commit()
    con.close()


def record_port_scan(
    kind: str,
    identifier: str,
    ip: str,
    mac: str,
    ports: List[int],
    services: List[str],
) -> Dict[str, Any]:
    con = get_connection()
    cur = con.cursor()
    now_ts = _now_iso()
    cur.execute(
        """
    INSERT INTO port_scans(kind,identifier,ip,mac,ports,services,last_scan)
    VALUES(?,?,?,?,?,?,?)
    ON CONFLICT(kind,identifier) DO UPDATE SET
      ip=excluded.ip,
      mac=excluded.mac,
      ports=excluded.ports,
      services=excluded.services,
      last_scan=excluded.last_scan
    """,
        (kind, identifier, ip or "", mac or "", json.dumps(ports), json.dumps(services), now_ts),
    )
    con.commit()
    con.close()
    return {
        "kind": kind,
        "identifier": identifier,
        "ip": ip,
        "mac": mac,
        "ports": ports,
        "services": services,
        "last_scan": now_ts,
    }


def get_port_scan(kind: str, identifier: str) -> Optional[Dict[str, Any]]:
    con = get_connection()
    cur = con.cursor()
    cur.execute("SELECT * FROM port_scans WHERE kind=? AND identifier=?", (kind, identifier))
    row = cur.fetchone()
    con.close()
    if not row:
        return None
    try:
        ports = json.loads(row["ports"]) if row["ports"] else []
    except json.JSONDecodeError:
        ports = []
    try:
        services = json.loads(row["services"]) if row["services"] else []
    except json.JSONDecodeError:
        services = []
    return {
        "kind": row["kind"],
        "identifier": row["identifier"],
        "ip": row["ip"],
        "mac": row["mac"],
        "ports": ports,
        "services": services,
        "last_scan": row["last_scan"],
    }


def get_recent_events(limit: int = 25, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
    con = get_connection()
    cur = con.cursor()
    if event_type:
        cur.execute(
            "SELECT * FROM events WHERE event_type=? ORDER BY timestamp DESC LIMIT ?",
            (event_type, limit),
        )
    else:
        cur.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    con.close()
    return [dict(row) for row in rows]
