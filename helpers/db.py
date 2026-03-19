from __future__ import annotations

import json
import re
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


_ALLOWED_TABLES = frozenset({"known_devices", "observations", "events", "port_scans", "wifi_observations", "config"})
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _ensure_column(cursor: sqlite3.Cursor, table: str, column: str, definition: str) -> None:
    if table not in _ALLOWED_TABLES:
        raise ValueError(f"Table '{table}' is not in the allowed list")
    if not _IDENTIFIER_RE.match(column):
        raise ValueError(f"Column name '{column}' contains invalid characters")
    # definition is also validated to contain only safe SQL type tokens
    if not re.match(r"^[A-Z ]+(?:DEFAULT\s+'[^']*')?$", definition, re.IGNORECASE):
        raise ValueError(f"Column definition '{definition}' is not safe")
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
    CREATE TABLE IF NOT EXISTS scan_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT,
        identifier TEXT,
        scan_type TEXT,
        timestamp TEXT,
        ip TEXT,
        ports TEXT,
        services TEXT,
        raw TEXT,
        info_lines TEXT
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
        frequency TEXT,
        UNIQUE(bssid)
    )
    """
    )
    _ensure_column(cur, "wifi_observations", "frequency", "TEXT DEFAULT ''")

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


def record_scan_history(
    kind: str,
    identifier: str,
    scan_type: str,
    ip: str,
    ports: List[int],
    services: List[str],
    raw: str,
    info_lines: List[str],
) -> None:
    con = get_connection()
    cur = con.cursor()
    now_ts = _now_iso()
    cur.execute(
        """
    INSERT INTO scan_history(kind,identifier,scan_type,timestamp,ip,ports,services,raw,info_lines)
    VALUES(?,?,?,?,?,?,?,?,?)
    """,
        (
            kind,
            identifier,
            scan_type,
            now_ts,
            ip or "",
            json.dumps(ports),
            json.dumps(services),
            raw or "",
            json.dumps(info_lines),
        ),
    )
    con.commit()
    con.close()


def get_scan_history(kind: str, identifier: str, limit: int = 5) -> List[Dict[str, Any]]:
    con = get_connection()
    cur = con.cursor()
    cur.execute(
        "SELECT * FROM scan_history WHERE kind=? AND identifier=? ORDER BY timestamp DESC LIMIT ?",
        (kind, identifier, limit),
    )
    rows = cur.fetchall()
    con.close()
    history: List[Dict[str, Any]] = []
    for row in rows:
        try:
            ports = json.loads(row["ports"]) if row["ports"] else []
        except json.JSONDecodeError:
            ports = []
        try:
            services = json.loads(row["services"]) if row["services"] else []
        except json.JSONDecodeError:
            services = []
        try:
            info_lines = json.loads(row["info_lines"]) if row["info_lines"] else []
        except json.JSONDecodeError:
            info_lines = []
        history.append(
            {
                "kind": row["kind"],
                "identifier": row["identifier"],
                "scan_type": row["scan_type"],
                "timestamp": row["timestamp"],
                "ip": row["ip"],
                "ports": ports,
                "services": services,
                "raw": row["raw"],
                "info_lines": info_lines,
            }
        )
    return history


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


def get_wifi_observation(bssid: str) -> Optional[Dict[str, Any]]:
    con = get_connection()
    cur = con.cursor()
    cur.execute("SELECT * FROM wifi_observations WHERE bssid=?", (bssid,))
    row = cur.fetchone()
    con.close()
    if not row:
        return None
    return dict(row)


def record_wifi_observation(
    bssid: str,
    ssid: str,
    channel: Optional[str],
    frequency: Optional[str],
) -> Dict[str, Any]:
    existing = get_wifi_observation(bssid)
    now_ts = _now_iso()
    con = get_connection()
    cur = con.cursor()
    if existing:
        cur.execute(
            """
        UPDATE wifi_observations
        SET ssid=?, last_seen=?, channel=?, frequency=?
        WHERE bssid=?
        """,
            (ssid or existing.get("ssid", ""), now_ts, channel or existing.get("channel", ""), frequency or existing.get("frequency", ""), bssid),
        )
        con.commit()
        con.close()
        previous_ssid = existing.get("ssid", "") or ""
        changed_ssid = bool(ssid and previous_ssid and ssid != previous_ssid)
        return {
            "created": False,
            "changed": changed_ssid,
            "previous_ssid": previous_ssid,
        }
    cur.execute(
        """
    INSERT INTO wifi_observations(bssid,ssid,first_seen,last_seen,channel,frequency)
    VALUES(?,?,?,?,?,?)
    """,
        (bssid, ssid or "", now_ts, now_ts, channel or "", frequency or ""),
    )
    con.commit()
    con.close()
    return {"created": True, "changed": False, "previous_ssid": ""}


def get_wifi_observations(limit: int = 25) -> List[Dict[str, Any]]:
    con = get_connection()
    cur = con.cursor()
    cur.execute("SELECT * FROM wifi_observations ORDER BY last_seen DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    con.close()
    return [dict(row) for row in rows]
