from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import subprocess
import sqlite3
import re
import shutil
import os
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List

app = FastAPI(title="Pi Network Sensor")

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "known.db"
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Prefer environment overrides and PATH discovery.
ARP_SCAN = os.environ.get("ARP_SCAN") or shutil.which("arp-scan") or "/usr/sbin/arp-scan"
BLUETOOTHCTL = os.environ.get("BLUETOOTHCTL") or shutil.which("bluetoothctl") or "/usr/bin/bluetoothctl"
BASH = shutil.which("bash") or "/usr/bin/bash"
TIMEOUT = shutil.which("timeout") or "/usr/bin/timeout"

NEW_WINDOW_SECONDS = 300

BASE_CATEGORIES = [
    "pc","laptop","nas","server","iot","mobile","tablet",
    "tv","watch","camera","printer","router","switch","ap","unknown"
]


def now() -> datetime:
    return datetime.now(timezone.utc)


def format_ts(ts: Optional[str]) -> Optional[str]:
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(ts)
        return d.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ts


def run(cmd, timeout: int = 60) -> str:
    try:
        return subprocess.check_output(cmd, text=True, timeout=timeout, stderr=subprocess.STDOUT)
    except FileNotFoundError as e:
        raise RuntimeError(f"Command not found: {cmd[0]}") from e
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Command failed ({' '.join(cmd)}): {e.output.strip()}") from e


def _check_command(path: str, friendly: str):
    if not path or not Path(path).exists():
        raise RuntimeError(f"{friendly} not found. Ensure it is installed and available on PATH.")


def upsert_observation(kind: str, identifier: str, ip: Optional[str] = None):
    now_ts = now().isoformat()
    con = db()
    cur = con.cursor()

    cur.execute("SELECT first_seen, last_ip FROM observations WHERE kind=? AND identifier=?", (kind, identifier))
    row = cur.fetchone()

    if row:
        last_ip = ip if ip else row["last_ip"]
        cur.execute(
            "UPDATE observations SET last_seen=?, last_ip=? WHERE kind=? AND identifier=?",
            (now_ts, last_ip, kind, identifier),
        )
    else:
        cur.execute(
            "INSERT INTO observations(kind,identifier,first_seen,last_seen,last_ip) VALUES(?,?,?,?,?)",
            (kind, identifier, now_ts, now_ts, ip or ""),
        )

    con.commit()
    con.close()


def get_observations(kind: str) -> Dict[str, Any]:
    con = db()
    cur = con.cursor()
    cur.execute("SELECT * FROM observations WHERE kind=?", (kind,))
    rows = cur.fetchall()
    con.close()
    return {r["identifier"]: dict(r) for r in rows}


def _is_new(first_seen: Optional[str]) -> bool:
    if not first_seen:
        return False
    try:
        first = datetime.fromisoformat(first_seen)
    except Exception:
        return False
    return (now() - first) < timedelta(seconds=NEW_WINDOW_SECONDS)


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS known_devices(
        kind TEXT,
        identifier TEXT,
        alias TEXT,
        category TEXT,
        notes TEXT,
        approved INTEGER DEFAULT 1,
        UNIQUE(kind,identifier)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS observations(
        kind TEXT,
        identifier TEXT,
        first_seen TEXT,
        last_seen TEXT,
        last_ip TEXT,
        UNIQUE(kind,identifier)
    )
    """)

    con.commit()
    con.close()


init_db()


def get_known(kind):
    con = db()
    cur = con.cursor()
    cur.execute("SELECT * FROM known_devices WHERE kind=?", (kind,))
    rows = cur.fetchall()
    con.close()
    return {r["identifier"]: dict(r) for r in rows}


def get_categories():
    con = db()
    cur = con.cursor()
    cur.execute("SELECT DISTINCT category FROM known_devices")
    rows = [r[0] for r in cur.fetchall() if r[0]]
    con.close()
    return sorted(set(BASE_CATEGORIES + rows))


def upsert_known(kind, identifier, alias, category, notes, approved):
    con = db()
    cur = con.cursor()

    cur.execute("""
    INSERT INTO known_devices(kind,identifier,alias,category,notes,approved)
    VALUES(?,?,?,?,?,?)
    ON CONFLICT(kind,identifier)
    DO UPDATE SET alias=?,category=?,notes=?,approved=?
    """, (kind, identifier, alias, category, notes, approved, alias, category, notes, approved))

    con.commit()
    con.close()


def delete_known(kind: str, identifier: str):
    con = db()
    cur = con.cursor()
    cur.execute("DELETE FROM known_devices WHERE kind=? AND identifier=?", (kind, identifier))
    con.commit()
    con.close()


def lan_scan() -> List[Dict[str, Any]]:
    _check_command(ARP_SCAN, "arp-scan")

    out = run([ARP_SCAN, "--localnet"], 45)

    hosts: List[Dict[str, Any]] = []

    for l in out.splitlines():
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s+(.*)", l)
        if m:
            mac = m.group(2).lower()
            ip = m.group(1)
            hosts.append({
                "ip": ip,
                "mac": mac,
                "vendor": m.group(3),
            })
            upsert_observation("lan", mac, ip)

    return hosts


def ble_scan() -> List[Dict[str, Any]]:
    _check_command(BLUETOOTHCTL, "bluetoothctl")

    discovery = ble_nearby()
    devices = discovery.get("devices", [])
    results: List[Dict[str, Any]] = []

    for device in devices:
        addr = device.get("addr")
        name = device.get("name")
        if not addr:
            continue

        results.append({"addr": addr, "name": name})
        upsert_observation("ble", addr)

    return results


def ble_nearby() -> Dict[str, Any]:
    cmd = f"{TIMEOUT} 10s {BLUETOOTHCTL} scan on"
    try:
        out = run([BASH, "-c", cmd], timeout=25)
    except RuntimeError as exc:
        message = str(exc)
        if "NotReady" in message or "SetDiscoveryFilter failed" in message:
            raise RuntimeError(
                "El adaptador Bluetooth no está listo. Asegúrate de que Bluetooth esté activado."
            ) from exc
        raise

    devices: Dict[str, str] = {}

    for line in out.splitlines():
        m = re.search(r"Device\s+([0-9A-F:]{17})\s+(.+)$", line)
        if not m:
            continue

        addr = m.group(1).lower()
        name = m.group(2).strip()

        if name.startswith("RSSI"):
            continue

        devices[addr] = name

    out_list = [{"addr": a, "name": n} for a, n in devices.items()]
    return {"count": len(out_list), "devices": out_list}



@app.get("/",response_class=HTMLResponse)
def root():
    return RedirectResponse("/ui")


@app.get("/ui", response_class=HTMLResponse)
def ui(request: Request):
    raw_scan = request.query_params.get("scan")
    scan_mode = None
    if raw_scan:
        lower = raw_scan.lower()
        scan_mode = "all" if lower in {"1", "true", "yes", "all"} else lower
    scan = bool(scan_mode)
    scan_lan = scan and scan_mode in ("all", "lan")
    scan_ble = scan and scan_mode in ("all", "ble")
    filter_mode = request.query_params.get("filter", "all")
    search = (request.query_params.get("q") or "").strip().lower()

    errors: List[str] = []

    lan_scan_results: List[Dict[str, Any]] = []
    ble_scan_results: List[Dict[str, Any]] = []

    if scan:
        if scan_lan:
            try:
                lan_scan_results = lan_scan()
            except Exception as e:
                errors.append(f"LAN scan: {e}")
        if scan_ble:
            try:
                ble_scan_results = ble_scan()
            except Exception as e:
                errors.append(f"Bluetooth scan: {e}")
 
    known_lan = get_known("lan")
    known_ble = get_known("ble")
    obs_lan = get_observations("lan")
    obs_ble = get_observations("ble")

    def build_device_list(kind: str, scanned: List[Dict[str, Any]], known: Dict[str, Any], observed: Dict[str, Any]):
        # Build a single list of devices that includes scanned results,
        # observations, and known devices.
        devices_by_id: Dict[str, Dict[str, Any]] = {}

        if scanned:
            for d in scanned:
                identifier = d.get("mac") or d.get("addr")
                obs = observed.get(identifier, {})
                known_entry = known.get(identifier, {})
                is_new = _is_new(obs.get("first_seen"))
                devices_by_id[identifier] = {
                    "kind": kind,
                    "identifier": identifier,
                    "ip": d.get("ip"),
                    "vendor": d.get("vendor") or d.get("name"),
                    "alias": known_entry.get("alias", ""),
                    "category": known_entry.get("category", ""),
                    "approved": known_entry.get("approved", 0),
                    "known": bool(known_entry),
                    "first_seen": format_ts(obs.get("first_seen")),
                    "last_seen": format_ts(obs.get("last_seen")),
                    "last_ip": obs.get("last_ip"),
                    "new": is_new,
                    "notes": known_entry.get("notes", ""),
                }
        else:
            for identifier, obs in observed.items():
                known_entry = known.get(identifier, {})
                is_new = _is_new(obs.get("first_seen"))
                devices_by_id[identifier] = {
                    "kind": kind,
                    "identifier": identifier,
                    "ip": obs.get("last_ip"),
                    "vendor": None,
                    "alias": known_entry.get("alias", ""),
                    "category": known_entry.get("category", ""),
                    "approved": known_entry.get("approved", 0),
                    "known": bool(known_entry),
                    "first_seen": format_ts(obs.get("first_seen")),
                    "last_seen": format_ts(obs.get("last_seen")),
                    "last_ip": obs.get("last_ip"),
                    "new": is_new,
                    "notes": known_entry.get("notes", ""),
                }

        # Include known devices even if they aren't currently observed.
        for identifier, known_entry in known.items():
            if identifier in devices_by_id:
                continue
            devices_by_id[identifier] = {
                "kind": kind,
                "identifier": identifier,
                "ip": None,
                "vendor": None,
                "alias": known_entry.get("alias", ""),
                "category": known_entry.get("category", ""),
                "approved": known_entry.get("approved", 0),
                "known": True,
                "first_seen": None,
                "last_seen": None,
                "last_ip": None,
                "new": False,
                "notes": known_entry.get("notes", ""),
            }

        devices = list(devices_by_id.values())

        def matches_filter(dev: Dict[str, Any]) -> bool:
            if filter_mode == "unknown" and dev.get("known"):
                return False
            if filter_mode == "new" and not dev.get("new"):
                return False
            if filter_mode == "unapproved" and dev.get("approved") == 1:
                return False
            if search:
                haystack = " ".join(str(dev.get(k, "") or "") for k in ["identifier", "ip", "vendor", "alias", "category", "notes"])
                if search not in haystack.lower():
                    return False
            return True

        return [d for d in devices if matches_filter(d)]

    lan_devices = build_device_list("lan", lan_scan_results, known_lan, obs_lan)
    ble_devices = build_device_list("ble", ble_scan_results, known_ble, obs_ble)

    return templates.TemplateResponse(
        "ui.html",
        {
            "request": request,
            "lan": lan_devices,
            "ble": ble_devices,
            "known_lan": known_lan,
            "known_ble": known_ble,
            "categories": get_categories(),
            "errors": errors,
            "filter": filter_mode,
            "search": search,
            "scan": scan,
            "return_url": str(request.url),
            "scan_mode": scan_mode,
            "scan_label": {
                "lan": "LAN",
                "ble": "Bluetooth",
                "all": "Ambos",
            }.get(scan_mode, ""),
        },
    )


@app.post("/set/lan")
def set_lan(
    identifier: str = Form(...),
    alias: str = Form(""),
    category: str = Form(""),
    notes: str = Form(""),
    approved: int = Form(0),
    action: str = Form("save"),
    return_url: str = Form("/ui"),
):
    if action == "delete":
        delete_known("lan", identifier)
    else:
        upsert_known("lan", identifier, alias, category, notes, approved)

    return RedirectResponse(return_url or "/ui", status_code=303)


@app.post("/set/ble")
def set_ble(
    identifier: str = Form(...),
    alias: str = Form(""),
    category: str = Form(""),
    notes: str = Form(""),
    approved: int = Form(0),
    action: str = Form("save"),
    return_url: str = Form("/ui"),
):

    if action == "delete":
        delete_known("ble", identifier)
    else:
        upsert_known("ble", identifier, alias, category, notes, approved)

    return RedirectResponse(return_url or "/ui", status_code=303)
