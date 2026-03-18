from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from helpers.db import (
    get_connection,
    init_db,
    log_event,
    record_port_scan,
    get_port_scan,
    get_recent_events,
    record_wifi_observation,
    get_wifi_observations,
)
from helpers.scans import scan_ports_for_ip
import subprocess
import re
import shutil
import os
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Callable

app = FastAPI(title="Pi Network Sensor")

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Prefer environment overrides and PATH discovery.
ARP_SCAN = os.environ.get("ARP_SCAN") or shutil.which("arp-scan") or "/usr/sbin/arp-scan"
BLUETOOTHCTL = os.environ.get("BLUETOOTHCTL") or shutil.which("bluetoothctl") or "/usr/bin/bluetoothctl"
BASH = shutil.which("bash") or "/usr/bin/bash"
TIMEOUT = shutil.which("timeout") or "/usr/bin/timeout"
IW_CMD = shutil.which("iw") or "/usr/sbin/iw"
IWLIST_CMD = shutil.which("iwlist") or "/sbin/iwlist"
BLE_SCAN_DURATION = int(os.environ.get("BLE_SCAN_DURATION") or "8")

NEW_WINDOW_SECONDS = 300

BASE_CATEGORIES = [
    "pc","laptop","nas","server","iot","mobile","tablet",
    "tv","watch","camera","printer","router","switch","ap","unknown"
]


EVENT_TYPES = [
    "new_device",
    "ip_changed",
    "vendor_changed",
    "ble_name_changed",
    "new_open_ports",
    "port_scan_failed",
    "wifi_bssid_new",
    "wifi_ssid_changed",
    "system_login_failure",
    "system_scan_detected",
    "system_attack_detected",
]


PORT_SCAN_INTERVAL = timedelta(minutes=30)

LAN_SORT_FIELDS: Dict[str, Callable[[Dict[str, Any]], Any]] = {
    "ip": lambda d: d.get("ip") or "",
    "mac": lambda d: d.get("identifier") or "",
    "vendor": lambda d: (d.get("vendor") or "").lower(),
    "alias": lambda d: (d.get("alias") or "").lower(),
    "category": lambda d: (d.get("category") or "").lower(),
    "last_seen": lambda d: d.get("last_seen_raw") or "",
}


SYSTEM_LOG_PATHS = [
    Path("/var/log/auth.log"),
    Path("/var/log/syslog"),
    Path("/var/log/messages"),
]

SYSTEM_LOG_KEYWORDS = {
    "system_login_failure": [
        "failed password",
        "authentication failure",
        "invalid user",
        "pam:authentication failure",
        "login incorrect",
        "maximum authentication attempts",
    ],
    "system_scan_detected": [
        "nmap",
        "masscan",
        "zmap",
        "port scan",
        "scan detected",
        "scanning",
    ],
    "system_attack_detected": [
        "attack",
        "dos",
        "bruteforce",
        "invalid packet",
        "malformed",
        "denied",
    ],
}


init_db()


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


def _tail_lines(path: Path, limit: int = 200) -> List[str]:
    lines = deque(maxlen=limit)
    try:
        with path.open('r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                lines.append(line.rstrip())
    except FileNotFoundError:
        return []
    return list(lines)


def _parse_log_timestamp(line: str) -> Optional[str]:
    match = re.match(r"^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    if not match:
        return None
    ts_str = match.group(1)
    try:
        parsed = datetime.strptime(f"{now().year} {ts_str}", "%Y %b %d %H:%M:%S")
        parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.isoformat()
    except ValueError:
        return None


def _match_system_event(line: str) -> Optional[str]:
    normalized = line.lower()
    for event_type, keywords in SYSTEM_LOG_KEYWORDS.items():
        if any(keyword in normalized for keyword in keywords):
            return event_type
    return None


def get_system_events(limit: int = 25, event_type_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for path in SYSTEM_LOG_PATHS:
        if len(events) >= limit:
            break
        if not path.exists():
            continue
        lines_tail = _tail_lines(path, limit=200)
        for line in reversed(lines_tail):
            detected = _match_system_event(line)
            if not detected:
                continue
            if event_type_filter and detected != event_type_filter:
                continue
            timestamp = _parse_log_timestamp(line) or now().isoformat()
            ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            events.append(
                {
                    "timestamp": timestamp,
                    "event_type": detected,
                    "kind": "system",
                    "identifier": path.name,
                    "detail": line,
                    "ip": ip_match.group(1) if ip_match else None,
                }
            )
            if len(events) >= limit:
                break
    return events


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


def upsert_observation(kind: str, identifier: str, ip: Optional[str] = None, vendor: Optional[str] = None, display_name: Optional[str] = None):
    now_ts = now().isoformat()
    con = get_connection()
    cur = con.cursor()

    cur.execute(
        "SELECT first_seen, last_ip, vendor, display_name FROM observations WHERE kind=? AND identifier=?",
        (kind, identifier),
    )
    row = cur.fetchone()

    vendor_value = vendor or ""
    name_value = display_name or ""

    if row:
        previous_ip = row["last_ip"] or ""
        previous_vendor = row["vendor"] or ""
        previous_name = row["display_name"] or ""
        last_ip = ip if ip else previous_ip
        updated_vendor = vendor_value or previous_vendor
        updated_name = name_value or previous_name
        cur.execute(
            "UPDATE observations SET last_seen=?, last_ip=?, vendor=?, display_name=? WHERE kind=? AND identifier=?",
            (now_ts, last_ip, updated_vendor, updated_name, kind, identifier),
        )
        con.commit()
        con.close()
        return {
            "created": False,
            "ip_changed": bool(ip and previous_ip and previous_ip != ip),
            "vendor_changed": bool(vendor_value and previous_vendor and previous_vendor != vendor_value),
            "display_name_changed": bool(name_value and previous_name and previous_name != name_value),
            "previous_ip": previous_ip,
            "previous_vendor": previous_vendor,
            "previous_display_name": previous_name,
        }

    cur.execute(
        "INSERT INTO observations(kind,identifier,first_seen,last_seen,last_ip,vendor,display_name) VALUES(?,?,?,?,?,?,?)",
        (kind, identifier, now_ts, now_ts, ip or "", vendor_value, name_value),
    )
    con.commit()
    con.close()
    return {
        "created": True,
        "ip_changed": False,
        "vendor_changed": False,
        "display_name_changed": False,
        "previous_ip": "",
        "previous_vendor": "",
        "previous_display_name": "",
    }


def get_observations(kind: str) -> Dict[str, Any]:
    con = get_connection()
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




def get_known(kind):
    con = get_connection()
    cur = con.cursor()
    cur.execute("SELECT * FROM known_devices WHERE kind=?", (kind,))
    rows = cur.fetchall()
    con.close()
    return {r["identifier"]: dict(r) for r in rows}


def get_categories():
    con = get_connection()
    cur = con.cursor()
    cur.execute("SELECT DISTINCT category FROM known_devices")
    rows = [r[0] for r in cur.fetchall() if r[0]]
    con.close()
    return sorted(set(BASE_CATEGORIES + rows))


def upsert_known(kind, identifier, alias, category, notes, approved):
    con = get_connection()
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
    con = get_connection()
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
            vendor = m.group(3).strip()
            hosts.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
            })
            result = upsert_observation("lan", mac, ip, vendor=vendor)
            if result.get("created"):
                log_event("new_device", "lan", mac, f"IP {ip} • vendor {vendor}")
            else:
                if result.get("ip_changed"):
                    log_event("ip_changed", "lan", mac, f"{result['previous_ip']} → {ip}")
                if result.get("vendor_changed"):
                    log_event("vendor_changed", "lan", mac, f"{result['previous_vendor']} → {vendor}")

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

        results.append({"addr": addr, "name": name, "vendor": name})
        result = upsert_observation("ble", addr, vendor=name, display_name=name)
        if result.get("display_name_changed"):
            log_event("ble_name_changed", "ble", addr, f"{result['previous_display_name']} → {name}")
        elif result.get("created"):
            log_event("new_device", "ble", addr, f"Name {name}")

    return results


def ble_nearby() -> Dict[str, Any]:
    ensure_bluetooth_adapter()
    script = "\n".join(
        [
            f"{BLUETOOTHCTL} <<'EOF'",
            "power on",
            "scan on",
            f"sleep {BLE_SCAN_DURATION}",
            "devices",
            "scan off",
            "exit",
            "EOF",
        ]
    )
    timeout = BLE_SCAN_DURATION + 18
    try:
        out = run([BASH, "-c", script], timeout=timeout)
    except RuntimeError as exc:
        message = str(exc)
        if "NotReady" in message or "SetDiscoveryFilter failed" in message:
            raise RuntimeError(
                "El adaptador Bluetooth no está listo. Asegúrate de que Bluetooth esté activado."
            ) from exc
        raise

    devices: Dict[str, str] = {}
    for line in out.splitlines():
        m = re.search(r"Device\s+([0-9A-F:]{17})\s+(.+)", line)
        if not m:
            continue
        addr = m.group(1).lower()
        name = m.group(2).strip()
        if name.startswith("RSSI"):
            continue
        devices[addr] = name

    out_list = [{"addr": a, "name": n} for a, n in devices.items()]
    return {"count": len(out_list), "devices": out_list}


def ensure_bluetooth_adapter() -> None:
    try:
        run([BASH, "-c", f"{BLUETOOTHCTL} power on"], timeout=10)
    except RuntimeError:
        pass


def get_wifi_interface() -> Optional[str]:
    if not IW_CMD:
        return None
    try:
        out = run([IW_CMD, "dev"])
    except RuntimeError:
        return None
    for line in out.splitlines():
        m = re.search(r"Interface\s+(\w+)", line)
        if m:
            return m.group(1)
    return None


def wifi_scan() -> List[Dict[str, Any]]:
    if not IWLIST_CMD:
        raise RuntimeError("IWLIST no disponible en el sistema.")
    iface = get_wifi_interface()
    if not iface:
        raise RuntimeError("No se detecta ninguna interfaz WiFi activa.")
    out = run([IWLIST_CMD, iface, "scan"], timeout=60)
    entries: List[Dict[str, Any]] = []
    blocks = re.split(r"\n\s+Cell\s+\d+\s+-\s+", out)
    for block in blocks[1:]:
        bssid_match = re.search(r"Address:\s*([0-9A-F:]{17})", block)
        ssid_match = re.search(r'ESSID:"([^"]*)"', block)
        channel_match = re.search(r"Channel:(\d+)", block)
        freq_match = re.search(r"Frequency:([0-9\.\sGHz]+)", block)
        signal_match = re.search(r"Signal level=(-?\d+)\s*dBm", block)
        if not bssid_match:
            continue
        bssid = bssid_match.group(1).lower()
        ssid = ssid_match.group(1).strip() if ssid_match else ""
        channel = channel_match.group(1) if channel_match else ""
        frequency = freq_match.group(1).strip() if freq_match else ""
        signal = int(signal_match.group(1)) if signal_match else None
        entries.append(
            {
                "bssid": bssid,
                "ssid": ssid,
                "channel": channel,
                "frequency": frequency,
                "signal": signal,
            }
        )
    return entries


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def _should_scan_ports(identifier: str, ip: str, known_entry: Optional[Dict[str, Any]], port_entry: Optional[Dict[str, Any]]) -> bool:
    if not ip:
        return False
    is_new = not known_entry
    is_unapproved = bool(known_entry and known_entry.get("approved", 0) == 0)
    if not (is_new or is_unapproved):
        return False
    if not port_entry:
        return True
    last_scan = _parse_iso(port_entry.get("last_scan"))
    if not last_scan:
        return True
    return (now() - last_scan) > PORT_SCAN_INTERVAL


def ensure_port_scan_for_device(device: Dict[str, Any], known_entry: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    identifier = device.get("mac")
    ip = device.get("ip")
    if not identifier or not ip:
        return None

    port_entry = get_port_scan("lan", identifier)
    if not _should_scan_ports(identifier, ip, known_entry, port_entry):
        return port_entry

    try:
        scan_result = scan_ports_for_ip(ip)
    except RuntimeError as exc:
        log_event("port_scan_failed", "lan", identifier, str(exc))
        return port_entry

    new_record = record_port_scan("lan", identifier, ip, identifier, scan_result["ports"], scan_result["services"])
    previous_ports = set(port_entry.get("ports", [])) if port_entry else set()
    new_ports = set(new_record.get("ports", []))
    added_ports = sorted(new_ports - previous_ports)
    if added_ports:
        log_event("new_open_ports", "lan", identifier, f"Nuevos puertos: {', '.join(str(p) for p in added_ports)}")

    return new_record



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
    scan_wifi = scan and scan_mode == "wifi"
    filter_mode = request.query_params.get("filter", "all")
    search = (request.query_params.get("q") or "").strip().lower()
    event_type_filter = request.query_params.get("event_type")

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
        if scan_wifi:
            try:
                wifi_scan_results = wifi_scan()
                for net in wifi_scan_results:
                    detail_ssid = net.get("ssid") or "<oculto>"
                    detail = f"{detail_ssid} · canal {net.get('channel','-')}"
                    obs = record_wifi_observation(
                        net["bssid"],
                        net.get("ssid", ""),
                        net.get("channel"),
                        net.get("frequency"),
                    )
                    if obs.get("created"):
                        log_event("wifi_bssid_new", "wifi", net["bssid"], detail)
                    elif obs.get("changed"):
                        log_event(
                            "wifi_ssid_changed",
                            "wifi",
                            net["bssid"],
                            f"{obs.get('previous_ssid','')} → {detail_ssid}",
                        )
            except Exception as e:
                errors.append(f"WiFi scan: {e}")

    known_lan = get_known("lan")
    known_ble = get_known("ble")
    obs_lan = get_observations("lan")
    obs_ble = get_observations("ble")

    port_scan_cache: Dict[str, Dict[str, Any]] = {}
    if scan and scan_lan:
        for host in lan_scan_results:
            identifier = host.get("mac")
            entry = ensure_port_scan_for_device(host, known_lan.get(identifier))
            if entry:
                port_scan_cache[identifier] = entry

    def build_device_list(
        kind: str,
        scanned: List[Dict[str, Any]],
        known: Dict[str, Any],
        observed: Dict[str, Any],
        port_scan_cache: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        # Build a single list of devices that includes scanned results,
        # observations, and known devices.
        devices_by_id: Dict[str, Dict[str, Any]] = {}
        cache = port_scan_cache or {}

        if scanned:
            for d in scanned:
                identifier = d.get("mac") or d.get("addr")
                port_info = cache.get(identifier) or get_port_scan(kind, identifier)
                obs = observed.get(identifier, {})
                known_entry = known.get(identifier, {})
                is_new = _is_new(obs.get("first_seen"))
                ports_list = port_info.get("ports", []) if port_info else []
                services_list = port_info.get("services", []) if port_info else []
                last_scan_ts = port_info.get("last_scan") if port_info else None
                last_scan_fmt = format_ts(last_scan_ts) if last_scan_ts else None
                obs_vendor = obs.get("vendor") or obs.get("display_name")
                devices_by_id[identifier] = {
                    "kind": kind,
                    "identifier": identifier,
                    "ip": d.get("ip"),
                    "vendor": d.get("vendor") or d.get("name") or obs_vendor,
                    "alias": known_entry.get("alias", ""),
                    "category": known_entry.get("category", ""),
                    "approved": known_entry.get("approved", 0),
                    "known": bool(known_entry),
                    "first_seen": format_ts(obs.get("first_seen")),
                    "last_seen": format_ts(obs.get("last_seen")),
                    "first_seen_raw": obs.get("first_seen"),
                    "last_seen_raw": obs.get("last_seen"),
                    "last_ip": obs.get("last_ip"),
                    "new": is_new,
                    "notes": known_entry.get("notes", ""),
                    "ports": ports_list,
                    "services": services_list,
                    "last_scan": last_scan_ts,
                    "last_scan_fmt": last_scan_fmt,
                    "ports_summary": ", ".join(str(p) for p in ports_list[:6]),
                    "ports_count": len(ports_list),
                }
        else:
            for identifier, obs in observed.items():
                port_info = cache.get(identifier) or get_port_scan(kind, identifier)
                known_entry = known.get(identifier, {})
                is_new = _is_new(obs.get("first_seen"))
                ports_list = port_info.get("ports", []) if port_info else []
                services_list = port_info.get("services", []) if port_info else []
                last_scan_ts = port_info.get("last_scan") if port_info else None
                last_scan_fmt = format_ts(last_scan_ts) if last_scan_ts else None
                obs_vendor = obs.get("vendor") or obs.get("display_name")
                devices_by_id[identifier] = {
                    "kind": kind,
                    "identifier": identifier,
                    "ip": obs.get("last_ip"),
                    "vendor": obs_vendor,
                    "alias": known_entry.get("alias", ""),
                    "category": known_entry.get("category", ""),
                    "approved": known_entry.get("approved", 0),
                    "known": bool(known_entry),
                    "first_seen": format_ts(obs.get("first_seen")),
                    "last_seen": format_ts(obs.get("last_seen")),
                    "first_seen_raw": obs.get("first_seen"),
                    "last_seen_raw": obs.get("last_seen"),
                    "last_ip": obs.get("last_ip"),
                    "new": is_new,
                    "notes": known_entry.get("notes", ""),
                    "ports": ports_list,
                    "services": services_list,
                    "last_scan": last_scan_ts,
                    "last_scan_fmt": last_scan_fmt,
                    "ports_summary": ", ".join(str(p) for p in ports_list[:6]),
                    "ports_count": len(ports_list),
                }

        # Include known devices even if they aren't currently observed.
        for identifier, known_entry in known.items():
            if identifier in devices_by_id:
                continue
            port_info = cache.get(identifier) or get_port_scan(kind, identifier)
            obs = observed.get(identifier, {})
            obs_vendor = obs.get("vendor") or obs.get("display_name")
            ports_list = port_info.get("ports", []) if port_info else []
            services_list = port_info.get("services", []) if port_info else []
            last_scan_ts = port_info.get("last_scan") if port_info else None
            last_scan_fmt = format_ts(last_scan_ts) if last_scan_ts else None
            devices_by_id[identifier] = {
                "kind": kind,
                "identifier": identifier,
                "ip": None,
                "vendor": obs_vendor,
                "alias": known_entry.get("alias", ""),
                "category": known_entry.get("category", ""),
                "approved": known_entry.get("approved", 0),
                "known": True,
                "first_seen": None,
                "last_seen": None,
                "first_seen_raw": None,
                "last_seen_raw": None,
                "last_ip": None,
                "new": False,
                "notes": known_entry.get("notes", ""),
                "ports": ports_list,
                "services": services_list,
                "last_scan": last_scan_ts,
                "last_scan_fmt": last_scan_fmt,
                "ports_summary": ", ".join(str(p) for p in ports_list[:6]),
                "ports_count": len(ports_list),
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

    lan_devices = build_device_list("lan", lan_scan_results, known_lan, obs_lan, port_scan_cache)
    ble_devices = build_device_list("ble", ble_scan_results, known_ble, obs_ble)
    lan_sort_by = (request.query_params.get("sort_by") or "").lower()
    lan_sort_dir = (request.query_params.get("sort_dir") or "asc").lower()
    if lan_sort_dir not in {"asc", "desc"}:
        lan_sort_dir = "asc"
    if lan_sort_by in LAN_SORT_FIELDS:
        lan_devices.sort(key=LAN_SORT_FIELDS[lan_sort_by], reverse=(lan_sort_dir == "desc"))

    recent_events = get_recent_events(event_type=event_type_filter)
    system_events = get_system_events(event_type_filter=event_type_filter)
    combined_events = recent_events + system_events
    combined_events.sort(key=lambda ev: ev.get("timestamp") or "", reverse=True)
    combined_events = combined_events[:30]

    wifi_observations_raw = get_wifi_observations()
    observations_map = {
        "lan": obs_lan,
        "ble": obs_ble,
        "wifi": {obs["bssid"]: obs for obs in wifi_observations_raw},
    }
    formatted_events = []
    for ev in combined_events:
        ts = format_ts(ev.get("timestamp"))
        kind = ev.get("kind")
        identifier = ev.get("identifier")
        obs = observations_map.get(kind, {}).get(identifier) if identifier else None
        obs_name = None
        if obs:
            obs_name = obs.get("vendor") or obs.get("display_name") or obs.get("ssid") or obs.get("alias")
        obs_ip = obs.get("last_ip") if obs else None
        target_parts: List[str] = []
        if identifier:
            target_parts.append(identifier)
        if obs_name and obs_name not in target_parts:
            target_parts.append(obs_name)
        if obs_ip and obs_ip not in target_parts:
            target_parts.append(obs_ip)
        event_ip = ev.get("ip")
        if event_ip and event_ip not in target_parts:
            target_parts.append(event_ip)
        target_label = " · ".join(target_parts) if target_parts else "-"
        formatted_events.append(
            {
                **ev,
                "timestamp_fmt": ts or ev.get("timestamp", ""),
                "target_label": target_label,
            }
        )
    wifi_count = len(wifi_observations_raw)
    wifi_observations = [
        {**obs, "last_seen_fmt": format_ts(obs.get("last_seen"))}
        for obs in wifi_observations_raw
    ]

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
                "wifi": "WiFi",
            }.get(scan_mode, ""),
            "events": formatted_events,
            "event_types": EVENT_TYPES,
            "event_type_filter": event_type_filter,
            "wifi_observations": wifi_observations,
            "wifi_count": wifi_count,
            "lan_sort_by": lan_sort_by,
            "lan_sort_dir": lan_sort_dir,
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
