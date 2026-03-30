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
    record_scan_history,
    get_scan_history,
    record_monitor_history,
    record_monitor_history_at,
    get_monitor_history_since,
    delete_monitor_history_before,
    get_monitor_status,
    upsert_monitor_status,
    get_events_for_identifier,
    monitor_history_exists,
)
from helpers.scans import scan_ports_for_ip
import subprocess
import re
import shutil
import os
from pathlib import Path
from datetime import datetime, timezone, timedelta, tzinfo
from typing import Optional, Dict, Any, List, Callable
from collections import Counter, deque, OrderedDict
from threading import Event, Lock, Thread
import socket
from urllib.parse import urlparse

app = FastAPI(title="Pi Network Sensor")


def _safe_redirect(url: str, fallback: str = "/ui") -> str:
    """Return url only if it is a safe relative path; otherwise return fallback."""
    parsed = urlparse(url)
    # Reject anything with a scheme or netloc (absolute URLs / protocol-relative)
    if parsed.scheme or parsed.netloc:
        return fallback
    # Must start with /
    if not url.startswith("/"):
        return fallback
    return url

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Prefer environment overrides and PATH discovery.
ARP_SCAN = os.environ.get("ARP_SCAN") or shutil.which("arp-scan") or "/usr/sbin/arp-scan"
BLUETOOTHCTL = os.environ.get("BLUETOOTHCTL") or shutil.which("bluetoothctl") or "/usr/bin/bluetoothctl"
BASH = shutil.which("bash") or "/usr/bin/bash"
TIMEOUT = shutil.which("timeout") or "/usr/bin/timeout"
IW_CMD = shutil.which("iw") or "/usr/sbin/iw"
IWLIST_CMD = shutil.which("iwlist") or "/sbin/iwlist"
JOURNALCTL = shutil.which("journalctl")

def _int_env(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default

BLE_SCAN_DURATION = _int_env("BLE_SCAN_DURATION", 8)

NEW_WINDOW_SECONDS = 300

BASE_CATEGORIES = [
    "pc","laptop","nas","server","iot","mobile","tablet",
    "tv","watch","camera","printer","router","switch","ap","console",
    "repeater","bridge","gateway","speaker","unknown"
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
    "system_login_success",
    "system_login_failure",
    "system_scan_detected",
    "system_attack_detected",
]


PORT_SCAN_INTERVAL = timedelta(minutes=30)

SCAN_INTERVAL_SECONDS = _int_env("SCAN_INTERVAL_SECONDS", 300)
ABSENCE_SCAN_THRESHOLD = max(1, _int_env("ABSENCE_SCAN_THRESHOLD", 3))
app.state.scan_interval = SCAN_INTERVAL_SECONDS
MONITOR_DEFAULT_INTERVAL_MINUTES = _int_env("MONITOR_DEFAULT_INTERVAL_MINUTES", 3)
MONITOR_HISTORY_RETENTION_DAYS = 5
MONITOR_LOG_PATH = BASE_DIR / "logs" / "monitor_history.log"
MONITOR_STATUS_LABELS = {
    "presente": "Presente",
    "ausente": "Ausente",
}
monitor_stop_event = Event()
monitor_lock = Lock()
MONITOR_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
SCAN_HISTORY_LIMIT = 6
SCAN_TYPES = {
    "rapido": "Rápido",
    "medio": "Medio",
    "profundidad": "Profundidad",
}
SCAN_NO_TIMEOUT = {"medio", "profundidad"}

SENSITIVE_PORTS = {22, 23, 80, 443, 445, 554, 3389, 5900, 8080, 8443}

EVENT_RISK_LEVELS = {
    "system_attack_detected": "high",
    "system_scan_detected": "medium",
    "system_login_failure": "medium",
    "system_login_success": "low",
    "new_open_ports": "medium",
    "port_scan_failed": "medium",
    "ble_name_changed": "low",
    "wifi_bssid_new": "low",
    "wifi_ssid_changed": "low",
    "new_device": "medium",
    "ip_changed": "medium",
    "vendor_changed": "low",
}

EVENT_RISK_COLORS = {
    "high": "#b91c1c",
    "medium": "#d97706",
    "low": "#047857",
}

EVENT_RISK_LABELS = {
    "high": "Alto",
    "medium": "Medio",
    "low": "Bajo",
}


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
    "system_login_success": [
        "accepted password",
        "accepted publickey",
        "session opened for user",
        "authentication succeeded",
    ],
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
        "drop",
        "blocked",
        "ban",
    ],
}


scan_cache_lock = Lock()
scan_cache: Dict[str, Any] = {
    "lan": [],
    "ble": [],
    "wifi": [],
    "timestamp": None,
    "lan_summary": {},
    "wifi_summary": {},
}
scan_stop_event = Event()
_DETAIL_CACHE_MAX = 200  # cap entries to avoid unbounded memory growth
detailed_scan_cache: Dict[str, Dict[str, Any]] = {}
detail_cache_lock = Lock()


def _get_local_timezone() -> tzinfo:
    tzinfo_value = datetime.now().astimezone().tzinfo
    if tzinfo_value is None:
        return timezone.utc
    return tzinfo_value


init_db()


def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def now() -> datetime:
    return datetime.now(_get_local_timezone())


def format_ts(ts: Optional[str]) -> Optional[str]:
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(ts)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        local = d.astimezone(_get_local_timezone())
        offset = local.strftime("%z")
        zone = local.strftime("%Z") or offset
        return local.strftime("%Y-%m-%d %H:%M:%S ") + zone
    except Exception:
        return ts


def _tail_lines(path: Path, limit: int = 200) -> List[str]:
    lines = deque(maxlen=limit)
    try:
        with path.open('r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                lines.append(line.rstrip())
    except (FileNotFoundError, PermissionError, OSError):
        return []
    return list(lines)


def _lan_summary(devices: List[Dict[str, Any]]) -> Dict[str, Any]:
    ips = sorted({d.get("ip") for d in devices if d.get("ip")})
    if ips:
        ip_range = f"{ips[0]} - {ips[-1]}" if len(ips) > 1 else ips[0]
        parts = ips[0].split(".")
        network_hint = ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else None
    else:
        ip_range = "-"
        network_hint = None
    vendors = sorted({d.get("vendor") for d in devices if d.get("vendor")})
    vendor_sample = ", ".join(vendors[:3]) if vendors else "-"
    return {
        "count": len(devices),
        "ip_range": ip_range,
        "network_hint": network_hint,
        "vendor_count": len(vendors),
        "vendor_sample": vendor_sample,
    }


def _wifi_summary(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    channels = Counter((entry.get("channel") or "desconocido") for entry in entries)
    channel_list = [
        f"{ch} ({count})" for ch, count in channels.most_common(3) if ch and count
    ]
    return {
        "count": len(entries),
        "top_channels": channel_list or ["Sin datos"],
    }


def assess_device_risk(device: Dict[str, Any]) -> Dict[str, Any]:
    score = 0
    reasons: List[str] = []
    if device.get("new"):
        score += 2
        reasons.append("Dispositivo nuevo")
    if not device.get("known"):
        score += 1
        reasons.append("Dispositivo desconocido")
    if device.get("approved") == 0:
        score += 2
        reasons.append("No aprobado")
    if not device.get("category"):
        score += 1
        reasons.append("Sin tipo asignado")
    ports = device.get("ports") or []
    sensitive = [p for p in ports if p in SENSITIVE_PORTS]
    if sensitive:
        score += len(sensitive)
        reasons.append(
            f"Puertos sensibles abiertos: {', '.join(str(p) for p in sensitive[:3])}"
        )
    level = "low"
    if score >= 6:
        level = "high"
    elif score >= 3:
        level = "medium"
    return {
        "risk_score": score,
        "risk_level": level,
        "risk_reason": "; ".join(reasons) if reasons else "Sin alertas",
        "risk_label": EVENT_RISK_LABELS.get(level, level.title()),
        "risk_color": EVENT_RISK_COLORS.get(level, EVENT_RISK_COLORS["low"]),
    }


def get_event_risk_level(event_type: Optional[str]) -> str:
    return EVENT_RISK_LEVELS.get(event_type, "low")


def _update_scan_cache(lan: List[Dict[str, Any]], ble: List[Dict[str, Any]], wifi: List[Dict[str, Any]]) -> None:
    with scan_cache_lock:
        scan_cache["lan"] = lan
        scan_cache["ble"] = ble
        scan_cache["wifi"] = wifi
        scan_cache["timestamp"] = now().isoformat()
        scan_cache["lan_summary"] = _lan_summary(lan)
        scan_cache["wifi_summary"] = _wifi_summary(wifi)


def _perform_scan_cycle() -> None:
    lan, ble, wifi = [], [], []
    try:
        lan = lan_scan()
    except Exception:
        pass
    try:
        ble = ble_scan()
    except Exception:
        pass
    try:
        wifi = wifi_scan()
    except Exception:
        pass
    _update_scan_cache(lan, ble, wifi)


def _periodic_scanner() -> None:
    _perform_scan_cycle()
    while not scan_stop_event.wait(SCAN_INTERVAL_SECONDS):
        _perform_scan_cycle()


@app.on_event("startup")
def start_periodic_scans():
    thread = Thread(target=_periodic_scanner, daemon=True)
    thread.start()


@app.on_event("shutdown")
def stop_periodic_scans():
    scan_stop_event.set()


def _monitor_background_worker():
    interval = MONITOR_DEFAULT_INTERVAL_MINUTES
    while not monitor_stop_event.wait(interval * 60):
        try:
            collect_monitor_data(interval)
        except Exception as exc:
            print(f"Monitor background error: {exc}")


@app.on_event("startup")
def start_monitor_worker():
    thread = Thread(target=_monitor_background_worker, daemon=True)
    thread.start()


@app.on_event("shutdown")
def stop_monitor_worker():
    monitor_stop_event.set()


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


def _parse_journal_timestamp(line: str) -> Optional[str]:
    match = re.match(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line)
    if not match:
        return None
    ts_str = match.group(1)
    try:
        parsed = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
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
    if events:
        return events
    if not JOURNALCTL:
        return events
    try:
        journal_out = run([JOURNALCTL, "-n", "300", "--no-pager", "-o", "short-iso"], timeout=6)
    except Exception:
        return events
    for line in journal_out.splitlines():
        detected = _match_system_event(line)
        if not detected:
            continue
        if event_type_filter and detected != event_type_filter:
            continue
        timestamp = _parse_journal_timestamp(line) or now().isoformat()
        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        events.append(
            {
                "timestamp": timestamp,
                "event_type": detected,
                "kind": "system",
                "identifier": "journalctl",
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
        previous_previous_ip = row["previous_ip"] if "previous_ip" in row.keys() and row["previous_ip"] else ""
        new_previous_ip = previous_previous_ip
        last_ip = ip if ip else previous_ip
        if ip and previous_ip and ip != previous_ip:
            new_previous_ip = previous_ip
        updated_vendor = vendor_value or previous_vendor
        updated_name = name_value or previous_name
        cur.execute(
            "UPDATE observations SET last_seen=?, last_ip=?, previous_ip=?, vendor=?, display_name=? WHERE kind=? AND identifier=?",
            (now_ts, last_ip, new_previous_ip, updated_vendor, updated_name, kind, identifier),
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


def _build_detail_entry(
    identifier: str,
    ip: Optional[str],
    scan_type: str,
    status: str,
    scan_result: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
    message: Optional[str] = None,
) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "identifier": identifier,
        "ip": ip,
        "scan_type": scan_type,
        "scan_type_label": SCAN_TYPES.get(scan_type, scan_type.title()),
        "status": status,
        "timestamp": now().isoformat(),
    }
    if message:
        entry["status_message"] = message
    if scan_result:
        entry.update(
            {
                "ports": scan_result.get("ports", []),
                "services": scan_result.get("services", []),
                "raw": scan_result.get("raw", ""),
                "info_lines": scan_result.get("info_lines", []),
            }
        )
    if error:
        entry["error"] = error
    return entry


def _store_recent_detail(identifier: str, detail: Dict[str, Any]) -> None:
    with detail_cache_lock:
        if len(detailed_scan_cache) >= _DETAIL_CACHE_MAX:
            detailed_scan_cache.pop(next(iter(detailed_scan_cache)))
        detailed_scan_cache[identifier] = detail


def _execute_scan(identifier: str, ip: str, scan_type: str) -> Dict[str, Any]:
    port_entry = get_port_scan("lan", identifier)
    previous_ports = set(port_entry.get("ports", [])) if port_entry else set()
    timeout_value = None if scan_type in SCAN_NO_TIMEOUT else 60
    try:
        scan_result = scan_ports_for_ip(ip, profile=scan_type, timeout=timeout_value)
        new_record = record_port_scan("lan", identifier, ip, identifier, scan_result["ports"], scan_result["services"])
        record_scan_history(
            "lan",
            identifier,
            scan_type,
            ip,
            scan_result["ports"],
            scan_result["services"],
            scan_result.get("raw", ""),
            scan_result.get("info_lines", []),
        )
        new_ports = set(new_record.get("ports", [])) if new_record else set()
        added_ports = sorted(new_ports - previous_ports)
        if added_ports:
            log_event("new_open_ports", "lan", identifier, f"Nuevos puertos: {', '.join(str(p) for p in added_ports)}")
        return _build_detail_entry(identifier, ip, scan_type, "done", scan_result=scan_result)
    except RuntimeError as exc:
        return _build_detail_entry(identifier, ip, scan_type, "error", error=str(exc))
    except Exception:
        return _build_detail_entry(identifier, ip, scan_type, "error", error="Error inesperado durante el escaneo.")


def _background_scan_worker(identifier: str, ip: str, scan_type: str) -> None:
    detail = _execute_scan(identifier, ip, scan_type)
    _store_recent_detail(identifier, detail)


def _append_monitor_history_log(entries: List[Dict[str, Any]]) -> None:
    if not entries:
        return
    MONITOR_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with MONITOR_LOG_PATH.open("a", encoding="utf-8") as log_file:
        for entry in entries:
            timestamp = entry.get("timestamp") or ""
            identifier = entry.get("identifier") or ""
            status = entry.get("status") or ""
            ip = entry.get("ip") or "-"
            previous_ip = entry.get("previous_ip") or "-"
            detail = (entry.get("detail") or "").replace("\n", " ").strip()
            log_file.write(
                f"{timestamp} {identifier} {status} ip={ip} prev={previous_ip} {detail}\n"
            )


_MONITOR_LOG_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<identifier>\S+)\s+(?P<status>\S+)\s+ip=(?P<ip>\S+)\s+prev=(?P<prev>\S+)\s*(?P<detail>.*)$"
)


def _parse_monitor_log_line(line: str) -> Optional[Dict[str, str]]:
    match = _MONITOR_LOG_RE.match(line.strip())
    if not match:
        return None
    return {
        "timestamp": match.group("ts"),
        "identifier": match.group("identifier"),
        "status": match.group("status"),
        "ip": match.group("ip") if match.group("ip") != "-" else "",
        "previous_ip": match.group("prev") if match.group("prev") != "-" else "",
        "detail": (match.group("detail") or "").strip(),
    }


def _sync_monitor_statuses(kind: str, devices: List[Dict[str, Any]]) -> None:
    for device in devices:
        identifier = device["identifier"]
        status = device["status"]
        ip = device.get("ip") or ""
        previous_ip = device.get("previous_ip") or ""
        last_seen = device.get("last_seen") or ""
        status_detail = device.get("status_detail") or ""

        stored_status = get_monitor_status(kind, identifier)
        stored_status_value = stored_status.get("status") if stored_status else None
        stored_ip = stored_status.get("ip") if stored_status else ""

        ip_changed = bool(ip and stored_ip and ip != stored_ip)
        should_record = stored_status_value != status
        event_detail = status_detail
        history_type = "note"
        if stored_status_value is None:
            history_type = "new" if status == "presente" else "exit"
        elif status != stored_status_value:
            history_type = "entry" if status == "presente" else "exit"
        if not should_record and ip_changed and status == "presente":
            should_record = True
            history_type = "entry"
            if not event_detail:
                event_detail = f"Cambio IP: {stored_ip} > {ip}"

        if should_record:
            record_monitor_history(
                kind,
                identifier,
                status,
                ip,
                previous_ip or stored_ip,
                event_detail,
                history_type=history_type,
            )

        upsert_monitor_status(kind, identifier, status, last_seen, ip, previous_ip)


def collect_monitor_data(interval_minutes: Optional[int] = None) -> Dict[str, Any]:
    with monitor_lock:
        try:
            interval_value = int(interval_minutes) if interval_minutes is not None else MONITOR_DEFAULT_INTERVAL_MINUTES
        except (ValueError, TypeError):
            interval_value = MONITOR_DEFAULT_INTERVAL_MINUTES
        interval_value = max(1, min(60, interval_value))
        scan_interval_seconds = max(1, SCAN_INTERVAL_SECONDS)
        absence_window = timedelta(seconds=scan_interval_seconds * ABSENCE_SCAN_THRESHOLD)
        observed = get_observations("lan")
        known_devices = get_known("lan")
        now_ts = now()
        devices: List[Dict[str, Any]] = []
        for identifier, obs in observed.items():
            known_entry = known_devices.get(identifier, {})
            last_seen_dt = _parse_iso(obs.get("last_seen"))
            last_seen_seconds: Optional[int] = None
            status = "ausente"
            status_class = "missing"
            scans_since_last_seen = 0
            if last_seen_dt:
                delta = now_ts - last_seen_dt
                last_seen_seconds = int(delta.total_seconds())
                scans_since_last_seen = int(last_seen_seconds // scan_interval_seconds)
                if delta < absence_window:
                    status = "presente"
                    status_class = "present"
            current_ip = obs.get("last_ip") or "-"
            previous_ip = obs.get("previous_ip") or ""
            ip_note = ""
            if previous_ip and previous_ip != current_ip and current_ip != "-":
                ip_note = f"Anteriormente {previous_ip}"
            status_detail = ""
            if status == "presente":
                if previous_ip and previous_ip != current_ip and current_ip != "-":
                    status_detail = f"Cambio IP: {previous_ip} > {current_ip}"
                else:
                    status_detail = "Dispositivo presente"
            else:
                last_seen_fmt = format_ts(obs.get("last_seen"))
                status_detail = f"No detectado desde {last_seen_fmt or 'desconocido'}"
            device_name = (
                obs.get("display_name")
                or obs.get("vendor")
                or known_entry.get("alias")
                or "-"
            )
            ip_change_note = ""
            if (
                known_entry
                and previous_ip
                and current_ip != "-"
                and current_ip != previous_ip
            ):
                ip_change_note = f"Cambio IP: {previous_ip} > {current_ip}"
                if device_name and device_name != "-":
                    device_name = f"{device_name} ({ip_change_note})"
                else:
                    device_name = ip_change_note
            devices.append(
                {
                    "identifier": identifier,
                    "ip": current_ip,
                    "previous_ip": previous_ip,
                    "vendor": obs.get("vendor") or "-",
                    "alias": known_entry.get("alias", ""),
                    "category": known_entry.get("category", ""),
                    "approved": known_entry.get("approved", 0),
                    "notes": known_entry.get("notes", ""),
                    "status": status,
                    "status_label": MONITOR_STATUS_LABELS.get(status, status.title()),
                    "status_class": status_class,
                    "status_detail": status_detail,
                    "device_name": device_name,
                    "last_seen": obs.get("last_seen"),
                    "last_seen_fmt": format_ts(obs.get("last_seen")) or "-",
                    "last_seen_delta": last_seen_seconds,
                    "scans_since_last_seen": scans_since_last_seen,
                    "new": _is_new(obs.get("first_seen")),
                    "ip_note": ip_note,
                }
            )
        devices.sort(key=lambda d: (d["status"] != "presente", -(d["last_seen_delta"] or 0), d["identifier"]))
        _sync_monitor_statuses("lan", devices)
        cutoff_iso = (datetime.now(timezone.utc) - timedelta(days=MONITOR_HISTORY_RETENTION_DAYS)).isoformat()
        old_entries = delete_monitor_history_before("lan", cutoff_iso)
        _append_monitor_history_log(old_entries)
        history_entries = get_monitor_history_since("lan", cutoff_iso)
        history_payload = [
            {
                "timestamp": entry.get("timestamp"),
                "timestamp_fmt": format_ts(entry.get("timestamp")) or entry.get("timestamp"),
                "identifier": entry.get("identifier"),
                "alias": known_devices.get(entry.get("identifier"), {}).get("alias", "") if entry.get("identifier") else "",
                "status": entry.get("status"),
                "status_label": MONITOR_STATUS_LABELS.get(entry.get("status"), entry.get("status", "").title()),
                "ip": entry.get("ip") or "-",
                "previous_ip": entry.get("previous_ip") or "-",
                "detail": entry.get("detail") or "-",
                "history_type": entry.get("history_type") or "note",
            }
            for entry in history_entries
        ]
        return {
            "timestamp": now_ts.isoformat(),
            "interval_minutes": interval_value,
            "interval_seconds": interval_value * 60,
            "devices": devices,
            "history": history_payload,
            "history_retention_days": MONITOR_HISTORY_RETENTION_DAYS,
        }
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
                log_event("new_device", "lan", mac, f"IP {ip} > vendor {vendor}")
            else:
                if result.get("ip_changed"):
                    log_event("ip_changed", "lan", mac, f"{result['previous_ip']} > {ip}")
                if result.get("vendor_changed"):
                    log_event("vendor_changed", "lan", mac, f"{result['previous_vendor']} > {vendor}")

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
            log_event("ble_name_changed", "ble", addr, f"{result['previous_display_name']} > {name}")
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
                "El adaptador Bluetooth no esta listo. Asegurate de que Bluetooth este activado."
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


def _normalize_ts(ts: Optional[str]) -> Optional[datetime]:
    dt = _parse_iso(ts)
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_get_local_timezone())


def _build_presence_heatmap(
    history_entries: List[Dict[str, Any]],
    days: int = 5,
    current_status: Optional[str] = None,
    last_seen: Optional[str] = None,
    last_changed: Optional[str] = None,
) -> Dict[str, Any]:
    tz = _get_local_timezone()
    now_ts = now()
    window_start_date = (now_ts - timedelta(days=days - 1)).date()
    window_start = datetime(
        window_start_date.year,
        window_start_date.month,
        window_start_date.day,
        0,
        0,
        0,
        tzinfo=tz,
    )
    window_end = now_ts

    events: List[Dict[str, Any]] = []
    for entry in history_entries:
        ts = _normalize_ts(entry.get("timestamp"))
        if not ts:
            continue
        events.append(
            {
                "timestamp": ts,
                "history_type": entry.get("history_type") or "note",
                "status": entry.get("status"),
            }
        )
    events.sort(key=lambda e: e["timestamp"])

    intervals: List[tuple[datetime, datetime]] = []
    current_start: Optional[datetime] = None
    if events:
        first_type = events[0]["history_type"]
        if first_type == "exit":
            current_start = window_start
    else:
        if current_status == "presente":
            seed_ts = _normalize_ts(last_changed) or _normalize_ts(last_seen) or window_start
            current_start = max(window_start, seed_ts)

    for ev in events:
        ts = ev["timestamp"]
        if ts < window_start:
            continue
        if ev["history_type"] in {"entry", "new"}:
            if current_start is None:
                current_start = ts
        elif ev["history_type"] == "exit":
            start = current_start or window_start
            end = ts
            if end > window_start and start < window_end:
                intervals.append((max(start, window_start), min(end, window_end)))
            current_start = None

    if current_start is not None:
        intervals.append((max(current_start, window_start), window_end))

    weekday_labels = ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"]
    days_list: List[Dict[str, Any]] = []
    for offset in range(days):
        day = window_start_date + timedelta(days=offset)
        label = f"{weekday_labels[day.weekday()]} {day.strftime('%d/%m')}"
        hours_present: List[Dict[str, Any]] = []
        for hour in range(24):
            hour_start = datetime(day.year, day.month, day.day, hour, 0, 0, tzinfo=tz)
            hour_end = hour_start + timedelta(hours=1)
            minutes_present = 0
            for interval_start, interval_end in intervals:
                overlap_start = max(interval_start, hour_start)
                overlap_end = min(interval_end, hour_end)
                if overlap_end > overlap_start:
                    minutes_present += int((overlap_end - overlap_start).total_seconds() // 60)
            minutes_present = min(60, max(0, minutes_present))
            hours_present.append(
                {
                    "minutes": minutes_present,
                    "present": minutes_present > 0,
                }
            )
        days_list.append({"label": label, "hours": hours_present})

    return {"hours": list(range(24)), "days": days_list, "window_start": window_start}


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
    local_ip = get_local_ip()

    errors: List[str] = []
    with scan_cache_lock:
        cached_scan = {
            "lan": list(scan_cache["lan"]),
            "ble": list(scan_cache["ble"]),
            "wifi": list(scan_cache["wifi"]),
            "timestamp": scan_cache.get("timestamp"),
            "lan_summary": dict(scan_cache.get("lan_summary") or {}),
            "wifi_summary": dict(scan_cache.get("wifi_summary") or {}),
        }

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
                            f"{obs.get('previous_ssid','')} > {detail_ssid}",
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
                device_entry = {
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
                device_entry.update(assess_device_risk(device_entry))
                devices_by_id[identifier] = device_entry
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
                device_entry = {
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
                device_entry.update(assess_device_risk(device_entry))
                devices_by_id[identifier] = device_entry

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
            device_entry = {
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
            device_entry.update(assess_device_risk(device_entry))
            devices_by_id[identifier] = device_entry

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

    if not scan_lan:
        lan_scan_results = lan_scan_results or cached_scan["lan"]
    if not scan_ble:
        ble_scan_results = ble_scan_results or cached_scan["ble"]

    lan_devices = build_device_list("lan", lan_scan_results, known_lan, obs_lan, port_scan_cache)
    ble_devices = build_device_list("ble", ble_scan_results, known_ble, obs_ble)
    lan_sort_by = (request.query_params.get("sort_by") or "").lower()
    lan_sort_dir = (request.query_params.get("sort_dir") or "asc").lower()
    if lan_sort_dir not in {"asc", "desc"}:
        lan_sort_dir = "asc"
    if lan_sort_by in LAN_SORT_FIELDS:
        lan_devices.sort(key=LAN_SORT_FIELDS[lan_sort_by], reverse=(lan_sort_dir == "desc"))

    approved_devices = sorted(
        [d for d in lan_devices if d.get("approved") == 1],
        key=lambda item: (item.get("alias") or item.get("identifier")),
    )
    detail_id = request.query_params.get("detail_id")
    with detail_cache_lock:
        detail_scan = detailed_scan_cache.get(detail_id) if detail_id else None
    last_scan_time = cached_scan.get("timestamp")
    lan_summary = cached_scan.get("lan_summary", {})
    wifi_summary = cached_scan.get("wifi_summary", {})

    recent_events = get_recent_events(event_type=event_type_filter)
    system_events = get_system_events(event_type_filter=event_type_filter)
    combined_events = recent_events + system_events
    combined_events.sort(key=lambda ev: ev.get("timestamp") or "", reverse=True)
    combined_events = combined_events[:30]

    wifi_observations_raw = get_wifi_observations()
    wifi_count = len(wifi_observations_raw)
    wifi_observations = [
        {**obs, "last_seen_fmt": format_ts(obs.get("last_seen"))}
        for obs in wifi_observations_raw
    ]
    observations_map = {
        "lan": obs_lan,
        "ble": obs_ble,
        "wifi": {obs["bssid"]: obs for obs in wifi_observations_raw if obs.get("bssid")},
    }
    formatted_events = []
    for ev in combined_events:
        ts = format_ts(ev.get("timestamp"))
        kind = ev.get("kind")
        identifier = ev.get("identifier")
        obs = observations_map.get(kind, {}).get(identifier) if identifier else None
        obs_ip = obs.get("last_ip") if obs else None
        target_parts: List[str] = []
        event_ip = ev.get("ip")
        identifier_ip = obs_ip or event_ip
        if identifier:
            identifier_label = identifier
            if identifier_ip:
                identifier_label = f"{identifier} ({identifier_ip})"
            target_parts.append(identifier_label)
        known_alias = None
        if kind == "lan" and identifier:
            known_alias = known_lan.get(identifier, {}).get("alias")
        obs_name = (
            known_alias
            or (obs.get("display_name") if obs else None)
            or (obs.get("vendor") if obs else None)
            or (obs.get("ssid") if obs else None)
            or (obs.get("alias") if obs else None)
        )
        if event_ip and event_ip not in (identifier_ip, obs_ip):
            target_parts.append(event_ip)
        if obs_name and obs_name not in target_parts:
            target_parts.append(obs_name)
        target_label = " · ".join(target_parts) if target_parts else "-"
        risk_level = ev.get("risk_level") or get_event_risk_level(ev.get("event_type"))
        formatted_events.append(
            {
                **ev,
                "timestamp_fmt": ts or ev.get("timestamp", ""),
                "target_label": target_label,
                "device_name": obs_name or "-",
                "risk_level": risk_level,
                "risk_label": EVENT_RISK_LABELS.get(risk_level, risk_level.title()),
                "risk_color": EVENT_RISK_COLORS.get(risk_level, EVENT_RISK_COLORS["low"]),
            }
        )

    scan_history: List[Dict[str, Any]] = []
    if detail_id:
        history_entries = get_scan_history("lan", detail_id, limit=SCAN_HISTORY_LIMIT)
        for record in history_entries:
            record["timestamp_fmt"] = format_ts(record.get("timestamp")) or record.get("timestamp")
            ports_list = record.get("ports") or []
            services_list = record.get("services") or []
            record["ports_summary"] = ", ".join(str(p) for p in ports_list[:6]) if ports_list else "-"
            record["services_summary"] = ", ".join(services_list[:3]) if services_list else "-"
            record["info_lines"] = record.get("info_lines") or []
        scan_history = history_entries

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
            "approved_devices": approved_devices,
            "last_scan_time": last_scan_time,
            "lan_summary": lan_summary,
            "wifi_summary": wifi_summary,
            "local_ip": local_ip,
            "detail_scan": detail_scan,
            "detail_id": detail_id,
            "scan_history": scan_history,
            "scan_types": SCAN_TYPES,
            "monitor_interval_default": MONITOR_DEFAULT_INTERVAL_MINUTES,
            "monitor_log_path": str(MONITOR_LOG_PATH),
            "monitor_history_retention_days": MONITOR_HISTORY_RETENTION_DAYS,
        },
    )


@app.get("/api/monitor", response_class=JSONResponse)
def monitor_devices(interval_minutes: Optional[int] = None):
    try:
        payload = collect_monitor_data(interval_minutes)
        return JSONResponse(payload)
    except Exception as exc:
        error_detail = str(exc)
        print(f"Monitor API error: {error_detail}")
        return JSONResponse({"error": error_detail, "history": [], "devices": [], "timestamp": now().isoformat(), "interval_minutes": MONITOR_DEFAULT_INTERVAL_MINUTES, "history_retention_days": MONITOR_HISTORY_RETENTION_DAYS})


@app.post("/api/monitor/rebuild", response_class=JSONResponse)
def rebuild_monitor_history():
    if not MONITOR_LOG_PATH.exists():
        return JSONResponse({"error": "No existe el log de monitor.", "inserted": 0, "skipped": 0})
    inserted = 0
    skipped = 0
    try:
        with MONITOR_LOG_PATH.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                parsed = _parse_monitor_log_line(line)
                if not parsed:
                    skipped += 1
                    continue
                if monitor_history_exists(
                    "lan",
                    parsed["identifier"],
                    parsed["status"],
                    parsed["timestamp"],
                    parsed["ip"],
                    parsed["previous_ip"],
                    parsed["detail"],
                ):
                    skipped += 1
                    continue
                record_monitor_history_at(
                    "lan",
                    parsed["identifier"],
                    parsed["status"],
                    parsed["timestamp"],
                    parsed["ip"],
                    parsed["previous_ip"],
                    parsed["detail"],
                    history_type="note",
                )
                inserted += 1
    except Exception as exc:
        return JSONResponse({"error": str(exc), "inserted": inserted, "skipped": skipped})
    return JSONResponse({"inserted": inserted, "skipped": skipped})


@app.get("/device/{identifier}", response_class=HTMLResponse)
def device_detail(request: Request, identifier: str):
    observations = get_observations("lan")
    known_devices = get_known("lan")
    obs = observations.get(identifier, {})
    known = known_devices.get(identifier, {})
    if not obs and not known:
        return RedirectResponse("/ui")

    alias = known.get("alias") or obs.get("display_name") or obs.get("vendor") or ""
    vendor = obs.get("vendor") or known.get("alias") or "Desconocido"
    last_seen = format_ts(obs.get("last_seen")) or "Nunca"
    current_ip = obs.get("last_ip") or "-"
    previous_ip = obs.get("previous_ip") or "-"

    cutoff_iso = (datetime.now(timezone.utc) - timedelta(days=MONITOR_HISTORY_RETENTION_DAYS)).isoformat()
    history_entries = [
        entry
        for entry in get_monitor_history_since("lan", cutoff_iso)
        if entry.get("identifier") == identifier
    ]
    history_sorted = sorted(history_entries, key=lambda entry: entry.get("timestamp") or "", reverse=True)
    day_counts = OrderedDict()
    for offset in range(MONITOR_HISTORY_RETENTION_DAYS - 1, -1, -1):
        day = (now() - timedelta(days=offset)).date()
        label = day.strftime("%d/%m")
        day_counts[label] = {"entry": 0, "exit": 0, "new": 0}

    online_seconds_by_day = {label: 0.0 for label in day_counts}
    session_start: Optional[datetime] = None
    for entry in history_sorted:
        timestamp = _parse_iso(entry.get("timestamp"))
        if not timestamp:
            continue
        day_label = timestamp.date().strftime("%d/%m")
        if day_label not in day_counts:
            continue
        history_type = entry.get("history_type") or "note"
        if history_type in {"entry", "new"}:
            if history_type == "new":
                day_counts[day_label]["new"] += 1
            else:
                day_counts[day_label]["entry"] += 1
            if session_start is None:
                session_start = timestamp
        elif history_type == "exit":
            day_counts[day_label]["exit"] += 1
            if session_start:
                duration = (timestamp - session_start).total_seconds()
                duration_label = session_start.date().strftime("%d/%m")
                if duration_label in online_seconds_by_day:
                    online_seconds_by_day[duration_label] += max(duration, 0)
                session_start = None
    if session_start:
        duration = (now() - session_start).total_seconds()
        duration_label = session_start.date().strftime("%d/%m")
        if duration_label in online_seconds_by_day:
            online_seconds_by_day[duration_label] += max(duration, 0)

    presence_chart = {
        "labels": list(day_counts.keys()),
        "entries": [counts["entry"] for counts in day_counts.values()],
        "exits": [counts["exit"] for counts in day_counts.values()],
        "news": [counts["new"] for counts in day_counts.values()],
    }
    uptime_chart = {
        "labels": list(online_seconds_by_day.keys()),
        "hours": [round(seconds / 3600, 2) for seconds in online_seconds_by_day.values()],
    }

    ip_history = sorted(
        {entry.get("ip") for entry in history_entries if entry.get("ip")},
        reverse=True,
    )
    recent_events = get_events_for_identifier(identifier, limit=12)
    scan_history = get_scan_history("lan", identifier, limit=SCAN_HISTORY_LIMIT)
    monitor_status = get_monitor_status("lan", identifier)
    derived_status = None
    last_seen_dt = _normalize_ts(obs.get("last_seen"))
    if last_seen_dt:
        scan_interval_seconds = max(1, SCAN_INTERVAL_SECONDS)
        absence_window = timedelta(seconds=scan_interval_seconds * ABSENCE_SCAN_THRESHOLD)
        if (now() - last_seen_dt) < absence_window:
            derived_status = "presente"
    presence_heatmap = _build_presence_heatmap(
        history_entries,
        days=MONITOR_HISTORY_RETENTION_DAYS,
        current_status=(derived_status or (monitor_status.get("status") if monitor_status else None)),
        last_seen=(monitor_status.get("last_seen") if monitor_status else obs.get("last_seen")),
        last_changed=(monitor_status.get("last_changed") if monitor_status else None),
    )
    history_rows = []
    for entry in history_sorted:
        history_rows.append(
            {
                **entry,
                "timestamp_fmt": format_ts(entry.get("timestamp")) or entry.get("timestamp"),
                "timestamp_raw": entry.get("timestamp") or "",
            }
        )

    return templates.TemplateResponse(
        "device_detail.html",
        {
            "request": request,
            "device": {
                "identifier": identifier,
                "alias": alias,
                "vendor": vendor,
                "ip": current_ip,
                "previous_ip": previous_ip,
                "last_seen": last_seen,
                "notes": known.get("notes", ""),
            },
            "history_entries": history_rows,
            "presence_chart": presence_chart,
            "uptime_chart": uptime_chart,
            "recent_events": recent_events,
            "scan_history": scan_history,
            "ip_history": ip_history,
            "monitor_history_retention_days": MONITOR_HISTORY_RETENTION_DAYS,
            "format_ts": format_ts,
            "presence_heatmap": presence_heatmap,
        },
    )

def _format_duration(seconds: float) -> str:
    seconds = int(round(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    parts = []
    if hours:
        parts.append(f"{hours}h")
    if minutes or (hours and secs):
        parts.append(f"{minutes}m")
    if secs:
        parts.append(f"{secs}s")
    return " ".join(parts) if parts else "0s"


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

    return RedirectResponse(_safe_redirect(return_url), status_code=303)


@app.post("/lan/scan")
def lan_manual_scan(
    identifier: str = Form(...),
    scan_type: str = Form("rapido"),
    return_url: str = Form("/ui"),
):
    scan_type = (scan_type or "rapido").lower()
    if scan_type not in SCAN_TYPES:
        scan_type = "rapido"
    observations = get_observations("lan")
    entry = observations.get(identifier, {})
    ip = entry.get("last_ip")
    if not ip:
        detail = _build_detail_entry(
            identifier,
            ip,
            scan_type,
            "error",
            error="No hay IP conocida para este dispositivo.",
        )
        _store_recent_detail(identifier, detail)
    else:
        if scan_type in SCAN_NO_TIMEOUT:
            detail = _build_detail_entry(
                identifier,
                ip,
                scan_type,
                "running",
                message=f"Ejecutando escaneo {SCAN_TYPES.get(scan_type)} en curso. Esto puede tardar algunos minutos.",
            )
            _store_recent_detail(identifier, detail)
            thread = Thread(target=_background_scan_worker, args=(identifier, ip, scan_type), daemon=True)
            thread.start()
        else:
            detail = _execute_scan(identifier, ip, scan_type)
            _store_recent_detail(identifier, detail)
    redirect = _safe_redirect(return_url)
    separator = "&" if "?" in redirect else "?"
    return RedirectResponse(f"{redirect}{separator}detail_id={identifier}", status_code=303)


@app.get("/api/scan-status", response_class=JSONResponse)
def scan_status(identifier: str):
    if not identifier:
        return JSONResponse({"status": "missing"})
    with detail_cache_lock:
        detail = detailed_scan_cache.get(identifier)
    if not detail:
        return JSONResponse({"status": "missing"})
    return JSONResponse(detail)


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

    return RedirectResponse(_safe_redirect(return_url), status_code=303)

