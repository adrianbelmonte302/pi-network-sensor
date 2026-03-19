from __future__ import annotations

from typing import Any, Dict, List, Optional

import ipaddress
import re
import subprocess

INFO_PREFIXES = (
    "Service Info:",
    "OS details:",
    "Network Distance:",
    "Aggressive OS guesses:",
    "Device type:",
    "Running:",
    "No exact OS matches for host:",
)


SCAN_PROFILES = {
    "rapido": {
        "args": ["-Pn", "-T4", "-sV", "--version-all", "--reason"],
        "timeout": 60,
    },
    "medio": {
        "args": ["-Pn", "-T3", "-sS", "-sV", "--version-light", "--reason"],
        "timeout": None,
    },
    "profundidad": {
        "args": ["-Pn", "-T2", "-A", "-p-", "--max-retries", "1", "--reason"],
        "timeout": None,
    },
}


def _build_cmd(ip: str, profile: str) -> (List[str], Optional[int]):
    profile_key = (profile or "rapido").lower()
    if profile_key not in SCAN_PROFILES:
        profile_key = "rapido"
    config = SCAN_PROFILES[profile_key]
    timeout = config["timeout"]
    cmd = ["nmap", *config["args"], ip]
    return cmd, timeout


def scan_ports_for_ip(ip: str, profile: str = "rapido", timeout: Optional[int] = 60) -> Dict[str, Any]:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise RuntimeError(f"Dirección IP no válida: {ip!r}")
    cmd, profile_timeout = _build_cmd(ip, profile)
    effective_timeout = profile_timeout if timeout is None else timeout
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=effective_timeout)
    except FileNotFoundError as exc:
        raise RuntimeError("nmap no está instalado o no está en PATH.") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"nmap falló: {exc.output.strip()}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("nmap tardó demasiado y fue detenido automáticamente.") from exc

    ports: List[int] = []
    services: List[str] = []
    info_lines: List[str] = []

    for line in output.splitlines():
        match = re.search(r"^(\d+)/tcp\s+open\s+([^\s]+)\s*(.*)$", line)
        if not match:
            continue
        port = int(match.group(1))
        service = match.group(2)
        extra = match.group(3).strip()
        ports.append(port)
        label = f"{port}/{service}"
        if extra:
            label = f"{label} {extra}"
        services.append(label)
    for line in output.splitlines():
        stripped = line.strip()
        for prefix in INFO_PREFIXES:
            if stripped.startswith(prefix):
                info_lines.append(stripped[len(prefix) :].strip())
                break

    return {"ports": ports, "services": services, "raw": output, "info_lines": info_lines}
