from __future__ import annotations

import re
import subprocess
from typing import Any, Dict, List


def scan_ports_for_ip(ip: str, timeout: int = 60) -> Dict[str, Any]:
    cmd = ["nmap", "-Pn", "-T4", "-F", ip]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise RuntimeError("nmap no está instalado o no está en PATH.") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"nmap falló: {exc.output.strip()}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("nmap tardó demasiado y fue detenido automáticamente.") from exc

    ports: List[int] = []
    services: List[str] = []

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

    return {"ports": ports, "services": services, "raw": output}
