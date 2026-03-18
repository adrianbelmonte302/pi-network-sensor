from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Optional
import html

CONFIG_PATHS = [Path(".env"), Path("config.json")]


def _load_config() -> Dict[str, str]:
    cfg = {
        "bot_token": os.environ.get("TELEGRAM_BOT_TOKEN", "").strip(),
        "chat_id": os.environ.get("TELEGRAM_CHAT_ID", "").strip(),
    }
    env_path = Path(".env")
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key == "TELEGRAM_BOT_TOKEN" and not cfg["bot_token"]:
                cfg["bot_token"] = val
            if key == "TELEGRAM_CHAT_ID" and not cfg["chat_id"]:
                cfg["chat_id"] = val
    config_json = Path("config.json")
    if config_json.exists():
        try:
            data = json.loads(config_json.read_text())
        except json.JSONDecodeError:
            data = {}
        cfg.setdefault("bot_token", data.get("TELEGRAM_BOT_TOKEN", "").strip())
        cfg.setdefault("chat_id", data.get("TELEGRAM_CHAT_ID", "").strip())
    return cfg


CONFIG = _load_config()


def is_telegram_configured() -> bool:
    return bool(CONFIG.get("bot_token") and CONFIG.get("chat_id"))


def _escape(value: Optional[str]) -> str:
    return html.escape(str(value or "-"))


def _format_message(event_type: str, kind: str, identifier: str, detail: str, alias: Optional[str], category: Optional[str], ip: Optional[str]) -> str:
    parts = [
        "<b>Pi Network Sensor</b>",
        f"<b>{_escape(event_type)}</b>",
        f"Tipo: {_escape(kind)}",
        f"Identificador: {_escape(identifier)}",
        f"IP: {_escape(ip)}",
        f"Alias: {_escape(alias)}",
        f"Categoría: {_escape(category)}",
        f"Detalle: {_escape(detail)}",
    ]
    return "\n".join(parts)


def send_telegram_message(text: str) -> bool:
    if not is_telegram_configured():
        return False
    token = CONFIG["bot_token"]
    chat_id = CONFIG["chat_id"]
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
    }
    data = urllib.parse.urlencode(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False
