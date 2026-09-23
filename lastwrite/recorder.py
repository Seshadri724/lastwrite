"""Storage and configuration manager for the lastwrite persistent rolling recorder."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

MAX_BUFFER_SIZE_MB = 512
BUFFER_DIR_NAME = "lastwrite"


def get_buffer_dir() -> Path:
    """Return the platform-appropriate directory for rolling trace buffers."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            d = Path(base) / BUFFER_DIR_NAME / "buffer"
        else:
            d = Path.home() / ".lastwrite" / "buffer"
    else:
        d = Path.home() / ".lastwrite" / "buffer"
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_status_file() -> Path:
    return get_buffer_dir() / "agent_status.json"


def get_active_buffer_path() -> Path:
    return get_buffer_dir() / "rolling_trace.etl"


def get_active_csv_path() -> Path:
    return get_buffer_dir() / "rolling_trace.csv"


def read_agent_status() -> dict[str, Any]:
    sf = get_status_file()
    if not sf.exists():
        return {"running": False, "pid": None, "lost_events": 0}
    try:
        return json.loads(sf.read_text(encoding="utf-8"))
    except Exception:
        return {"running": False, "pid": None, "lost_events": 0}


def write_agent_status(status_data: dict[str, Any]) -> None:
    sf = get_status_file()
    sf.write_text(json.dumps(status_data, indent=2), encoding="utf-8")


def clear_agent_status() -> None:
    sf = get_status_file()
    if sf.exists():
        try:
            sf.unlink()
        except Exception:
            pass
