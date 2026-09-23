"""Parse human-readable durations like '30s', '10m', '1h30m', '2h'."""

from __future__ import annotations

import re

_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_TOKEN_RE = re.compile(r"(\d+)\s*([smhd])", re.IGNORECASE)


def parse_duration(text: str) -> int:
    """Return seconds. Accepts '30s', '10m', '1h', '1h30m', or bare integer seconds."""
    if text is None:
        raise ValueError("duration is required")
    s = text.strip().lower()
    if not s:
        raise ValueError("empty duration")
    if s.isdigit():
        return int(s)
    total = 0
    matched_span = 0
    for m in _TOKEN_RE.finditer(s):
        total += int(m.group(1)) * _UNIT_SECONDS[m.group(2)]
        matched_span += len(m.group(0))
    # Reject garbage like "10x" or "abc"
    if total == 0 or matched_span != len(s.replace(" ", "")):
        raise ValueError(f"could not parse duration: {text!r}")
    return total


def format_ago(seconds: float) -> str:
    """Format a 'how long ago' string for display."""
    s = int(seconds)
    if s < 0:
        s = 0
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60}m {s % 60}s ago"
    return f"{s // 3600}h {(s % 3600) // 60}m ago"


def format_bytes(n: int) -> str:
    """Human-readable byte count."""
    x = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if x < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(x)} {unit}"
            return f"{x:.1f} {unit}"
        x /= 1024
    return f"{x:.1f} TB"
