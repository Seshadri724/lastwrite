"""Admin / elevation helpers. ETW kernel trace requires admin (same as procmon)."""

from __future__ import annotations

import ctypes
import sys


def is_admin() -> bool:
    """Return True iff the current process is running with admin rights."""
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def require_admin(skip: bool = False) -> None:
    """Print a clear message and exit if not running as admin."""
    if skip or is_admin():
        return
    sys.stderr.write(
        "lastwrite: this command needs Administrator privileges to start an ETW kernel\n"
        "           trace (same requirement as Microsoft's Process Monitor).\n"
        "           Re-run from an elevated terminal, or pass --no-admin-check to skip\n"
        "           this gate (the underlying logman call will then fail with 'Access denied').\n"
    )
    sys.exit(2)
