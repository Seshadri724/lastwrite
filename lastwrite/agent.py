"""Background agent controller for the lastwrite persistent ETW rolling recorder."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from typing import Any

from . import admin, collector, recorder


def start_agent(no_admin_check: bool = False) -> dict[str, Any]:
    """Start the persistent rolling recorder ETW session."""
    if not collector.is_windows():
        sys.exit("lastwrite agent: rolling recorder requires Windows OS.")

    admin.require_admin(skip=no_admin_check)

    current_status = get_agent_status()
    if current_status.get("running"):
        print("lastwrite agent: rolling recorder is already running.")
        return current_status

    if collector.kernel_session_exists():
        sys.exit(
            f'lastwrite agent: ETW session "{collector.KERNEL_SESSION_NAME}" is already in use '
            "by Procmon or another tool. Stop it before starting the agent."
        )

    etl_path = recorder.get_active_buffer_path()
    collector.start_kernel_capture(etl_path)

    status_data = {
        "running": True,
        "pid": os.getpid(),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "buffer_file": str(etl_path),
        "lost_events": 0,
    }
    recorder.write_agent_status(status_data)

    print("lastwrite agent: persistent rolling recorder started.")
    print(f"Buffer location: {etl_path}")
    return status_data


def get_agent_status() -> dict[str, Any]:
    """Return status of the rolling recorder agent."""
    recorded_status = recorder.read_agent_status()
    if not collector.is_windows():
        recorded_status["running"] = False
        return recorded_status

    stats = collector.get_session_stats()
    is_running = stats.get("running", False)

    buffer_path = recorder.get_active_buffer_path()
    buffer_size = buffer_path.stat().st_size if buffer_path.exists() else 0

    return {
        "running": is_running,
        "pid": recorded_status.get("pid"),
        "started_at": recorded_status.get("started_at"),
        "buffer_file": str(buffer_path),
        "buffer_size_bytes": buffer_size,
        "buffer_size_mb": round(buffer_size / (1024 * 1024), 2),
        "lost_events": stats.get("lost_events", 0),
        "lost_buffers": stats.get("lost_buffers", 0),
    }


def stop_agent(no_admin_check: bool = False) -> dict[str, Any]:
    """Stop the persistent rolling recorder ETW session."""
    if not collector.is_windows():
        sys.exit("lastwrite agent: rolling recorder requires Windows OS.")

    admin.require_admin(skip=no_admin_check)

    stats = collector.get_session_stats()
    lost_events = stats.get("lost_events", 0)

    if stats.get("running"):
        collector.stop_kernel_capture()

    etl_path = recorder.get_active_buffer_path()
    csv_path = recorder.get_active_csv_path()

    if etl_path.exists():
        try:
            collector.etl_to_csv(etl_path, csv_path)
        except Exception as e:
            sys.stderr.write(f"lastwrite agent warning: failed converting buffer to CSV: {e}\n")

    recorder.clear_agent_status()
    print("lastwrite agent: rolling recorder stopped.")
    return {"running": False, "lost_events": lost_events, "csv_buffer": str(csv_path)}
