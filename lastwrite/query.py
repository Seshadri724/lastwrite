"""Historical query engine for querying persistent rolling trace buffers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from .analyzer import Filter, aggregate, filter_events
from .collector import etl_to_csv, resolve_processes, temp_workdir
from .duration import parse_duration
from .parser import correlate_paths, parse_tracerpt_csv
from .recorder import get_active_buffer_path, get_active_csv_path, read_agent_status


def query_historical_buffer(
    duration_str: str = "10m",
    pids: set[int] | None = None,
    process_names: list[str] | None = None,
    path_prefix: str | None = None,
    op: str = "write",
    group_by: str = "folder",
    top: int = 20,
    trace_file: str | Path | None = None,
) -> dict:
    """Query historical file events from active rolling buffer or specified trace file."""
    if trace_file:
        src = Path(trace_file)
        if not src.exists():
            raise FileNotFoundError(f"Trace file not found: {src}")
        if src.suffix.lower() == ".etl":
            with temp_workdir() as wd:
                tmp_csv = wd / "converted.csv"
                etl_to_csv(src, tmp_csv)
                events = list(correlate_paths(parse_tracerpt_csv(tmp_csv)))
        else:
            events = list(correlate_paths(parse_tracerpt_csv(src)))
    else:
        # Check active agent CSV or ETL buffer
        csv_path = get_active_csv_path()
        etl_path = get_active_buffer_path()

        if etl_path.exists():
            # If active trace is running, convert current buffer snapshot
            with temp_workdir() as wd:
                tmp_csv = wd / "query_snapshot.csv"
                try:
                    etl_to_csv(etl_path, tmp_csv)
                    events = list(correlate_paths(parse_tracerpt_csv(tmp_csv)))
                except Exception as ex:
                    if csv_path.exists():
                        events = list(correlate_paths(parse_tracerpt_csv(csv_path)))
                    else:
                        raise RuntimeError(f"Failed parsing rolling recorder buffer: {ex}") from ex
        elif csv_path.exists():
            events = list(correlate_paths(parse_tracerpt_csv(csv_path)))
        else:
            raise RuntimeError(
                "No active rolling recorder buffer found. Start the agent with 'lastwrite agent start'."
            )

    seconds = parse_duration(duration_str) if duration_str else 600
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=seconds)

    target_pids = set(pids) if pids else set()
    if process_names:
        target_pids.update(resolve_processes(process_names))

    ops = {op} if op != "all" else {"write", "read", "create", "delete", "rename", "close"}
    flt = Filter(pids=target_pids if target_pids else None, path_prefix=path_prefix, ops=ops, since=cutoff)
    matched = filter_events(events, flt)

    rows = aggregate(matched, group_by=group_by)
    if top and len(rows) > top:
        rows = rows[:top]

    status = read_agent_status()
    lost_events = status.get("lost_events", 0)

    return {
        "matched_events_count": len(matched),
        "total_events_in_buffer": len(events),
        "since": duration_str,
        "lost_events": lost_events,
        "rows": rows,
        "events": matched,
    }
