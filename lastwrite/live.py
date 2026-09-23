"""Live (streaming) mode — repeated short captures rendered as a rolling tail.

We don't have a stable real-time ETW consumer in pure stdlib Python, so live
mode is implemented as a loop: capture for `interval` seconds, parse, filter,
print the new events, repeat until the user hits Ctrl-C. The interval is
short (default 2s) so the UX feels live without losing many events between
windows.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone

from . import collector
from .analyzer import Filter
from .parser import correlate_paths, parse_tracerpt_csv
from .render import render_events_table


def stream(flt: Filter, interval_seconds: float = 2.0,
           on_batch: Callable | None = None) -> None:
    """Loop: capture, parse, emit events matching `flt`. Runs until Ctrl-C."""
    print(f"lastwrite live: capturing in {interval_seconds:.1f}s windows — Ctrl-C to stop\n")
    try:
        while True:
            cap = collector.capture_for(interval_seconds)
            events = list(correlate_paths(parse_tracerpt_csv(cap.csv_path)))
            # Live mode: each iteration is its own fresh capture window.
            local_flt = Filter(pids=flt.pids, path_prefix=flt.path_prefix, ops=flt.ops, since=None)
            matched = [e for e in events if local_flt.matches(e)]
            matched.sort(key=lambda e: e.timestamp)
            if matched:
                header = f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] {len(matched)} event(s)"
                render_events_table(matched, header=header)
            if on_batch is not None:
                on_batch(matched)
    except KeyboardInterrupt:
        print("\nlastwrite live: stopped")
