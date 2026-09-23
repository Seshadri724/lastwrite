"""Render aggregated rows as table / json / csv."""

from __future__ import annotations

import csv as _csv
import json
import sys
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import TextIO

from .analyzer import GroupRow, totals
from .duration import format_ago, format_bytes

_GROUP_LABEL = {
    "folder": "FOLDER",
    "file": "FILE",
    "process": "PID",
    "ext": "EXT",
}


def _header_line(pid: int | None, proc_name: str | None,
                 process_names: list[str] | None,
                 path_prefix: str | None,
                 since_seconds: int, group_by: str, op: str,
                 source: str | None = None) -> str:
    bits = []
    if pid is not None:
        if proc_name:
            bits.append(f"PID {pid} ({proc_name})")
        else:
            bits.append(f"PID {pid}")
    if process_names:
        bits.append("process=" + ",".join(process_names))
    if path_prefix:
        bits.append(f"path^={path_prefix}")
    if not bits:
        bits.append("all processes")
    bits.append(f"from {source} (LAST = before trace end)" if source else f"captured for {since_seconds}s")
    bits.append(f"grouped by {group_by}")
    bits.append(f"op={op}")
    return " - ".join([bits[0]] + [", ".join(bits[1:])]) if len(bits) > 1 else bits[0]


def render_table(rows: list[GroupRow], *, group_by: str,
                 header: str | None = None,
                 stream: TextIO | None = None,
                 use_color: bool | None = None,
                 now: datetime | None = None) -> None:
    stream = stream or sys.stdout
    now = now or datetime.now(timezone.utc)

    try:
        from rich.console import Console
        from rich.table import Table
        rich_ok = True
    except Exception:
        rich_ok = False

    if rich_ok:
        console = Console(file=stream, force_terminal=use_color, highlight=False)
        if header:
            console.print(header, style="bold")
            console.print()
        table = Table(show_header=True, header_style="bold", show_lines=False, pad_edge=False)
        table.add_column(_GROUP_LABEL.get(group_by, group_by.upper()), overflow="fold", no_wrap=False)
        table.add_column("FILES", justify="right")
        table.add_column("OPS", justify="right")
        table.add_column("BYTES", justify="right")
        table.add_column("LAST", justify="right")
        for r in rows:
            age = (now - r.last_seen).total_seconds() if r.last_seen.year > 1970 else 0
            table.add_row(
                r.key,
                str(r.file_count),
                str(r.op_count),
                format_bytes(r.total_bytes),
                format_ago(age),
            )
        if rows:
            t = totals(rows)
            table.add_section()
            table.add_row("TOTAL", str(t.file_count), str(t.op_count), format_bytes(t.total_bytes), "")
        console.print(table)
        if not rows:
            console.print("[dim](no events matched)[/dim]")
        return

    # Plain-text fallback (no rich).
    if header:
        stream.write(header + "\n\n")
    label = _GROUP_LABEL.get(group_by, group_by.upper())
    if not rows:
        stream.write(f"{label}: (no events matched)\n")
        return
    key_w = max(len(label), max(len(r.key) for r in rows))
    stream.write(f"{label.ljust(key_w)}  FILES   OPS     BYTES  LAST\n")
    for r in rows:
        age = (now - r.last_seen).total_seconds() if r.last_seen.year > 1970 else 0
        stream.write(
            f"{r.key.ljust(key_w)}  "
            f"{r.file_count:>5}  {r.op_count:>4}  {format_bytes(r.total_bytes):>8}  {format_ago(age)}\n"
        )
    t = totals(rows)
    stream.write(f"{'TOTAL'.ljust(key_w)}  {t.file_count:>5}  {t.op_count:>4}  {format_bytes(t.total_bytes):>8}\n")


def render_json(rows: list[GroupRow], *, group_by: str,
                meta: dict | None = None, stream: TextIO | None = None) -> None:
    stream = stream or sys.stdout
    out = {
        "group_by": group_by,
        "rows": [r.to_dict() for r in rows],
        "totals": totals(rows).to_dict(),
    }
    if meta:
        out["meta"] = meta
    json.dump(out, stream, indent=2, default=str)
    stream.write("\n")


def render_csv(rows: list[GroupRow], *, group_by: str, stream: TextIO | None = None) -> None:
    stream = stream or sys.stdout
    w = _csv.writer(stream, lineterminator="\n")
    w.writerow([group_by, "files", "ops", "bytes", "last_seen"])
    for r in rows:
        w.writerow([r.key, r.file_count, r.op_count, r.total_bytes, r.last_seen.isoformat()])


def render_events_table(events: Iterable, *, header: str | None = None,
                        stream: TextIO | None = None, now: datetime | None = None) -> None:
    """Live / verbose mode: one row per event, newest first as they arrive."""
    stream = stream or sys.stdout
    now = now or datetime.now(timezone.utc)
    try:
        from rich.console import Console
        from rich.table import Table
    except Exception:
        Console = None  # type: ignore

    if Console is None:
        if header:
            stream.write(header + "\n")
        for e in events:
            stream.write(f"{e.timestamp.isoformat()}  pid={e.pid}  {e.op:6}  {format_bytes(e.size):>8}  {e.file_path}\n")
        return

    console = Console(file=stream, highlight=False)
    if header:
        console.print(header, style="bold")
    table = Table(show_header=True, header_style="bold")
    table.add_column("TIME", justify="right")
    table.add_column("PID", justify="right")
    table.add_column("OP")
    table.add_column("BYTES", justify="right")
    table.add_column("FILE", overflow="fold")
    for e in events:
        age = (now - e.timestamp).total_seconds() if e.timestamp.year > 1970 else 0
        table.add_row(format_ago(age), str(e.pid), e.op, format_bytes(e.size), e.file_path)
    console.print(table)
