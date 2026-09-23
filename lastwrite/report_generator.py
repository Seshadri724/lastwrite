"""Self-contained HTML and JSON evidence report generator."""

from __future__ import annotations

import hashlib
import html
import platform
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analyzer import GroupRow
from .parser import FileIoEvent
from .rules import RuleMatch


def compute_sha256(filepath: str | Path) -> str:
    """Compute SHA-256 digest of input trace file."""
    p = Path(filepath)
    if not p.exists():
        return "N/A"
    try:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "N/A"


def build_report_data(
    events: Iterable[FileIoEvent],
    group_rows: list[GroupRow],
    rule_matches: list[RuleMatch],
    source_file: str = "Live Trace",
    lost_events: int = 0,
    process_info: str = "All Processes",
    filters_used: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble structured report dictionary."""
    evt_list = list(events)
    start_time = min((e.timestamp for e in evt_list), default=datetime.now(timezone.utc)).isoformat()
    end_time = max((e.timestamp for e in evt_list), default=datetime.now(timezone.utc)).isoformat()
    total_bytes = sum(e.size for e in evt_list)

    trace_sha256 = compute_sha256(source_file) if source_file != "Live Trace" else "N/A"

    return {
        "metadata": {
            "tool": "lastwrite",
            "version": "0.3.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "host_os": f"{platform.system()} {platform.release()}",
            "hostname": platform.node(),
            "source_trace": str(source_file),
            "trace_sha256": trace_sha256,
            "lost_events": lost_events,
            "filters": filters_used or {},
            "process_info": process_info,
            "time_window": {
                "start": start_time,
                "end": end_time,
            },
        },
        "summary": {
            "total_events": len(evt_list),
            "total_bytes": total_bytes,
            "grouped_items": len(group_rows),
            "suspicious_flags_count": len(rule_matches),
        },
        "rule_flags": [r.to_dict() for r in rule_matches],
        "top_groups": [g.to_dict() for g in group_rows[:50]],
    }


def render_html_report(data: dict[str, Any]) -> str:
    """Render self-contained HTML evidence report with embedded CSS and HTML-escaped data."""
    meta = data["metadata"]
    summary = data["summary"]
    flags = data["rule_flags"]
    groups = data["top_groups"]

    escaped_generated_at = html.escape(str(meta['generated_at']))
    escaped_process_info = html.escape(str(meta['process_info']))
    escaped_source_trace = html.escape(str(meta['source_trace']))
    escaped_trace_sha256 = html.escape(str(meta['trace_sha256']))

    flags_html = ""
    if flags:
        for f in flags:
            severity = html.escape(str(f['severity']))
            rule = html.escape(str(f['rule']))
            description = html.escape(str(f['description']))
            ev_items = "".join(f"<li><code>{html.escape(str(e))}</code></li>" for e in f["evidence"][:10])
            flags_html += f"""
            <div class="flag-card {severity}">
                <div class="flag-title">[{severity.upper()}] {rule} - {description}</div>
                <ul>{ev_items}</ul>
            </div>
            """
    else:
        flags_html = "<p class='no-flags'>No suspicious security flags detected.</p>"

    rows_html = ""
    for g in groups:
        key = html.escape(str(g['key']))
        last_seen = html.escape(str(g['last_seen']))
        rows_html += f"""
        <tr>
            <td><code>{key}</code></td>
            <td class="num">{g['files']}</td>
            <td class="num">{g['ops']}</td>
            <td class="num">{g['bytes']:,} B</td>
            <td>{last_seen}</td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>lastwrite Evidence Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: #1e293b; border-radius: 8px; padding: 2rem; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
        h1 {{ margin-top: 0; color: #38bdf8; font-size: 1.8rem; border-bottom: 2px solid #334155; padding-bottom: 0.5rem; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; background: #0f172a; padding: 1rem; border-radius: 6px; margin-bottom: 2rem; font-size: 0.9rem; }}
        .meta-item strong {{ color: #94a3b8; display: block; font-size: 0.75rem; text-transform: uppercase; }}
        .flag-card {{ padding: 1rem; border-radius: 6px; margin-bottom: 1rem; border-left: 4px solid #64748b; background: #0f172a; }}
        .flag-card.high {{ border-left-color: #ef4444; background: #2c1219; }}
        .flag-card.medium {{ border-left-color: #f59e0b; background: #2b2210; }}
        .flag-title {{ font-weight: bold; margin-bottom: 0.5rem; color: #f1f5f9; }}
        ul {{ margin: 0; padding-left: 1.2rem; font-size: 0.85rem; color: #cbd5e1; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.9rem; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #94a3b8; font-weight: 600; }}
        td.num {{ font-family: monospace; text-align: right; }}
        code {{ font-family: monospace; color: #38bdf8; word-break: break-all; }}
        .no-flags {{ color: #10b981; font-style: italic; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>lastwrite Forensic Evidence Report</h1>
        <div class="meta-grid">
            <div class="meta-item"><strong>Generated At</strong>{escaped_generated_at}</div>
            <div class="meta-item"><strong>Target Process</strong>{escaped_process_info}</div>
            <div class="meta-item"><strong>Source Trace</strong>{escaped_source_trace}</div>
            <div class="meta-item"><strong>SHA-256 Digest</strong><code>{escaped_trace_sha256[:16]}...</code></div>
            <div class="meta-item"><strong>Total Bytes Tracked</strong>{summary['total_bytes']:,} B</div>
            <div class="meta-item"><strong>Lost Events</strong>{meta['lost_events']}</div>
        </div>

        <h2>Security Rules & Anomaly Flags</h2>
        {flags_html}

        <h2>Top Aggregated File Activity</h2>
        <table>
            <thead>
                <tr>
                    <th>Folder / File Path</th>
                    <th style="text-align:right">Files</th>
                    <th style="text-align:right">Ops</th>
                    <th style="text-align:right">Bytes</th>
                    <th>Last Touch</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
