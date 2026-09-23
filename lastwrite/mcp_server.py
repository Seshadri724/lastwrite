"""MCP Server exposing lastwrite evidence engine tools for AI agents."""

from __future__ import annotations

import json
import sys
from typing import Any

from . import __version__
from .analyzer import Filter, aggregate, filter_events
from .collector import etl_to_csv, temp_workdir
from .diff_engine import compute_diff
from .parser import correlate_paths, parse_tracerpt_csv
from .query import query_historical_buffer
from .report_generator import build_report_data
from .rules import evaluate_rules

TOOLS = [
    {
        "name": "capture_file_activity",
        "description": "Summarize file I/O activity for a process/PID or path from an ETL trace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "etl_file": {"type": "string", "description": "Path to .etl or .csv trace file"},
                "pid": {"type": "integer", "description": "Target PID to filter"},
                "group_by": {"type": "string", "enum": ["folder", "file", "process", "ext"], "default": "folder"},
                "top": {"type": "integer", "default": 20, "maximum": 100},
            },
            "required": ["etl_file"],
        },
    },
    {
        "name": "query_file_history",
        "description": "Query historical file events from active rolling recorder buffer or trace file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "etl_file": {"type": "string", "description": "Optional trace file path. If omitted, queries active rolling buffer."},
                "since": {"type": "string", "default": "10m", "description": "Time window e.g. 10m, 1h"},
                "path_prefix": {"type": "string", "description": "Filter by starting path"},
                "op": {"type": "string", "enum": ["write", "read", "create", "delete", "all"], "default": "write"},
                "limit": {"type": "integer", "default": 50, "maximum": 500},
            },
        },
    },
    {
        "name": "compare_process_behavior",
        "description": "Run differential analysis between 'before' and 'after' trace files (e.g. installer audit).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "before_etl": {"type": "string", "description": "Path to clean/before .etl file"},
                "after_etl": {"type": "string", "description": "Path to after/installer .etl file"},
                "expected_roots": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of expected installation directories",
                },
            },
            "required": ["before_etl", "after_etl"],
        },
    },
    {
        "name": "detect_suspicious_writes",
        "description": "Evaluate deterministic security rules on a trace file to detect anomalous file activity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "etl_file": {"type": "string", "description": "Path to .etl or .csv trace file"},
                "process_name": {"type": "string", "description": "Process name for context checking"},
                "expected_roots": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Expected install paths",
                },
            },
            "required": ["etl_file"],
        },
    },
    {
        "name": "generate_evidence_report",
        "description": "Produce a complete structured JSON evidence bundle for incident triage.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "etl_file": {"type": "string", "description": "Path to .etl or .csv trace file"},
                "pid": {"type": "integer", "description": "PID filter if applicable"},
            },
            "required": ["etl_file"],
        },
    },
]


def _read_events_from_file(filepath: str):
    if filepath.lower().endswith(".etl"):
        with temp_workdir() as wd:
            csv_path = wd / "trace.csv"
            etl_to_csv(filepath, csv_path)
            return list(correlate_paths(parse_tracerpt_csv(csv_path)))
    return list(correlate_paths(parse_tracerpt_csv(filepath)))


def handle_call_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    try:
        if name == "capture_file_activity":
            raw_top = int(args.get("top", 20))
            top = max(1, min(raw_top, 100))
            events = _read_events_from_file(args["etl_file"])
            flt = Filter(pids={args["pid"]} if "pid" in args and args["pid"] is not None else None)
            filtered = filter_events(events, flt)
            group_by = args.get("group_by", "folder")
            rows = aggregate(filtered, group_by=group_by)[:top]
            return {"rows": [r.to_dict() for r in rows]}

        elif name == "query_file_history":
            raw_limit = int(args.get("limit", 50))
            limit = max(1, min(raw_limit, 500))
            proc_names = [args["process_name"]] if args.get("process_name") else None
            res = query_historical_buffer(
                duration_str=args.get("since", "10m"),
                process_names=proc_names,
                path_prefix=args.get("path_prefix"),
                op=args.get("op", "write"),
                trace_file=args.get("etl_file"),
            )
            return {
                "since": res["since"],
                "lost_events": res["lost_events"],
                "total_matched": res["matched_events_count"],
                "events": [
                    {
                        "op": e.op,
                        "pid": e.pid,
                        "file_path": e.file_path,
                        "bytes": e.size,
                        "timestamp": e.timestamp.isoformat(),
                    }
                    for e in res["events"][:limit]
                ],
            }

        elif name == "compare_process_behavior":
            before = _read_events_from_file(args["before_etl"])
            after = _read_events_from_file(args["after_etl"])
            res = compute_diff(before, after, expected_roots=args.get("expected_roots"))
            return res.to_dict()

        elif name == "detect_suspicious_writes":
            events = _read_events_from_file(args["etl_file"])
            rules = evaluate_rules(
                events,
                expected_roots=args.get("expected_roots"),
                process_name=args.get("process_name"),
            )
            return {"flags": [r.to_dict() for r in rules]}

        elif name == "generate_evidence_report":
            events = _read_events_from_file(args["etl_file"])
            flt = Filter(pids={args["pid"]} if "pid" in args and args["pid"] is not None else None)
            filtered = filter_events(events, flt)
            rows = aggregate(filtered, group_by="folder")
            rules = evaluate_rules(filtered)
            report = build_report_data(
                filtered,
                rows,
                rules,
                source_file=args["etl_file"],
            )
            return report

        else:
            return {"error": f"Unknown tool: {name}"}
    except Exception as ex:
        return {"error": str(ex)}


def run_mcp_server():
    """Run JSON-RPC stdio server for MCP integration."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            method = req.get("method")
            msg_id = req.get("id")

            if "id" not in req:
                continue  # JSON-RPC notification (e.g. notifications/initialized): never reply
            if method == "initialize":
                res = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "lastwrite-mcp", "version": __version__},
                    },
                }
            elif method == "ping":
                res = {"jsonrpc": "2.0", "id": msg_id, "result": {}}
            elif method == "tools/list":
                res = {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}
            elif method == "tools/call":
                params = req.get("params", {})
                tool_name = params.get("name")
                tool_args = params.get("arguments", {})
                out = handle_call_tool(tool_name, tool_args)
                res = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(out, indent=2)}],
                        "isError": "error" in out,
                    },
                }
            else:
                res = {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "Method not found"}}

            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stderr.write(f"Error parsing MCP input: {e}\n")


if __name__ == "__main__":
    run_mcp_server()
