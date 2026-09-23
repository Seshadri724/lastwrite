"""lastwrite CLI entry point — The evidence engine for humans and AI agents."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, admin, agent, collector, live, query
from .analyzer import Filter, aggregate, filter_events, since_from_seconds
from .audit import evaluate_audit, load_policy, to_sarif
from .diff_engine import compute_diff
from .duration import parse_duration
from .mcp_server import run_mcp_server
from .parser import ALL_OPS, correlate_paths, parse_tracerpt_csv
from .render import render_csv, render_events_table, render_json, render_table
from .report_generator import build_report_data, render_html_report
from .rules import evaluate_rules


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lastwrite",
        description="The evidence engine that lets humans and AI agents explain what a Windows process did.",
    )
    p.add_argument("--version", action="version", version=f"lastwrite {__version__}")

    subparsers = p.add_subparsers(dest="subcommand", help="Available subcommands")

    # diff subcommand
    diff_p = subparsers.add_parser("diff", help="Run differential analysis between 'before' and 'after' trace captures.")
    diff_p.add_argument("--before", required=True, help="Clean or 'before' trace file (.etl or .csv)")
    diff_p.add_argument("--after", required=True, help="Installer or 'after' trace file (.etl or .csv)")
    diff_p.add_argument("--expected-roots", action="append", default=[], help="Expected install root directories")
    diff_p.add_argument("--report", help="Save self-contained HTML evidence report")

    audit_p = subparsers.add_parser(
        "audit",
        help="CI gate: fail if installer traces violate a write policy.",
    )
    audit_p.add_argument("--before", required=True, help="Clean / before trace (.etl or .csv)")
    audit_p.add_argument("--after", required=True, help="After-install trace (.etl or .csv)")
    audit_p.add_argument("--policy", help="JSON policy (TOML on Python 3.11+). See examples/installer.policy.json")
    audit_p.add_argument("--expected-roots", action="append", default=[], help="Allowed install roots (merged with --policy)")
    audit_p.add_argument(
        "--fail-on",
        action="append",
        default=[],
        help="Rule IDs that fail the run. Default: installer-relevant rules. Use * for every rule.",
    )
    audit_p.add_argument("--sarif", help="Write SARIF 2.1 for GitHub code scanning")
    audit_p.add_argument("--format", choices=("table", "json"), default="table")
    audit_p.add_argument("--output", "-o", default=None, help="Write table/JSON to a file instead of stdout")

    # explain subcommand
    exp_p = subparsers.add_parser("explain", help="Produce plain-English process behavior triage with evidence links.")
    exp_p.add_argument("--pid", type=int, help="Target PID")
    exp_p.add_argument("--process", help="Target process name")
    exp_p.add_argument("--duration", default="2m", help="Duration to analyze")
    exp_p.add_argument("--from-etl", help="Parse existing trace file")

    # report subcommand
    rep_p = subparsers.add_parser("report", help="Generate HTML or JSON forensic evidence report.")
    rep_p.add_argument("--from-etl", required=True, help="Source trace file (.etl or .csv)")
    rep_p.add_argument("--output", "-o", default="evidence_report.html", help="Report output filename")

    # agent subcommand
    agent_p = subparsers.add_parser("agent", help="Control persistent background rolling ETW recorder agent.")
    agent_p.add_argument("action", choices=["start", "status", "stop"], help="Agent action")

    # query subcommand
    query_p = subparsers.add_parser("query", help="Query history from active rolling recorder buffer.")
    query_p.add_argument("--pid", type=int, help="Filter by PID")
    query_p.add_argument("--process", help="Filter by process name")
    query_p.add_argument("--since", default="10m", help="Time window (e.g. 10m, 1h)")
    query_p.add_argument("--group", choices=("folder", "file", "process", "ext"), default="folder", help="Group output by")
    query_p.add_argument("--format", choices=("table", "json", "csv"), default="table")
    query_p.add_argument("--output", "-o", default=None)

    # mcp subcommand
    subparsers.add_parser("mcp", help="Run stdio MCP server for AI agent integration")

    # Global / Default snapshot flags
    sel = p.add_argument_group("target selection")
    sel.add_argument("--pid", type=int, action="append", default=[], help="Filter by PID (repeatable).")
    sel.add_argument("--process", action="append", default=[], help="Filter by process name, e.g. chrome.exe.")
    sel.add_argument("--path", default=None, help="Filter by starting path prefix.")

    cap = p.add_argument_group("capture")
    cap.add_argument("--duration", "--since", dest="duration", default="30s", help="Duration window (e.g. 30s, 10m).")
    cap.add_argument("--from-etl", default=None, help="Parse existing .etl or tracerpt CSV file.")
    cap.add_argument("--live", action="store_true", help="Stream events continuously.")
    cap.add_argument("--no-admin-check", action="store_true", help="Skip admin check elevation.")

    flt = p.add_argument_group("filtering & grouping")
    flt.add_argument("--op", choices=list(ALL_OPS) + ["all"], default="write", help="Operation filter. Default: write.")
    flt.add_argument("--group", choices=("folder", "file", "process", "ext"), default="folder", help="Group by.")
    flt.add_argument("--top", type=int, default=20, help="Show top N rows.")

    out = p.add_argument_group("output")
    out.add_argument("--format", choices=("table", "json", "csv"), default="table")
    out.add_argument("--output", "-o", default=None, help="Output file path.")
    out.add_argument("--events", action="store_true", help="Emit un-aggregated raw event stream.")
    out.add_argument("--report", dest="report_file", default=None, help="Output HTML evidence report.")
    return p


def _resolve_ops(op_arg: str) -> set[str]:
    if op_arg == "all":
        return set(ALL_OPS)
    return {op_arg}


def _resolve_pids(pid_args: list[int], proc_args: list[str], *, from_trace: bool = False) -> set[int] | None:
    if not pid_args and not proc_args:
        return None
    pids = set(pid_args)
    if proc_args:
        resolved = collector.resolve_processes(proc_args)
        if from_trace:
            # Saved traces carry PIDs only; names can only be looked up among live processes.
            sys.stderr.write(
                "lastwrite: warning: saved traces record PIDs, not process names. "
                f"--process matched running PIDs {sorted(resolved) or 'none'}, which may not "
                "be the PIDs in this trace. Use --pid for saved traces.\n"
            )
        pids |= resolved
    return pids or set()


def _read_trace_file(filepath: str) -> list:
    src = Path(filepath)
    if not src.exists():
        raise FileNotFoundError(f"trace file does not exist: {src}")
    if src.suffix.lower() == ".etl":
        with collector.temp_workdir() as wd:
            csv_path = wd / "trace.csv"
            collector.etl_to_csv(src, csv_path)
            return list(correlate_paths(parse_tracerpt_csv(csv_path)))
    return list(correlate_paths(parse_tracerpt_csv(src)))


def _open_output(path: str | None):
    if not path:
        return sys.stdout, False
    return open(path, "w", encoding="utf-8", newline=""), True


def handle_diff_command(args) -> int:
    before_events = _read_trace_file(args.before)
    after_events = _read_trace_file(args.after)

    diff_res = compute_diff(
        before_events,
        after_events,
        expected_roots=args.expected_roots or None,
    )

    print("\n--- lastwrite Differential Analysis ---")
    print(f"New Files Created: {len(diff_res.new_files)}")
    for nf in diff_res.new_files[:15]:
        print(f"  + {nf}")
    if len(diff_res.new_files) > 15:
        print(f"  ... (+{len(diff_res.new_files) - 15} more)")

    print(f"\nTouched Existing Files: {len(diff_res.touched_files)}")
    if diff_res.deleted_files:
        print(f"Deleted Paths: {len(diff_res.deleted_files)}")
    print(f"Total Bytes Written: {diff_res.total_new_bytes:,} B across {diff_res.total_new_ops} operations")

    if diff_res.rule_matches:
        print("\n--- Suspicious Rule Matches ---")
        for match in diff_res.rule_matches:
            print(f"[{match.severity.upper()}] {match.rule_id}: {match.description}")
            for ev in match.evidence[:5]:
                print(f"    - {ev}")

    if args.report:
        report_data = build_report_data(
            after_events,
            diff_res.folder_summary,
            diff_res.rule_matches,
            source_file=args.after,
        )
        html_content = render_html_report(report_data)
        Path(args.report).write_text(html_content, encoding="utf-8")
        print(f"\nSaved self-contained evidence report to {args.report}")

    return 0


def handle_audit_command(args) -> int:
    policy = load_policy(
        args.policy,
        expected_roots=args.expected_roots or None,
        fail_on=args.fail_on or None,
    )
    after = _read_trace_file(args.after)
    if not after:
        # Fail closed: a broken capture step must not turn the CI gate green.
        raise ValueError(f"after trace {args.after} contains no file I/O events; refusing to pass")
    result = evaluate_audit(_read_trace_file(args.before), after, policy)

    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(result), indent=2), encoding="utf-8")

    payload = result.to_dict()
    stream, close = _open_output(args.output)
    try:
        if args.format == "json":
            json.dump(payload, stream, indent=2)
            stream.write("\n")
        else:
            status = "PASS" if result.passed else "FAIL"
            stream.write(f"lastwrite audit: {status}")
            if result.violations:
                stream.write(f" ({len(result.violations)} policy violation(s))\n")
            else:
                stream.write("\n")
            stream.write(
                f"New files: {len(result.diff.new_files)}  "
                f"Touched: {len(result.diff.touched_files)}  "
                f"Deleted: {len(result.diff.deleted_files)}\n"
            )
            if not result.policy.expected_roots:
                stream.write(
                    "Note: no expected_roots set; writes_outside_expected_roots will not fire.\n"
                )
            for match in result.violations:
                stream.write(f"[{match.severity.upper()}] {match.rule_id}: {match.description}\n")
                for ev in match.evidence[:20]:
                    stream.write(f"    {ev}\n")
                if len(match.evidence) > 20:
                    stream.write(f"    ... (+{len(match.evidence) - 20} more)\n")
            if args.sarif:
                stream.write(f"SARIF: {args.sarif}\n")
    finally:
        if close:
            stream.close()

    return 0 if result.passed else 1


def handle_explain_command(args) -> int:
    events = []
    lost_events = 0
    if args.from_etl:
        events = _read_trace_file(args.from_etl)
    elif collector.is_windows():
        seconds = parse_duration(args.duration)
        sys.stderr.write(f"lastwrite: capturing activity for {seconds}s...\n")
        cap = collector.capture_for(seconds)
        events = list(correlate_paths(parse_tracerpt_csv(cap.csv_path)))
        lost_events = cap.lost_events
    else:
        sys.exit("lastwrite explain requires Windows or --from-etl.")

    pids = _resolve_pids(
        [args.pid] if args.pid else [],
        [args.process] if args.process else [],
        from_trace=bool(args.from_etl),
    )
    flt = Filter(pids=pids)
    matched = filter_events(events, flt)
    rules = evaluate_rules(matched, process_name=args.process)
    rows = aggregate(matched, group_by="folder")

    total_bytes = sum(e.size for e in matched)
    proc = args.process or (f"PID {args.pid}" if args.pid else "Target Process")

    print(f"\nBehavior Summary for {proc}:")
    print(f"  - Total Operations: {len(matched)}")
    print(f"  - Total Bytes Tracked: {total_bytes:,} B")
    print(f"  - Unique Folders Touched: {len(rows)}")
    print(f"  - Lost Events Counter: {lost_events}")

    if lost_events > 100:
        confidence = "Low (High ETW event loss during trace)"
    elif lost_events > 0:
        confidence = "Medium (Trace dropped events; totals are a lower bound)"
    elif not matched:
        confidence = "Low (No matching events recorded)"
    elif not args.process and not args.pid:
        confidence = "Medium (Unbounded process query)"
    else:
        confidence = "High (Clean capture, 0 lost events)"

    if rules:
        print("\nSecurity Analysis:")
        for r in rules:
            print(f"  [!] [{r.severity.upper()}] {r.description}")
            for ev in r.evidence[:3]:
                print(f"      Evidence: {ev}")
        print("\nTriage Recommendation: Review recommended due to rule flags.")
        print(f"Confidence: {confidence}")
    else:
        print("\nSecurity Analysis: Normal activity. No suspicious startup, system, or temp writes detected.")
        print(f"Confidence: {confidence}")
    return 0


def _force_utf8_stdio() -> None:
    for s in (sys.stdout, sys.stderr):
        reconfigure = getattr(s, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8_stdio()
    args = _build_parser().parse_args(argv)
    try:
        return _run(args)
    except (OSError, ValueError, RuntimeError) as e:
        # Exit 2 = input/environment error, distinct from audit's 1 = policy violation.
        sys.stderr.write(f"lastwrite: {e}\n")
        return 2


def _run(args) -> int:
    if args.subcommand == "mcp":
        run_mcp_server()
        return 0
    elif args.subcommand == "diff":
        return handle_diff_command(args)
    elif args.subcommand == "audit":
        return handle_audit_command(args)
    elif args.subcommand == "explain":
        return handle_explain_command(args)
    elif args.subcommand == "agent":
        if args.action == "start":
            agent.start_agent(no_admin_check=getattr(args, "no_admin_check", False))
        elif args.action == "status":
            st = agent.get_agent_status()
            print(json.dumps(st, indent=2))
        elif args.action == "stop":
            agent.stop_agent(no_admin_check=getattr(args, "no_admin_check", False))
        return 0
    elif args.subcommand == "query":
        pids = {args.pid} if args.pid else None
        res = query.query_historical_buffer(
            duration_str=args.since,
            pids=pids,
            process_names=[args.process] if args.process else None,
            group_by=args.group,
        )
        stream, close = _open_output(args.output)
        try:
            if args.format == "json":
                render_json(res["rows"], group_by=args.group, meta={
                    "since": res["since"],
                    "matched_events": res["matched_events_count"],
                    "lost_events": res["lost_events"],
                }, stream=stream)
            elif args.format == "csv":
                render_csv(res["rows"], group_by=args.group, stream=stream)
            else:
                header = f"Rolling Recorder Query — last {res['since']} (Lost Events: {res['lost_events']})"
                render_table(res["rows"], group_by=args.group, header=header, stream=stream)
        finally:
            if close:
                stream.close()
        return 0
    elif args.subcommand == "report":
        events = _read_trace_file(args.from_etl)
        rows = aggregate(events, group_by="folder")
        rules = evaluate_rules(events)
        data = build_report_data(events, rows, rules, source_file=args.from_etl)
        if args.output.endswith(".json"):
            Path(args.output).write_text(json.dumps(data, indent=2), encoding="utf-8")
        else:
            html = render_html_report(data)
            Path(args.output).write_text(html, encoding="utf-8")
        print(f"Generated report at {args.output}")
        return 0

    # Default snapshot / live mode logic
    if args.live:
        if not collector.is_windows():
            sys.exit("lastwrite: --live requires Windows.")
        admin.require_admin(skip=args.no_admin_check)
        ops = _resolve_ops(args.op)
        pids = _resolve_pids(args.pid, args.process)
        live.stream(Filter(pids=pids, path_prefix=args.path, ops=ops, since=None))
        return 0

    # Validate even with --from-etl so a typo is reported instead of silently ignored.
    duration_seconds = parse_duration(args.duration)
    if not args.from_etl:
        admin.require_admin(skip=args.no_admin_check)

    events = _read_trace_file(args.from_etl) if args.from_etl else []
    lost_events = 0
    if not args.from_etl and collector.is_windows():
        sys.stderr.write(f"lastwrite: capturing kernel file I/O for {duration_seconds}s...\n")
        cap = collector.capture_for(duration_seconds)
        events = list(correlate_paths(parse_tracerpt_csv(cap.csv_path)))
        lost_events = cap.lost_events

    seconds = duration_seconds if not args.from_etl else 0
    flt = Filter(
        pids=_resolve_pids(args.pid, args.process, from_trace=bool(args.from_etl)),
        path_prefix=args.path,
        ops=_resolve_ops(args.op),
        since=since_from_seconds(seconds) if seconds else None,
    )
    matched = filter_events(events, flt)

    if args.events:
        return _emit_events(matched, args)

    rows = aggregate(matched, group_by=args.group)
    if args.top and len(rows) > args.top:
        rows = rows[: args.top]

    if args.report_file:
        rules = evaluate_rules(matched, process_name=args.process[0] if args.process else None)
        data = build_report_data(matched, rows, rules, source_file=args.from_etl or "Live Capture", lost_events=lost_events)
        html = render_html_report(data)
        Path(args.report_file).write_text(html, encoding="utf-8")
        print(f"Generated report at {args.report_file}")
        return 0

    proc_name = collector.process_name(args.pid[0]) if (args.pid and len(args.pid) == 1) else None
    from .render import _header_line
    header = _header_line(
        pid=args.pid[0] if len(args.pid) == 1 else None,
        proc_name=proc_name,
        process_names=args.process or None,
        path_prefix=args.path,
        since_seconds=seconds or 0,
        group_by=args.group,
        op=args.op,
        source=args.from_etl,
    )
    # For a saved trace, "LAST" is measured back from the trace's end, not from now.
    trace_end = max((e.timestamp for e in events), default=None) if args.from_etl else None

    stream, close = _open_output(args.output)
    try:
        if args.format == "json":
            render_json(rows, group_by=args.group, meta={
                "header": header,
                "matched_events": len(matched),
                "lost_events": lost_events,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }, stream=stream)
        elif args.format == "csv":
            render_csv(rows, group_by=args.group, stream=stream)
        else:
            render_table(rows, group_by=args.group, header=header, stream=stream, now=trace_end)
    finally:
        if close:
            stream.close()

    return 0


def _emit_events(events: list, args) -> int:
    """--events: one row per raw event, no grouping."""
    events = sorted(events, key=lambda e: e.timestamp)
    if args.top:
        events = events[-args.top:]
    records = [
        {
            "timestamp": e.timestamp.isoformat(),
            "pid": e.pid,
            "op": e.op,
            "bytes": e.size,
            "file_path": e.file_path,
        }
        for e in events
    ]
    stream, close = _open_output(args.output)
    try:
        if args.format == "json":
            json.dump(records, stream, indent=2)
            stream.write("\n")
        elif args.format == "csv":
            w = csv.DictWriter(stream, fieldnames=list(records[0]) if records else ["timestamp"], lineterminator="\n")
            w.writeheader()
            w.writerows(records)
        else:
            render_events_table(events, header=f"{len(events)} event(s)", stream=stream,
                                now=events[-1].timestamp if events and args.from_etl else None)
    finally:
        if close:
            stream.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
