# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `lastwrite audit --before --after`: installer CI gate with JSON policy, non-zero
  exit on violations, and optional SARIF 2.1 (`--sarif`). Example policy in
  `examples/installer.policy.json`.
- `lastwrite diff --before --after`: differential file-activity analysis between two
  trace captures, with `--expected-roots` allowlisting and an optional `--report` HTML export.
- `lastwrite explain --pid/--process --duration`: plain-English process behavior triage
  with evidence links, backed by the deterministic rules engine.
- `lastwrite report --from-etl --output`: standalone HTML/JSON forensic evidence report.
- `lastwrite agent start|status|stop`: persistent background rolling ETW recorder.
- `lastwrite query --pid/--process --since`: query historical activity from the rolling
  recorder buffer without starting a new trace.
- `lastwrite mcp`: stdio MCP server exposing capture/query/compare/detect/report tools
  for AI agent integration.
- Deterministic suspicious-write rules engine (temp executables, startup-folder touches,
  system directory writes, ADS writes, writes outside expected install roots).

### Fixed (from [offline test findings](docs/OFFLINE-TEST-FINDINGS.md))
- `audit`/`diff`: rules now judge only activity absent from the `--before` baseline, so
  background noise no longer fails clean installers.
- `audit` fails closed (exit 2) on unreadable/empty traces, unknown `fail_on` rule IDs,
  and malformed policies. `expected_roots`/`fail_on` accept a single string.
- Input/environment errors print one line and exit 2 instead of a traceback.
- `--events` now emits raw events (table/json/csv). `--duration` is validated with
  `--from-etl`. Saved-trace output shows the source file and times relative to trace end.
- `--process` on a saved trace warns that names are matched against running PIDs;
  `explain --process` now actually filters.
- MCP: no replies to notifications, `ping` supported, `isError` set on tool failures,
  `serverInfo.version` from the package, `.etl` inputs converted before parsing.

### Known gaps before release
- Executable is not code-signed (see `lastwrite.spec`); Windows SmartScreen will warn on
  first run of the built `.exe`.
- ETW kernel-capture code paths (`collector.py`, `agent.py`) are covered by tests that
  mock the underlying `logman`/kernel-session calls; no automated test exercises real
  Windows kernel tracing — verify manually on a real machine before tagging a release.

## [0.1.0] - 2026-06-23

### Added
- Initial release.
- `lastwrite` CLI: per-process file I/O forensics over ETW kernel tracing.
- Snapshot mode (`--since 30s`), replay mode (`--from-etl`), and live streaming (`--live`).
- Target selection by `--pid`, `--process NAME` (partial match), and `--path` prefix.
- Aggregation grouped by `folder`, `file`, `process`, or `ext`, with byte/op totals.
- Operation filter (`--op write|read|create|delete|rename|close|all`).
- Output as `table` (rich), `json`, or `csv`; `--top N` and `--output FILE`.
- FileObject→path correlation so Write events with blank filenames are back-filled
  from their matching Create event.
- Admin gate matching Process Monitor's privilege requirement (`--no-admin-check` to bypass).
- Test suite (parser, analyzer, duration, end-to-end CLI replay).
