# lastwrite — PRD

## One-liner
Per-process file I/O forensics in 30 seconds. A procmon replacement that's actually usable.

## Problem
Microsoft's Process Monitor produces 100MB of XML, has a 1990s UI, and asking
"what did PID 8842 just write?" takes 15 clicks and three filter dialogs.
SREs, sysadmins, malware analysts, and IT support need a one-liner answer.

## Users
- Sysadmins debugging "what's chewing my disk?"
- Security engineers doing live IR / triage ("what did this process touch?")
- Developers tracking down stray temp-file writes from their own builds
- Helpdesk: "which app wrote to AppData last?"

## Solution
A single Windows CLI (`lastwrite`) that wraps Windows ETW kernel file I/O
tracing into one-liner questions:

```
lastwrite --pid 8842 --since 10m --group folder
lastwrite --process chrome.exe --since 5m --top 20
lastwrite --path C:\Users\me\AppData --since 1h
lastwrite --live --pid 8842            # tail -f for file writes
```

Output is a flat, sortable table with totals — bytes, op count, last-touched
timestamp, per folder or per file. JSON / CSV export for piping.

## How it works
- **Capture**: ETW kernel `FileIo` provider via the built-in
  `logman.exe` (`"NT Kernel Logger"`). No driver install, no third-party
  binaries. Requires admin (same as procmon).
- **Snapshot mode** (default): start trace, sleep N seconds, stop trace,
  parse via `tracerpt.exe -of CSV`, aggregate, print.
- **Replay mode**: parse an existing `.etl` file.
- **Live mode**: spawn `logman` with a rotating buffer and poll
  `tracerpt` output for incremental updates.

## CLI surface (v0.1)

```
lastwrite [--pid N | --process NAME | --path PATH]
          [--since DURATION]          # 30s, 10m, 1h  (default 30s)
          [--op write|read|create|delete|all]   # default: write
          [--group folder|file|process|ext]     # default: folder
          [--top N]                              # default: 20
          [--format table|json|csv]              # default: table
          [--output FILE]
          [--live]                               # stream as it happens
          [--from-etl FILE]                      # replay
          [--no-admin-check]                     # skip admin prompt
```

## Output (default table)

```
$ lastwrite --pid 8842 --since 10m --group folder
PID 8842 (notepad.exe) — last 10m, grouped by folder, op=write

FOLDER                                              FILES   OPS    BYTES   LAST
C:\Users\me\Documents                                  3     47   2.1 MB   3s ago
C:\Users\me\AppData\Local\Temp                        12    218   840 KB   1s ago
C:\Users\me\AppData\Roaming\Notepad\Backups            1      8    14 KB   12s ago
                                                    ───   ────   ──────
                                                     16    273   3.0 MB
```

## Non-goals (v0.1)
- Cross-platform (Linux/macOS) — Windows only, that's the differentiator.
- Network I/O (separate tool).
- Registry I/O (separate tool).
- Long-running daemon / always-on service.
- GUI.

## Success metrics
- `pip install lastwrite && lastwrite --pid 1234 --since 10m` works on a stock
  Windows 10/11 box (with admin) in under 60 seconds.
- Output for a typical 30s trace renders in under 2s.
- README has the screenshot that makes someone DM it to their team.

## Distribution
- PyPI: `pip install lastwrite` (single binary entry-point).
- Standalone .exe via PyInstaller (no Python required) — v0.2.

## Architecture

```
lastwrite/
  __init__.py
  cli.py           # argparse, top-level command routing
  collector.py     # logman / tracerpt subprocess driver
  parser.py        # tracerpt CSV → typed events
  analyzer.py      # filter, group, aggregate
  render.py        # table / json / csv output
  live.py          # streaming mode
  admin.py         # admin check & re-launch helper
  duration.py      # "10m", "1h30m" parsing
tests/
  test_duration.py
  test_parser.py
  test_analyzer.py
README.md
pyproject.toml
```

## Dependencies
- `rich` — table rendering and live updates
- stdlib only otherwise

## Out-of-process tools used
- `logman.exe`     (built into Windows)
- `tracerpt.exe`   (built into Windows)
- `tasklist.exe` / WMI for PID → process name lookup
