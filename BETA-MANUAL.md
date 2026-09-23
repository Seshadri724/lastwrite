# lastwrite Beta User Manual

`lastwrite` is a Windows file-I/O evidence tool for developers, installer authors,
CI engineers, and security testers. It captures Windows ETW file activity and
turns it into summaries, installer-audit results, JSON, and SARIF.

This is beta software. Use it first on a test machine or disposable VM, not on
production systems.

## What this beta can do

- Capture file activity for a new time window.
- Read existing tracerpt CSV or ETL traces.
- Compare before/after installer traces.
- Fail CI when configured policy rules are violated.
- Produce SARIF for GitHub Code Scanning.
- Generate HTML evidence reports.
- Maintain a bounded rolling ETW buffer and query recent history.
- Expose structured tools through the local MCP server.

The beta does not yet provide a full Windows Service, signed executable, or
guaranteed compatibility with every Windows build.

## Requirements

- Windows 10 or Windows 11.
- Administrator rights for live capture and the rolling recorder.
- Python 3.10 or newer for the Python installation.
- PowerShell or Command Prompt.
- Enough free disk space for the configured trace buffer.

`lastwrite` uses the Windows `logman.exe` and `tracerpt.exe` tools. It does not
install a kernel driver or inject into processes.

## Important safety notes

1. Live capture requires an elevated terminal. Open PowerShell with **Run as administrator**.
2. Windows has a shared `NT Kernel Logger` session. `lastwrite` refuses to start if
   another tool, such as Procmon, already owns it.
3. Trace files can contain usernames, folder names, process names, and sensitive
   application activity. Sanitize traces before sharing them.
4. Keep the first tests short, such as 10–30 seconds.
5. Stop the rolling recorder when you are finished testing.
6. Do not treat a clean result as proof that a system is safe. Lost events or
   incomplete tracing can make results a lower bound.

## Installation

### Option A: install from a wheel or source checkout

Open an elevated PowerShell in the project directory:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
lastwrite --version
```

For development and tests:

```powershell
python -m pip install -e ".[dev]"
pytest
ruff check .
```

### Option B: install a released package

If a beta wheel is provided:

```powershell
python -m pip install lastwrite==0.3.0
lastwrite --version
```

### Option C: standalone executable

If a beta `.exe` is provided:

```powershell
.\lastwrite.exe --version
```

The beta executable may be unsigned and may trigger a SmartScreen warning. Verify
the checksum supplied by the project owner before running it. Do not bypass a
security warning unless you trust the source and have verified the file.

## First validation

### Offline validation without Administrator rights

The sample trace can be analyzed without starting ETW:

```powershell
lastwrite --from-etl examples\sample_trace.csv --format json
lastwrite report --from-etl examples\sample_trace.csv --output sample-report.html
lastwrite explain --from-etl examples\sample_trace.csv
```

Open `sample-report.html` in a browser and confirm that the report renders.

### Live capture validation

Close Procmon and other ETW tools first. Open an elevated PowerShell:

```powershell
lastwrite --duration 10s --op all --format json -o capture.json
```

Create some activity during the capture, for example by opening and saving a text
file. Confirm that the command completes and produces JSON output.

## Installer audit workflow

The beta audit workflow compares a clean trace with an after-install trace. It is
the primary feature for beta validation.

### 1. Capture the clean baseline

From an elevated PowerShell:

```powershell
lastwrite --duration 10s --op all --format csv -o clean.csv
```

Keep the machine idle during this capture.

### 2. Run the installer

Run the installer using its documented silent or unattended command. Example:

```powershell
.\setup.exe /quiet
```

Use the actual arguments required by your installer.

### 3. Capture the after-install trace

```powershell
lastwrite --duration 30s --op all --format csv -o install.csv
```

Give the installed application enough time to finish post-install work before
capturing.

### 4. Create or adjust the policy

Start with:

```powershell
Copy-Item examples\installer.policy.json .\installer.policy.json
notepad .\installer.policy.json
```

Example:

```json
{
  "expected_roots": [
    "C:\\Program Files\\Acme",
    "C:\\ProgramData\\Acme"
  ],
  "fail_on": [
    "writes_to_startup",
    "executable_written_to_temp",
    "alternate_data_stream",
    "writes_outside_expected_roots"
  ]
}
```

Only add a path to `expected_roots` after confirming that the installer genuinely
needs to write there. Do not weaken the policy just to make a test pass.

### 5. Run the audit

```powershell
lastwrite audit `
  --before clean.csv `
  --after install.csv `
  --policy .\installer.policy.json `
  --sarif .\lastwrite.sarif

$LASTEXITCODE
```

Exit codes:

- `0`: no configured policy violation was detected.
- `1`: one or more configured rules were violated.
- `2`: command or input failure (missing/unreadable trace, an after-trace with no
  file I/O events, bad policy, unknown rule ID). The audit never passes on bad input.

Expected beta behavior:

- A known-good installer should eventually produce `0`.
- A test that writes an executable to Temp or writes to Startup should produce `1`.
- `lastwrite.sarif` should be created even when the audit fails.

## Useful audit commands

JSON output for scripts:

```powershell
lastwrite audit `
  --before clean.csv `
  --after install.csv `
  --policy installer.policy.json `
  --format json `
  --output audit.json
```

Fail on every detected rule:

```powershell
lastwrite audit --before clean.csv --after install.csv --fail-on '*'
```

Add an allowed root without editing the policy:

```powershell
lastwrite audit `
  --before clean.csv `
  --after install.csv `
  --policy installer.policy.json `
  --expected-roots 'C:\ProgramData\Acme'
```

## GitHub Actions integration

Copy the example workflow:

```powershell
New-Item -ItemType Directory -Force .github\workflows | Out-Null
Copy-Item examples\github-audit.yml .github\workflows\installer-audit.yml
```

The example assumes that `clean.csv` and `install.csv` already exist on the
runner. The repository does not yet automate elevated trace generation around an
installer. You must add that capture step separately and confirm that the runner
permits the required ETW operation.

The audit step should look like:

```yaml
- name: Audit installer writes
  run: >
    lastwrite audit
    --before clean.csv
    --after install.csv
    --policy examples/installer.policy.json
    --sarif lastwrite.sarif

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: lastwrite.sarif
```

## Rolling recorder and historical queries

The recorder uses a bounded circular ETW buffer.

Start it from an elevated PowerShell:

```powershell
lastwrite agent start
lastwrite agent status
```

Query recent activity:

```powershell
lastwrite query --since 1m
lastwrite query --process notepad.exe --since 10m --format json
lastwrite query --pid 1234 --since 5m --group file
```

Stop it after testing:

```powershell
lastwrite agent stop
```

If Procmon or another ETW session is running, stop that tool before starting the
recorder. Confirm the buffer size in `agent status` and report any unexpected
growth.

## MCP integration

The beta includes a local stdio MCP server:

```powershell
lastwrite mcp
```

Register it with an MCP-compatible client using the command appropriate to that
client. For Claude Code, the intended shape is:

```powershell
claude mcp add lastwrite -- lastwrite mcp
```

The server exposes structured operations for trace summaries, historical queries,
diffs, suspicious-write rules, and evidence reports. Keep it local and do not
expose the stdio process over a network.

## Troubleshooting

### Access denied

Reopen PowerShell using **Run as administrator**. Offline CSV/ETL analysis does not
need Administrator rights.

### ETW session already in use

Close Procmon or the other tracing tool and retry. Do not forcibly stop a session
you do not own.

### No events found

Increase the duration, use `--op all`, and remove filters temporarily:

```powershell
lastwrite --duration 30s --op all
```

### Policy fails for a known-good installer

Inspect the violation paths. Determine whether the installer legitimately needs
those paths, then update `expected_roots` only when justified. Keep Startup,
Temp-executable, and ADS rules strict unless you have a documented reason.

### Lost events

Treat the result as a lower bound. Shorten the capture, reduce unrelated system
activity, increase the buffer where supported, and report the lost-event count.

### Unicode or strange paths

Retry with JSON output and include the sanitized result in the bug report:

```powershell
lastwrite --duration 10s --op all --format json -o capture.json
```

## Privacy and sharing

Before sharing a trace, report, or SARIF file:

- Remove usernames and company/project names where possible.
- Check paths for secrets, tokens, customer names, and internal hostnames.
- Evidence reports (HTML/JSON and the MCP `generate_evidence_report` tool) include
  this machine's hostname and OS version.
- Prefer sharing a minimized CSV fixture instead of a full ETL.
- Never upload raw traces from production without authorization.

## Beta bug report template

```text
lastwrite version:
Windows edition and version:
Python version or executable build:
Command used:
Expected result:
Actual result:
Exit code:
Was PowerShell elevated? yes/no
Was Procmon or another ETW tool running? yes/no
Lost events reported:
Relevant sanitized output:
Can the issue be reproduced? yes/no
```

Attach only sanitized traces or fixtures. Do not attach credentials or sensitive
production paths.

## Beta acceptance checklist

- [ ] Offline sample trace works.
- [ ] Live 10-second capture works on Windows.
- [ ] Known-good installer passes audit.
- [ ] Intentional Temp executable fails audit.
- [ ] Intentional Startup write fails audit.
- [ ] SARIF is generated on both PASS and FAIL.
- [ ] GitHub Actions job receives the expected exit code.
- [ ] Rolling recorder starts, queries, and stops.
- [ ] Process-name history filtering works.
- [ ] No unexpected trace growth occurs.
- [ ] Sanitized bug report can be reproduced by the maintainer.
