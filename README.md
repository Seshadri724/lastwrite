# lastwrite

> **The evidence engine that lets humans and AI agents explain what a Windows process did.**

`lastwrite` turns raw Windows ETW file I/O streams into verifiable, structured evidence and clear explanations. Built for developers, security engineers, IT admins, and AI agents.

---

## Key Capabilities

### 1. Installer CI audit (the product)
Fail a build when an installer writes outside allowed roots, drops an exe in Temp, or touches Startup:

```powershell
lastwrite audit --before clean.csv --after install.csv --policy examples/installer.policy.json --sarif lastwrite.sarif
```

Exit `0` = pass, `1` = policy violation, `2` = bad input (never a silent pass). Point GitHub at the SARIF file.

```text
lastwrite audit: FAIL (2 policy violation(s))
New files: 3  Touched: 1  Deleted: 0
[HIGH] writes_to_startup: File modification in Startup or Task Scheduler directory
    C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\service.lnk
[MEDIUM] executable_written_to_temp: Executable file written to Temporary directory
    C:\Users\...\AppData\Local\Temp\update.exe
```

### 2. Deterministic Security Rules
No vague AI guesses. Static rule engine flags suspicious behaviors with direct evidence pointers:
- Executables created in `%TEMP%` / `%TMP%`
- Persistence-related directory touches (Startup, Run-key adjacent, Task Scheduler)
- System directory writes (`System32`, `SysWOW64`)
- NTFS Alternate Data Stream (ADS) writes
- Processes writing outside expected installation roots allowlist

### 3. AI-Agent Integration (MCP Server)
AI agents shouldn't summarize raw noise. Native MCP server exposes 5 structured tools:

```json
{
  "tools": [
    "capture_file_activity",
    "query_file_history",
    "compare_process_behavior",
    "detect_suspicious_writes",
    "generate_evidence_report"
  ]
}
```

Connect in `claude_desktop_config.json` or Claude Code:
```bash
claude mcp add lastwrite -- lastwrite mcp
```

### 4. Process Behavior Explanations
Triage process activity in 30 seconds with verifiable evidence:

```powershell
lastwrite explain --pid 1234 --duration 2m
```

Result:
```text
chrome.exe wrote mostly browser state and cache files (6.9 MB total across 27 files).
No writes to startup folders, system directories, or executable files detected.
Confidence: High (Trace loss: 0 events).
Evidence: 196 total operations across C:\Users\...\AppData\Local\Google\Chrome.
```

---

## Quickstart

### Standard Process Snapshot
```powershell
lastwrite --process notepad.exe --duration 5m
```

### Top Noisy Files
```powershell
lastwrite --process chrome.exe --duration 5m --group file --top 10
```

### Export HTML Evidence Package
```powershell
lastwrite --pid 8842 --duration 10m --report evidence.html
```

---

## Privacy

`lastwrite` runs entirely on your machine. It makes no network calls, phones
home to nothing, and never uploads captured trace data anywhere — everything
stays in the `.etl`/`.csv`/report files you tell it to write. Verify this
yourself: the source ships no HTTP client, socket, or telemetry code.

---

## Documentation

- **[PRD v2 Strategy](docs/PRD-V2.md)** — Strategy, market wedges, and positioning.
- **[Version Roadmap](docs/ROADMAP.md)** — Milestone trajectory from v0.2 to v1.0.
- **[User Guide](docs/USAGE.md)** — Detailed CLI flags, recipes, and MCP setup.
- **[Maintainer Guide](docs/MAINTAINER.md)** — Development and build instructions.

---

## License

MIT.
