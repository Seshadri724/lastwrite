"""Drive Windows ETW capture via the built-in logman.exe + tracerpt.exe.

We use the kernel "NT Kernel Logger" session with the file_io and
file_io_init keywords, which captures every file I/O operation on the
machine. No driver install, no third-party binary — these tools ship in
every modern Windows install.

Lifecycle:
    1. `logman stop "NT Kernel Logger" -ets`   (best-effort, in case a stale
       session is hanging around)
    2. `logman create trace "NT Kernel Logger" -p "Windows Kernel Trace"
        (file_io,file_io_init) -o <etl> -ets`
    3. sleep N seconds (or, in live mode, rotate buffers)
    4. `logman stop "NT Kernel Logger" -ets`
    5. `tracerpt <etl> -of CSV -o <csv> -y` (overwrite)
    6. Yield CSV path; caller hands it to parser.parse_tracerpt_csv.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

KERNEL_SESSION_NAME = "NT Kernel Logger"
KERNEL_PROVIDER = "Windows Kernel Trace"
# file_io: per-op file operations (Read/Write/Create/Delete/...)
# file_io_init: gives us filenames at Create time so Writes can be correlated
DEFAULT_KEYWORDS = "file_io,file_io_init"


class CollectorError(RuntimeError):
    """Raised when an underlying logman/tracerpt invocation fails."""


@dataclass
class CaptureResult:
    etl_path: Path
    csv_path: Path
    duration_seconds: float
    lost_events: int = 0


def get_session_stats(session_name: str = KERNEL_SESSION_NAME) -> dict:
    """Query logman ETW session stats and extract lost event counter."""
    result = _run([_logman(), "query", session_name, "-ets"], check=False, timeout=15)
    if result.returncode != 0:
        return {"running": False, "lost_events": 0, "lost_buffers": 0}

    lost_events = 0
    lost_buffers = 0
    for line in result.stdout.splitlines():
        line_lower = line.lower()
        if "events lost" in line_lower or "events dropped" in line_lower:
            parts = line.split(":")
            if len(parts) >= 2:
                try:
                    lost_events = int(parts[1].strip().replace(",", ""))
                except ValueError:
                    pass
        elif "buffers lost" in line_lower:
            parts = line.split(":")
            if len(parts) >= 2:
                try:
                    lost_buffers = int(parts[1].strip().replace(",", ""))
                except ValueError:
                    pass

    return {
        "running": True,
        "lost_events": lost_events,
        "lost_buffers": lost_buffers,
        "stdout": result.stdout,
    }


def _run(cmd: list[str], *, check: bool = True, timeout: float | None = None) -> subprocess.CompletedProcess:
    try:
        cp = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except FileNotFoundError as e:
        raise CollectorError(f"required Windows tool not found: {cmd[0]}") from e
    except subprocess.TimeoutExpired as e:
        raise CollectorError(f"{cmd[0]} timed out after {timeout}s") from e
    if check and cp.returncode != 0:
        raise CollectorError(
            f"{' '.join(cmd)}\nexit={cp.returncode}\nstdout={cp.stdout}\nstderr={cp.stderr}"
        )
    return cp


def _logman() -> str:
    return shutil.which("logman.exe") or "logman.exe"


def _tracerpt() -> str:
    return shutil.which("tracerpt.exe") or "tracerpt.exe"


def kernel_session_exists() -> bool:
    """Return whether the shared kernel logger session is already running.

    Do not stop a session we did not create: it may belong to Procmon, an EDR,
    or another diagnostic tool.
    """
    result = _run(
        [_logman(), "query", KERNEL_SESSION_NAME, "-ets"],
        check=False,
        timeout=15,
    )
    return result.returncode == 0


def build_start_capture_cmd(etl_path: Path, keywords: str = DEFAULT_KEYWORDS, max_mb: int = 512) -> list[str]:
    """Build logman command line with circular buffer mode (-f bincirc -max <max_mb>)."""
    return [
        _logman(),
        "create", "trace", KERNEL_SESSION_NAME,
        "-p", KERNEL_PROVIDER, f"({keywords})",
        "-o", str(etl_path),
        "-f", "bincirc",
        "-max", str(max_mb),
        "-ets",
    ]


def start_kernel_capture(etl_path: Path, keywords: str = DEFAULT_KEYWORDS, max_mb: int = 512) -> None:
    """Start the NT Kernel Logger writing to `etl_path` in circular buffer mode."""
    etl_path.parent.mkdir(parents=True, exist_ok=True)
    if etl_path.exists():
        try:
            etl_path.unlink()
        except Exception:
            pass
    cmd = build_start_capture_cmd(etl_path, keywords=keywords, max_mb=max_mb)
    _run(cmd, timeout=30)


def stop_kernel_capture() -> None:
    _run([_logman(), "stop", KERNEL_SESSION_NAME, "-ets"], timeout=30)


def etl_to_csv(etl_path: Path, csv_path: Path) -> None:
    """Convert an .etl file to CSV using tracerpt."""
    if csv_path.exists():
        csv_path.unlink()
    cmd = [
        _tracerpt(),
        str(etl_path),
        "-of", "CSV",
        "-o", str(csv_path),
        "-y",  # overwrite without prompting
    ]
    _run(cmd, timeout=120)


@contextmanager
def temp_workdir(prefix: str = "lastwrite-") -> Iterator[Path]:
    d = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        yield d
    finally:
        # Be polite — leave the dir if something inside is in use.
        try:
            shutil.rmtree(d, ignore_errors=True)
        except Exception:
            pass


def capture_for(seconds: float, keywords: str = DEFAULT_KEYWORDS,
                workdir: Path | None = None,
                progress=None) -> CaptureResult:
    """Capture kernel file I/O for `seconds`, then convert to CSV and return paths.

    `progress` is an optional callable(elapsed, total) for status updates.
    """
    own_dir = workdir is None
    if own_dir:
        workdir = Path(tempfile.mkdtemp(prefix="lastwrite-"))
    else:
        workdir.mkdir(parents=True, exist_ok=True)

    etl = workdir / "trace.etl"
    csv_path = workdir / "trace.csv"

    if kernel_session_exists():
        raise CollectorError(
            f'ETW session "{KERNEL_SESSION_NAME}" is already running; '
            "stop the existing capture before starting lastwrite"
        )

    start_kernel_capture(etl, keywords=keywords)
    t0 = time.monotonic()
    try:
        if progress is None:
            time.sleep(seconds)
        else:
            tick = 0.25
            elapsed = 0.0
            while elapsed < seconds:
                time.sleep(min(tick, seconds - elapsed))
                elapsed = time.monotonic() - t0
                try:
                    progress(elapsed, seconds)
                except Exception:
                    pass
        lost_events = 0
    finally:
        stats = get_session_stats()
        lost_events = stats.get("lost_events", 0)
        stop_kernel_capture()
    duration = time.monotonic() - t0

    etl_to_csv(etl, csv_path)
    return CaptureResult(etl_path=etl, csv_path=csv_path, duration_seconds=duration, lost_events=lost_events)


def list_processes() -> dict[int, str]:
    """Return {pid: image_name} using tasklist.exe."""
    out: dict[int, str] = {}
    try:
        cp = _run(["tasklist.exe", "/FO", "CSV", "/NH"], timeout=15)
    except CollectorError:
        return out
    import csv as _csv
    import io
    for row in _csv.reader(io.StringIO(cp.stdout)):
        if len(row) < 2:
            continue
        name, pid_s = row[0], row[1]
        try:
            out[int(pid_s)] = name
        except ValueError:
            continue
    return out


def resolve_processes(names: list[str]) -> set[int]:
    """Map a list of process names (case-insensitive, partial match) to PIDs."""
    if not names:
        return set()
    wanted = {n.lower() for n in names}
    matched: set[int] = set()
    for pid, name in list_processes().items():
        n = name.lower()
        if n in wanted or any(w in n for w in wanted):
            matched.add(pid)
    return matched


def process_name(pid: int) -> str | None:
    return list_processes().get(pid)


def is_windows() -> bool:
    return os.name == "nt"
