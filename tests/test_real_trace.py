"""Parser + audit against real tracerpt output captured on a windows-latest runner.

Fixtures are trimmed from the live-smoke CI artifact: `record` around
.github/ci/fake_installer.py (good / bad) plus an idle baseline.
"""

from __future__ import annotations

from pathlib import Path

from lastwrite.cli import main
from lastwrite.parser import _normalize_path, parse_tracerpt_csv

REAL = Path(__file__).parent / "fixtures" / "real"
ROOT = r"C:\Program Files\LwAcme"


def _audit(after: str) -> int:
    return main(["audit", "--before", str(REAL / "clean.csv"), "--after", str(REAL / after), "--expected-roots", ROOT])


def test_real_trace_parses_installer_writes():
    events = list(parse_tracerpt_csv(REAL / "bad.csv"))
    writes = {e.file_path: e for e in events if e.op == "write"}
    exe = writes[r"C:\Program Files\LwAcme\acme.exe"]
    assert exe.size == 50_002 and exe.pid == 7412
    assert r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\lw-agent.lnk" in writes
    assert all(e.pid == 7412 for e in events)  # scoped to the recorded process tree
    assert all(e.timestamp.year == 2026 for e in events)  # FILETIME decoded


def test_open_existing_is_not_a_create():
    creates = [e.file_path for e in parse_tracerpt_csv(REAL / "bad.csv") if e.op == "create"]
    assert not any(p.endswith("python.exe") for p in creates)  # python.exe was only opened
    assert not any("RUNNER~1" in p for p in creates)  # 8.3 alias replaced by the rundown name


def test_unscoped_baseline_sees_whole_machine():
    pids = {e.pid for e in parse_tracerpt_csv(REAL / "clean.csv")}
    assert len(pids) > 3


def test_real_good_installer_passes(capsys):
    assert _audit("good.csv") == 0
    assert "PASS" in capsys.readouterr().out


def test_real_bad_installer_fails_on_the_right_files(capsys):
    assert _audit("bad.csv") == 1
    out = capsys.readouterr().out
    assert r"[HIGH] writes_to_startup" in out and "lw-agent.lnk" in out
    assert "executable_written_to_temp" in out and r"Temp\lw-update.exe" in out
    assert "acme.exe" not in out.split("New files")[1]  # inside the allowed root


def test_device_paths_map_to_drive_letters():
    devices = {r"\Device\HarddiskVolume4": "C:"}
    assert _normalize_path(r"\Device\HarddiskVolume4\Program Files\x.exe", devices) == r"C:\Program Files\x.exe"
    assert _normalize_path(r"\Device\HarddiskVolume9\x", devices) == r"\Device\HarddiskVolume9\x"
    assert _normalize_path(r"C:\already\fine", devices) == r"C:\already\fine"
