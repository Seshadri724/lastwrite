"""Installer audit CLI: policy + SARIF + non-zero exit."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from lastwrite.audit import DEFAULT_FAIL_ON, evaluate_audit, load_policy, to_sarif
from lastwrite.cli import main
from lastwrite.parser import FileIoEvent

CSV_HEAD = """preamble
Event Name,Type,Event ID,Version,Channel,Level,Opcode,Task,Keyword,PID,TID,Processor Number,Instance ID,Parent Instance ID,Activity ID,Related Activity ID,Clock-Time,Kernel(ms),User(ms),IrpPtr,FileObject,FileKey,FileName,IoSize
"""


def _csv(tmp_path: Path, name: str, rows: str) -> Path:
    p = tmp_path / name
    p.write_text(CSV_HEAD + rows, encoding="utf-8")
    return p


def _write_row(path: str, pid: int = 1001) -> str:
    return (
        f"FileIo/Write,Info,0,0,0,0,0,0,0,{pid},1,0,0,0,0,0,"
        f"8/14/2024-15:31:42.000000,0,0,0,0xAAA,0xAAA,{path},1024\n"
    )


def test_audit_fails_on_startup_write(tmp_path, capsys):
    before = _csv(tmp_path, "before.csv", "")
    after = _csv(
        tmp_path,
        "after.csv",
        _write_row(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\evil.lnk"),
    )
    rc = main(["audit", "--before", str(before), "--after", str(after)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "writes_to_startup" in out


def test_audit_passes_in_expected_root(tmp_path, capsys):
    before = _csv(tmp_path, "before.csv", "")
    after = _csv(tmp_path, "after.csv", _write_row(r"C:\Program Files\Acme\app.exe"))
    rc = main([
        "audit",
        "--before", str(before),
        "--after", str(after),
        "--expected-roots", r"C:\Program Files\Acme",
    ])
    assert rc == 0
    assert "PASS" in capsys.readouterr().out


def test_audit_policy_json_and_sarif(tmp_path):
    policy = tmp_path / "p.json"
    policy.write_text(
        json.dumps({
            "expected_roots": [r"C:\Program Files\Acme"],
            "fail_on": ["writes_outside_expected_roots"],
        }),
        encoding="utf-8",
    )
    before = _csv(tmp_path, "before.csv", "")
    after = _csv(tmp_path, "after.csv", _write_row(r"C:\Temp\surprise.dll"))
    sarif_path = tmp_path / "out.sarif"
    json_out = tmp_path / "out.json"
    rc = main([
        "audit",
        "--before", str(before),
        "--after", str(after),
        "--policy", str(policy),
        "--sarif", str(sarif_path),
        "--format", "json",
        "-o", str(json_out),
    ])
    assert rc == 1
    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert data["passed"] is False
    assert data["violations"][0]["rule"] == "writes_outside_expected_roots"
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]


def test_load_policy_cli_overrides_fail_on(tmp_path):
    p = tmp_path / "p.json"
    p.write_text(json.dumps({"fail_on": ["writes_to_startup"]}), encoding="utf-8")
    pol = load_policy(str(p), fail_on=["alternate_data_stream"])
    assert pol.fail_on == frozenset({"alternate_data_stream"})


def test_evaluate_audit_star_fails_all():
    now = datetime(2024, 8, 14, tzinfo=timezone.utc)
    after = [
        FileIoEvent(
            op="write",
            pid=1,
            tid=1,
            file_path=r"C:\Users\x\AppData\Local\Temp\x.exe",
            file_object="0x1",
            size=1,
            timestamp=now,
        )
    ]
    policy = load_policy(None, fail_on=["*"])
    result = evaluate_audit([], after, policy)
    assert not result.passed
    assert any(v.rule_id == "executable_written_to_temp" for v in result.violations)
    sarif = to_sarif(result)
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "lastwrite"


def test_default_fail_on_includes_startup():
    assert "writes_to_startup" in DEFAULT_FAIL_ON
