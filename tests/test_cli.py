"""End-to-end smoke test using --from-etl with a CSV sample, no admin needed."""

import json
from pathlib import Path

import pytest

from lastwrite.cli import main

SAMPLE_CSV = """preamble
Event Name,Type,Event ID,Version,Channel,Level,Opcode,Task,Keyword,PID,TID,Processor Number,Instance ID,Parent Instance ID,Activity ID,Related Activity ID,Clock-Time,Kernel(ms),User(ms),IrpPtr,FileObject,FileKey,FileName,IoSize
FileIo/Create,Info,0,0,0,0,0,0,0,8842,1,0,0,0,0,0,8/14/2024-15:31:42.000000,0,0,0,0xAAA,0xAAA,C:\\Users\\me\\Documents\\a.txt,0
FileIo/Write,Info,0,0,0,0,0,0,0,8842,1,0,0,0,0,0,8/14/2024-15:31:42.100000,0,0,0,0xAAA,0xAAA,,4096
FileIo/Write,Info,0,0,0,0,0,0,0,8842,1,0,0,0,0,0,8/14/2024-15:31:42.200000,0,0,0,0xAAA,0xAAA,,2048
FileIo/Write,Info,0,0,0,0,0,0,0,4001,1,0,0,0,0,0,8/14/2024-15:31:43.000000,0,0,0,0xBBB,0xBBB,C:\\Windows\\System32\\foo.log,512
"""


@pytest.fixture
def etl_csv(tmp_path: Path) -> Path:
    p = tmp_path / "trace.csv"
    p.write_text(SAMPLE_CSV, encoding="utf-8")
    return p


def test_cli_json_from_csv(etl_csv, tmp_path, capsys):
    out_file = tmp_path / "out.json"
    rc = main([
        "--from-etl", str(etl_csv),
        "--pid", "8842",
        "--group", "folder",
        "--format", "json",
        "--output", str(out_file),
    ])
    assert rc == 0
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["group_by"] == "folder"
    assert data["rows"], "expected at least one row for pid 8842"
    assert data["totals"]["bytes"] == 4096 + 2048


def test_cli_csv_filters_path(etl_csv, tmp_path):
    out_file = tmp_path / "out.csv"
    rc = main([
        "--from-etl", str(etl_csv),
        "--path", r"C:\Windows",
        "--format", "csv",
        "--output", str(out_file),
    ])
    assert rc == 0
    text = out_file.read_text(encoding="utf-8")
    assert "System32" in text or "Windows" in text
    assert "Documents" not in text


def test_cli_table_default(etl_csv, capsys):
    rc = main(["--from-etl", str(etl_csv), "--no-admin-check"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "TOTAL" in out or "(no events matched)" in out
