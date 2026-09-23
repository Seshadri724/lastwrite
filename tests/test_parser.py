from datetime import datetime, timezone
from pathlib import Path

from lastwrite.parser import FileIoEvent, correlate_paths, parse_tracerpt_csv

SAMPLE_CSV = """Microsoft Tracerpt 10.0.19041 -- preamble line ignored
some other preamble
Event Name,Type,Event ID,Version,Channel,Level,Opcode,Task,Keyword,PID,TID,Processor Number,Instance ID,Parent Instance ID,Activity ID,Related Activity ID,Clock-Time,Kernel(ms),User(ms),IrpPtr,FileObject,FileKey,FileName,IoSize
FileIo/Create,Info,0,0,0,0,0,0,0,8842,12,0,0,0,0,0,8/14/2024-15:31:42.123456,0,0,0xFFFF1,0xABCD1234,0xABCD1234,C:\\Users\\me\\Documents\\a.txt,0
FileIo/Write,Info,0,0,0,0,0,0,0,8842,12,0,0,0,0,0,8/14/2024-15:31:42.223456,0,0,0xFFFF2,0xABCD1234,0xABCD1234,,4096
FileIo/Write,Info,0,0,0,0,0,0,0,8842,12,0,0,0,0,0,8/14/2024-15:31:42.323456,0,0,0xFFFF3,0xABCD1234,0xABCD1234,,2048
SomeOtherProvider/Event,Info,0,0,0,0,0,0,0,1,1,0,0,0,0,0,8/14/2024-15:31:42.323456,0,0,0,0,0,0,0
FileIo/Write,Info,0,0,0,0,0,0,0,4001,3,0,0,0,0,0,8/14/2024-15:31:43.000000,0,0,0xFFFF4,0xDEADBEEF,0xDEADBEEF,C:\\Windows\\System32\\foo.log,512
"""


def _write(tmp_path: Path, name: str = "trace.csv") -> Path:
    p = tmp_path / name
    p.write_text(SAMPLE_CSV, encoding="utf-8")
    return p


def test_parser_emits_only_fileio_rows(tmp_path):
    p = _write(tmp_path)
    events = list(parse_tracerpt_csv(p))
    assert len(events) == 4
    ops = {e.op for e in events}
    assert ops == {"create", "write"}


def test_parser_extracts_pid_and_size(tmp_path):
    p = _write(tmp_path)
    events = list(parse_tracerpt_csv(p))
    writes = [e for e in events if e.op == "write"]
    assert any(e.size == 4096 and e.pid == 8842 for e in writes)
    assert any(e.size == 512 and e.pid == 4001 for e in writes)


def test_correlate_fills_missing_paths_via_file_object(tmp_path):
    p = _write(tmp_path)
    events = list(parse_tracerpt_csv(p))
    fixed = correlate_paths(events)
    # The two pid=8842 Writes had blank FileName but share FileObject with the
    # Create row — they should be back-filled.
    writes_8842 = [e for e in fixed if e.op == "write" and e.pid == 8842]
    assert all(e.file_path.endswith("a.txt") for e in writes_8842)
    # The pid=4001 Write had its own path; should be untouched.
    assert any(e.file_path.endswith("foo.log") for e in fixed)


def test_folder_and_ext_properties():
    e = FileIoEvent(
        op="write", pid=1, tid=1,
        file_path=r"C:\Users\me\Documents\report.PDF",
        file_object="", size=1, timestamp=datetime.now(timezone.utc),
    )
    assert e.folder == r"C:\Users\me\Documents"
    assert e.extension == ".pdf"


def test_invalid_timestamp_is_skipped_instead_of_being_made_current(tmp_path):
    csv = SAMPLE_CSV.replace("8/14/2024-15:31:42.123456", "not-a-timestamp", 1)
    p = tmp_path / "bad-time.csv"
    p.write_text(csv, encoding="utf-8")

    events = list(parse_tracerpt_csv(p))

    assert len(events) == 3


def test_missing_size_does_not_guess_from_unrelated_columns(tmp_path):
    csv = SAMPLE_CSV.replace(",4096\n", ",\n", 1)
    p = tmp_path / "missing-size.csv"
    p.write_text(csv, encoding="utf-8")

    writes = [e for e in parse_tracerpt_csv(p) if e.op == "write"]

    assert writes[0].size == 0
