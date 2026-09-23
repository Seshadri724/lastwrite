from datetime import datetime, timedelta, timezone

from lastwrite.analyzer import Filter, aggregate, filter_events, totals
from lastwrite.parser import FileIoEvent


def _evt(pid=100, op="write", path=r"C:\Users\me\Documents\a.txt", size=1024, t=None):
    return FileIoEvent(
        op=op,
        pid=pid,
        tid=1,
        file_path=path,
        file_object="0x1",
        size=size,
        timestamp=t or datetime.now(timezone.utc),
    )


def test_filter_by_pid():
    events = [_evt(pid=100), _evt(pid=200)]
    flt = Filter(pids={100}, ops={"write"})
    out = filter_events(events, flt)
    assert len(out) == 1 and out[0].pid == 100


def test_filter_by_op():
    events = [_evt(op="write"), _evt(op="read")]
    flt = Filter(ops={"write"})
    out = filter_events(events, flt)
    assert [e.op for e in out] == ["write"]


def test_filter_by_path_prefix_case_insensitive():
    events = [
        _evt(path=r"C:\Users\me\Documents\a.txt"),
        _evt(path=r"C:\Windows\system32\b.dll"),
    ]
    flt = Filter(ops={"write"}, path_prefix=r"c:\users")
    out = filter_events(events, flt)
    assert len(out) == 1


def test_filter_by_since():
    now = datetime.now(timezone.utc)
    events = [
        _evt(t=now - timedelta(seconds=120)),
        _evt(t=now - timedelta(seconds=10)),
    ]
    flt = Filter(ops={"write"}, since=now - timedelta(seconds=60))
    out = filter_events(events, flt)
    assert len(out) == 1


def test_aggregate_by_folder_sorts_by_bytes():
    events = [
        _evt(path=r"C:\A\one.txt", size=100),
        _evt(path=r"C:\A\two.txt", size=200),
        _evt(path=r"C:\B\big.bin", size=10_000),
    ]
    rows = aggregate(events, group_by="folder")
    assert rows[0].key == r"C:\B"
    assert rows[0].total_bytes == 10_000
    assert rows[1].key == r"C:\A"
    assert rows[1].file_count == 2
    assert rows[1].op_count == 2
    assert rows[1].total_bytes == 300


def test_aggregate_by_ext():
    events = [
        _evt(path=r"C:\a\one.txt", size=10),
        _evt(path=r"C:\a\two.txt", size=20),
        _evt(path=r"C:\a\big.bin", size=1000),
    ]
    rows = aggregate(events, group_by="ext")
    keys = [r.key for r in rows]
    assert ".bin" in keys and ".txt" in keys
    assert rows[0].key == ".bin"


def test_totals():
    events = [_evt(size=100), _evt(size=50, path=r"C:\X\y.txt")]
    rows = aggregate(events, group_by="folder")
    t = totals(rows)
    assert t.total_bytes == 150
    assert t.op_count == 2
