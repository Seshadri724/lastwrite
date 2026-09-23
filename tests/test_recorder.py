"""Unit tests for rolling recorder, agent, and query engine."""

from __future__ import annotations

from datetime import datetime, timezone

from lastwrite import query, recorder


def test_recorder_buffer_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(recorder, "get_buffer_dir", lambda: tmp_path)

    status_file = recorder.get_status_file()
    assert status_file.name == "agent_status.json"

    buffer_path = recorder.get_active_buffer_path()
    assert buffer_path.name == "rolling_trace.etl"

    initial_status = recorder.read_agent_status()
    assert initial_status["running"] is False

    test_data = {"running": True, "pid": 1234, "lost_events": 5}
    recorder.write_agent_status(test_data)
    read_back = recorder.read_agent_status()
    assert read_back["running"] is True
    assert read_back["pid"] == 1234
    assert read_back["lost_events"] == 5

    recorder.clear_agent_status()
    assert recorder.read_agent_status()["running"] is False


def test_query_historical_buffer_from_sample(tmp_path, monkeypatch):
    monkeypatch.setattr(recorder, "get_buffer_dir", lambda: tmp_path)

    now_ts = datetime.now(timezone.utc).strftime("%m/%d/%Y-%H:%M:%S.%f")
    sample_csv = tmp_path / "rolling_trace.csv"
    sample_csv.write_text(
        'Event Name, Type, Event ID, Version, Channel, Level, Opcode, Task, Keyword, PID, TID, Clock-Time, FileObject, FileName, Size\n'
        f'FileIo/Write, Write, 1, 0, 0, 0, 0, 0, 0, 8842, 100, {now_ts}, 0x1, "C:\\Users\\me\\Doc.txt", 1024\n',
        encoding="utf-8"
    )

    res = query.query_historical_buffer(duration_str="1h", trace_file=str(sample_csv))
    assert res["matched_events_count"] == 1
    assert res["rows"][0].file_count == 1


def test_query_historical_buffer_with_process_name(tmp_path, monkeypatch):
    monkeypatch.setattr(recorder, "get_buffer_dir", lambda: tmp_path)
    monkeypatch.setattr("lastwrite.query.resolve_processes", lambda names: {8842} if "notepad" in names[0] else set())

    now_ts = datetime.now(timezone.utc).strftime("%m/%d/%Y-%H:%M:%S.%f")
    sample_csv = tmp_path / "rolling_trace.csv"
    sample_csv.write_text(
        'Event Name, Type, Event ID, Version, Channel, Level, Opcode, Task, Keyword, PID, TID, Clock-Time, FileObject, FileName, Size\n'
        f'FileIo/Write, Write, 1, 0, 0, 0, 0, 0, 0, 8842, 100, {now_ts}, 0x1, "C:\\Users\\me\\Doc.txt", 1024\n',
        encoding="utf-8"
    )

    res = query.query_historical_buffer(duration_str="1h", process_names=["notepad"], trace_file=str(sample_csv))
    assert res["matched_events_count"] == 1
