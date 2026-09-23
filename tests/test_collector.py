from pathlib import Path

import pytest

from lastwrite import collector


def test_kernel_session_exists_uses_query_result(monkeypatch):
    monkeypatch.setattr(
        collector,
        "_run",
        lambda *args, **kwargs: type("Result", (), {"returncode": 0})(),
    )

    assert collector.kernel_session_exists() is True


def test_capture_refuses_to_stop_an_existing_session(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(collector, "kernel_session_exists", lambda: True)
    monkeypatch.setattr(
        collector,
        "start_kernel_capture",
        lambda *args, **kwargs: pytest.fail("must not start over an existing session"),
    )

    with pytest.raises(collector.CollectorError, match="already running"):
        collector.capture_for(0, workdir=tmp_path)


def test_build_start_capture_cmd_includes_bincirc():
    cmd = collector.build_start_capture_cmd(Path("trace.etl"), max_mb=512)
    assert "-f" in cmd
    assert "bincirc" in cmd
    assert "-max" in cmd
    assert "512" in cmd
