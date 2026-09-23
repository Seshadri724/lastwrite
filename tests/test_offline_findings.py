"""Regressions for docs/OFFLINE-TEST-FINDINGS.md (fixtures in tests/fixtures/offline)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from lastwrite.audit import load_policy
from lastwrite.cli import main

FX = Path(__file__).parent / "fixtures" / "offline"
SAMPLE = Path(__file__).parents[1] / "examples" / "sample_trace.csv"
POLICY = Path(__file__).parents[1] / "examples" / "installer.policy.json"


def _audit(after: str, *extra: str) -> int:
    return main(["audit", "--before", str(FX / "clean.csv"), "--after", str(FX / after), *extra])


def test_h1_baseline_noise_does_not_fail_clean_installer(capsys):
    assert _audit("good_install.csv", "--policy", str(POLICY)) == 0
    assert "PASS" in capsys.readouterr().out


def test_h1_malicious_installer_still_fails(capsys):
    assert _audit("bad_install.csv", "--policy", str(POLICY)) == 1
    out = capsys.readouterr().out
    for rule in ("writes_to_startup", "executable_written_to_temp", "alternate_data_stream"):
        assert rule in out
    assert "app\\log.txt" not in out  # baseline noise excluded


@pytest.mark.parametrize("after", ["garbage.csv", "empty.csv"])
def test_h2_unreadable_after_trace_fails_closed(after, capsys):
    assert _audit(after, "--policy", str(POLICY)) == 2
    assert "not a tracerpt CSV" in capsys.readouterr().err


def test_h2_header_only_after_trace_fails_closed(tmp_path, capsys):
    header_only = tmp_path / "h.csv"
    header_only.write_text((FX / "clean.csv").read_text().splitlines()[0] + "\n")
    rc = main(["audit", "--before", str(FX / "clean.csv"), "--after", str(header_only)])
    assert rc == 2
    assert "no file I/O events" in capsys.readouterr().err


def test_h3_unknown_fail_on_rule_is_rejected(capsys):
    assert _audit("bad_install.csv", "--fail-on", "typo_rule") == 2
    assert "unknown rule id" in capsys.readouterr().err


def test_h4_expected_roots_string_is_one_root(capsys):
    assert _audit("good_install.csv", "--policy", str(FX / "strroots.json")) == 0
    assert load_policy(str(FX / "strroots.json")).expected_roots == [r"C:\Program Files\Acme"]


def test_policy_rejects_non_string_roots(tmp_path):
    p = tmp_path / "p.json"
    p.write_text(json.dumps({"expected_roots": 5}))
    with pytest.raises(ValueError, match="expected_roots"):
        load_policy(str(p))


def test_l1_malformed_policy_is_clean_error(tmp_path, capsys):
    p = tmp_path / "p.json"
    p.write_text("{bad json")
    assert _audit("bad_install.csv", "--policy", str(p)) == 2
    err = capsys.readouterr().err
    assert "invalid policy JSON" in err and "Traceback" not in err


def test_l2_unwritable_report_is_clean_error(tmp_path, capsys):
    out = tmp_path / "missing_dir" / "r.html"
    assert main(["report", "--from-etl", str(SAMPLE), "-o", str(out)]) == 2
    assert "lastwrite:" in capsys.readouterr().err


def test_l3_query_without_agent_is_clean_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    assert main(["query", "--since", "10m"]) == 2
    err = capsys.readouterr().err
    assert "No active rolling recorder buffer" in err and "Traceback" not in err


def test_l4_events_flag_emits_raw_events(capsys):
    assert main(["--from-etl", str(SAMPLE), "--events", "--format", "json"]) == 0
    events = json.loads(capsys.readouterr().out)
    assert len(events) == 6 and {"timestamp", "pid", "op", "bytes", "file_path"} <= set(events[0])


def test_l5_bad_duration_is_rejected(capsys):
    assert main(["--from-etl", str(SAMPLE), "--duration", "abc"]) == 2
    assert "could not parse duration" in capsys.readouterr().err


def test_l6_saved_trace_header_and_last_are_trace_relative(capsys):
    assert main(["--from-etl", str(SAMPLE)]) == 0
    out = capsys.readouterr().out
    assert "captured for 0s" not in out and "sample_trace.csv" in out
    assert "h " not in out.split("TOTAL")[0].split("LAST")[1]  # no "18478h ago"


def test_m1_process_filter_on_saved_trace_warns(capsys):
    main(["--from-etl", str(SAMPLE), "--process", "surely-not-running.exe"])
    assert "saved traces record PIDs" in capsys.readouterr().err


def test_m2_m3_mcp_protocol():
    reqs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "ping"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "nope", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": "detect_suspicious_writes", "arguments": {"etl_file": str(SAMPLE)}}},
    ]
    proc = subprocess.run(
        [sys.executable, "-m", "lastwrite", "mcp"],
        input="\n".join(json.dumps(r) for r in reqs) + "\n",
        capture_output=True, text=True, timeout=30,
    )
    replies = [json.loads(line) for line in proc.stdout.splitlines()]
    assert [r["id"] for r in replies] == [1, 2, 3, 4]  # notification got no reply
    from lastwrite import __version__
    assert replies[0]["result"]["serverInfo"]["version"] == __version__
    assert replies[2]["result"]["isError"] is True
    assert replies[3]["result"]["isError"] is False
