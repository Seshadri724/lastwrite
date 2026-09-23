"""Tests for the evidence engine components: rules, diff, report, and MCP server."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from lastwrite.diff_engine import compute_diff
from lastwrite.mcp_server import TOOLS
from lastwrite.parser import FileIoEvent
from lastwrite.report_generator import build_report_data, render_html_report
from lastwrite.rules import evaluate_rules


@pytest.fixture
def sample_events():
    now = datetime.now(timezone.utc)
    return [
        FileIoEvent(
            op="write",
            pid=1001,
            tid=2001,
            file_path=r"C:\Users\Test\AppData\Local\Temp\update.exe",
            file_object="0x1234",
            size=1024,
            timestamp=now,
        ),
        FileIoEvent(
            op="write",
            pid=1001,
            tid=2001,
            file_path=r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\launch.lnk",
            file_object="0x5678",
            size=512,
            timestamp=now,
        ),
        FileIoEvent(
            op="write",
            pid=1001,
            tid=2001,
            file_path=r"C:\Program Files\App\config.json",
            file_object="0x9abc",
            size=2048,
            timestamp=now,
        ),
    ]


def test_evaluate_rules(sample_events):
    matches = evaluate_rules(sample_events)
    rule_ids = {m.rule_id for m in matches}
    assert "executable_written_to_temp" in rule_ids
    assert "writes_to_startup" in rule_ids


def test_evaluate_rules_expected_roots(sample_events):
    matches = evaluate_rules(sample_events, expected_roots=[r"C:\Program Files\App"])
    rule_ids = {m.rule_id for m in matches}
    assert "writes_outside_expected_roots" in rule_ids


def test_root_boundary_matching():
    now = datetime.now(timezone.utc)
    ev = [
        FileIoEvent(
            op="write",
            pid=1001,
            tid=2001,
            file_path=r"C:\Program Files\App2\service.exe",
            file_object="0x1234",
            size=1024,
            timestamp=now,
        )
    ]
    # C:\Program Files\App2 should NOT match C:\Program Files\App
    matches = evaluate_rules(ev, expected_roots=[r"C:\Program Files\App"])
    rule_ids = {m.rule_id for m in matches}
    assert "writes_outside_expected_roots" in rule_ids


def test_ads_detection():
    now = datetime.now(timezone.utc)
    ev = [
        FileIoEvent(
            op="write",
            pid=1001,
            tid=2001,
            file_path=r"C:\Users\Test\Documents\file.txt:hidden.exe",
            file_object="0x1234",
            size=1024,
            timestamp=now,
        )
    ]
    matches = evaluate_rules(ev)
    rule_ids = {m.rule_id for m in matches}
    assert "alternate_data_stream" in rule_ids


def test_compute_diff(sample_events):
    before = sample_events[:1]
    after = sample_events
    diff_res = compute_diff(before, after)
    assert len(diff_res.new_files) == 2
    assert len(diff_res.touched_files) == 1
    assert diff_res.total_new_bytes > 0


def test_report_html_escaping_anti_xss():
    now = datetime.now(timezone.utc)
    xss_events = [
        FileIoEvent(
            op="write",
            pid=1001,
            tid=2001,
            file_path=r"C:\Users\<script>alert('xss')</script>\payload.exe",
            file_object="0x1234",
            size=1024,
            timestamp=now,
        )
    ]
    from lastwrite.analyzer import aggregate
    rows = aggregate(xss_events, group_by="folder")
    rules = evaluate_rules(xss_events)

    data = build_report_data(
        xss_events,
        rows,
        rules,
        source_file="<script>alert(1)</script>.etl",
        process_info="<img src=x onerror=alert(1)>",
    )
    html_output = render_html_report(data)
    assert "<script>" not in html_output
    assert "&lt;script&gt;" in html_output
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_output


def test_mcp_tools_list():
    assert len(TOOLS) == 5
    tool_names = {t["name"] for t in TOOLS}
    assert "capture_file_activity" in tool_names
    assert "query_file_history" in tool_names
    assert "compare_process_behavior" in tool_names
    assert "detect_suspicious_writes" in tool_names
    assert "generate_evidence_report" in tool_names
