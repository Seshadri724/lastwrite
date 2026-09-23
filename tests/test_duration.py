import pytest

from lastwrite.duration import format_ago, format_bytes, parse_duration


@pytest.mark.parametrize("text,expected", [
    ("30s", 30),
    ("10m", 600),
    ("1h", 3600),
    ("1h30m", 5400),
    ("2h15m30s", 8130),
    ("45", 45),
    ("  10m  ", 600),
])
def test_parse_duration_ok(text, expected):
    assert parse_duration(text) == expected


@pytest.mark.parametrize("text", ["", "10x", "abc", "h", "1h2x"])
def test_parse_duration_bad(text):
    with pytest.raises(ValueError):
        parse_duration(text)


def test_format_bytes():
    assert format_bytes(0) == "0 B"
    assert format_bytes(1023) == "1023 B"
    assert format_bytes(1024) == "1.0 KB"
    assert format_bytes(1024 * 1024 * 2) == "2.0 MB"


def test_format_ago():
    assert format_ago(0) == "0s ago"
    assert format_ago(45) == "45s ago"
    assert format_ago(125).startswith("2m")
    assert format_ago(7325).startswith("2h")
