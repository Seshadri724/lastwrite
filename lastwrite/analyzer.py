"""Filter and aggregate FileIoEvent streams."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .parser import FileIoEvent


@dataclass
class Filter:
    pids: set[int] | None = None
    path_prefix: str | None = None       # case-insensitive starts-with
    ops: set[str] = field(default_factory=lambda: {"write"})
    since: datetime | None = None        # UTC

    def matches(self, e: FileIoEvent) -> bool:
        if self.ops and e.op not in self.ops:
            return False
        if self.pids is not None and e.pid not in self.pids:
            return False
        if self.since is not None and e.timestamp < self.since:
            return False
        if self.path_prefix:
            if not e.file_path:
                return False
            if not e.file_path.lower().startswith(self.path_prefix.lower()):
                return False
        return True


@dataclass
class GroupRow:
    key: str
    file_count: int
    op_count: int
    total_bytes: int
    last_seen: datetime
    sample_path: str = ""

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "files": self.file_count,
            "ops": self.op_count,
            "bytes": self.total_bytes,
            "last_seen": self.last_seen.isoformat(),
        }


def filter_events(events: Iterable[FileIoEvent], flt: Filter) -> list[FileIoEvent]:
    return [e for e in events if flt.matches(e)]


def _key_for(e: FileIoEvent, group_by: str) -> str:
    if group_by == "file":
        return e.file_path or "<unknown>"
    if group_by == "folder":
        return e.folder
    if group_by == "process":
        return str(e.pid)
    if group_by == "ext":
        return e.extension or "<no-ext>"
    raise ValueError(f"unknown group_by: {group_by}")


def aggregate(events: Iterable[FileIoEvent], group_by: str = "folder") -> list[GroupRow]:
    """Aggregate events by the chosen key. Sorted by total_bytes desc, then op_count desc."""
    buckets: dict[str, dict] = defaultdict(lambda: {
        "files": set(),
        "ops": 0,
        "bytes": 0,
        "last": datetime.fromtimestamp(0, tz=timezone.utc),
        "sample": "",
    })
    for e in events:
        key = _key_for(e, group_by)
        b = buckets[key]
        if e.file_path:
            b["files"].add(e.file_path)
            if not b["sample"]:
                b["sample"] = e.file_path
        b["ops"] += 1
        b["bytes"] += e.size
        if e.timestamp > b["last"]:
            b["last"] = e.timestamp

    rows = [
        GroupRow(
            key=k,
            file_count=len(v["files"]) or 1,
            op_count=v["ops"],
            total_bytes=v["bytes"],
            last_seen=v["last"],
            sample_path=v["sample"],
        )
        for k, v in buckets.items()
    ]
    rows.sort(key=lambda r: (-r.total_bytes, -r.op_count, r.key))
    return rows


def totals(rows: list[GroupRow]) -> GroupRow:
    if not rows:
        now = datetime.now(timezone.utc)
        return GroupRow(key="TOTAL", file_count=0, op_count=0, total_bytes=0, last_seen=now)
    return GroupRow(
        key="TOTAL",
        file_count=sum(r.file_count for r in rows),
        op_count=sum(r.op_count for r in rows),
        total_bytes=sum(r.total_bytes for r in rows),
        last_seen=max(r.last_seen for r in rows),
    )


def since_from_seconds(seconds: int, now: datetime | None = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    return now - timedelta(seconds=seconds)
