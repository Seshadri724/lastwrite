"""Parse tracerpt CSV output into typed FileIoEvent records.

tracerpt -of CSV emits a header line, a column-names line, then rows.
Each row's columns vary by event type. We care about kernel FileIo events:
  - FileIo/Write, FileIo/Read, FileIo/Create, FileIo/Delete, FileIo/Rename, FileIo/Close

Column layout for kernel FileIo events (tracerpt CSV):
  Event Name, Type, Event ID, Version, Channel, Level, Opcode, Task, Keyword,
  PID, TID, Processor Number, Instance ID, Parent Instance ID, Activity ID,
  Related Activity ID, Clock-Time, Kernel(ms), User(ms), User Data...

The "User Data" tail holds event-specific fields. For FileIo/Write & Read it
includes IrpPtr, FileObject, FileKey, ExtraInfo, IoSize, IoFlags. For
FileIo/Create it includes IrpPtr, FileObject, FileName, ... .

We do best-effort parsing: skip rows we can't classify; surface what we can.
"""

from __future__ import annotations

import csv
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# Op codes we surface to the user.
OP_WRITE = "write"
OP_READ = "read"
OP_CREATE = "create"
OP_DELETE = "delete"
OP_RENAME = "rename"
OP_CLOSE = "close"

ALL_OPS = (OP_WRITE, OP_READ, OP_CREATE, OP_DELETE, OP_RENAME, OP_CLOSE)


@dataclass(frozen=True)
class FileIoEvent:
    op: str            # one of ALL_OPS
    pid: int
    tid: int
    file_path: str     # may be empty when only a FileObject pointer is known
    file_object: str   # hex pointer; useful to correlate Write→Create
    size: int          # bytes for read/write, 0 otherwise
    timestamp: datetime  # UTC

    @property
    def folder(self) -> str:
        if not self.file_path:
            return "<unknown>"
        try:
            p = Path(self.file_path)
            return str(p.parent) if p.parent != Path("") else self.file_path
        except Exception:
            return self.file_path

    @property
    def extension(self) -> str:
        if not self.file_path:
            return ""
        _, _, ext = self.file_path.rpartition(".")
        return ("." + ext.lower()) if ext and "." in self.file_path else ""


_EVENT_OP_MAP = {
    "FileIo/Write": OP_WRITE,
    "FileIo/Read": OP_READ,
    "FileIo/Create": OP_CREATE,
    "FileIo/Delete": OP_DELETE,
    "FileIo/Rename": OP_RENAME,
    "FileIo/Cleanup": OP_CLOSE,
    "FileIo/Close": OP_CLOSE,
}


# tracerpt timestamp: "8/14/2024-15:31:42.123456" or ISO-ish. Be permissive.
_TS_FORMATS = (
    "%m/%d/%Y-%H:%M:%S.%f",
    "%m/%d/%Y %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S.%f",
)


def _parse_ts(raw: str) -> datetime | None:
    raw = raw.strip().strip('"')
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _looks_like_path(s: str) -> bool:
    if not s:
        return False
    s = s.strip().strip('"')
    if len(s) < 3:
        return False
    # Drive letter, UNC, or kernel \Device\... path
    if re.match(r"^[a-zA-Z]:[\\/]", s):
        return True
    if s.startswith("\\\\") or s.startswith(r"\Device"):
        return True
    return False


def _to_int(s: str, base: int = 10) -> int:
    s = s.strip().strip('"')
    if not s or s.lower() in ("n/a", "0x0", "0"):
        return 0
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s, base)
    except ValueError:
        return 0


def _normalize_path(raw: str) -> str:
    """Translate kernel device paths to drive-letter paths when obvious."""
    raw = raw.strip().strip('"')
    if not raw:
        return raw
    # Common case: \Device\HarddiskVolumeN\Users\... — leave as-is; we can't
    # reliably resolve volume mappings here without extra Win32 calls. The
    # filename still reads naturally to a human ("HarddiskVolume3\Users\me\...").
    return raw


def parse_tracerpt_csv(path: str | Path) -> Iterator[FileIoEvent]:
    """Yield FileIoEvent rows from a tracerpt-produced CSV file.

    Tolerates the multi-line preamble tracerpt writes before the table.
    Tolerates extra trailing columns and missing fields.
    """
    p = Path(path)
    with p.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        header_idx: dict[str, int] = {}
        for row in reader:
            if not row:
                continue
            first = row[0].strip()
            # Locate the column header. tracerpt usually emits it as a row
            # whose first cell is "Event Name".
            if not header_idx:
                if first.lower() == "event name":
                    header_idx = {c.strip().lower(): i for i, c in enumerate(row)}
                continue
            event_name = first
            op = _EVENT_OP_MAP.get(event_name)
            if op is None:
                continue
            evt = _row_to_event(row, header_idx, op)
            if evt is not None:
                yield evt
    if not header_idx:
        # Garbage or empty input must not look like "a clean trace with no activity".
        raise ValueError(f"{p} is not a tracerpt CSV (no 'Event Name' header row)")


def _row_to_event(row: list[str], idx: dict[str, int], op: str) -> FileIoEvent | None:
    def cell(name: str) -> str:
        i = idx.get(name.lower())
        if i is None or i >= len(row):
            return ""
        return row[i]

    pid = _to_int(cell("PID") or cell("Process ID"))
    tid = _to_int(cell("TID") or cell("Thread ID"))
    ts_raw = cell("Clock-Time") or cell("TimeStamp") or cell("Time Stamp")
    ts = _parse_ts(ts_raw) if ts_raw else None
    if ts is None:
        # Never replace an invalid event timestamp with "now": that makes an
        # old or malformed trace look current and breaks time filtering.
        return None

    # Try named columns first.
    file_path = ""
    for name in ("FileName", "OpenPath", "FilePath", "File Name"):
        v = cell(name)
        if v and _looks_like_path(v):
            file_path = _normalize_path(v)
            break

    file_object = cell("FileObject") or cell("FileKey")

    # Fallback: scan the row tail (User Data fields) for the first cell that
    # looks like a path. tracerpt's per-event columns vary, so this is the
    # most robust way to grab the filename.
    if not file_path:
        for v in row[10:]:
            if _looks_like_path(v):
                file_path = _normalize_path(v)
                break

    size = 0
    if op in (OP_WRITE, OP_READ):
        for name in ("IoSize", "Size", "Length", "TransferSize"):
            v = cell(name)
            if v:
                size = _to_int(v)
                if size > 0:
                    break
        # If tracerpt did not expose a named size field, retain zero rather
        # than guessing from arbitrary user-data columns (which can be a PID,
        # pointer, flag, or unrelated event field).

    if pid == 0 and not file_path:
        return None

    return FileIoEvent(
        op=op,
        pid=pid,
        tid=tid,
        file_path=file_path,
        file_object=(file_object or "").strip().strip('"'),
        size=size,
        timestamp=ts,
    )


def correlate_paths(events: Iterable[FileIoEvent]) -> list[FileIoEvent]:
    """Fill in missing file paths on Write/Read events by matching FileObject
    pointers against earlier Create events.

    tracerpt sometimes emits Write rows that only carry a FileObject pointer;
    the filename lives on the matching Create row. We walk the stream once,
    remember Create→path mappings, and patch later events that share the
    pointer.
    """
    fo_to_path: dict[str, str] = {}
    fixed: list[FileIoEvent] = []
    for e in events:
        path = e.file_path
        if e.file_object:
            if path:
                fo_to_path[e.file_object] = path
            elif e.file_object in fo_to_path:
                path = fo_to_path[e.file_object]
        if path != e.file_path:
            e = FileIoEvent(
                op=e.op,
                pid=e.pid,
                tid=e.tid,
                file_path=path,
                file_object=e.file_object,
                size=e.size,
                timestamp=e.timestamp,
            )
        fixed.append(e)
    return fixed
