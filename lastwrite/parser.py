"""Parse tracerpt CSV output into typed FileIoEvent records.

Real kernel traces (`tracerpt -of CSV`, verified on windows-latest) have one header row:
  Event Name, Type, ..., PID, TID, ..., Clock-Time, Kernel(ms), User(ms), User Data
Event Name and Type are separate cells ("FileIo", "Write"), Clock-Time is a FILETIME
integer, and event fields follow positionally from the "User Data" column:
  Create      IrpPtr, FileObject, TTID, CreateOptions, FileAttributes, ShareAccess, OpenPath
  Read/Write  Offset, IrpPtr, FileObject, FileKey, TTID, IoSize, IoFlags, ExtraFlags
  Delete/Rename/Cleanup/Close  IrpPtr, FileObject, FileKey, ...
  FileCreate/FileRundown/FileDelete  FileKey, FileName  (name rundown, `file` keyword)
Names arrive on Create (per FileObject) and FileCreate (per FileKey), often *after* the
reads/writes they name, so kernel traces are resolved in two passes.

Rows `lastwrite-device,<device>,<drive>` before the header (written by
collector.etl_to_csv on the capturing machine) map device paths to drive letters.

The older named-column layout (FileIo/Write rows with FileName/IoSize columns) used by
the sample trace and unit tests is still read.
"""

from __future__ import annotations

import csv
import functools
import os
import re
import string
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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


@functools.cache
def local_device_map() -> dict[str, str]:
    r"""{'\Device\HarddiskVolume4': 'C:'} for this machine (empty off Windows)."""
    if os.name != "nt":
        return {}
    import ctypes

    out: dict[str, str] = {}
    buf = ctypes.create_unicode_buffer(1024)
    for letter in string.ascii_uppercase:
        if ctypes.windll.kernel32.QueryDosDeviceW(f"{letter}:", buf, len(buf)):
            out.setdefault(buf.value, f"{letter}:")
    return out


def _normalize_path(raw: str, devices: dict[str, str] | None = None) -> str:
    r"""Translate \Device\HarddiskVolumeN\... to a drive-letter path when the volume is known."""
    raw = raw.strip().strip('"')
    if not raw.startswith("\\Device\\"):
        return raw
    parts = raw.split("\\", 3)  # ['', 'Device', 'HarddiskVolume4', 'rest...']
    drive = (devices or {}).get("\\Device\\" + parts[2])
    if not drive:
        return raw
    return drive + "\\" + (parts[3] if len(parts) > 3 else "")


def parse_tracerpt_csv(path: str | Path) -> Iterator[FileIoEvent]:
    """Yield FileIoEvent rows from a tracerpt-produced CSV file."""
    p = Path(path)
    with p.open("r", encoding="utf-8", errors="replace", newline="") as f:
        rows = list(csv.reader(f))

    header_idx: dict[str, int] = {}
    devices: dict[str, str] = {}
    root_pid: int | None = None
    body: list[list[str]] = []
    for i, row in enumerate(rows):
        first = row[0].strip() if row else ""
        if first == "lastwrite-device" and len(row) >= 3:
            devices[row[1].strip()] = row[2].strip()
        elif first == "lastwrite-root-pid" and len(row) >= 2:
            root_pid = _to_int(row[1])
        elif first.lower() == "event name":
            header_idx = {c.strip().lower(): j for j, c in enumerate(row)}
            body = rows[i + 1:]
            break
    if not header_idx:
        # Garbage or empty input must not look like "a clean trace with no activity".
        raise ValueError(f"{p} is not a tracerpt CSV (no 'Event Name' header row)")

    if "user data" in header_idx:
        yield from _parse_kernel_rows(body, header_idx, devices or local_device_map(), root_pid)
        return

    for row in body:
        if not row:
            continue
        op = _EVENT_OP_MAP.get(row[0].strip())
        if op is None:
            continue
        evt = _row_to_event(row, header_idx, op)
        if evt is not None:
            yield evt


_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_FILE_OPEN = 1  # CreateDisposition (top byte of CreateOptions): open an existing file only
_KERNEL_OPS = {"Create": OP_CREATE, "Read": OP_READ, "Write": OP_WRITE, "Delete": OP_DELETE,
               "Rename": OP_RENAME, "Cleanup": OP_CLOSE, "Close": OP_CLOSE}
_NAME_EVENTS = {"FileCreate", "FileRundown", "FileDelete"}


def _process_tree(rows: list[list[str]], u, root_pid: int) -> set[int]:
    """PIDs of root_pid and its descendants, plus any msiexec.exe in the trace.

    Process Start/DCStart fields: UniqueProcessKey, ProcessId, ParentId, ..., ImageFileName (8).
    ponytail: MSI installs write from the Windows Installer service (msiexec.exe, not a child
    of setup.exe), so every msiexec in the window counts as the installer. A tracked process
    tree via a per-capture service PID would be exact if unrelated MSI activity ever matters.
    """
    parents: dict[int, int] = {}
    tree = {root_pid}
    for r in rows:
        if r[0].strip() == "Process" and r[1].strip() in ("Start", "DCStart"):
            pid = _to_int(u(r, 1))
            parents[pid] = _to_int(u(r, 2))
            if u(r, 8).lower() == "msiexec.exe":
                tree.add(pid)
    grew = True
    while grew:
        before = len(tree)
        tree |= {pid for pid, ppid in parents.items() if ppid in tree}
        grew = len(tree) > before
    return tree


def _parse_kernel_rows(rows: list[list[str]], idx: dict[str, int],
                       devices: dict[str, str], root_pid: int | None = None) -> Iterator[FileIoEvent]:
    ud, pid_i, tid_i, ts_i = idx["user data"], idx.get("pid"), idx.get("tid"), idx.get("clock-time")

    def u(row: list[str], k: int) -> str:
        return row[ud + k].strip().strip('"') if ud + k < len(row) else ""

    # `record -- <command>` stamps the command's PID: judge only what it (and its children) did,
    # not the rest of the machine (Defender, event logs, indexers, the CI runner itself).
    tree = _process_tree(rows, u, root_pid) if root_pid else None

    file_rows = [r for r in rows if len(r) > ud and r[0].strip() == "FileIo"]
    by_key: dict[str, str] = {}
    by_obj: dict[str, str] = {}
    create_key: dict[int, str] = {}  # Create row index -> FileKey of the handle it opened
    pending: dict[str, int] = {}  # FileObject -> its latest Create (FileObject addresses get reused)
    for i, r in enumerate(file_rows):
        kind = r[1].strip()
        if kind in _NAME_EVENTS:
            by_key.setdefault(u(r, 0), u(r, 1))
        elif kind == "Create":
            by_obj[u(r, 1)] = u(r, 6)
            pending[u(r, 1)] = i
        elif kind in ("Read", "Write") and u(r, 2) in pending:
            create_key[pending.pop(u(r, 2))] = u(r, 3)
        elif kind in ("Cleanup", "Close", "Delete", "Rename") and u(r, 1) in pending:
            create_key[pending.pop(u(r, 1))] = u(r, 2)

    for i, r in enumerate(file_rows):
        op = _KERNEL_OPS.get(r[1].strip())
        if op is None:
            continue
        pid = _to_int(r[pid_i]) if pid_i is not None else 0
        if tree is not None and pid not in tree:
            continue
        size, path = 0, ""
        if op == OP_CREATE:
            # The kernel logs a Create for every open; only count ones that can create/overwrite.
            if _to_int(u(r, 3)) >> 24 == _FILE_OPEN:
                continue
            # Prefer the FileKey rundown name: Create's OpenPath can be an 8.3 alias (RUNNER~1).
            fo, fk = u(r, 1), create_key.get(i, "")
            path = by_key.get(fk) or u(r, 6)
        elif op in (OP_READ, OP_WRITE):
            fo, fk, size = u(r, 2), u(r, 3), _to_int(u(r, 5))
        else:
            fo, fk = u(r, 1), u(r, 2)
        path = path or by_key.get(fk) or by_obj.get(fo, "")
        ticks = _to_int(r[ts_i]) if ts_i is not None and ts_i < len(r) else 0
        if not ticks:
            continue
        yield FileIoEvent(
            op=op,
            pid=pid,
            tid=_to_int(r[tid_i]) if tid_i is not None else 0,
            file_path=_normalize_path(path, devices),
            file_object=fo,
            size=size,
            timestamp=_FILETIME_EPOCH + timedelta(microseconds=ticks // 10),
        )


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
