"""Differential analysis engine for comparing trace captures or baselines."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .analyzer import GroupRow, aggregate
from .parser import OP_CREATE, OP_DELETE, OP_RENAME, OP_WRITE, FileIoEvent
from .rules import MUTATING_OPS, RuleMatch, evaluate_rules


@dataclass
class DiffResult:
    new_files: list[str]
    touched_files: list[str]
    deleted_files: list[str]
    total_new_bytes: int
    total_new_ops: int
    rule_matches: list[RuleMatch]
    folder_summary: list[GroupRow]

    def to_dict(self) -> dict:
        return {
            "new_files_count": len(self.new_files),
            "new_files": self.new_files,
            "touched_files_count": len(self.touched_files),
            "touched_files": self.touched_files,
            "deleted_files_count": len(self.deleted_files),
            "deleted_files": self.deleted_files,
            "total_new_bytes": self.total_new_bytes,
            "total_new_ops": self.total_new_ops,
            "rule_matches": [r.to_dict() for r in self.rule_matches],
            "folders": [f.to_dict() for f in self.folder_summary],
        }


def compute_diff(
    before_events: Iterable[FileIoEvent],
    after_events: Iterable[FileIoEvent],
    expected_roots: list[str] | None = None,
    process_name: str | None = None,
) -> DiffResult:
    """Compute differential file activity between 'before' baseline and 'after' trace captures.

    Categorizes:
    - new_files: files first observed in the after trace
    - touched_files: existing files written/modified during the after trace
    - deleted_files: paths deleted during the after trace
    """
    before_list = list(before_events)
    before_paths = {e.file_path for e in before_list if e.file_path}
    after_list = list(after_events)

    new_paths: set[str] = set()
    touched_paths: set[str] = set()
    deleted_paths: set[str] = set()
    total_bytes = 0

    for e in after_list:
        p = e.file_path
        if e.op in (OP_WRITE, OP_CREATE):
            total_bytes += e.size

        if not p:
            continue

        if e.op in (OP_DELETE, OP_RENAME):
            deleted_paths.add(p)
        elif p not in before_paths:
            new_paths.add(p)
        else:
            touched_paths.add(p)

    # Rules only judge activity the baseline didn't already show, so background
    # noise (writes present in both traces) can't fail an audit.
    # ponytail: path-level baseline — an installer rewriting a file the baseline
    # also wrote is suppressed; switch to PID-tree filtering if that matters.
    baseline_writes = {
        e.file_path.lower() for e in before_list if e.file_path and e.op in MUTATING_OPS
    }
    delta = [e for e in after_list if e.file_path.lower() not in baseline_writes]
    rules = evaluate_rules(delta, expected_roots=expected_roots, process_name=process_name)
    folder_rows = aggregate(after_list, group_by="folder")

    return DiffResult(
        new_files=sorted(list(new_paths)),
        touched_files=sorted(list(touched_paths)),
        deleted_files=sorted(list(deleted_paths)),
        total_new_bytes=total_bytes,
        total_new_ops=len(after_list),
        rule_matches=rules,
        folder_summary=folder_rows,
    )
