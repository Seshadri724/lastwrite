"""Deterministic security rules engine for FileIo events."""

from __future__ import annotations

import ntpath
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from .parser import OP_CREATE, OP_RENAME, OP_WRITE, FileIoEvent


@dataclass
class RuleMatch:
    rule_id: str
    description: str
    severity: str  # "high", "medium", "low", "info"
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
        }


EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".ps1", ".vbs", ".cmd", ".msi", ".sys", ".com", ".scr", ".hta", ".cpl"
}

OFFICE_PDF_PROCESSES = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrord32.exe", "acrobat.exe", "foxitreader.exe"
}

MUTATING_OPS = {OP_WRITE, OP_CREATE, OP_RENAME}

RULE_IDS = frozenset({
    "executable_written_to_temp",
    "writes_to_startup",
    "writes_to_system_dirs",
    "alternate_data_stream",
    "office_pdf_spawning_exe",
    "writes_outside_expected_roots",
})

# Regex to detect Alternate Data Streams (e.g. C:\path\file.txt:stream.exe, ignoring C:\...)
_ADS_REGEX = re.compile(r"^(?:[a-zA-Z]:)?[^:]+:(?![\\/])[^:]+$")


def _is_path_under_root(path_norm: str, root_norm: str) -> bool:
    """Check if path_norm is equal to or under root_norm using strict path boundary check."""
    path_norm = ntpath.normpath(path_norm.lower())
    root_norm = ntpath.normpath(root_norm.lower())
    if path_norm == root_norm:
        return True
    if not root_norm.endswith(ntpath.sep):
        root_norm += ntpath.sep
    return path_norm.startswith(root_norm)


def evaluate_rules(
    events: Iterable[FileIoEvent],
    expected_roots: list[str] | None = None,
    process_name: str | None = None,
) -> list[RuleMatch]:
    """Evaluate deterministic security rules against mutating event stream."""

    temp_exe_paths = set()
    startup_paths = set()
    system_paths = set()
    ads_paths = set()
    office_pdf_exe_paths = set()
    outside_expected_paths = set()

    if isinstance(expected_roots, str):  # a bare string would iterate per character
        expected_roots = [expected_roots]
    normalized_roots = [ntpath.normpath(r).lower() for r in expected_roots] if expected_roots else []
    proc_lower = process_name.lower() if process_name else ""

    for e in events:
        # Rules strictly apply to mutating file ops (writes/creates/renames)
        if e.op not in MUTATING_OPS:
            continue

        p = e.file_path
        if not p:
            continue

        p_norm = ntpath.normpath(p.lower())
        ext = e.extension.lower()

        # 1. Executable written to Temp
        if ext in EXECUTABLE_EXTENSIONS and (f"{ntpath.sep}temp{ntpath.sep}" in p_norm or f"{ntpath.sep}tmp{ntpath.sep}" in p_norm):
            temp_exe_paths.add(p)

        # 2. Writes to Startup / Task Scheduler
        if (
            f"{ntpath.sep}start menu{ntpath.sep}programs{ntpath.sep}startup" in p_norm
            or f"{ntpath.sep}windows{ntpath.sep}tasks" in p_norm
            or f"{ntpath.sep}system32{ntpath.sep}tasks" in p_norm
        ):
            startup_paths.add(p)

        # 3. Writes to System32 / SysWOW64
        if f"{ntpath.sep}windows{ntpath.sep}system32{ntpath.sep}" in p_norm or f"{ntpath.sep}windows{ntpath.sep}syswow64{ntpath.sep}" in p_norm:
            system_paths.add(p)

        # 4. Alternate Data Stream (ADS)
        if _ADS_REGEX.match(p):
            ads_paths.add(p)

        # 5. Office/PDF process creating executable files
        if proc_lower in OFFICE_PDF_PROCESSES and ext in EXECUTABLE_EXTENSIONS:
            office_pdf_exe_paths.add(p)

        # 6. Writes outside expected roots (if allowlist provided)
        if normalized_roots:
            in_root = any(_is_path_under_root(p_norm, root) for root in normalized_roots)
            if not in_root:
                outside_expected_paths.add(p)

    matches: list[RuleMatch] = []

    if temp_exe_paths:
        matches.append(
            RuleMatch(
                rule_id="executable_written_to_temp",
                description="Executable file written to Temporary directory",
                severity="medium",
                evidence=sorted(list(temp_exe_paths)),
            )
        )

    if startup_paths:
        matches.append(
            RuleMatch(
                rule_id="writes_to_startup",
                description="File modification in Startup or Task Scheduler directory",
                severity="high",
                evidence=sorted(list(startup_paths)),
            )
        )

    if system_paths:
        matches.append(
            RuleMatch(
                rule_id="writes_to_system_dirs",
                description="File modification in Windows System directories",
                severity="high",
                evidence=sorted(list(system_paths)),
            )
        )

    if ads_paths:
        matches.append(
            RuleMatch(
                rule_id="alternate_data_stream",
                description="File write targeting NTFS Alternate Data Stream",
                severity="high",
                evidence=sorted(list(ads_paths)),
            )
        )

    if office_pdf_exe_paths:
        matches.append(
            RuleMatch(
                rule_id="office_pdf_spawning_exe",
                description="Office or PDF reader process written an executable file",
                severity="high",
                evidence=sorted(list(office_pdf_exe_paths)),
            )
        )

    if outside_expected_paths:
        matches.append(
            RuleMatch(
                rule_id="writes_outside_expected_roots",
                description="Process wrote files outside designated expected installation paths",
                severity="medium",
                evidence=sorted(list(outside_expected_paths)),
            )
        )

    return matches
