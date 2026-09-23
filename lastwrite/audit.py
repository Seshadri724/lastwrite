"""Installer-policy audit: fail a run when rule matches violate a policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .diff_engine import DiffResult, compute_diff
from .parser import FileIoEvent
from .rules import RULE_IDS, RuleMatch

# Default fail set for installer CI. Omit writes_to_system_dirs — many
# legit installers touch System32 (services, drivers). Add it in policy if needed.
DEFAULT_FAIL_ON = frozenset({
    "writes_to_startup",
    "executable_written_to_temp",
    "alternate_data_stream",
    "office_pdf_spawning_exe",
    "writes_outside_expected_roots",
})


@dataclass
class Policy:
    expected_roots: list[str]
    fail_on: frozenset[str]


@dataclass
class AuditResult:
    passed: bool
    violations: list[RuleMatch]
    diff: DiffResult
    policy: Policy

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "violations": [v.to_dict() for v in self.violations],
            "policy": {
                "expected_roots": self.policy.expected_roots,
                "fail_on": sorted(self.policy.fail_on),
            },
            "diff": self.diff.to_dict(),
        }


def _str_list(value: Any, key: str) -> list[str]:
    """Policy lists may be written as a single string; anything else is an error."""
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return list(value)
    raise ValueError(f"policy '{key}' must be a string or a list of strings")


def load_policy(
    path: str | None,
    *,
    expected_roots: list[str] | None = None,
    fail_on: list[str] | None = None,
) -> Policy:
    data: dict[str, Any] = {}
    if path:
        src = Path(path)
        if not src.exists():
            raise FileNotFoundError(f"policy file does not exist: {src}")
        text = src.read_text(encoding="utf-8")
        suffix = src.suffix.lower()
        if suffix == ".toml":
            try:
                import tomllib
            except ImportError:
                raise ValueError("TOML policies need Python 3.11+. Use a .json policy file.") from None
            data = tomllib.loads(text)
        else:
            try:
                data = json.loads(text)
            except json.JSONDecodeError as e:
                raise ValueError(f"invalid policy JSON in {src}: {e}") from None

    roots = _str_list(data.get("expected_roots"), "expected_roots")
    if expected_roots:
        roots.extend(expected_roots)

    if fail_on:
        fail_ids = fail_on
    elif "fail_on" in data:
        fail_ids = _str_list(data["fail_on"], "fail_on")
    else:
        fail_ids = list(DEFAULT_FAIL_ON)

    if fail_ids == ["*"]:
        fail_set = frozenset({"*"})
    else:
        # An unknown ID would silently never match and turn the gate green.
        unknown = set(fail_ids) - RULE_IDS
        if unknown:
            raise ValueError(
                f"unknown rule id(s) in fail_on: {', '.join(sorted(unknown))}. "
                f"Valid: {', '.join(sorted(RULE_IDS))}, or *"
            )
        fail_set = frozenset(fail_ids)

    return Policy(expected_roots=roots, fail_on=fail_set)


def evaluate_audit(
    before: list[FileIoEvent],
    after: list[FileIoEvent],
    policy: Policy,
) -> AuditResult:
    diff = compute_diff(
        before,
        after,
        expected_roots=policy.expected_roots or None,
    )
    if "*" in policy.fail_on:
        violations = list(diff.rule_matches)
    else:
        violations = [m for m in diff.rule_matches if m.rule_id in policy.fail_on]
    return AuditResult(
        passed=not violations,
        violations=violations,
        diff=diff,
        policy=policy,
    )


def _file_uri(path: str) -> str:
    try:
        return Path(path).as_uri()
    except (ValueError, OSError):
        return path.replace("\\", "/")


def to_sarif(result: AuditResult) -> dict[str, Any]:
    rules_seen: dict[str, RuleMatch] = {v.rule_id: v for v in result.violations}
    driver_rules = [
        {
            "id": rid,
            "shortDescription": {"text": match.description},
        }
        for rid, match in sorted(rules_seen.items())
    ]
    sarif_results = []
    for v in result.violations:
        for evidence in v.evidence:
            sarif_results.append({
                "ruleId": v.rule_id,
                "level": "error",
                "message": {"text": f"{v.description}: {evidence}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": _file_uri(evidence)},
                    }
                }],
            })
        if not v.evidence:
            sarif_results.append({
                "ruleId": v.rule_id,
                "level": "error",
                "message": {"text": v.description},
            })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "lastwrite",
                    "version": __version__,
                    "rules": driver_rules,
                }
            },
            "results": sarif_results,
        }],
    }
