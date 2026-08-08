#!/usr/bin/env python3
"""Validate automated engineering audits without granting human-review credit."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = ROOT / "docs" / "audits" / "manifest.yaml"
SCHEMA_PATH = ROOT / "docs" / "audits" / "automated-audit-v1.schema.json"

AUDIT_KEYS = {
    "schema_version",
    "audit_id",
    "status",
    "title",
    "perspective",
    "automated_agent",
    "human_reviewer",
    "automated_agent_id",
    "audited_at",
    "audited_commit",
    "scope",
    "findings",
    "dispositions",
    "evidence",
    "limitations",
    "human_gate_effect",
}
FINDING_KEYS = {"finding_id", "severity", "title", "description", "evidence_ids"}
DISPOSITION_KEYS = {
    "finding_id",
    "status",
    "rationale",
    "blocker",
    "evidence_ids",
}
EVIDENCE_KEYS = {"evidence_id", "path", "sha256", "purpose"}
REQUIRED_PERSPECTIVES = {
    "artifact-blind-integrity",
    "mlkem-kyberslash-protocol",
    "signature-harness-contracts",
    "native-analysis-statistics",
}
SEVERITIES = {"critical", "high", "medium", "low"}
DISPOSITION_STATUSES = {"addressed", "accepted-with-blocker", "open"}
ENGINEERING_CLOSED = {"addressed", "accepted-with-blocker"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
POST_AUDIT_GOVERNANCE_PREFIXES = ("docs/audits/", "docs/reviews/")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_yaml(path: Path) -> dict[str, Any]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: root must be a mapping")
    return raw


def _repo_path(root: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty repository-relative path")
    raw = Path(value)
    if raw.is_absolute() or ".." in raw.parts:
        raise ValueError(f"{label} escapes repository: {value!r}")
    root = root.resolve()
    candidate = root / raw
    if candidate.is_symlink() or any(
        parent.is_symlink()
        for parent in candidate.parents
        if parent != root and parent.is_relative_to(root)
    ):
        raise ValueError(f"{label} contains a symlink: {value!r}")
    path = candidate.resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"{label} escapes repository: {value!r}")
    return path


def _string(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise ValueError(f"{label} must be {qualifier}")
    return value


def _string_list(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ValueError(
            f"{label} must be a {'possibly empty' if allow_empty else 'non-empty'} list"
        )
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{label} must contain non-empty strings")
    return value


def _parse_timestamp(value: Any, label: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")


def evidence_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _audit_provenance_errors(root: Path, commit: str, label: str) -> list[str]:
    errors: list[str] = []
    try:
        ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, "HEAD"],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        if ancestor.returncode != 0:
            errors.append(f"{label}: audited_commit is not an ancestor of HEAD")
            return errors
        changed = subprocess.run(
            ["git", "diff", "--name-only", f"{commit}..HEAD"],
            cwd=root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        ).stdout.splitlines()
        critical = sorted(
            path for path in changed if not path.startswith(POST_AUDIT_GOVERNANCE_PREFIXES)
        )
        if critical:
            errors.append(f"{label}: non-governance files changed after audited_commit: {critical}")
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        ).stdout.strip()
        if dirty:
            errors.append(f"{label}: current worktree must be clean for audit readiness")
    except subprocess.SubprocessError as exc:
        errors.append(f"{label}: cannot verify audited_commit provenance: {exc}")
    return errors


def validate_audit(
    audit: dict[str, Any],
    *,
    root: Path,
    path: Path,
    expected_perspective: str,
    enforce_current_tree: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    label = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
    unknown = sorted(set(audit) - AUDIT_KEYS)
    missing = sorted(AUDIT_KEYS - set(audit))
    if unknown:
        errors.append(f"{label}: unknown keys {unknown}")
    if missing:
        errors.append(f"{label}: missing keys {missing}")
        return {}, errors
    if audit["schema_version"] != "1.0":
        errors.append(f"{label}: schema_version must be '1.0'")
    audit_id = audit["audit_id"]
    if not isinstance(audit_id, str) or not ID_RE.fullmatch(audit_id):
        errors.append(f"{label}: invalid audit_id={audit_id!r}")
    if audit["status"] != "complete":
        errors.append(f"{label}: status must be complete")
    if audit["perspective"] != expected_perspective:
        errors.append(f"{label}: perspective differs from manifest")
    if audit["perspective"] not in REQUIRED_PERSPECTIVES:
        errors.append(f"{label}: unknown perspective={audit['perspective']!r}")
    if audit["automated_agent"] is not True:
        errors.append(f"{label}: automated_agent must be true")
    if audit["human_reviewer"] is not False:
        errors.append(f"{label}: human_reviewer must be false")
    if audit["human_gate_effect"] != "none":
        errors.append(f"{label}: automated audit human_gate_effect must be none")
    for field in ("title", "automated_agent_id"):
        try:
            _string(audit[field], f"{label}: {field}")
        except ValueError as exc:
            errors.append(str(exc))
    if not isinstance(audit["automated_agent_id"], str) or not ID_RE.fullmatch(
        audit["automated_agent_id"]
    ):
        errors.append(f"{label}: automated_agent_id is malformed")
    try:
        _parse_timestamp(audit["audited_at"], f"{label}: audited_at")
    except ValueError as exc:
        errors.append(str(exc))
    commit = audit["audited_commit"]
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        errors.append(f"{label}: audited_commit must be a full lowercase git hash")
    else:
        try:
            subprocess.run(
                ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            )
        except subprocess.SubprocessError as exc:
            errors.append(f"{label}: audited_commit is unavailable: {exc}")
        if enforce_current_tree:
            errors.extend(_audit_provenance_errors(root, commit, label))
    for field in ("scope", "limitations"):
        try:
            _string_list(audit[field], f"{label}: {field}")
        except ValueError as exc:
            errors.append(str(exc))

    evidence = audit["evidence"]
    evidence_ids: set[str] = set()
    evidence_records: list[dict[str, str]] = []
    if not isinstance(evidence, list) or not evidence:
        errors.append(f"{label}: evidence must be a non-empty list")
        evidence = []
    for index, item in enumerate(evidence):
        item_label = f"{label}: evidence[{index}]"
        if not isinstance(item, dict) or set(item) != EVIDENCE_KEYS:
            errors.append(f"{item_label} fields must be {sorted(EVIDENCE_KEYS)}")
            continue
        evidence_id = item["evidence_id"]
        if not isinstance(evidence_id, str) or not ID_RE.fullmatch(evidence_id):
            errors.append(f"{item_label}: invalid evidence_id")
            continue
        if evidence_id in evidence_ids:
            errors.append(f"{label}: duplicate evidence_id={evidence_id!r}")
            continue
        evidence_ids.add(evidence_id)
        try:
            evidence_path = _repo_path(root, item["path"], f"{item_label}.path")
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not evidence_path.is_file() or evidence_path.is_symlink():
            errors.append(f"{item_label}: evidence must be a regular file")
            continue
        expected_hash = item["sha256"]
        actual_hash = evidence_sha256(evidence_path)
        if not isinstance(expected_hash, str) or not SHA256_RE.fullmatch(expected_hash):
            errors.append(f"{item_label}: sha256 is malformed")
        elif expected_hash != actual_hash:
            errors.append(f"{item_label}: sha256 mismatch")
        try:
            purpose = _string(item["purpose"], f"{item_label}.purpose")
        except ValueError as exc:
            errors.append(str(exc))
            purpose = ""
        evidence_records.append(
            {
                "evidence_id": evidence_id,
                "path": str(item["path"]),
                "sha256": str(expected_hash),
                "purpose": purpose,
            }
        )

    findings = audit["findings"]
    finding_ids: set[str] = set()
    finding_severity: dict[str, str] = {}
    if not isinstance(findings, list) or not findings:
        errors.append(f"{label}: findings must be a non-empty list")
        findings = []
    for index, finding in enumerate(findings):
        finding_label = f"{label}: findings[{index}]"
        if not isinstance(finding, dict) or set(finding) != FINDING_KEYS:
            errors.append(f"{finding_label} fields must be {sorted(FINDING_KEYS)}")
            continue
        finding_id = finding["finding_id"]
        if not isinstance(finding_id, str) or not ID_RE.fullmatch(finding_id):
            errors.append(f"{finding_label}: invalid finding_id")
            continue
        if finding_id in finding_ids:
            errors.append(f"{label}: duplicate finding_id={finding_id!r}")
            continue
        finding_ids.add(finding_id)
        severity = finding["severity"]
        if severity not in SEVERITIES:
            errors.append(f"{finding_label}: invalid severity={severity!r}")
        else:
            finding_severity[finding_id] = severity
        for field in ("title", "description"):
            try:
                _string(finding[field], f"{finding_label}.{field}")
            except ValueError as exc:
                errors.append(str(exc))
        try:
            refs = _string_list(finding["evidence_ids"], f"{finding_label}.evidence_ids")
        except ValueError as exc:
            errors.append(str(exc))
            refs = []
        unknown_refs = sorted(set(refs) - evidence_ids)
        if unknown_refs:
            errors.append(f"{finding_label}: unknown evidence_ids {unknown_refs}")

    dispositions = audit["dispositions"]
    disposition_by_finding: dict[str, str] = {}
    if not isinstance(dispositions, list) or not dispositions:
        errors.append(f"{label}: dispositions must be a non-empty list")
        dispositions = []
    for index, disposition in enumerate(dispositions):
        disposition_label = f"{label}: dispositions[{index}]"
        if not isinstance(disposition, dict) or set(disposition) != DISPOSITION_KEYS:
            errors.append(f"{disposition_label} fields must be {sorted(DISPOSITION_KEYS)}")
            continue
        finding_id = disposition["finding_id"]
        if finding_id not in finding_ids:
            errors.append(f"{disposition_label}: unknown finding_id={finding_id!r}")
            continue
        if finding_id in disposition_by_finding:
            errors.append(f"{label}: duplicate disposition for {finding_id!r}")
            continue
        status = disposition["status"]
        if status not in DISPOSITION_STATUSES:
            errors.append(f"{disposition_label}: invalid status={status!r}")
            continue
        disposition_by_finding[finding_id] = status
        try:
            _string(disposition["rationale"], f"{disposition_label}.rationale")
            blocker = _string(
                disposition["blocker"],
                f"{disposition_label}.blocker",
                allow_empty=True,
            )
        except ValueError as exc:
            errors.append(str(exc))
            blocker = ""
        if status == "addressed" and blocker:
            errors.append(f"{disposition_label}: addressed disposition cannot retain blocker")
        if status in {"accepted-with-blocker", "open"} and not blocker.strip():
            errors.append(f"{disposition_label}: {status} requires an explicit blocker")
        try:
            refs = _string_list(disposition["evidence_ids"], f"{disposition_label}.evidence_ids")
        except ValueError as exc:
            errors.append(str(exc))
            refs = []
        unknown_refs = sorted(set(refs) - evidence_ids)
        if unknown_refs:
            errors.append(f"{disposition_label}: unknown evidence_ids {unknown_refs}")
    missing_dispositions = sorted(finding_ids - set(disposition_by_finding))
    if missing_dispositions:
        errors.append(f"{label}: findings without dispositions {missing_dispositions}")

    unresolved_high = sorted(
        finding_id
        for finding_id, severity in finding_severity.items()
        if severity in {"critical", "high"}
        and disposition_by_finding.get(finding_id) not in ENGINEERING_CLOSED
    )
    accepted_blockers = sorted(
        finding_id
        for finding_id, status in disposition_by_finding.items()
        if status == "accepted-with-blocker"
    )
    open_findings = sorted(
        finding_id for finding_id, status in disposition_by_finding.items() if status == "open"
    )
    record = {
        "audit_id": str(audit_id),
        "audited_commit": str(commit),
        "path": label,
        "perspective": str(audit["perspective"]),
        "automated_agent": audit["automated_agent"] is True,
        "human_reviewer": False,
        "human_gate_effect": "none",
        "finding_counts": dict(sorted(Counter(finding_severity.values()).items())),
        "disposition_counts": dict(sorted(Counter(disposition_by_finding.values()).items())),
        "unresolved_high_or_critical": unresolved_high,
        "accepted_blockers": accepted_blockers,
        "open_findings": open_findings,
        "evidence": evidence_records,
    }
    return record, errors


def evaluate_manifest(
    manifest_path: Path = DEFAULT_MANIFEST,
    *,
    root: Path = ROOT,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    try:
        schema = json.loads((root / SCHEMA_PATH.relative_to(ROOT)).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {}, [f"automated audit schema unreadable: {exc}"]
    if set(schema.get("required", [])) != AUDIT_KEYS:
        errors.append("automated audit schema required fields drift from checker")
    if set(schema.get("properties", {})) != AUDIT_KEYS:
        errors.append("automated audit schema properties drift from checker")
    try:
        manifest = _load_yaml(manifest_path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return {}, [f"automated audit manifest unreadable: {exc}"]
    expected_manifest_keys = {
        "schema_version",
        "plan_id",
        "engineering_ready_rule",
        "human_review_boundary",
        "audits",
    }
    if set(manifest) != expected_manifest_keys:
        errors.append("automated audit manifest keys drift")
    if manifest.get("schema_version") != "1.0":
        errors.append("automated audit manifest schema_version must be '1.0'")
    if manifest.get("engineering_ready_rule") != (
        "all-critical-and-high-addressed-or-accepted-with-blocker"
    ):
        errors.append("automated audit engineering_ready_rule drift")
    if manifest.get("human_review_boundary") != ("no-automated-audit-satisfies-paper-human-review"):
        errors.append("automated audit human_review_boundary drift")
    entries = manifest.get("audits")
    if not isinstance(entries, list) or not entries:
        errors.append("automated audit manifest requires audits")
        entries = []

    records: list[dict[str, Any]] = []
    seen_paths: set[Path] = set()
    seen_perspectives: set[str] = set()
    seen_ids: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "perspective",
            "required_for_engineering",
        }:
            errors.append(
                f"audits[{index}] must contain path, perspective, required_for_engineering"
            )
            continue
        perspective = entry["perspective"]
        if perspective not in REQUIRED_PERSPECTIVES or perspective in seen_perspectives:
            errors.append(f"audits[{index}] has unknown/duplicate perspective={perspective!r}")
            continue
        seen_perspectives.add(str(perspective))
        if entry["required_for_engineering"] is not True:
            errors.append(f"audits[{index}] must be required_for_engineering=true")
        try:
            path = _repo_path(root, entry["path"], f"audits[{index}].path")
        except ValueError as exc:
            errors.append(str(exc))
            continue
        audits_root = (root / "docs/audits").resolve()
        if not path.is_relative_to(audits_root):
            errors.append(f"audits[{index}] must stay under docs/audits, never docs/reviews")
            continue
        if path in seen_paths:
            errors.append(f"duplicate automated audit path: {entry['path']}")
            continue
        seen_paths.add(path)
        try:
            audit = _load_yaml(path)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            errors.append(f"automated audit unreadable {entry['path']}: {exc}")
            continue
        record, audit_errors = validate_audit(
            audit,
            root=root,
            path=path,
            expected_perspective=str(perspective),
            enforce_current_tree=True,
        )
        errors.extend(audit_errors)
        if record:
            if record["audit_id"] in seen_ids:
                errors.append(f"duplicate automated audit_id: {record['audit_id']}")
            seen_ids.add(record["audit_id"])
            records.append(record)
    missing_perspectives = sorted(REQUIRED_PERSPECTIVES - seen_perspectives)
    if missing_perspectives:
        errors.append(f"automated audit perspectives missing: {missing_perspectives}")
    audited_commits = {
        record["audited_commit"] for record in records if record.get("audited_commit")
    }
    if len(audited_commits) != 1:
        errors.append("all required automated audits must bind one exact audited_commit")

    unresolved = sorted(
        f"{record['audit_id']}:{finding_id}"
        for record in records
        for finding_id in record["unresolved_high_or_critical"]
    )
    accepted_blockers = sorted(
        f"{record['audit_id']}:{finding_id}"
        for record in records
        for finding_id in record["accepted_blockers"]
    )
    report = {
        "schema_version": "1.0",
        "kind": "automated-engineering-audit-readiness",
        "generated_at": _utc_now(),
        "plan_id": manifest.get("plan_id", ""),
        "static_valid": not errors,
        "engineering_ready": not errors
        and seen_perspectives == REQUIRED_PERSPECTIVES
        and not unresolved,
        "unresolved_high_or_critical": unresolved,
        "accepted_blockers": accepted_blockers,
        "automated_audit_count": len(records),
        "human_review_credit": False,
        "pre_measurement_human_gate_satisfied": False,
        "final_human_gate_satisfied": False,
        "audits": records,
    }
    return report, errors


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--write-report", type=Path)
    parser.add_argument("--require-engineering-ready", action="store_true")
    args = parser.parse_args(argv)
    report, errors = evaluate_manifest(args.manifest.resolve())
    for error in errors:
        print(f"[automated-audit] ERROR: {error}", file=sys.stderr)
    if args.write_report is not None and report:
        _write_json_atomic(args.write_report.resolve(), report)
    if errors:
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.require_engineering_ready and not report["engineering_ready"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
