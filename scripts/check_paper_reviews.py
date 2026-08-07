#!/usr/bin/env python3
"""Validate independent two-person review packets and report paper readiness.

The committed packets intentionally start as ``pending``.  This checker makes
the work assignable before measurement without pretending that an AI or one
maintainer constitutes two independent reviewers.  Static validation exits 0
for complete, well-formed pending packets; readiness modes exit 2 until the
required human sign-offs are present.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = ROOT / "docs" / "reviews" / "paper" / "manifest.yaml"
SCHEMA_PATH = ROOT / "docs" / "reviews" / "paper-review-v2.schema.json"
REVIEW_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
PACKET_KEYS = {
    "schema_version",
    "review_id",
    "status",
    "title",
    "review_phase",
    "source_revision_policy",
    "scope",
    "threat_model",
    "secret_origin",
    "observed_dependency",
    "declassification_predicate",
    "public_transcript",
    "security_argument",
    "known_limitations",
    "evidence",
    "expected_evidence",
    "reviewers",
    "expiry_conditions",
}
FINAL_STATUSES = {"reviewed", "disputed", "expired"}


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
    candidate = (root / value).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} escapes repository: {value!r}") from exc
    return candidate


def _string_list(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ValueError(
            f"{label} must be a {'possibly empty ' if allow_empty else 'non-empty '}list"
        )
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{label} must contain non-empty strings")
    return value


def validate_packet(
    packet: dict[str, Any],
    *,
    root: Path,
    path: Path,
    minimum_reviewers: int,
    required_before_measurement: bool,
) -> list[str]:
    errors: list[str] = []
    label = path.relative_to(root) if path.is_relative_to(root) else path
    unknown = sorted(set(packet) - PACKET_KEYS)
    missing = sorted(PACKET_KEYS - set(packet))
    if unknown:
        errors.append(f"{label}: unknown keys {unknown}")
    if missing:
        errors.append(f"{label}: missing keys {missing}")
        return errors
    if packet["schema_version"] != "2.0":
        errors.append(f"{label}: schema_version must be '2.0'")
    review_id = packet["review_id"]
    if not isinstance(review_id, str) or not REVIEW_ID_RE.fullmatch(review_id):
        errors.append(f"{label}: invalid review_id={review_id!r}")
    status = packet["status"]
    if status not in {"pending", "reviewed", "disputed", "expired"}:
        errors.append(f"{label}: invalid status={status!r}")
    phase = packet["review_phase"]
    if phase not in {"pre-measurement", "post-measurement"}:
        errors.append(f"{label}: invalid review_phase={phase!r}")
    if required_before_measurement and phase != "pre-measurement":
        errors.append(f"{label}: pre-measurement-required packet has phase={phase!r}")
    if not required_before_measurement and phase != "post-measurement":
        errors.append(f"{label}: post-measurement packet has phase={phase!r}")
    if packet["source_revision_policy"] != "exact-clean-git-head-at-review":
        errors.append(f"{label}: source_revision_policy drift")

    scopes = packet["scope"]
    if not isinstance(scopes, list) or not scopes:
        errors.append(f"{label}: scope must be a non-empty list")
    else:
        seen_scope: set[tuple[str, str, str]] = set()
        for index, scope in enumerate(scopes):
            if not isinstance(scope, dict) or set(scope) != {"target", "harness", "build_scope"}:
                errors.append(f"{label}: scope[{index}] must contain target/harness/build_scope")
                continue
            values = (scope["target"], scope["harness"], scope["build_scope"])
            if any(not isinstance(value, str) or not value.strip() for value in values):
                errors.append(f"{label}: scope[{index}] values must be non-empty strings")
            elif values in seen_scope:
                errors.append(f"{label}: duplicate scope {values}")
            seen_scope.add(values)

    for field in (
        "title",
        "threat_model",
        "secret_origin",
        "observed_dependency",
        "declassification_predicate",
        "public_transcript",
        "security_argument",
    ):
        value = packet[field]
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{label}: {field} must be a non-empty string")
    for field in ("known_limitations", "expiry_conditions"):
        try:
            _string_list(packet[field], f"{label}: {field}")
        except ValueError as exc:
            errors.append(str(exc))
    for field in ("evidence", "expected_evidence"):
        try:
            values = _string_list(packet[field], f"{label}: {field}", allow_empty=True)
        except ValueError as exc:
            errors.append(str(exc))
            values = []
        if field == "evidence":
            for value in values:
                try:
                    evidence_path = _repo_path(root, value, f"{label}: evidence")
                except ValueError as exc:
                    errors.append(str(exc))
                    continue
                if not evidence_path.exists():
                    errors.append(f"{label}: evidence path missing: {value}")

    reviewers = packet["reviewers"]
    if not isinstance(reviewers, list):
        errors.append(f"{label}: reviewers must be a list")
        reviewers = []
    reviewer_ids: set[str] = set()
    decisions: list[str] = []
    for index, reviewer in enumerate(reviewers):
        if not isinstance(reviewer, dict):
            errors.append(f"{label}: reviewers[{index}] must be a mapping")
            continue
        expected = {
            "id",
            "independent_from_artifact_author",
            "decision",
            "reviewed_at",
            "notes",
        }
        if set(reviewer) != expected:
            errors.append(f"{label}: reviewers[{index}] fields must be {sorted(expected)}")
            continue
        reviewer_id = reviewer["id"]
        if not isinstance(reviewer_id, str) or not REVIEW_ID_RE.fullmatch(reviewer_id):
            errors.append(f"{label}: reviewers[{index}] has invalid id")
        elif reviewer_id in reviewer_ids:
            errors.append(f"{label}: duplicate reviewer id {reviewer_id!r}")
        reviewer_ids.add(str(reviewer_id))
        if reviewer["independent_from_artifact_author"] is not True:
            errors.append(f"{label}: reviewer {reviewer_id!r} is not independent")
        decision = reviewer["decision"]
        if decision not in {"approve", "reject", "abstain"}:
            errors.append(f"{label}: reviewer {reviewer_id!r} has invalid decision")
        decisions.append(str(decision))
        for field in ("reviewed_at", "notes"):
            if not isinstance(reviewer[field], str) or not reviewer[field].strip():
                errors.append(f"{label}: reviewer {reviewer_id!r} requires {field}")

    if status == "reviewed":
        if len(reviewers) < minimum_reviewers:
            errors.append(
                f"{label}: reviewed requires at least {minimum_reviewers} independent reviewers"
            )
        if any(decision != "approve" for decision in decisions):
            errors.append(f"{label}: reviewed requires unanimous approve decisions")
    elif status == "disputed":
        if len(reviewers) < minimum_reviewers or "reject" not in decisions:
            errors.append(f"{label}: disputed requires quorum and at least one reject")
    elif status == "pending" and reviewers:
        errors.append(f"{label}: partial sign-offs must remain external until quorum is complete")
    return errors


def evaluate_manifest(
    manifest_path: Path = DEFAULT_MANIFEST,
    *,
    root: Path = ROOT,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    try:
        schema = json.loads((root / SCHEMA_PATH.relative_to(ROOT)).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {}, [f"review schema unreadable: {exc}"]
    if set(schema.get("required", [])) != PACKET_KEYS:
        errors.append("paper review JSON schema required fields drift from checker")
    if set(schema.get("properties", {})) != PACKET_KEYS:
        errors.append("paper review JSON schema properties drift from checker")

    try:
        manifest = _load_yaml(manifest_path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return {}, [f"review manifest unreadable: {exc}"]
    expected_manifest_keys = {
        "schema_version",
        "plan_id",
        "minimum_reviewers",
        "independence_rule",
        "packets",
    }
    if set(manifest) != expected_manifest_keys:
        errors.append("review manifest keys drift")
    if manifest.get("schema_version") != "1.0":
        errors.append("review manifest schema_version must be '1.0'")
    minimum = manifest.get("minimum_reviewers")
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 2:
        errors.append("minimum_reviewers must be an integer >= 2")
        minimum = 2
    entries = manifest.get("packets")
    if not isinstance(entries, list) or not entries:
        errors.append("review manifest requires packets")
        entries = []

    records: list[dict[str, Any]] = []
    seen_paths: set[Path] = set()
    seen_ids: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {"path", "required_before_measurement"}:
            errors.append(f"packets[{index}] must contain path and required_before_measurement")
            continue
        required = entry["required_before_measurement"]
        if not isinstance(required, bool):
            errors.append(f"packets[{index}].required_before_measurement must be boolean")
            continue
        try:
            path = _repo_path(root, entry["path"], f"packets[{index}].path")
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if path in seen_paths:
            errors.append(f"duplicate packet path: {entry['path']}")
            continue
        seen_paths.add(path)
        try:
            packet = _load_yaml(path)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            errors.append(f"packet unreadable {entry['path']}: {exc}")
            continue
        errors.extend(
            validate_packet(
                packet,
                root=root,
                path=path,
                minimum_reviewers=minimum,
                required_before_measurement=required,
            )
        )
        review_id = str(packet.get("review_id", ""))
        if review_id in seen_ids:
            errors.append(f"duplicate paper review_id: {review_id}")
        seen_ids.add(review_id)
        records.append(
            {
                "review_id": review_id,
                "path": str(path.relative_to(root)),
                "status": packet.get("status"),
                "review_phase": packet.get("review_phase"),
                "required_before_measurement": required,
                "reviewer_count": len(packet.get("reviewers", []))
                if isinstance(packet.get("reviewers"), list)
                else 0,
            }
        )
    statuses = Counter(str(record["status"]) for record in records)
    pre = [record for record in records if record["required_before_measurement"]]
    report = {
        "schema_version": "1.0",
        "kind": "paper-review-readiness",
        "generated_at": _utc_now(),
        "plan_id": manifest.get("plan_id", ""),
        "minimum_reviewers": minimum,
        "static_valid": not errors,
        "pre_measurement_ready": bool(pre)
        and all(
            record["status"] == "reviewed" and record["reviewer_count"] >= minimum for record in pre
        ),
        "paper_ready": bool(records)
        and all(
            record["status"] == "reviewed" and record["reviewer_count"] >= minimum
            for record in records
        ),
        "status_counts": dict(sorted(statuses.items())),
        "packets": records,
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
    readiness = parser.add_mutually_exclusive_group()
    readiness.add_argument("--require-pre-measurement", action="store_true")
    readiness.add_argument("--require-complete", action="store_true")
    args = parser.parse_args(argv)

    report, errors = evaluate_manifest(args.manifest.resolve())
    for error in errors:
        print(f"[paper-review] ERROR: {error}", file=sys.stderr)
    if args.write_report is not None and report:
        _write_json_atomic(args.write_report.resolve(), report)
    if errors:
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.require_pre_measurement and not report["pre_measurement_ready"]:
        return 2
    if args.require_complete and not report["paper_ready"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
