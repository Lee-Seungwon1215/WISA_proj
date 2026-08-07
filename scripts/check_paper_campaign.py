#!/usr/bin/env python3
"""Fail-closed static checker for the frozen paper measurement campaign."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.run_native_timing_campaign import (  # noqa: E402
    CampaignError,
    static_check,
)
from scripts.run_native_timing_campaign import (  # noqa: E402
    load_campaign as load_native_manifest,
)

DEFAULT_MANIFEST = ROOT / "docs/measurement/paper_native_campaign_v1.yaml"
DIVERSE_MANIFEST = ROOT / "docs/corpus/diverse_upstreams_v1.yaml"
EXPECTED_COMPONENTS = (
    ("committed-corpus-refresh", "docs/measurement/native_timing_v2_campaign.yaml"),
    ("kyberslash-contrast", "docs/measurement/kyberslash_native_v1.yaml"),
    ("falcon-contrast", "docs/measurement/falcon_native_v1.yaml"),
    ("diverse-lineages", "docs/measurement/diverse_native_v1.yaml"),
)


def _repo_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a repository-relative path")
    path = (ROOT / value).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"{label} escapes repository: {value}") from exc
    return path


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("paper campaign root must be a mapping")
    return data


def validate(manifest: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    if manifest.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if manifest.get("status") != "premeasurement-frozen":
        errors.append("status must remain premeasurement-frozen")

    policy = manifest.get("execution_policy")
    if not isinstance(policy, dict):
        errors.append("execution_policy must be a mapping")
        policy = {}
    required_policy = {
        "minimum_physical_hosts": 2,
        "minimum_distinct_cpu_models": 2,
        "operating_system": "Linux",
        "architecture": "x86_64",
        "virtualization_allowed": False,
        "emulation_allowed": False,
        "same_commit_required": True,
        "pilot_and_final_separated": True,
        "final_code_changes_allowed": False,
        "cross_component_artifact_reuse": False,
    }
    for key, expected in required_policy.items():
        if policy.get(key) != expected:
            errors.append(f"execution_policy.{key} must be {expected!r}")

    components = manifest.get("components")
    if not isinstance(components, list):
        errors.append("components must be a list")
        components = []
    identities = [
        (item.get("id"), item.get("manifest")) for item in components if isinstance(item, dict)
    ]
    if identities != list(EXPECTED_COMPONENTS):
        errors.append(f"component order/scope drift: {identities!r}")

    component_report: list[dict[str, Any]] = []
    total_axes = 0
    total_protocol_rows = 0
    for index, item in enumerate(components):
        if not isinstance(item, dict):
            errors.append(f"components[{index}] must be a mapping")
            continue
        try:
            path = _repo_path(item.get("manifest"), f"components[{index}].manifest")
            native = load_native_manifest(path)
            native_errors = static_check(native)
        except (OSError, ValueError, CampaignError) as exc:
            errors.append(f"components[{index}] cannot load: {exc}")
            continue
        if native_errors:
            errors.extend(f"{item.get('id')}: {error}" for error in native_errors)
        expected_command = (
            "python3 scripts/run_native_timing_campaign.py --manifest "
            f"{item['manifest']} --output-root measurement_runs/host-ID/"
            f"{ {'committed-corpus-refresh': 'committed-corpus', 'kyberslash-contrast': 'kyberslash', 'falcon-contrast': 'falcon', 'diverse-lineages': 'diverse'}[item['id']] } --execute"
        )
        if item.get("command") != expected_command:
            errors.append(f"{item.get('id')}: execution command drift")
        axes = sum(len(target.harnesses) for target in native.targets)
        protocol_rows = 0
        for target in native.targets:
            per_harness = native.protocol.process_repeats * (
                target.target_measurements
                + (2 + len(target.positive_control_effects)) * target.control_measurements
            )
            protocol_rows += len(target.harnesses) * per_harness
        total_axes += axes
        total_protocol_rows += protocol_rows
        component_report.append(
            {
                "id": item.get("id"),
                "campaign_id": native.campaign_id,
                "coverage_mode": native.coverage_mode,
                "targets": len(native.targets),
                "timing_axes": axes,
                "protocol_rows": protocol_rows,
                "static_ok": not native_errors,
            }
        )

    baseline = manifest.get("same_corpus_baseline")
    if not isinstance(baseline, dict):
        errors.append("same_corpus_baseline must be a mapping")
        baseline = {}
    if baseline.get("check_command") != "python3 scripts/run_same_corpus_baselines.py --check":
        errors.append("same-corpus check command drift")
    if baseline.get("automatic_promotion") is not False:
        errors.append("same-corpus baseline must not auto-promote")

    promotion = manifest.get("promotion")
    if not isinstance(promotion, dict):
        errors.append("promotion must be a mapping")
        promotion = {}
    for key in (
        "require_artifact_hashes",
        "require_two_person_review",
        "require_both_hosts",
        "require_control_pass",
    ):
        if promotion.get(key) is not True:
            errors.append(f"promotion.{key} must be true")
    if promotion.get("automatic_corpus_mutation") is not False:
        errors.append("promotion.automatic_corpus_mutation must be false")
    for key in ("review_manifest", "preregistration"):
        try:
            required_path = _repo_path(promotion.get(key), f"promotion.{key}")
            if not required_path.is_file():
                errors.append(f"promotion.{key} is missing")
        except ValueError as exc:
            errors.append(str(exc))

    try:
        diverse = yaml.safe_load(DIVERSE_MANIFEST.read_text(encoding="utf-8"))
        frozen = manifest.get("upstream_freeze", {})
        for lineage in ("mlkem-native", "mldsa-native"):
            expected = diverse["lineages"][lineage]
            actual = frozen.get(lineage, {})
            for source_key, freeze_key in (
                ("release", "release"),
                ("revision", "revision"),
                ("tree_sha256", "tree_sha256"),
            ):
                if actual.get(freeze_key) != expected.get(source_key):
                    errors.append(f"upstream_freeze.{lineage}.{freeze_key} drift")
    except (OSError, TypeError, KeyError, yaml.YAMLError) as exc:
        errors.append(f"cannot cross-check upstream freeze: {exc}")

    report = {
        "campaign_id": manifest.get("campaign_id"),
        "status": "static-plan-valid" if not errors else "invalid",
        "physical_hosts_required": policy.get("minimum_physical_hosts"),
        "components": component_report,
        "component_count": len(component_report),
        "target_executions": sum(item["targets"] for item in component_report),
        "timing_axes": total_axes,
        "protocol_rows_per_host": total_protocol_rows,
        "protocol_rows_all_hosts": total_protocol_rows * 2,
        "errors": errors,
    }
    return errors, report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.manifest)
        errors, report = validate(manifest)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"[paper-campaign] ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if errors:
        for error in errors:
            print(f"[paper-campaign] ERROR: {error}", file=sys.stderr)
        return 2
    print(
        f"[paper-campaign] OK: {report['component_count']} components, "
        f"{report['target_executions']} target executions, {report['timing_axes']} axes, "
        f"{report['protocol_rows_all_hosts']} protocol rows across two hosts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
