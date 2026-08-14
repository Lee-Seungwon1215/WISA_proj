#!/usr/bin/env python3
"""Fail-closed static checker for the frozen paper measurement campaign."""

from __future__ import annotations

import argparse
import json
import re
import shlex
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

DEFAULT_MANIFEST = ROOT / "docs/measurement/paper_native_campaign_v9.yaml"
DIVERSE_MANIFEST = ROOT / "docs/corpus/diverse_upstreams_v1.yaml"
EXPECTED_COMPONENTS = (
    ("committed-corpus-refresh", "docs/measurement/native_timing_v4_campaign.yaml"),
    ("kyberslash-contrast", "docs/measurement/kyberslash_native_v4.yaml"),
    ("falcon-contrast", "docs/measurement/falcon_native_v3.yaml"),
    ("diverse-lineages", "docs/measurement/diverse_native_v3.yaml"),
)
PREVIOUS_COMPONENTS = {
    "committed-corpus-refresh": "docs/measurement/native_timing_v3_campaign.yaml",
    "kyberslash-contrast": "docs/measurement/kyberslash_native_v3.yaml",
    "falcon-contrast": "docs/measurement/falcon_native_v2.yaml",
    "diverse-lineages": "docs/measurement/diverse_native_v2.yaml",
}
EXPECTED_OUTPUT_DIRS = {
    "committed-corpus-refresh": "committed-corpus-v4",
    "kyberslash-contrast": "kyberslash-v4",
    "falcon-contrast": "falcon-v3",
    "diverse-lineages": "diverse-v3",
}
CALIBRATION_PATH = ROOT / "docs/measurement/paper_control_rehearsal_v1_calibration.yaml"
V9_EFFECT_OVERRIDES = {
    ("committed-corpus-refresh", "pqclean_mlkem768"): (64, 512, 8192),
    ("committed-corpus-refresh", "pqclean_falcon512_reference"): (512, 8192, 131072),
    ("kyberslash-contrast", "pqclean_mlkem768"): (64, 512, 8192),
    ("kyberslash-contrast", "pqclean_mlkem768_kyberslash2"): (64, 512, 8192),
    ("kyberslash-contrast", "pqclean_mlkem768_kyberslash"): (64, 512, 8192),
    ("falcon-contrast", "pqclean_falcon512_reference"): (512, 8192, 131072),
    ("falcon-contrast", "pqclean_falcon1024_reference"): (512, 8192, 131072),
    ("falcon-contrast", "c_fndsa512_fpr_emu"): (512, 8192, 131072),
    ("diverse-lineages", "mlkem_native_768_portable"): (64, 512, 8192),
}
EXPECTED_CALIBRATION_SOURCE = {
    "profile_id": "ctkat-paper-control-rehearsal-v1",
    "profile_sha256": "9bce1506848b6f23b9624b8b344c193771da6df76cb756e72fbc4d77970d0ea5",
    "candidate_commit": "0ed9ea5359c00d7e1aac115001dbd9dc270d6d9a",
    "run_id": "18fc18bf328b417b9a4faf1ef2607406",
    "started_at": "2026-08-12T11:28:26.861473Z",
    "finished_at": "2026-08-12T12:53:51.985878Z",
    "report_sha256": "03385b3cb17d8103c2dacd4b9c185b02f026c1849738663bc4b885f7114fae65",
    "markdown_sha256": "8338741a791bf2f8aef349e53ac0db65c212028db8175acf535a3b4956fd5243",
    "completed_without_interruption": True,
    "smoke_axes_passed": 28,
    "native_axes_assessed": 28,
    "baselines_passed": 3,
    "assembly_passed": True,
    "pipeline_closure_passed": True,
    "blocker_count": 8,
}
BASELINE_COMMAND_ORDER = ("official_dudect", "timecop", "microwalk_pin")
EXECUTION_PLACEHOLDERS = ("host-ID", "CPU-ID", "TIMECOP-PREFIX", "QUALIFICATION")
HOST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
EXPECTED_CLAIM_LIMITS = (
    "a static plan or automated integrity gate is not timing evidence or independent human approval",
    "an engineering or pilot run is not final evidence",
    (
        "single-host final evidence supports only host-scoped findings and does not "
        "establish cross-host reproducibility"
    ),
    "no independent review, declassification, or inter-rater agreement claim is made",
    (
        "v6 final, pre-v7 engineering, failed v7 and v8 final attempts, and both v1 "
        "control-rehearsal artifacts are diagnostic or calibration evidence and are not "
        "reusable in v9"
    ),
    "the v9 largest-effect changes use one uniform control-only rule and no reduced target statistic",
    (
        "every v9 final command requires a machine-validated qualification from two "
        "blocker-free v2 control rehearsals at the exact final commit"
    ),
    (
        "v1 Falcon and diverse plus v2 committed-corpus engineering traces are "
        "calibration evidence and are not reusable in their replacement final campaigns"
    ),
    (
        "KyberSlash v2 operand traces have invalid-placebo and class-address setup "
        "confounds and are not reusable in v3 or v4"
    ),
    (
        "every final timing axis requires a pre-measurement source, binary, compiler, "
        "config, and linked-input build seal"
    ),
    (
        "non-operand KEM and signature class setup uses dual-read-masked-select-v4 to "
        "read both pools and select into shared work buffers before timing"
    ),
    (
        "every resolved timing harness has an explicit semantic randomness policy "
        "independent of randombytes_header and runtime observations must match it"
    ),
    (
        "KyberSlash operand and c-fn-dsa harnesses require seeded-interpose despite a "
        "null randombytes_header"
    ),
    ("KyberSlash operand timing records zero RNG calls inside the measured decapsulation interval"),
    "only the deterministic self-contained toy baseline declares external-or-none randomness",
    (
        "the ML-KEM valid-tuple axis changes secret and public material together and "
        "cannot support secret attribution"
    ),
    "chosen-ciphertext timing is a public-input contrast and not secret attribution",
    "operand-bin timing is a hardware-latency canary and not a full attack or key recovery",
    "full-signature Falcon timing includes variable-length encoding",
    "c-fn-dsa is prospective comparator evidence, not a FIPS 206 conformance claim",
    "OpenSSL is a provider-API integration case and not an independent lineage",
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


def render_execution_commands(
    manifest: dict[str, Any],
    *,
    host_id: str,
    cpu: int,
    timecop_prefix: Path,
    control_qualification: Path,
) -> list[str]:
    """Render the frozen four-component and three-baseline final commands."""

    if not HOST_ID_RE.fullmatch(host_id):
        raise ValueError("host id must contain only letters, digits, dot, underscore, or hyphen")
    if isinstance(cpu, bool) or cpu < 0:
        raise ValueError("cpu must be a non-negative logical CPU id")
    if not timecop_prefix.is_absolute():
        raise ValueError("TIMECOP prefix must be an absolute path")
    if not control_qualification.is_absolute():
        raise ValueError("control qualification must be an absolute path")

    components = manifest.get("components")
    baseline = manifest.get("same_corpus_baseline")
    execute_commands = baseline.get("execute_commands") if isinstance(baseline, dict) else None
    if not isinstance(components, list) or not isinstance(execute_commands, dict):
        raise ValueError("frozen execution command matrix is malformed")
    raw_commands = [item.get("command") for item in components if isinstance(item, dict)] + [
        execute_commands.get(tool_id) for tool_id in BASELINE_COMMAND_ORDER
    ]
    if len(raw_commands) != 7 or any(not isinstance(command, str) for command in raw_commands):
        raise ValueError("frozen execution command matrix must contain exactly seven commands")

    replacements = {
        "CPU-ID": str(cpu),
        "TIMECOP-PREFIX": str(timecop_prefix),
        "QUALIFICATION": str(control_qualification),
    }
    rendered: list[str] = []
    for raw_command in raw_commands:
        assert isinstance(raw_command, str)
        argv = []
        for token in shlex.split(raw_command):
            token = token.replace("host-ID", host_id)
            token = replacements.get(token, token)
            argv.append(token)
        command = shlex.join(argv)
        remaining = [value for value in EXECUTION_PLACEHOLDERS if value in command]
        if remaining:
            raise ValueError(f"unresolved execution placeholders: {remaining}")
        rendered.append(command)
    return rendered


def validate(manifest: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    expected_top_level = {
        "schema_version",
        "campaign_id",
        "status",
        "frozen_at",
        "execution_policy",
        "components",
        "same_corpus_baseline",
        "analysis",
        "upstream_freeze",
        "promotion",
        "claim_limits",
    }
    if set(manifest) != expected_top_level:
        errors.append("paper campaign top-level field set drift")
    if manifest.get("schema_version") != 3:
        errors.append("schema_version must be 3")
    if manifest.get("campaign_id") != "ctkat-paper-native-v9-single-host":
        errors.append("campaign_id must be ctkat-paper-native-v9-single-host")
    if manifest.get("status") != "premeasurement-frozen":
        errors.append("status must remain premeasurement-frozen")
    if manifest.get("claim_limits") != list(EXPECTED_CLAIM_LIMITS):
        errors.append("claim_limits drift")

    policy = manifest.get("execution_policy")
    if not isinstance(policy, dict):
        errors.append("execution_policy must be a mapping")
        policy = {}
    required_policy = {
        "minimum_physical_hosts": 1,
        "minimum_distinct_cpu_models": 1,
        "operating_system": "Linux",
        "architecture": "x86_64",
        "virtualization_allowed": False,
        "emulation_allowed": False,
        "same_commit_required": True,
        "pilot_and_final_separated": True,
        "final_code_changes_allowed": False,
        "cross_component_artifact_reuse": False,
        "final_run_kind": "final",
        "engineering_results_promotable": False,
        "pilot_results_promotable": False,
        "final_resume_allowed": False,
        "premeasurement_gate": "automated-frozen-input-integrity",
        "independent_human_review_required": False,
        "cross_host_reproducibility_claimed": False,
        "required_clean_control_rehearsals": 2,
        "control_qualification_required": True,
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
        if set(item) != {"id", "purpose", "manifest", "command"}:
            errors.append(f"components[{index}] field set drift")
        component_id = item.get("id")
        previous_manifest = PREVIOUS_COMPONENTS.get(str(component_id))
        output_dir = EXPECTED_OUTPUT_DIRS.get(str(component_id))
        if previous_manifest is None or output_dir is None:
            errors.append(f"components[{index}] has an unknown component id")
            continue
        try:
            path = _repo_path(item.get("manifest"), f"components[{index}].manifest")
            native = load_native_manifest(path)
            native_errors = static_check(native)
            previous = load_native_manifest(ROOT / previous_manifest)
        except (OSError, ValueError, CampaignError) as exc:
            errors.append(f"components[{index}] cannot load: {exc}")
            continue
        if native_errors:
            errors.extend(f"{item.get('id')}: {error}" for error in native_errors)
        if (
            native.coverage_mode != previous.coverage_mode
            or native.corpus_axis_replacements != previous.corpus_axis_replacements
            or native.host != previous.host
            or native.protocol != previous.protocol
            or [target.id for target in native.targets]
            != [target.id for target in previous.targets]
        ):
            errors.append(f"{item.get('id')}: V9 changed scope or non-effect protocol fields")
        for old_target, new_target in zip(previous.targets, native.targets, strict=True):
            if (
                old_target.family != new_target.family
                or old_target.config != new_target.config
                or old_target.harnesses != new_target.harnesses
                or old_target.axes != new_target.axes
                or old_target.target_measurements != new_target.target_measurements
                or old_target.control_measurements != new_target.control_measurements
                or old_target.timeout != new_target.timeout
            ):
                errors.append(
                    f"{item.get('id')}/{new_target.id}: V9 changed a non-effect target field"
                )
            expected_effects = V9_EFFECT_OVERRIDES.get(
                (str(component_id), new_target.id),
                old_target.positive_control_effects,
            )
            if new_target.positive_control_effects != expected_effects:
                errors.append(f"{item.get('id')}/{new_target.id}: V9 effect calibration drift")
        expected_command = (
            "uv run --frozen python scripts/run_native_timing_campaign.py --manifest "
            f"{item['manifest']} --output-root measurement_runs/host-ID/"
            f"{output_dir} "
            "--run-kind final --final-gate single-host --control-qualification "
            "QUALIFICATION --cpu CPU-ID --execute"
        )
        if item.get("command") != expected_command:
            errors.append(f"{item.get('id')}: execution command drift")
        axes = sum(len(target.harnesses) for target in native.targets)
        protocol_rows = 0
        for target in native.targets:
            per_harness = native.protocol.process_repeats * (
                2 * target.target_measurements
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
    if baseline.get("check_command") != (
        "uv run --frozen python scripts/run_same_corpus_baselines.py --check"
    ):
        errors.append("same-corpus check command drift")
    expected_baseline_commands = {
        "official_dudect": (
            "uv run --frozen python scripts/run_same_corpus_baselines.py "
            "--run-dudect --run-kind final --final-gate single-host "
            "--control-qualification QUALIFICATION --cpu CPU-ID "
            "--output-root measurement_runs/host-ID/same-corpus"
        ),
        "timecop": (
            "uv run --frozen python scripts/run_same_corpus_baselines.py "
            "--run-timecop --run-kind final --final-gate single-host "
            "--control-qualification QUALIFICATION --prefix TIMECOP-PREFIX "
            "--output-root measurement_runs/host-ID/same-corpus"
        ),
        "microwalk_pin": (
            "uv run --frozen python scripts/run_same_corpus_baselines.py "
            "--run-microwalk --run-kind final --final-gate single-host "
            "--control-qualification QUALIFICATION "
            "--output-root measurement_runs/host-ID/same-corpus"
        ),
    }
    if baseline.get("execute_commands") != expected_baseline_commands:
        errors.append("same-corpus execution command matrix drift")
    if baseline.get("automatic_promotion") is not False:
        errors.append("same-corpus baseline must not auto-promote")

    try:
        calibration = yaml.safe_load(CALIBRATION_PATH.read_text(encoding="utf-8"))
        selected = calibration.get("selected_targets") if isinstance(calibration, dict) else None
        if (
            not isinstance(calibration, dict)
            or calibration.get("schema_version") != "1.0"
            or calibration.get("kind") != "ctkat-paper-control-calibration-record"
            or calibration.get("calibration_id") != "ctkat-paper-control-rehearsal-v1-calibration"
            or calibration.get("recorded_at") != "2026-08-14"
            or calibration.get("source_rehearsal") != EXPECTED_CALIBRATION_SOURCE
        ):
            errors.append("V9 control calibration identity/source provenance drift")
        observed_overrides = {
            (str(item.get("component")), str(item.get("target"))): tuple(
                item.get("new_effects") or []
            )
            for item in selected or []
            if isinstance(item, dict)
        }
        if (
            not isinstance(selected, list)
            or len(selected) != 9
            or len(observed_overrides) != 9
            or observed_overrides != V9_EFFECT_OVERRIDES
        ):
            errors.append("V9 control calibration selected-target matrix drift")
        boundary = calibration.get("evidence_boundary") if isinstance(calibration, dict) else None
        if (
            not isinstance(boundary, dict)
            or boundary.get("target_statistics_used_for_calibration") is not False
            or boundary.get("source_rehearsal_reusable_in_final") is not False
        ):
            errors.append("V9 control calibration evidence boundary drift")
        rule = (
            calibration.get("uniform_remediation_rule") if isinstance(calibration, dict) else None
        )
        if (
            not isinstance(rule, dict)
            or rule.get("selection_unit") != "manifest-target"
            or rule.get("select_when")
            != "any axis in the target has largest-effect worst-repeat t_score > -20"
            or rule.get("adjustment")
            != "retain the first two effect points and double only the largest effect"
            or rule.get("thresholds_unchanged") is not True
            or rule.get("counts_unchanged") is not True
            or rule.get("seeds_unchanged") is not True
            or rule.get("repeats_unchanged") is not True
        ):
            errors.append("V9 control calibration remediation rule drift")
    except (OSError, TypeError, yaml.YAMLError) as exc:
        errors.append(f"V9 control calibration is unreadable: {exc}")

    analysis = manifest.get("analysis")
    if not isinstance(analysis, dict):
        errors.append("analysis must be a mapping")
        analysis = {}
    expected_analysis = {
        "script": "scripts/analyze_paper_native_results.py",
        "contract": "docs/measurement/PAPER_NATIVE_ANALYSIS_V2.md",
        "mode": "named-single-host",
        "command": (
            "uv run --frozen python scripts/analyze_paper_native_results.py "
            "--bundle BUNDLE.yaml "
            "--verification-commit COMMIT --output-root analysis/named "
            "--output-mode named"
        ),
        "primary_decision": "valid-single-host-result",
        "holm_within_preregistered_family": True,
        "report_host_heterogeneity": False,
    }
    if analysis != expected_analysis:
        errors.append("analysis/blinding contract drift")
    try:
        if not _repo_path(analysis.get("script"), "analysis.script").is_file():
            errors.append("analysis.script is missing")
    except ValueError as exc:
        errors.append(str(exc))

    promotion = manifest.get("promotion")
    if not isinstance(promotion, dict):
        errors.append("promotion must be a mapping")
        promotion = {}
    for key in (
        "require_artifact_hashes",
        "require_clean_frozen_commit",
        "require_automated_premeasurement_gate",
        "require_single_physical_host",
        "require_control_pass",
        "require_two_clean_control_rehearsals",
        "require_control_qualification_artifact",
    ):
        if promotion.get(key) is not True:
            errors.append(f"promotion.{key} must be true")
    for key in ("require_two_person_human_review", "require_both_hosts"):
        if promotion.get(key) is not False:
            errors.append(f"promotion.{key} must be false")
    if promotion.get("automatic_corpus_mutation") is not False:
        errors.append("promotion.automatic_corpus_mutation must be false")
    for key in ("preregistration", "control_calibration", "control_rehearsal"):
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
        "protocol_rows_all_hosts": total_protocol_rows
        * int(policy.get("minimum_physical_hosts") or 0),
        "errors": errors,
    }
    return errors, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--json", type=Path)
    parser.add_argument(
        "--print-commands",
        action="store_true",
        help="print seven final commands with all host placeholders resolved",
    )
    parser.add_argument("--host-id", help="safe host label used in output paths")
    parser.add_argument("--cpu", type=int, help="logical CPU id for pinned timing commands")
    parser.add_argument(
        "--timecop-prefix",
        type=Path,
        help="absolute exact-pinned patched Valgrind installation prefix",
    )
    parser.add_argument(
        "--control-qualification",
        type=Path,
        help="absolute qualification JSON produced from two clean control rehearsals",
    )
    args = parser.parse_args(argv)
    render_args = (args.host_id, args.cpu, args.timecop_prefix, args.control_qualification)
    if args.print_commands and any(value is None for value in render_args):
        parser.error(
            "--print-commands requires --host-id, --cpu, --timecop-prefix, "
            "and --control-qualification"
        )
    if not args.print_commands and any(value is not None for value in render_args):
        parser.error(
            "--host-id, --cpu, --timecop-prefix, and --control-qualification "
            "require --print-commands"
        )
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
    if args.print_commands:
        assert args.host_id is not None
        assert args.cpu is not None
        assert args.timecop_prefix is not None
        assert args.control_qualification is not None
        try:
            commands = render_execution_commands(
                manifest,
                host_id=args.host_id,
                cpu=args.cpu,
                timecop_prefix=args.timecop_prefix,
                control_qualification=args.control_qualification,
            )
        except ValueError as exc:
            parser.error(str(exc))
        for command in commands:
            print(command)
        return 0
    print(
        f"[paper-campaign] OK: {report['component_count']} components, "
        f"{report['target_executions']} target executions, {report['timing_axes']} axes, "
        f"{report['protocol_rows_all_hosts']} protocol rows on one physical host"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
