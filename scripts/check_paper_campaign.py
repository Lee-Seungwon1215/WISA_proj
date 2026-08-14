#!/usr/bin/env python3
"""Fail-closed static checker for the frozen paper measurement campaign."""

from __future__ import annotations

import argparse
import hashlib
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

DEFAULT_MANIFEST = ROOT / "docs/measurement/paper_native_campaign_v10.yaml"
DIVERSE_MANIFEST = ROOT / "docs/corpus/diverse_upstreams_v1.yaml"
EXPECTED_COMPONENTS = (
    ("committed-corpus-refresh", "docs/measurement/native_timing_v5_campaign.yaml"),
    ("kyberslash-contrast", "docs/measurement/kyberslash_native_v5.yaml"),
    ("falcon-contrast", "docs/measurement/falcon_native_v4.yaml"),
    ("diverse-lineages", "docs/measurement/diverse_native_v4.yaml"),
)
PREVIOUS_COMPONENTS = {
    "committed-corpus-refresh": "docs/measurement/native_timing_v4_campaign.yaml",
    "kyberslash-contrast": "docs/measurement/kyberslash_native_v4.yaml",
    "falcon-contrast": "docs/measurement/falcon_native_v3.yaml",
    "diverse-lineages": "docs/measurement/diverse_native_v3.yaml",
}
EXPECTED_OUTPUT_DIRS = {
    "committed-corpus-refresh": "committed-corpus-v5",
    "kyberslash-contrast": "kyberslash-v5",
    "falcon-contrast": "falcon-v4",
    "diverse-lineages": "diverse-v4",
}
CALIBRATION_PATH = ROOT / "docs/measurement/paper_control_rehearsal_v2_calibration.yaml"
V2_PROFILE_PATH = ROOT / "docs/measurement/paper_control_rehearsal_v2.yaml"
V1_CALIBRATION_PATH = ROOT / "docs/measurement/paper_control_rehearsal_v1_calibration.yaml"
V9_PLAN_PATH = ROOT / "docs/measurement/paper_native_campaign_v9.yaml"
V10_EFFECT_OVERRIDES = {
    ("committed-corpus-refresh", "pqclean_mlkem768"): (64, 512, 16384),
    ("kyberslash-contrast", "pqclean_mlkem768"): (64, 512, 16384),
    ("kyberslash-contrast", "pqclean_mlkem768_kyberslash1"): (64, 512, 16384),
    ("kyberslash-contrast", "pqclean_mlkem768_kyberslash2"): (64, 512, 16384),
    ("kyberslash-contrast", "pqclean_mlkem768_kyberslash"): (64, 512, 16384),
    ("kyberslash-contrast", "kyberslash_operand_ks1_vulnerable"): (64, 512, 16384),
    ("kyberslash-contrast", "kyberslash_operand_ks1_patched"): (64, 512, 16384),
    ("kyberslash-contrast", "kyberslash_operand_ks2_poly_vulnerable"): (64, 512, 16384),
    ("kyberslash-contrast", "kyberslash_operand_ks2_poly_patched"): (64, 512, 16384),
    ("kyberslash-contrast", "kyberslash_operand_ks2_polyvec_vulnerable"): (
        64,
        512,
        16384,
    ),
    ("kyberslash-contrast", "kyberslash_operand_ks2_polyvec_patched"): (
        64,
        512,
        16384,
    ),
    ("diverse-lineages", "mlkem_native_768_portable"): (64, 512, 16384),
    ("diverse-lineages", "mlkem_native_768_x86_64"): (64, 512, 16384),
}
V10_OLD_EFFECTS = {
    ("committed-corpus-refresh", "pqclean_mlkem768"): (64, 512, 8192),
    ("kyberslash-contrast", "pqclean_mlkem768"): (64, 512, 8192),
    ("kyberslash-contrast", "pqclean_mlkem768_kyberslash1"): (64, 512, 4096),
    ("kyberslash-contrast", "pqclean_mlkem768_kyberslash2"): (64, 512, 8192),
    ("kyberslash-contrast", "pqclean_mlkem768_kyberslash"): (64, 512, 8192),
    ("kyberslash-contrast", "kyberslash_operand_ks1_vulnerable"): (64, 512, 4096),
    ("kyberslash-contrast", "kyberslash_operand_ks1_patched"): (64, 512, 4096),
    ("kyberslash-contrast", "kyberslash_operand_ks2_poly_vulnerable"): (64, 512, 4096),
    ("kyberslash-contrast", "kyberslash_operand_ks2_poly_patched"): (64, 512, 4096),
    ("kyberslash-contrast", "kyberslash_operand_ks2_polyvec_vulnerable"): (
        64,
        512,
        4096,
    ),
    ("kyberslash-contrast", "kyberslash_operand_ks2_polyvec_patched"): (
        64,
        512,
        4096,
    ),
    ("diverse-lineages", "mlkem_native_768_portable"): (64, 512, 8192),
    ("diverse-lineages", "mlkem_native_768_x86_64"): (64, 512, 4096),
}
V2_EXPECTED_BLOCKERS = [
    {
        "code": "control.aa-margin",
        "component": "committed-corpus-refresh",
        "target": "pqclean_mldsa44",
        "harness": "sign",
        "process_index": 0,
        "observed_abs_t_score": 3.7920758863707618,
        "v1_observed_abs_t_score": 3.779344508124509,
        "failed_rehearsal_rule": "abs_t_score < 3.5",
        "unchanged_final_rule": "abs_t_score < 4.5",
    },
    {
        "code": "control.positive-margin",
        "component": "kyberslash-contrast",
        "target": "pqclean_mlkem768_kyberslash1",
        "harness": "kem_dec_chosen_ct",
        "process_index": 1,
        "effect_ticks": 4096,
        "observed_t_score": -10.205320807745164,
        "rehearsal_rule": "t_score <= -15.0",
        "unchanged_final_rule": "abs_t_score >= 10.0 with expected direction",
    },
    {
        "code": "control.positive-margin",
        "component": "kyberslash-contrast",
        "target": "pqclean_mlkem768_kyberslash1",
        "harness": "kem_dec_chosen_ct",
        "process_index": 2,
        "effect_ticks": 4096,
        "observed_t_score": -13.650128151544706,
        "rehearsal_rule": "t_score <= -15.0",
        "unchanged_final_rule": "abs_t_score >= 10.0 with expected direction",
    },
]
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
        "v6 final, pre-v7 engineering, failed v7 and v8 final attempts, v1 artifacts, "
        "and failed v2-a are diagnostic or calibration evidence and are not reusable "
        "in v10"
    ),
    (
        "v10 uses the unchanged final 4.5 null limit because null t has no monotone "
        "headroom interpretation"
    ),
    (
        "v10 assigns the same 16384-tick largest sentinel to every target whose first "
        "two effects are 64 and 512 without using reduced target statistics"
    ),
    (
        "every v10 final command requires a machine-validated qualification from two "
        "blocker-free v3 control rehearsals at the exact final commit"
    ),
    (
        "the two v3 clean runs are operational reruns and are not claimed as independent "
        "inferential replicates"
    ),
    (
        "every v10 native component and the same-corpus official dudect run require "
        "SMT and turbo disabled before sampling"
    ),
    (
        "v1 Falcon and diverse plus v2 committed-corpus engineering traces are "
        "calibration evidence and are not reusable in their replacement final campaigns"
    ),
    (
        "KyberSlash v2 operand traces have invalid-placebo and class-address setup "
        "confounds and are not reusable in v3, v4, or v5"
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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    if manifest.get("campaign_id") != "ctkat-paper-native-v10-single-host":
        errors.append("campaign_id must be ctkat-paper-native-v10-single-host")
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
        "require_smt_disabled": True,
        "require_turbo_disabled": True,
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
            or native.protocol != previous.protocol
            or [target.id for target in native.targets]
            != [target.id for target in previous.targets]
        ):
            errors.append(f"{item.get('id')}: V10 changed scope or non-effect protocol fields")
        expected_host = {
            **previous.host,
            "require_smt_disabled": True,
            "require_turbo_disabled": True,
        }
        if native.host != expected_host:
            errors.append(f"{item.get('id')}: V10 host hygiene contract drift")
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
                    f"{item.get('id')}/{new_target.id}: V10 changed a non-effect target field"
                )
            expected_effects = V10_EFFECT_OVERRIDES.get(
                (str(component_id), new_target.id),
                old_target.positive_control_effects,
            )
            if new_target.positive_control_effects != expected_effects:
                errors.append(f"{item.get('id')}/{new_target.id}: V10 effect calibration drift")
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
        source = calibration.get("source_rehearsal") if isinstance(calibration, dict) else None
        if (
            not isinstance(calibration, dict)
            or calibration.get("schema_version") != "1.0"
            or calibration.get("kind") != "ctkat-paper-control-calibration-record"
            or calibration.get("calibration_id") != "ctkat-paper-control-rehearsal-v2-calibration"
            or calibration.get("recorded_at") != "2026-08-14"
        ):
            errors.append("V10 control calibration identity drift")
        if (
            not isinstance(source, dict)
            or source.get("profile_id") != "ctkat-paper-control-rehearsal-v2"
            or source.get("profile_sha256")
            != "15119eb11e49867738a2abbd807a0582057f83e536527c18b761788441075b44"
            or source.get("profile_sha256") != _sha256(V2_PROFILE_PATH)
            or source.get("source_calibration_sha256")
            != "f7536da19b9d3c1f9e383de1ed288f8f5014fa948b075415af0a2713b7dc4326"
            or source.get("source_calibration_sha256") != _sha256(V1_CALIBRATION_PATH)
            or source.get("source_campaign_sha256")
            != "8293e5ac2d7122f9a2bf9886a70e915a5286a266e38a76ea44dabe54872b3335"
            or source.get("source_campaign_sha256") != _sha256(V9_PLAN_PATH)
            or source.get("candidate_commit") != "39a1cdeb94e768300e4d5bab5adbe0f14130d47c"
            or source.get("run_id") != "34a8f9e74c094c0b97e5fc94e74a8777"
            or source.get("started_at") != "2026-08-14T02:02:21.044489Z"
            or source.get("finished_at") != "2026-08-14T03:26:04.602398Z"
            or source.get("completed_without_interruption") is not True
            or source.get("all_execution_steps_returncode_zero") is not True
            or source.get("smoke_axes_passed") != 28
            or source.get("native_axes_assessed") != 28
            or source.get("native_components_passing_qualification") != 2
            or source.get("baselines_passed") != 3
            or source.get("assembly_passed") is not True
            or source.get("pipeline_closure_passed") is not True
            or source.get("blocker_count") != 3
            or any(
                not isinstance(source.get(field), str)
                or re.fullmatch(r"[0-9a-f]{64}", source.get(field, "")) is None
                for field in ("report_sha256", "markdown_sha256")
            )
        ):
            errors.append("V10 control calibration source provenance drift")
        observed_selection = {
            (str(item.get("component")), str(item.get("target"))): (
                tuple(item.get("old_effects") or []),
                tuple(item.get("new_effects") or []),
            )
            for item in selected or []
            if isinstance(item, dict)
        }
        expected_selection = {
            key: (V10_OLD_EFFECTS[key], V10_EFFECT_OVERRIDES[key]) for key in V10_EFFECT_OVERRIDES
        }
        if (
            not isinstance(selected, list)
            or len(selected) != 13
            or any(
                not isinstance(item, dict)
                or set(item) != {"component", "target", "old_effects", "new_effects"}
                for item in selected
            )
            or len(observed_selection) != 13
            or observed_selection != expected_selection
        ):
            errors.append("V10 control calibration selected-target matrix drift")
        boundary = calibration.get("evidence_boundary") if isinstance(calibration, dict) else None
        if (
            not isinstance(boundary, dict)
            or boundary.get("target_measurements_per_process") != 1000
            or boundary.get("target_statistics_interpretable") is not False
            or boundary.get("target_statistics_used_for_calibration") is not False
            or boundary.get("target_artifacts_promotable") is not False
            or boundary.get("source_rehearsal_reusable_in_final") is not False
            or boundary.get("calibration_inputs")
            != [
                "A/A and setup-placebo control validity decisions",
                "largest-effect positive-control t-score and direction by process repeat",
                "recorded host SMT turbo governor and affinity state",
            ]
            or boundary.get("forbidden_inputs")
            != [
                "target t-score",
                "target raw status",
                "target repeat direction or consistency",
                "same-corpus baseline result as a paper finding",
            ]
        ):
            errors.append("V10 control calibration evidence boundary drift")
        if calibration.get("observed_blockers") != V2_EXPECTED_BLOCKERS:
            errors.append("V10 control calibration blocker matrix drift")
        null_rule = (
            calibration.get("null_control_correction") if isinstance(calibration, dict) else None
        )
        if (
            not isinstance(null_rule, dict)
            or null_rule.get("old_rehearsal_ceiling_exclusive") != 3.5
            or null_rule.get("new_rehearsal_ceiling_exclusive") != 4.5
            or null_rule.get("final_ceiling_exclusive") != 4.5
            or null_rule.get("final_aa_max_failures") != 0
            or null_rule.get("null_tests_per_rehearsal") != 168
            or null_rule.get("counts_unchanged") is not True
            or null_rule.get("seeds_unchanged") is not True
            or null_rule.get("repeats_unchanged") is not True
            or null_rule.get("final_threshold_unchanged") is not True
        ):
            errors.append("V10 null-control correction drift")
        rule = (
            calibration.get("fast_positive_control_rule") if isinstance(calibration, dict) else None
        )
        if (
            not isinstance(rule, dict)
            or rule.get("selection_unit") != "manifest-target"
            or rule.get("select_when")
            != "the first two positive control effects are exactly 64 and 512 ticks"
            or rule.get("adjustment")
            != "retain 64 and 512 and set the largest effect to 16384 ticks"
            or rule.get("applies_without_failed_target_selection") is not True
            or rule.get("largest_positive_rehearsal_t_ceiling_inclusive") != -15.0
            or rule.get("final_positive_abs_t_threshold") != 10.0
            or rule.get("counts_unchanged") is not True
            or rule.get("seeds_unchanged") is not True
            or rule.get("repeats_unchanged") is not True
            or rule.get("final_threshold_unchanged") is not True
        ):
            errors.append("V10 positive-control remediation rule drift")
        hygiene = (
            calibration.get("host_hygiene_correction") if isinstance(calibration, dict) else None
        )
        if (
            not isinstance(hygiene, dict)
            or hygiene.get("source_smt_active") != "1"
            or hygiene.get("source_intel_pstate_no_turbo") != "0"
            or hygiene.get("require_smt_disabled") is not True
            or hygiene.get("require_turbo_disabled") is not True
            or hygiene.get("require_performance_governor") is not True
            or hygiene.get("require_single_cpu_affinity") is not True
        ):
            errors.append("V10 host hygiene correction drift")
    except (OSError, TypeError, yaml.YAMLError) as exc:
        errors.append(f"V10 control calibration is unreadable: {exc}")

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
