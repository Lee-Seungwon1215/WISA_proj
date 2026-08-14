#!/usr/bin/env python3
"""Run and assess the non-promotable, continue-and-aggregate paper rehearsal."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctkat.cli import (  # noqa: E402
    _dudect_context,
    _run_timing_harness_with_build_seal,
)
from ctkat.config import load_config  # noqa: E402
from ctkat.timing_binary_contract import verify_timing_binary_contract  # noqa: E402
from ctkat.timing_build_provenance import (  # noqa: E402
    capture_timing_build_provenance,
    write_timing_build_provenance,
)
from ctkat.timing_harness_generator import generate_and_compile_timing  # noqa: E402
from scripts import check_paper_campaign  # noqa: E402
from scripts import run_same_corpus_baselines as baseline_runner  # noqa: E402
from scripts.run_native_timing_campaign import (  # noqa: E402
    CONTROL_REHEARSAL_PROFILE_ID as NATIVE_CONTROL_REHEARSAL_PROFILE_ID,
)
from scripts.run_native_timing_campaign import (  # noqa: E402
    CampaignError,
    _git_state,
    campaign_dudect,
    load_campaign,
    pin_current_process,
    static_check,
)

REHEARSAL_PROFILE_ID = "ctkat-paper-control-rehearsal-v2"
DEFAULT_PROFILE = ROOT / "docs/measurement/paper_control_rehearsal_v2.yaml"
DEFAULT_SCHEMA = ROOT / "docs/measurement/paper_control_rehearsal_v2.schema.json"
CALIBRATION_PATH = ROOT / "docs/measurement/paper_control_rehearsal_v1_calibration.yaml"
REPORT_NAME = "rehearsal_report.json"
MARKDOWN_NAME = "rehearsal_report.md"
SMOKE_MEASUREMENTS = 4
SMOKE_TIMEOUT_SECONDS = 600
COMPONENT_IDS = (
    "committed-corpus-refresh",
    "kyberslash-contrast",
    "falcon-contrast",
    "diverse-lineages",
)
BASELINE_IDS = ("official_dudect", "timecop", "microwalk_pin")
PRESERVED_FIELDS = (
    "process_repeats",
    "control_measurements",
    "positive_control_effects",
    "seed",
    "warmup",
    "batches",
    "pool_size",
    "aa_abs_t_limit",
    "positive_abs_t_threshold",
    "aa_max_failures",
    "target_power",
    "power_alpha",
    "compiler",
    "compiler_flags",
    "build_and_binary_contracts",
    "randomness_policy",
)
CLAIM_LIMITS = (
    "every artifact produced by this profile is engineering-only and non-promotable",
    "reduced target traces are execution and contract smoke only and must not be interpreted",
    "target status consistency and official target power are deliberately not rehearsal gates",
    "control counts seeds effects thresholds and process repeats remain final-equivalent",
    "rehearsal safety margins are operational headroom checks and do not replace final thresholds",
    "no rehearsal component raw trace statistic or baseline result may be relabeled as final evidence",
    "paper bundle and paper analysis are intentionally forbidden for rehearsal artifacts",
    "v1 rehearsal artifacts are immutable diagnostic inputs and no row is reused in v2",
)


class RehearsalError(RuntimeError):
    """The rehearsal profile, host, or artifact root is unsafe or malformed."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _relative(path: Path, root: Path = ROOT) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(resolved)


def _repo_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise RehearsalError(f"{label} must be a repository-relative path")
    raw = Path(value)
    if raw.is_absolute() or ".." in raw.parts:
        raise RehearsalError(f"{label} escapes the repository: {value!r}")
    path = (ROOT / raw).resolve()
    if not path.is_relative_to(ROOT.resolve()):
        raise RehearsalError(f"{label} escapes the repository: {value!r}")
    return path


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RehearsalError(f"{label} must be a mapping")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise RehearsalError(f"{label} must be a list")
    return value


def _load_yaml(path: Path, label: str) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RehearsalError(f"{label} unreadable: {path}: {exc}") from exc
    return _mapping(value, label)


def load_profile(path: Path = DEFAULT_PROFILE) -> dict[str, Any]:
    return _load_yaml(path.resolve(), "rehearsal profile")


def _load_schema() -> dict[str, Any]:
    try:
        schema = json.loads(DEFAULT_SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise RehearsalError(f"rehearsal result schema is invalid: {exc}") from exc
    return schema


def _profile_components(profile: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        _mapping(item, f"components[{index}]")
        for index, item in enumerate(_list(profile.get("components"), "components"))
    ]


def validate_profile(
    profile: dict[str, Any],
    *,
    profile_path: Path = DEFAULT_PROFILE,
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []

    def check(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    expected_keys = {
        "schema_version",
        "kind",
        "profile_id",
        "source_paper_campaign",
        "calibration",
        "run_kind",
        "promotion_allowed",
        "target_measurements",
        "preserve_from_component_manifests",
        "safety_margins",
        "qualification",
        "execution",
        "components",
        "same_corpus_baselines",
        "claim_limits",
    }
    check(set(profile) == expected_keys, "rehearsal profile top-level field set drift")
    check(profile.get("schema_version") == "2.0", "profile schema_version must be '2.0'")
    check(
        profile.get("kind") == "ctkat-paper-control-rehearsal-profile",
        "profile kind drift",
    )
    check(profile.get("profile_id") == REHEARSAL_PROFILE_ID, "profile id drift")
    check(profile.get("run_kind") == "engineering", "rehearsal must be engineering")
    check(profile.get("promotion_allowed") is False, "rehearsal promotion must be false")
    target_measurements = profile.get("target_measurements")
    check(
        isinstance(target_measurements, int)
        and not isinstance(target_measurements, bool)
        and 100 <= target_measurements < 20_000,
        "target_measurements must be in [100, 20000)",
    )
    check(
        profile.get("preserve_from_component_manifests") == list(PRESERVED_FIELDS),
        "preserved final-equivalent field list drift",
    )
    margins = profile.get("safety_margins")
    expected_margins = {
        "aa_abs_t_ceiling_exclusive": 3.5,
        "setup_placebo_abs_t_ceiling_exclusive": 3.5,
        "largest_positive_t_ceiling_inclusive": -15.0,
        "largest_positive_mean_delta_floor_exclusive": 0.0,
    }
    check(margins == expected_margins, "rehearsal safety margins drift")
    check(
        profile.get("qualification")
        == {
            "required_clean_runs": 2,
            "same_candidate_commit": True,
            "distinct_rehearsal_run_ids": True,
        },
        "rehearsal qualification contract drift",
    )
    check(
        profile.get("execution")
        == {
            "continue_after_step_failure": True,
            "continue_after_target_failure": True,
            "run_compile_contract_smoke": True,
            "run_full_assembly_evidence": True,
            "run_all_native_components": True,
            "run_all_same_corpus_baselines": True,
            "build_paper_bundle": False,
            "run_paper_analysis": False,
        },
        "rehearsal execution policy drift",
    )
    check(profile.get("claim_limits") == list(CLAIM_LIMITS), "claim limits drift")
    check(profile_path.resolve() == DEFAULT_PROFILE.resolve(), "only the frozen profile is valid")

    try:
        paper_path = _repo_path(profile.get("source_paper_campaign"), "source_paper_campaign")
        paper = check_paper_campaign.load_manifest(paper_path)
        paper_errors, paper_report = check_paper_campaign.validate(paper)
    except (OSError, ValueError, RehearsalError, yaml.YAMLError) as exc:
        paper_errors = [str(exc)]
        paper_report = {}
        paper = {}
    errors.extend(f"source paper campaign: {error}" for error in paper_errors)

    try:
        calibration_path = _repo_path(profile.get("calibration"), "calibration")
        calibration = _load_yaml(calibration_path, "control calibration")
        check(calibration_path == CALIBRATION_PATH, "control calibration path drift")
        check(
            calibration.get("kind") == "ctkat-paper-control-calibration-record"
            and calibration.get("calibration_id") == "ctkat-paper-control-rehearsal-v1-calibration",
            "control calibration identity drift",
        )
        boundary = _mapping(calibration.get("evidence_boundary"), "evidence_boundary")
        check(
            boundary.get("target_statistics_used_for_calibration") is False
            and boundary.get("target_artifacts_promotable") is False
            and boundary.get("source_rehearsal_reusable_in_final") is False,
            "control calibration evidence boundary drift",
        )
        rule = _mapping(calibration.get("uniform_remediation_rule"), "remediation rule")
        check(
            rule.get("selection_unit") == "manifest-target"
            and rule.get("select_when")
            == "any axis in the target has largest-effect worst-repeat t_score > -20"
            and rule.get("adjustment")
            == "retain the first two effect points and double only the largest effect",
            "control calibration remediation rule drift",
        )
        check(
            len(_list(calibration.get("selected_targets"), "selected_targets")) == 9,
            "control calibration must bind nine selected targets",
        )
    except (OSError, RehearsalError) as exc:
        errors.append(str(exc))

    try:
        components = _profile_components(profile)
    except RehearsalError as exc:
        errors.append(str(exc))
        components = []
    check([item.get("id") for item in components] == list(COMPONENT_IDS), "component order drift")
    expected_outputs = ("committed-corpus-v4", "kyberslash-v4", "falcon-v3", "diverse-v3")
    check(
        [item.get("output") for item in components] == list(expected_outputs),
        "component output routing drift",
    )
    paper_components = paper.get("components") if isinstance(paper, dict) else None
    if isinstance(paper_components, list):
        check(
            [(item.get("id"), item.get("manifest")) for item in components]
            == [
                (item.get("id"), item.get("manifest"))
                for item in paper_components
                if isinstance(item, dict)
            ],
            "rehearsal component manifests differ from source paper campaign",
        )

    native_summaries: list[dict[str, Any]] = []
    total_targets = 0
    total_axes = 0
    if isinstance(target_measurements, int):
        for component in components:
            try:
                if set(component) != {"id", "manifest", "output"}:
                    raise RehearsalError(f"{component.get('id')}: component field set drift")
                manifest_path = _repo_path(component.get("manifest"), "component manifest")
                campaign = load_campaign(manifest_path)
                native_errors = static_check(campaign)
            except (OSError, CampaignError, RehearsalError) as exc:
                errors.append(f"{component.get('id')}: {exc}")
                continue
            errors.extend(f"{component['id']}: {error}" for error in native_errors)
            if any(
                target_measurements >= target.target_measurements for target in campaign.targets
            ):
                errors.append(f"{component['id']}: reduced target is not below every source target")
            target_count = len(campaign.targets)
            axis_count = sum(len(target.harnesses) for target in campaign.targets)
            total_targets += target_count
            total_axes += axis_count
            native_summaries.append(
                {
                    "id": component["id"],
                    "campaign_id": campaign.campaign_id,
                    "targets": target_count,
                    "axes": axis_count,
                    "static_ok": not native_errors,
                }
            )
    check(total_targets == 26, f"rehearsal target count must be 26, got {total_targets}")
    check(total_axes == 28, f"rehearsal axis count must be 28, got {total_axes}")
    check(paper_report.get("timing_axes") in {None, 28}, "source paper axis count drift")

    baselines = profile.get("same_corpus_baselines")
    expected_baselines = [
        {"id": "official_dudect", "action": "run_dudect"},
        {"id": "timecop", "action": "run_timecop"},
        {"id": "microwalk_pin", "action": "run_microwalk"},
    ]
    check(baselines == expected_baselines, "same-corpus baseline matrix drift")
    try:
        baseline_manifest = baseline_runner.load_manifest()
        baseline_errors = baseline_runner.validate_static(baseline_manifest)
    except (OSError, ValueError) as exc:
        baseline_errors = [str(exc)]
    errors.extend(f"same-corpus baseline: {error}" for error in baseline_errors)

    try:
        _load_schema()
    except RehearsalError as exc:
        errors.append(str(exc))
    report = {
        "profile_id": profile.get("profile_id"),
        "status": "valid" if not errors else "invalid",
        "source_paper_campaign": profile.get("source_paper_campaign"),
        "calibration": profile.get("calibration"),
        "target_measurements": target_measurements,
        "components": native_summaries,
        "targets": total_targets,
        "axes": total_axes,
        "baselines": len(expected_baselines),
        "required_clean_runs": 2,
        "errors": errors,
    }
    return list(dict.fromkeys(errors)), report


def _safe_output_root(path: Path) -> Path:
    resolved = path.resolve()
    if resolved == ROOT.resolve() or ROOT.resolve().is_relative_to(resolved):
        raise RehearsalError("output root cannot be the repository or an ancestor")
    ignored_root = (ROOT / "measurement_runs").resolve()
    if resolved.is_relative_to(ROOT.resolve()) and not resolved.is_relative_to(ignored_root):
        raise RehearsalError("in-repository rehearsal output must live under measurement_runs/")
    if resolved.exists() and not resolved.is_dir():
        raise RehearsalError(f"output root is not a directory: {resolved}")
    return resolved


def _write_json_atomic(path: Path, payload: dict[str, Any], *, validate: bool = False) -> None:
    if validate:
        failures = sorted(
            Draft202012Validator(_load_schema()).iter_errors(payload),
            key=lambda error: tuple(str(item) for item in error.absolute_path),
        )
        if failures:
            messages = [
                f"{'/'.join(str(item) for item in error.absolute_path) or '<root>'}: "
                f"{error.message}"
                for error in failures
            ]
            raise RehearsalError("rehearsal report schema violation: " + "; ".join(messages))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _new_report(
    profile: dict[str, Any],
    profile_path: Path,
    *,
    phase: str,
    commit: str,
) -> dict[str, Any]:
    return {
        "schema_version": "2.0",
        "kind": "ctkat-paper-control-rehearsal-report",
        "profile_id": profile["profile_id"],
        "profile": _relative(profile_path),
        "profile_sha256": _sha256(profile_path),
        "source_paper_campaign": profile["source_paper_campaign"],
        "calibration": profile["calibration"],
        "calibration_sha256": _sha256(_repo_path(profile["calibration"], "calibration")),
        "target_measurements": profile["target_measurements"],
        "run_id": uuid.uuid4().hex,
        "run_kind": "engineering",
        "promotion_allowed": False,
        "ctkat_commit": commit,
        "started_at": _utc_now(),
        "finished_at": None,
        "status": "running",
        "phase": phase,
        "steps": {},
        "smoke": {
            "expected_axes": 28,
            "completed_axes": 0,
            "passed_axes": 0,
            "axes": {},
        },
        "native_components": {},
        "baselines": {},
        "assembly": None,
        "pipeline_closure": None,
        "summary": {},
        "blockers": [],
        "claim_limits": list(CLAIM_LIMITS),
    }


def _load_execution_report(
    root: Path,
    profile: dict[str, Any],
    profile_path: Path,
    *,
    phase: str,
    resume: bool,
) -> tuple[dict[str, Any], Path]:
    report_path = root / REPORT_NAME
    commit, dirty = _git_state()
    if dirty:
        raise RehearsalError("rehearsal execution requires a clean git worktree")
    if resume:
        if not report_path.is_file() or report_path.is_symlink():
            raise RehearsalError("--resume requires an existing regular rehearsal report")
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RehearsalError(f"existing rehearsal report is unreadable: {exc}") from exc
        if not isinstance(report, dict):
            raise RehearsalError("existing rehearsal report root must be an object")
        _write_json_atomic(report_path, report, validate=True)
        if report.get("profile_sha256") != _sha256(profile_path):
            raise RehearsalError("cannot resume after rehearsal profile drift")
        if report.get("ctkat_commit") != commit:
            raise RehearsalError("cannot resume after candidate commit drift")
        if report.get("run_kind") != "engineering" or report.get("promotion_allowed") is not False:
            raise RehearsalError("existing report is not a non-promotable engineering rehearsal")
        report["phase"] = phase
        report["status"] = "running"
        report["finished_at"] = None
        return report, report_path
    if root.exists() and any(root.iterdir()):
        raise RehearsalError(f"fresh rehearsal output root is non-empty: {root}")
    root.mkdir(parents=True, exist_ok=True)
    report = _new_report(profile, profile_path, phase=phase, commit=commit)
    _write_json_atomic(report_path, report, validate=True)
    return report, report_path


def _run_step(
    report: dict[str, Any],
    report_path: Path,
    root: Path,
    *,
    step_id: str,
    command: list[str],
    resume: bool,
    result: Path | None = None,
) -> dict[str, Any]:
    previous = report["steps"].get(step_id)
    if resume and isinstance(previous, dict) and previous.get("status") == "pass":
        print(f"[rehearsal] skip passed step: {step_id}", flush=True)
        return previous
    log_path = root / "orchestrator_logs" / f"{step_id}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    record: dict[str, Any] = {
        "id": step_id,
        "command": command,
        "started_at": _utc_now(),
        "finished_at": None,
        "status": "running",
        "returncode": None,
        "log": _relative(log_path, root),
        "result": _relative(result, root) if result is not None else None,
    }
    report["steps"][step_id] = record
    _write_json_atomic(report_path, report, validate=True)
    print(f"[rehearsal] start: {step_id}", flush=True)
    environment = dict(os.environ)
    environment["PYTHONUNBUFFERED"] = "1"
    try:
        with log_path.open("w", encoding="utf-8") as handle:
            handle.write("command=" + json.dumps(command, ensure_ascii=False) + "\n")
            handle.flush()
            completed = subprocess.run(
                command,
                cwd=ROOT,
                env=environment,
                stdout=handle,
                stderr=subprocess.STDOUT,
                check=False,
            )
        returncode = completed.returncode
    except OSError as exc:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"orchestrator execution error: {exc}\n")
        returncode = 127
    record["returncode"] = returncode
    record["finished_at"] = _utc_now()
    record["status"] = "pass" if returncode == 0 else "fail"
    _write_json_atomic(report_path, report, validate=True)
    print(f"[rehearsal] {record['status']}: {step_id} (rc={returncode})", flush=True)
    return record


def _preflight_commands(profile: dict[str, Any], cpu: int) -> list[tuple[str, list[str]]]:
    python = sys.executable
    commands: list[tuple[str, list[str]]] = [
        ("static-paper-campaign", [python, "scripts/check_paper_campaign.py"]),
        (
            "static-automated-audits",
            [python, "scripts/check_automated_audits.py", "--require-engineering-ready"],
        ),
        ("static-paper-artifacts", [python, "scripts/build_paper_artifacts.py", "--check"]),
        ("static-assembly", [python, "scripts/check_asm_evidence.py", "--static"]),
        ("static-same-corpus", [python, "scripts/run_same_corpus_baselines.py", "--check"]),
    ]
    for component in _profile_components(profile):
        commands.append(
            (
                f"preflight-{component['id']}",
                [
                    python,
                    "scripts/run_native_timing_campaign.py",
                    "--preflight",
                    "--manifest",
                    component["manifest"],
                    "--cpu",
                    str(cpu),
                ],
            )
        )
    return commands


def _resolve_config_path(config_path: Path, value: Path) -> Path:
    return value.resolve() if value.is_absolute() else (config_path.parent / value).resolve()


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): _sha256(path)
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix())
        if path.is_file() and not path.is_symlink()
    }


def _run_smoke_axis(
    *,
    component_id: str,
    campaign: Any,
    target: Any,
    harness_name: str,
    output_root: Path,
) -> dict[str, Any]:
    axis_root = output_root / component_id / target.id / harness_name
    errors: list[str] = []
    runtime_metadata: dict[str, str] = {}
    raw_measurements: int | None = None
    retained_measurements: int | None = None
    output_length_min: int | None = None
    output_length_max: int | None = None
    try:
        cfg = load_config(target.config)
        dudect = campaign_dudect(cfg, campaign, target, axis_root / "generated")
        configured = {item.name: item for item in dudect.harnesses}
        harness = configured[harness_name]
        sources = [_resolve_config_path(target.config, source) for source in harness.sources]
        includes = [
            _resolve_config_path(target.config, directory) for directory in harness.include_dirs
        ]
        workdir = _resolve_config_path(target.config, dudect.workdir)
        generated = generate_and_compile_timing(
            name=harness.name,
            template=harness.template,
            context=_dudect_context(
                harness,
                dudect,
                campaign.protocol.seed,
                campaign.protocol.clock,
            ),
            output_dir=axis_root / "generated",
            sources=sources,
            include_dirs=includes,
            cflags=dudect.compiler.cflags,
            cc=dudect.compiler.cc,
            workdir=workdir,
            timeout=campaign.protocol.compile_timeout,
        )
        if harness.binary_contract is not None:
            verify_timing_binary_contract(
                manifest_path=_resolve_config_path(
                    target.config,
                    harness.binary_contract.manifest,
                ),
                target=harness.binary_contract.target,
                binary_path=generated.binary_path,
                generated_source_path=generated.source_path,
                config_path=target.config,
                source_paths=sources,
                compiler=dudect.compiler.cc,
                cflags=list(dudect.compiler.cflags),
                compile_command=generated.compile_command,
                output_dir=axis_root / "binary_contract",
            )
        provenance = capture_timing_build_provenance(
            compiler=dudect.compiler.cc,
            cflags=dudect.compiler.cflags,
            include_dirs=includes,
            linked_sources=sources,
            generated_source=generated.source_path,
            binary=generated.binary_path,
            config_path=target.config,
            compile_command=generated.compile_command,
        )
        seal_path = axis_root / "build_provenance" / f"timing_{harness.name}.build-seal.json"
        seal_sha256 = write_timing_build_provenance(seal_path, provenance)
        samples = _run_timing_harness_with_build_seal(
            generated.binary_path,
            workdir,
            timeout=min(target.timeout, SMOKE_TIMEOUT_SECONDS),
            seed_override=campaign.protocol.seed,
            mode="target",
            measurements_override=SMOKE_MEASUREMENTS,
            signature_length_contract=(
                harness.signature_length_contract if harness.template == "sign" else None
            ),
            build_provenance=provenance,
            build_provenance_path=seal_path,
            build_provenance_sha256=seal_sha256,
        )
        runtime_metadata = dict(samples.runtime_metadata)
        raw_measurements = samples.raw_n_total
        retained_measurements = len(samples)
        witnessed_lengths = [value for value in samples.output_lengths if value is not None]
        witnessed_lengths.extend(
            item.output_length for item in samples.dropped_samples if item.output_length is not None
        )
        if witnessed_lengths:
            output_length_min = min(witnessed_lengths)
            output_length_max = max(witnessed_lengths)
        if samples.protocol_version != "timing-harness-v2":
            errors.append(f"protocol={samples.protocol_version!r}, expected timing-harness-v2")
        if samples.raw_n_total != SMOKE_MEASUREMENTS:
            errors.append(f"raw measurements={samples.raw_n_total}, expected={SMOKE_MEASUREMENTS}")
        if samples.malformed_count != 0:
            errors.append(f"malformed timing rows={samples.malformed_count}")
        if runtime_metadata.get("mode") != "target":
            errors.append(f"runtime mode={runtime_metadata.get('mode')!r}, expected target")
        if runtime_metadata.get("measurements") != str(SMOKE_MEASUREMENTS):
            errors.append("runtime measurement override was not observed")
        if runtime_metadata.get("randomness") != harness.randomness_policy:
            errors.append(
                f"runtime randomness={runtime_metadata.get('randomness')!r}, "
                f"expected={harness.randomness_policy!r}"
            )
        if not witnessed_lengths:
            errors.append("smoke trace retained no output-length witness")
    except BaseException as exc:
        if isinstance(exc, KeyboardInterrupt):
            raise
        errors.append(f"{type(exc).__name__}: {exc}")
    return {
        "component": component_id,
        "target": target.id,
        "harness": harness_name,
        "axis": target.axis_for(harness_name),
        "status": "pass" if not errors else "fail",
        "errors": errors,
        "raw_measurements": raw_measurements,
        "retained_measurements": retained_measurements,
        "output_length_min": output_length_min,
        "output_length_max": output_length_max,
        "runtime_metadata": runtime_metadata,
        "artifacts": _tree_hashes(axis_root) if axis_root.is_dir() else {},
    }


def _run_smoke(
    profile: dict[str, Any],
    report: dict[str, Any],
    report_path: Path,
    root: Path,
    *,
    resume: bool,
) -> None:
    axes = report["smoke"]["axes"]
    for component in _profile_components(profile):
        campaign = load_campaign(_repo_path(component["manifest"], "component manifest"))
        for target in campaign.targets:
            for harness_name in target.harnesses:
                key = f"{component['id']}/{target.id}/{harness_name}"
                previous = axes.get(key)
                if resume and isinstance(previous, dict) and previous.get("status") == "pass":
                    print(f"[rehearsal] skip passed smoke axis: {key}", flush=True)
                    continue
                print(f"[rehearsal] smoke: {key}", flush=True)
                axes[key] = _run_smoke_axis(
                    component_id=component["id"],
                    campaign=campaign,
                    target=target,
                    harness_name=harness_name,
                    output_root=root / "smoke",
                )
                report["smoke"]["completed_axes"] = len(axes)
                report["smoke"]["passed_axes"] = sum(
                    item.get("status") == "pass" for item in axes.values()
                )
                _write_json_atomic(report_path, report, validate=True)


def _set_step_result(
    report: dict[str, Any],
    report_path: Path,
    root: Path,
    step_id: str,
    result: Path | None,
) -> None:
    record = report["steps"].get(step_id)
    if isinstance(record, dict):
        record["result"] = _relative(result, root) if result is not None else None
        _write_json_atomic(report_path, report, validate=True)


def _latest_baseline_report(root: Path, tool_id: str) -> Path | None:
    candidates = sorted(root.glob(f"*-{tool_id}/baseline_report.json"))
    return candidates[-1] if candidates else None


def _run_controls(
    profile: dict[str, Any],
    report: dict[str, Any],
    report_path: Path,
    root: Path,
    *,
    cpu: int,
    timecop_prefix: Path,
    resume: bool,
) -> None:
    python = sys.executable
    commit = report["ctkat_commit"]
    assembly_root = root / "asm-evidence"
    assembly_bundle = assembly_root / "asm_evidence_bundle.json"
    _run_step(
        report,
        report_path,
        root,
        step_id="assembly-build",
        command=[
            python,
            "scripts/build_asm_evidence.py",
            "--output-root",
            str(assembly_root),
        ],
        resume=resume,
        result=assembly_bundle,
    )
    _run_step(
        report,
        report_path,
        root,
        step_id="assembly-validate",
        command=[
            python,
            "scripts/check_asm_evidence.py",
            "--bundle",
            str(assembly_bundle),
            "--expected-commit",
            commit,
        ],
        resume=resume,
        result=assembly_bundle,
    )

    for component in _profile_components(profile):
        component_root = root / component["output"]
        command = [
            python,
            "scripts/run_native_timing_campaign.py",
            "--manifest",
            component["manifest"],
            "--output-root",
            str(component_root),
            "--run-kind",
            "engineering",
            "--cpu",
            str(cpu),
            "--target-measurements-override",
            str(profile["target_measurements"]),
            "--continue-on-error",
            "--execute",
        ]
        if resume and (component_root / "campaign_report.json").is_file():
            command.append("--resume")
        _run_step(
            report,
            report_path,
            root,
            step_id=f"native-{component['id']}",
            command=command,
            resume=resume,
            result=component_root / "campaign_report.json",
        )
        _run_step(
            report,
            report_path,
            root,
            step_id=f"validate-native-{component['id']}",
            command=[
                python,
                "scripts/run_native_timing_campaign.py",
                "--manifest",
                component["manifest"],
                "--validate-run",
                str(component_root),
                "--expected-commit",
                commit,
                "--expected-run-kind",
                "engineering",
            ],
            resume=resume,
            result=component_root / "campaign_report.json",
        )

    baseline_root = root / "same-corpus"
    baseline_commands = {
        "official_dudect": [
            python,
            "scripts/run_same_corpus_baselines.py",
            "--run-dudect",
            "--run-kind",
            "engineering",
            "--cpu",
            str(cpu),
            "--output-root",
            str(baseline_root),
        ],
        "timecop": [
            python,
            "scripts/run_same_corpus_baselines.py",
            "--run-timecop",
            "--run-kind",
            "engineering",
            "--prefix",
            str(timecop_prefix),
            "--output-root",
            str(baseline_root),
        ],
        "microwalk_pin": [
            python,
            "scripts/run_same_corpus_baselines.py",
            "--run-microwalk",
            "--run-kind",
            "engineering",
            "--output-root",
            str(baseline_root),
        ],
    }
    for tool_id in BASELINE_IDS:
        execute_step = f"baseline-{tool_id}"
        previous = report["steps"].get(execute_step)
        result = None
        if resume and isinstance(previous, dict) and previous.get("status") == "pass":
            previous_result = previous.get("result")
            if isinstance(previous_result, str):
                result = (root / previous_result).resolve()
        record = _run_step(
            report,
            report_path,
            root,
            step_id=execute_step,
            command=baseline_commands[tool_id],
            resume=resume,
            result=result,
        )
        if result is None or not result.is_file():
            result = _latest_baseline_report(baseline_root, tool_id)
            _set_step_result(report, report_path, root, execute_step, result)
        validate_command = [
            python,
            "scripts/run_same_corpus_baselines.py",
            "--validate-result",
            str(result or baseline_root / "missing-baseline-report.json"),
            "--expected-commit",
            commit,
            "--expected-run-kind",
            "engineering",
        ]
        _run_step(
            report,
            report_path,
            root,
            step_id=f"validate-baseline-{tool_id}",
            command=validate_command,
            resume=resume and record.get("status") == "pass",
            result=result,
        )


def _blocker(
    code: str,
    stage: str,
    subject: str,
    message: str,
    observed: Any,
    required: Any,
) -> dict[str, Any]:
    return {
        "code": code,
        "stage": stage,
        "subject": subject,
        "message": message,
        "observed": observed,
        "required": required,
    }


def _finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    return result if math.isfinite(result) else None


def _assess_control_protocol(
    protocol: Any,
    *,
    subject: str,
    target_measurements: int,
    control_measurements: int,
    effects: tuple[int, ...],
    process_repeats: int,
    randomness_policy: str,
    margins: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    blockers: list[dict[str, Any]] = []
    if not isinstance(protocol, dict):
        return {}, [
            _blocker(
                "control.protocol-missing",
                "controls",
                subject,
                "harness protocol is missing",
                type(protocol).__name__,
                "object",
            )
        ]

    exact_fields = {
        "target_measurements": target_measurements,
        "control_measurements": control_measurements,
        "process_repeats_observed": process_repeats,
        "positive_power_passed": True,
        "aa_budget_passed": True,
        "setup_placebo_passed": True,
        "randomness_policy_expected": randomness_policy,
        "randomness_policies_observed": [randomness_policy],
    }
    for field, expected in exact_fields.items():
        observed = protocol.get(field)
        if observed != expected:
            blockers.append(
                _blocker(
                    f"control.{field}",
                    "controls",
                    subject,
                    f"{field} differs from the rehearsal contract",
                    observed,
                    expected,
                )
            )
    curve = protocol.get("positive_power_curve")
    observed_effects = (
        [item.get("effect_ticks") for item in curve if isinstance(item, dict)]
        if isinstance(curve, list)
        else None
    )
    if observed_effects != list(effects):
        blockers.append(
            _blocker(
                "control.positive-effect-ladder",
                "controls",
                subject,
                "positive-control effect ladder drifted",
                observed_effects,
                list(effects),
            )
        )

    control_sets = (
        ("aa_controls", process_repeats),
        ("setup_placebo_controls", process_repeats),
        ("positive_controls", process_repeats * len(effects)),
        ("target_repeats", process_repeats),
    )
    for field, expected_count in control_sets:
        value = protocol.get(field)
        if (
            not isinstance(value, list)
            or len(value) != expected_count
            or any(not isinstance(item, dict) for item in value)
        ):
            blockers.append(
                _blocker(
                    f"control.{field}-count",
                    "controls",
                    subject,
                    f"{field} is incomplete",
                    len(value) if isinstance(value, list) else None,
                    expected_count,
                )
            )

    aa_values: list[float] = []
    placebo_values: list[float] = []
    largest_positive_t: list[float] = []
    largest_positive_delta: list[float] = []
    for field, ceiling, destination, code in (
        (
            "aa_controls",
            margins["aa_abs_t_ceiling_exclusive"],
            aa_values,
            "aa-margin",
        ),
        (
            "setup_placebo_controls",
            margins["setup_placebo_abs_t_ceiling_exclusive"],
            placebo_values,
            "placebo-margin",
        ),
    ):
        values = protocol.get(field)
        if not isinstance(values, list):
            continue
        for index, item in enumerate(values):
            if not isinstance(item, dict):
                continue
            score = _finite_number(item.get("abs_t_score"))
            if score is not None:
                destination.append(score)
            if score is None or not score < float(ceiling):
                blockers.append(
                    _blocker(
                        f"control.{code}",
                        "safety-margin",
                        f"{subject}/repeat-{index}",
                        f"{field} lacks prerehearsal headroom",
                        score,
                        f"abs_t_score < {ceiling}",
                    )
                )

    positives = protocol.get("positive_controls")
    largest_effect = effects[-1]
    if isinstance(positives, list):
        largest = [
            item
            for item in positives
            if isinstance(item, dict) and item.get("effect_ticks") == largest_effect
        ]
        if len(largest) != process_repeats:
            blockers.append(
                _blocker(
                    "control.largest-positive-count",
                    "controls",
                    subject,
                    "largest-effect positive controls are incomplete",
                    len(largest),
                    process_repeats,
                )
            )
        for item in largest:
            process_index = item.get("process_index")
            t_score = _finite_number(item.get("t_score"))
            mean_delta = _finite_number(item.get("mean_delta"))
            if t_score is not None:
                largest_positive_t.append(t_score)
            if mean_delta is not None:
                largest_positive_delta.append(mean_delta)
            t_ceiling = float(margins["largest_positive_t_ceiling_inclusive"])
            delta_floor = float(margins["largest_positive_mean_delta_floor_exclusive"])
            if t_score is None or t_score > t_ceiling:
                blockers.append(
                    _blocker(
                        "control.positive-margin",
                        "safety-margin",
                        f"{subject}/repeat-{process_index}",
                        "largest positive control is too close to the final threshold",
                        t_score,
                        f"t_score <= {t_ceiling}",
                    )
                )
            if mean_delta is None or mean_delta <= delta_floor:
                blockers.append(
                    _blocker(
                        "control.positive-direction",
                        "controls",
                        f"{subject}/repeat-{process_index}",
                        "largest positive control has the wrong or missing direction",
                        mean_delta,
                        f"mean_delta > {delta_floor}",
                    )
                )

    summary = {
        "target_statistics_interpretable": False,
        "target_status_consistent_observed": protocol.get("target_status_consistent"),
        "aa_max_abs_t": max(aa_values) if aa_values else None,
        "placebo_max_abs_t": max(placebo_values) if placebo_values else None,
        "largest_positive_max_t": max(largest_positive_t) if largest_positive_t else None,
        "largest_positive_min_delta": (
            min(largest_positive_delta) if largest_positive_delta else None
        ),
        "final_controls_passed": all(
            protocol.get(field) is True
            for field in ("aa_budget_passed", "setup_placebo_passed", "positive_power_passed")
        ),
        "safety_margins_passed": not any(
            blocker["stage"] == "safety-margin" for blocker in blockers
        ),
    }
    return summary, blockers


def _read_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RehearsalError(f"{label} is missing: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RehearsalError(f"{label} is unreadable: {exc}") from exc
    return _mapping(value, label)


def _assess_native_components(
    profile: dict[str, Any],
    report: dict[str, Any],
    root: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    summaries: dict[str, Any] = {}
    blockers: list[dict[str, Any]] = []
    hosts: list[dict[str, Any]] = []
    margins = profile["safety_margins"]
    expected_profile = {
        "schema_version": "1.0",
        "kind": "control-rehearsal",
        "profile_id": NATIVE_CONTROL_REHEARSAL_PROFILE_ID,
        "target_measurements_override": profile["target_measurements"],
        "target_statistics_interpretable": False,
        "control_contract": "component-manifest-exact",
        "promotion_allowed": False,
    }
    for component in _profile_components(profile):
        component_id = component["id"]
        component_root = root / component["output"]
        campaign = load_campaign(_repo_path(component["manifest"], "component manifest"))
        component_summary: dict[str, Any] = {
            "manifest": component["manifest"],
            "expected_targets": len(campaign.targets),
            "expected_axes": sum(len(target.harnesses) for target in campaign.targets),
            "targets": {},
            "axes": {},
            "status": "fail",
        }
        summaries[component_id] = component_summary
        try:
            campaign_report = _read_json(
                component_root / "campaign_report.json",
                f"{component_id} campaign report",
            )
        except RehearsalError as exc:
            blockers.append(
                _blocker(
                    "native.report-missing",
                    "native-component",
                    component_id,
                    str(exc),
                    None,
                    "complete schema-2.1 campaign report",
                )
            )
            continue
        exact_report_fields = {
            "schema_version": "2.1",
            "campaign_id": campaign.campaign_id,
            "ctkat_commit": report["ctkat_commit"],
            "run_kind": "engineering",
            "status": "complete",
            "paper_promotion_ready": False,
            "execution_profile": expected_profile,
        }
        for field, expected in exact_report_fields.items():
            observed = campaign_report.get(field)
            if observed != expected:
                blockers.append(
                    _blocker(
                        f"native.{field}",
                        "native-component",
                        component_id,
                        f"campaign {field} differs from rehearsal contract",
                        observed,
                        expected,
                    )
                )
        host_preflight = campaign_report.get("host_preflight")
        environment = (
            host_preflight.get("environment") if isinstance(host_preflight, dict) else None
        )
        if isinstance(environment, dict):
            hosts.append(
                {
                    "source": component_id,
                    "machine_id_sha256": environment.get("machine_id_sha256"),
                    "boot_id_sha256": environment.get("boot_id_sha256"),
                    "cpu_model": environment.get("cpu_model"),
                    "cpu_affinity": environment.get("cpu_affinity"),
                    "system": environment.get("system"),
                    "machine": environment.get("machine"),
                }
            )
        target_index = campaign_report.get("targets")
        if not isinstance(target_index, dict):
            target_index = {}
        expected_target_ids = [target.id for target in campaign.targets]
        if sorted(target_index) != sorted(expected_target_ids):
            blockers.append(
                _blocker(
                    "native.target-coverage",
                    "native-component",
                    component_id,
                    "component target set is incomplete or contains extras",
                    sorted(target_index),
                    sorted(expected_target_ids),
                )
            )
        for target in campaign.targets:
            target_record = target_index.get(target.id)
            component_summary["targets"][target.id] = {
                "complete": target_record.get("complete")
                if isinstance(target_record, dict)
                else None,
                "errors": target_record.get("errors") if isinstance(target_record, dict) else None,
            }
            if (
                not isinstance(target_record, dict)
                or target_record.get("complete") is not True
                or target_record.get("errors") != []
            ):
                blockers.append(
                    _blocker(
                        "native.target-incomplete",
                        "native-component",
                        f"{component_id}/{target.id}",
                        "target artifact validation did not complete cleanly",
                        target_record,
                        "complete=true and errors=[]",
                    )
                )
            backend_path = component_root / target.id / "reports/dudect_backend_report.json"
            try:
                backend = _read_json(backend_path, f"{component_id}/{target.id} backend report")
            except RehearsalError as exc:
                blockers.append(
                    _blocker(
                        "native.backend-missing",
                        "native-component",
                        f"{component_id}/{target.id}",
                        str(exc),
                        None,
                        "backend report",
                    )
                )
                continue
            configured = load_config(target.config)
            configured_harnesses = {
                item.name: item
                for item in (configured.dudect.harnesses if configured.dudect else [])
            }
            backend_harnesses = backend.get("harnesses")
            actual: dict[str, dict[str, Any]] = {}
            if isinstance(backend_harnesses, list):
                for item in backend_harnesses:
                    if isinstance(item, dict) and isinstance(item.get("harness"), str):
                        actual[str(item["harness"])] = item
            if sorted(actual) != sorted(target.harnesses):
                blockers.append(
                    _blocker(
                        "native.axis-coverage",
                        "native-component",
                        f"{component_id}/{target.id}",
                        "backend harness set is incomplete or contains extras",
                        sorted(actual),
                        sorted(target.harnesses),
                    )
                )
            for harness_name in target.harnesses:
                subject = f"{component_id}/{target.id}/{harness_name}"
                item = actual.get(harness_name)
                if not isinstance(item, dict):
                    continue
                harness = configured_harnesses.get(harness_name)
                if harness is None:
                    blockers.append(
                        _blocker(
                            "native.config-harness-missing",
                            "native-component",
                            subject,
                            "harness is absent from current config",
                            None,
                            harness_name,
                        )
                    )
                    continue
                environment_record = item.get("environment")
                if not isinstance(environment_record, dict) or environment_record.get("rejected"):
                    blockers.append(
                        _blocker(
                            "native.environment-rejected",
                            "native-component",
                            subject,
                            "timing environment was rejected",
                            environment_record,
                            "rejected=false",
                        )
                    )
                axis_summary, axis_blockers = _assess_control_protocol(
                    item.get("harness_protocol"),
                    subject=subject,
                    target_measurements=profile["target_measurements"],
                    control_measurements=target.control_measurements,
                    effects=target.positive_control_effects,
                    process_repeats=campaign.protocol.process_repeats,
                    randomness_policy=harness.randomness_policy,
                    margins=margins,
                )
                axis_summary.update(
                    {
                        "axis": target.axis_for(harness_name),
                        "timing_validity_observed": item.get("timing_validity"),
                        "raw_status_observed": item.get("raw_status"),
                        "target_result_ignored": True,
                    }
                )
                component_summary["axes"][f"{target.id}/{harness_name}"] = axis_summary
                blockers.extend(axis_blockers)
        component_blockers = [
            blocker
            for blocker in blockers
            if blocker["subject"] == component_id
            or blocker["subject"].startswith(component_id + "/")
        ]
        component_summary["status"] = "pass" if not component_blockers else "fail"
    return summaries, blockers, hosts


def _assess_baselines(
    profile: dict[str, Any],
    report: dict[str, Any],
    root: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    summaries: dict[str, Any] = {}
    blockers: list[dict[str, Any]] = []
    hosts: list[dict[str, Any]] = []
    manifest = baseline_runner.load_manifest()
    source_config_path = _repo_path(
        manifest["source_snapshot"]["config"]["path"],
        "baseline source config",
    )
    source_config = load_config(source_config_path)
    for tool_id in BASELINE_IDS:
        execute_step = report["steps"].get(f"baseline-{tool_id}")
        result_value = execute_step.get("result") if isinstance(execute_step, dict) else None
        result_path = (root / result_value).resolve() if isinstance(result_value, str) else None
        summary: dict[str, Any] = {"status": "fail", "report": result_value}
        summaries[tool_id] = summary
        if result_path is None:
            blockers.append(
                _blocker(
                    "baseline.report-missing",
                    "baseline",
                    tool_id,
                    "baseline result path was not recorded",
                    None,
                    "fresh baseline_report.json",
                )
            )
            continue
        try:
            value = _read_json(result_path, f"{tool_id} baseline report")
        except RehearsalError as exc:
            blockers.append(
                _blocker(
                    "baseline.report-invalid",
                    "baseline",
                    tool_id,
                    str(exc),
                    None,
                    "valid baseline report",
                )
            )
            continue
        validation_errors = baseline_runner.validate_result(
            value,
            manifest,
            expected_commit=report["ctkat_commit"],
            expected_run_kind="engineering",
            artifact_root=result_path.parent,
        )
        if validation_errors:
            blockers.append(
                _blocker(
                    "baseline.integrity",
                    "baseline",
                    tool_id,
                    "baseline independent validation failed",
                    validation_errors,
                    [],
                )
            )
        rows = value.get("rows")
        row_statuses = []
        if isinstance(rows, list):
            row_statuses = [
                {
                    "case_id": item.get("case_id"),
                    "execution_status": item.get("execution_status"),
                    "known_issue_match": item.get("known_issue_match"),
                }
                for item in rows
                if isinstance(item, dict)
            ]
        if (
            len(row_statuses) != 2
            or any(item["execution_status"] != "completed" for item in row_statuses)
            or any(item["known_issue_match"] is not True for item in row_statuses)
            or value.get("errors") != []
            or value.get("promotion_ready") is not False
        ):
            blockers.append(
                _blocker(
                    "baseline.outcome",
                    "baseline",
                    tool_id,
                    "engineering baseline did not complete both expected cases cleanly",
                    {"rows": row_statuses, "errors": value.get("errors")},
                    "two completed known-issue matches, errors=[], promotion_ready=false",
                )
            )
        host = value.get("host")
        if isinstance(host, dict):
            hosts.append(
                {
                    "source": f"baseline-{tool_id}",
                    "machine_id_sha256": host.get("machine_id_sha256"),
                    "boot_id_sha256": host.get("boot_id_sha256"),
                    "cpu_model": host.get("cpu_model"),
                    "cpu_affinity": host.get("cpu_affinity"),
                    "system": host.get("system"),
                    "machine": host.get("machine"),
                }
            )
        summary.update({"rows": row_statuses, "integrity_errors": validation_errors})
        if tool_id == "official_dudect" and source_config.dudect is not None:
            raw_path_value = (
                value.get("backend", {}).get("raw_report")
                if isinstance(value.get("backend"), dict)
                else None
            )
            raw_path = (
                result_path.parent / raw_path_value
                if isinstance(raw_path_value, str)
                else result_path.parent / "missing-raw-report.json"
            )
            try:
                raw = _read_json(raw_path, "official baseline raw report")
            except RehearsalError as exc:
                blockers.append(
                    _blocker(
                        "baseline.control-report",
                        "baseline",
                        tool_id,
                        str(exc),
                        None,
                        "raw official-dudect report",
                    )
                )
            else:
                configured = {item.name: item for item in source_config.dudect.harnesses}
                control_summaries: dict[str, Any] = {}
                for item in raw.get("harnesses", []):
                    if not isinstance(item, dict) or item.get("harness") not in configured:
                        continue
                    name = item["harness"]
                    harness = configured[name]
                    axis_summary, axis_blockers = _assess_control_protocol(
                        item.get("harness_protocol"),
                        subject=f"baseline-official_dudect/{name}",
                        target_measurements=source_config.dudect.measurements,
                        control_measurements=(
                            source_config.dudect.timing_protocol.control_measurements
                            or source_config.dudect.measurements
                        ),
                        effects=tuple(
                            source_config.dudect.timing_protocol.positive_control_effects
                        ),
                        process_repeats=source_config.dudect.timing_protocol.process_repeats,
                        randomness_policy=harness.randomness_policy,
                        margins=profile["safety_margins"],
                    )
                    axis_summary["target_result_ignored"] = False
                    control_summaries[name] = axis_summary
                    blockers.extend(axis_blockers)
                summary["controls"] = control_summaries
        current_blockers = [
            blocker
            for blocker in blockers
            if blocker["subject"] == tool_id
            or blocker["subject"].startswith(f"baseline-{tool_id}/")
        ]
        summary["status"] = "pass" if not current_blockers else "fail"
    return summaries, blockers, hosts


def _assess_assembly(
    report: dict[str, Any],
    root: Path,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    blockers: list[dict[str, Any]] = []
    bundle_path = root / "asm-evidence/asm_evidence_bundle.json"
    try:
        value = _read_json(bundle_path, "assembly evidence bundle")
    except RehearsalError as exc:
        return None, [
            _blocker(
                "assembly.bundle-missing",
                "assembly",
                "mlkem-assembly",
                str(exc),
                None,
                "complete assembly bundle",
            )
        ]
    expected = {
        "kind": "ctkat-asm-evidence-bundle",
        "source_commit": report["ctkat_commit"],
        "coverage_status": "pass",
        "errors": [],
    }
    observed = {
        "kind": value.get("kind"),
        "source_commit": value.get("source_revision", {}).get("commit")
        if isinstance(value.get("source_revision"), dict)
        else None,
        "coverage_status": value.get("coverage", {}).get("status")
        if isinstance(value.get("coverage"), dict)
        else None,
        "errors": value.get("errors"),
    }
    if observed != expected:
        blockers.append(
            _blocker(
                "assembly.contract",
                "assembly",
                "mlkem-assembly",
                "assembly evidence does not match the candidate commit and full coverage",
                observed,
                expected,
            )
        )
    return {
        "status": "pass" if not blockers else "fail",
        "bundle": _relative(bundle_path, root),
        "sha256": _sha256(bundle_path),
        "coverage": value.get("coverage"),
        "artifact_paper_eligible_observed": value.get("paper_eligible"),
        "rehearsal_reuse_forbidden": True,
    }, blockers


def _assess_pipeline_closure(
    report: dict[str, Any],
    hosts: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    blockers: list[dict[str, Any]] = []
    expected_sources = {
        *COMPONENT_IDS,
        *(f"baseline-{tool_id}" for tool_id in BASELINE_IDS),
    }
    actual_sources = {item.get("source") for item in hosts}
    if actual_sources != expected_sources:
        blockers.append(
            _blocker(
                "closure.host-coverage",
                "pipeline-closure",
                "single-host-lineage",
                "host identity records do not cover all components and baselines",
                sorted(str(item) for item in actual_sources),
                sorted(expected_sources),
            )
        )
    identity_fields = ("machine_id_sha256", "boot_id_sha256", "cpu_model", "system", "machine")
    field_values = {
        field: sorted({json.dumps(item.get(field), sort_keys=True) for item in hosts})
        for field in identity_fields
    }
    for field, values in field_values.items():
        if len(values) != 1 or values == ["null"]:
            blockers.append(
                _blocker(
                    f"closure.{field}",
                    "pipeline-closure",
                    "single-host-lineage",
                    f"{field} differs or is missing across rehearsal steps",
                    values,
                    "one shared non-null value",
                )
            )
    affinities = sorted({json.dumps(item.get("cpu_affinity"), sort_keys=True) for item in hosts})
    if len(affinities) != 1:
        blockers.append(
            _blocker(
                "closure.cpu-affinity",
                "pipeline-closure",
                "single-host-lineage",
                "CPU affinity differs across rehearsal steps",
                affinities,
                "one shared logical CPU",
            )
        )
    return {
        "status": "pass" if not blockers else "fail",
        "ctkat_commit": report["ctkat_commit"],
        "sources": sorted(str(item) for item in actual_sources),
        "shared_identity_values": field_values,
        "affinities": affinities,
        "paper_bundle_built": False,
        "paper_analysis_run": False,
    }, blockers


def _deduplicate_blockers(blockers: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for blocker in blockers:
        key = json.dumps(blocker, sort_keys=True, separators=(",", ":"), allow_nan=False)
        unique[key] = blocker
    return sorted(
        unique.values(),
        key=lambda item: (item["stage"], item["code"], item["subject"], item["message"]),
    )


def _step_blockers(report: dict[str, Any], *, smoke_only: bool) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for step_id, record in report["steps"].items():
        if not isinstance(record, dict) or record.get("status") != "fail":
            continue
        if smoke_only and (
            step_id.startswith("native-")
            or step_id.startswith("validate-native-")
            or step_id.startswith("baseline-")
            or step_id.startswith("validate-baseline-")
            or step_id.startswith("assembly-")
        ):
            continue
        result.append(
            _blocker(
                "step.nonzero-exit",
                "orchestration",
                step_id,
                "rehearsal step returned non-zero",
                record.get("returncode"),
                0,
            )
        )
    return result


def _render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    lines = [
        "# CT-KAT paper control rehearsal",
        "",
        f"- Status: `{report['status']}`",
        f"- Candidate commit: `{report['ctkat_commit']}`",
        f"- Rehearsal run ID: `{report['run_id']}`",
        "- Evidence class: `engineering / non-promotable`",
        f"- Reduced target trace: `{report['target_measurements']}` per process",
        "- Target statistics: **interpretation forbidden**",
        "",
        "## Coverage",
        "",
        "| Item | Passed | Expected |",
        "|---|---:|---:|",
        f"| Compile/contract smoke axes | {summary.get('smoke_axes_passed', 0)} | 28 |",
        f"| Native component axes assessed | {summary.get('native_axes_assessed', 0)} | 28 |",
        f"| Native components clean | {summary.get('native_components_passed', 0)} | 4 |",
        f"| Same-corpus baselines clean | {summary.get('baselines_passed', 0)} | 3 |",
        f"| Blockers | {summary.get('blocker_count', 0)} | 0 |",
        "",
        "## Decision",
        "",
    ]
    if report["status"] == "pass":
        lines.extend(
            [
                "이 리허설 한 회는 깨끗하다. 그래도 final 진입은 금지다. 동일 candidate",
                "commit에서 서로 다른 run ID의 clean rehearsal이 한 회 더 필요하다.",
            ]
        )
    elif report["status"] == "smoke-complete":
        lines.extend(
            [
                "compile/contract smoke 단계만 끝났다. 이 결과는 control 합격을 뜻하지 않는다.",
                "같은 root에 `--phase controls --resume`으로 이어서 실행한다.",
            ]
        )
    else:
        lines.append("아래 blocker를 모두 해결하기 전에는 V9 동결이나 final 실행을 금지한다.")
    lines.extend(["", "## Blocker matrix", ""])
    blockers = report.get("blockers", [])
    if not blockers:
        lines.append("없음.")
    else:
        lines.extend(
            [
                "| Stage | Code | Subject | Problem | Observed | Required |",
                "|---|---|---|---|---|---|",
            ]
        )
        for blocker in blockers:
            cells = [
                blocker.get("stage"),
                blocker.get("code"),
                blocker.get("subject"),
                blocker.get("message"),
                json.dumps(blocker.get("observed"), ensure_ascii=False, sort_keys=True),
                json.dumps(blocker.get("required"), ensure_ascii=False, sort_keys=True),
            ]
            escaped = [str(value).replace("|", "\\|").replace("\n", " ") for value in cells]
            lines.append("| " + " | ".join(escaped) + " |")
    lines.extend(
        [
            "",
            "## Scope boundary",
            "",
            "Target/calibration trace를 줄였으므로 target PASS/FAIL과 t-score는 논문 결과가",
            "아니다. A/A, placebo, positive controls는 원 component manifest 수량을 그대로",
            "실행했지만, 이 전체 tree도 engineering lineage라서 final로 재사용할 수 없다.",
            "",
        ]
    )
    return "\n".join(lines)


def assess_report(
    profile: dict[str, Any],
    report: dict[str, Any],
    root: Path,
    *,
    smoke_only: bool,
) -> None:
    blockers: list[dict[str, Any]] = _step_blockers(report, smoke_only=smoke_only)
    smoke_axes = report["smoke"]["axes"]
    if len(smoke_axes) != 28:
        blockers.append(
            _blocker(
                "smoke.coverage",
                "compile-smoke",
                "all-axes",
                "compile/contract smoke did not cover every timing axis",
                len(smoke_axes),
                28,
            )
        )
    for key, item in smoke_axes.items():
        if not isinstance(item, dict) or item.get("status") != "pass":
            blockers.append(
                _blocker(
                    "smoke.axis-failed",
                    "compile-smoke",
                    key,
                    "compile, binary/build contract, or four-row runtime smoke failed",
                    item.get("errors") if isinstance(item, dict) else item,
                    [],
                )
            )
    native_summaries: dict[str, Any] = {}
    baseline_summaries: dict[str, Any] = {}
    assembly_summary: dict[str, Any] | None = None
    closure: dict[str, Any] | None = None
    if not smoke_only:
        native_summaries, native_blockers, native_hosts = _assess_native_components(
            profile,
            report,
            root,
        )
        baseline_summaries, baseline_blockers, baseline_hosts = _assess_baselines(
            profile,
            report,
            root,
        )
        assembly_summary, assembly_blockers = _assess_assembly(report, root)
        closure, closure_blockers = _assess_pipeline_closure(
            report,
            [*native_hosts, *baseline_hosts],
        )
        blockers.extend(native_blockers)
        blockers.extend(baseline_blockers)
        blockers.extend(assembly_blockers)
        blockers.extend(closure_blockers)
    blockers = _deduplicate_blockers(blockers)
    report["native_components"] = native_summaries
    report["baselines"] = baseline_summaries
    report["assembly"] = assembly_summary
    report["pipeline_closure"] = closure
    report["blockers"] = blockers
    native_axes = sum(
        len(item.get("axes", {})) for item in native_summaries.values() if isinstance(item, dict)
    )
    report["summary"] = {
        "smoke_axes_passed": sum(
            isinstance(item, dict) and item.get("status") == "pass" for item in smoke_axes.values()
        ),
        "native_axes_assessed": native_axes,
        "native_components_passed": sum(
            isinstance(item, dict) and item.get("status") == "pass"
            for item in native_summaries.values()
        ),
        "baselines_passed": sum(
            isinstance(item, dict) and item.get("status") == "pass"
            for item in baseline_summaries.values()
        ),
        "assembly_passed": (
            assembly_summary.get("status") == "pass"
            if isinstance(assembly_summary, dict)
            else False
        ),
        "pipeline_closure_passed": (
            closure.get("status") == "pass" if isinstance(closure, dict) else False
        ),
        "blocker_count": len(blockers),
        "target_statistics_interpretable": False,
        "promotion_allowed": False,
    }
    report["finished_at"] = _utc_now()
    if smoke_only:
        report["status"] = "smoke-complete" if not blockers else "fail"
    else:
        report["status"] = "pass" if not blockers else "fail"
    report_path = root / REPORT_NAME
    _write_json_atomic(report_path, report, validate=True)
    (root / MARKDOWN_NAME).write_text(_render_markdown(report), encoding="utf-8")


def qualify_reports(
    paths: list[Path],
    *,
    output: Path | None,
    expected_commit: str | None,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    if len(paths) != 2:
        return {}, ["qualification requires exactly two rehearsal reports"]
    reports: list[dict[str, Any]] = []
    validator = Draft202012Validator(_load_schema())
    for path in paths:
        try:
            report = _read_json(path.resolve(), "qualification rehearsal report")
        except RehearsalError as exc:
            errors.append(str(exc))
            continue
        schema_errors = sorted(
            validator.iter_errors(report),
            key=lambda error: tuple(str(item) for item in error.absolute_path),
        )
        errors.extend(f"{path}: schema: {error.message}" for error in schema_errors)
        if report.get("status") != "pass" or report.get("blockers") != []:
            errors.append(f"{path}: rehearsal is not blocker-free PASS")
        if report.get("promotion_allowed") is not False or report.get("run_kind") != "engineering":
            errors.append(f"{path}: rehearsal evidence boundary drift")
        expected_summary = {
            "smoke_axes_passed": 28,
            "native_axes_assessed": 28,
            "native_components_passed": 4,
            "baselines_passed": 3,
            "assembly_passed": True,
            "pipeline_closure_passed": True,
            "blocker_count": 0,
            "target_statistics_interpretable": False,
            "promotion_allowed": False,
        }
        if report.get("summary") != expected_summary:
            errors.append(f"{path}: clean rehearsal summary is incomplete or drifted")
        if report.get("smoke", {}).get("passed_axes") != 28:
            errors.append(f"{path}: compile/contract smoke is not 28/28")
        components = report.get("native_components")
        if (
            not isinstance(components, dict)
            or set(components) != set(COMPONENT_IDS)
            or any(
                not isinstance(item, dict) or item.get("status") != "pass"
                for item in components.values()
            )
        ):
            errors.append(f"{path}: native component qualification matrix is not 4/4 PASS")
        baselines = report.get("baselines")
        if (
            not isinstance(baselines, dict)
            or set(baselines) != set(BASELINE_IDS)
            or any(
                not isinstance(item, dict) or item.get("status") != "pass"
                for item in baselines.values()
            )
        ):
            errors.append(f"{path}: baseline qualification matrix is not 3/3 PASS")
        assembly = report.get("assembly")
        if not isinstance(assembly, dict) or assembly.get("status") != "pass":
            errors.append(f"{path}: assembly qualification did not pass")
        closure = report.get("pipeline_closure")
        if not isinstance(closure, dict) or closure.get("status") != "pass":
            errors.append(f"{path}: pipeline closure qualification did not pass")
        reports.append(report)
    commits = {item.get("ctkat_commit") for item in reports}
    run_ids = {item.get("run_id") for item in reports}
    profile_hashes = {item.get("profile_sha256") for item in reports}
    calibration_hashes = {item.get("calibration_sha256") for item in reports}
    if len(commits) != 1:
        errors.append("the two clean rehearsals do not share one candidate commit")
    if expected_commit is not None and commits != {expected_commit}:
        errors.append("qualified candidate commit differs from --expected-commit")
    if len(run_ids) != 2:
        errors.append("the two clean rehearsals do not have distinct run IDs")
    if len(profile_hashes) != 1:
        errors.append("the two clean rehearsals used different profile revisions")
    if len(calibration_hashes) != 1:
        errors.append("the two clean rehearsals used different calibration records")
    rehearsal_records = [
        {
            "path": str(path.resolve()),
            "sha256": _sha256(path.resolve()),
            "run_id": report.get("run_id"),
            "started_at": report.get("started_at"),
            "finished_at": report.get("finished_at"),
        }
        for path, report in zip(paths, reports, strict=False)
    ]
    result = {
        "schema_version": "2.0",
        "kind": "ctkat-v9-final-control-qualification",
        "created_at": _utc_now(),
        "candidate_commit": next(iter(commits)) if len(commits) == 1 else None,
        "profile_id": REHEARSAL_PROFILE_ID,
        "profile_sha256": next(iter(profile_hashes)) if len(profile_hashes) == 1 else None,
        "calibration_sha256": (
            next(iter(calibration_hashes)) if len(calibration_hashes) == 1 else None
        ),
        "rehearsal_run_ids": sorted(str(item) for item in run_ids),
        "rehearsals": rehearsal_records,
        "required_clean_runs": 2,
        "observed_clean_runs": sum(
            item.get("status") == "pass" and item.get("blockers") == [] for item in reports
        ),
        "final_launch_ready": not errors,
        "next_gate": "execute every V9 final component from fresh roots at candidate_commit",
        "errors": errors,
    }
    if output is not None:
        _write_json_atomic(output.resolve(), result)
    return result, errors


def execute(
    profile: dict[str, Any],
    profile_path: Path,
    *,
    output_root: Path,
    phase: str,
    cpu: int,
    timecop_prefix: Path,
    resume: bool,
) -> int:
    root = _safe_output_root(output_root)
    if phase == "controls" and not resume:
        raise RehearsalError("--phase controls requires --resume from a smoke rehearsal root")
    if not timecop_prefix.is_absolute():
        raise RehearsalError("--timecop-prefix must be absolute")
    pin_current_process(cpu)
    report, report_path = _load_execution_report(
        root,
        profile,
        profile_path,
        phase=phase,
        resume=resume,
    )
    try:
        for step_id, command in _preflight_commands(profile, cpu):
            _run_step(
                report,
                report_path,
                root,
                step_id=step_id,
                command=command,
                resume=resume,
            )
        if phase in {"smoke", "all"}:
            _run_smoke(profile, report, report_path, root, resume=resume)
        if phase in {"controls", "all"}:
            _run_controls(
                profile,
                report,
                report_path,
                root,
                cpu=cpu,
                timecop_prefix=timecop_prefix,
                resume=resume,
            )
        assess_report(profile, report, root, smoke_only=phase == "smoke")
    except KeyboardInterrupt:
        report["status"] = "interrupted"
        report["finished_at"] = _utc_now()
        _write_json_atomic(report_path, report, validate=True)
        raise
    print(f"[rehearsal] report: {report_path}")
    print(f"[rehearsal] markdown: {root / MARKDOWN_NAME}")
    print(
        f"[rehearsal] status={report['status']} blockers={len(report['blockers'])} "
        "promotion_allowed=false"
    )
    if phase == "smoke":
        return 0 if report["status"] == "smoke-complete" else 1
    return 0 if report["status"] == "pass" else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true", help="validate the frozen rehearsal")
    action.add_argument("--execute", action="store_true", help="execute a rehearsal phase")
    action.add_argument("--qualify", action="store_true", help="qualify two clean rehearsals")
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--phase", choices=("smoke", "controls", "all"), default="all")
    parser.add_argument("--cpu", type=int)
    parser.add_argument("--timecop-prefix", type=Path)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--rehearsal-report", type=Path, action="append", default=[])
    parser.add_argument("--qualification-output", type=Path)
    parser.add_argument("--expected-commit")
    args = parser.parse_args(argv)
    try:
        profile_path = args.profile.resolve()
        profile = load_profile(profile_path)
        errors, static_report = validate_profile(profile, profile_path=profile_path)
        if errors:
            for error in errors:
                print(f"[rehearsal] ERROR: {error}", file=sys.stderr)
            return 1
        if args.check:
            print(json.dumps(static_report, indent=2, sort_keys=True))
            return 0
        if args.qualify:
            if (
                args.output_root is not None
                or args.cpu is not None
                or args.timecop_prefix is not None
            ):
                parser.error("--qualify does not accept execution arguments")
            result, qualification_errors = qualify_reports(
                args.rehearsal_report,
                output=args.qualification_output,
                expected_commit=args.expected_commit,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if not qualification_errors else 2
        if args.rehearsal_report or args.qualification_output is not None or args.expected_commit:
            parser.error("qualification arguments require --qualify")
        if args.output_root is None or args.cpu is None or args.timecop_prefix is None:
            parser.error("--execute requires --output-root, --cpu, and --timecop-prefix")
        return execute(
            profile,
            profile_path,
            output_root=args.output_root,
            phase=args.phase,
            cpu=args.cpu,
            timecop_prefix=args.timecop_prefix,
            resume=args.resume,
        )
    except (CampaignError, RehearsalError, OSError, ValueError) as exc:
        print(f"[rehearsal] ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
