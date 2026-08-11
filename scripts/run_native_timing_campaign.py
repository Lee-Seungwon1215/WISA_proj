#!/usr/bin/env python3
"""Plan, execute, and validate the deferred native timing-v2 corpus campaign.

This script is deliberately repository-specific.  It freezes the exact set of
legacy timing rows that need replacement, applies paper-grade measurement
overrides without editing the example configs, and writes promotion *candidates*
without mutating the curated corpus.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctkat.cli import _do_dudect  # noqa: E402
from ctkat.config import CtkatConfig, DudectConfig, load_config  # noqa: E402
from ctkat.evidence import timing_from_raw  # noqa: E402
from ctkat.official_dudect import (  # noqa: E402
    OFFICIAL_DUDECT_BACKEND,
    OFFICIAL_DUDECT_MIN_CLASS0,
    OFFICIAL_DUDECT_PROTOCOL_TESTS,
    OFFICIAL_DUDECT_REVISION,
    OFFICIAL_DUDECT_THRESHOLD_LABEL,
    build_official_dudect_adapter,
)
from ctkat.official_dudect_verify import (  # noqa: E402
    OfficialDudectProtocolContract,
    verify_official_dudect_artifacts,
)
from ctkat.qemu_detect import detect_qemu_emulation  # noqa: E402
from ctkat.timing_binary_contract import (  # noqa: E402
    TimingBinaryContractError,
    evaluate_disassembly,
    load_timing_binary_contract,
)
from ctkat.timing_environment import collect_timing_environment  # noqa: E402
from ctkat.timing_input_contract import (  # noqa: E402
    OPERAND_V3_SETUP_CONTRACT,
    validate_operand_v3_harness_report,
    validate_valid_tuple_harness_report,
)

DEFAULT_MANIFEST = ROOT / "docs" / "measurement" / "native_timing_v3_campaign.yaml"
CORPUS_SUMMARY = ROOT / "docs" / "corpus" / "corpus_summary.csv"
OFFICIAL_TIMING_THRESHOLD = OFFICIAL_DUDECT_THRESHOLD_LABEL
RUN_KINDS = ("engineering", "pilot", "final")
TARGET_ATTESTATION = "run_attestation.json"
MEASUREMENT_CRITICAL_PATHS = (
    "ctkat",
    "scripts",
    "examples",
    "docs/measurement",
    "docs/baselines",
    "docs/ground_truth",
    "pyproject.toml",
    "uv.lock",
)
REQUIRED_ARTIFACTS = (
    "dudect_raw_timings.csv",
    "dudect_calibration_timings.csv",
    "dudect_protocol_timings.csv",
    "dudect_summary.csv",
    "dudect_backend_report.json",
)
SUMMARY_REQUIRED_COLUMNS = {
    "project",
    "harness",
    "n0",
    "n1",
    "abs_t_score",
    "status",
    "backend",
    "timing_validity",
    "raw_n_total",
    "analysis_seed",
    "harness_protocol",
    "process_repeats",
    "aa_failures",
    "positive_power_passed",
    "protocol_test_count",
    "upstream_revision",
}
PROTOCOL_HEADER = [
    "project",
    "harness",
    "role",
    "process_index",
    "seed",
    "effect_ticks",
    "sample_id",
    "class",
    "cycles",
    "aux_start",
    "aux_end",
    "drop_reason",
    "output_length",
    "signature_return_code",
    "protocol",
]
UPDATE_FIELDS = [
    "target",
    "family",
    "harness",
    "timing_validity",
    "timing_signal",
    "timing_backend",
    "timing_raw_status",
    "timing_abs_t",
    "timing_measurements",
    "timing_leak_target",
    "timing_seed",
    "timing_threshold",
    "report",
    "report_sha256",
    "promotion_ready",
    "blockers",
]


class CampaignError(RuntimeError):
    """A static, host, execution, or artifact-contract failure."""


@dataclass(frozen=True)
class ProtocolSpec:
    backend: str
    clock: str
    seed: int
    warmup: int
    batches: int
    process_repeats: int
    pool_size: int
    aa_abs_t_limit: float
    positive_abs_t_threshold: float
    aa_max_failures: int
    target_power: float
    power_alpha: float
    compiler: str
    compile_timeout: int
    backend_timeout: int


@dataclass(frozen=True)
class TargetSpec:
    id: str
    family: str
    config: Path
    harnesses: tuple[str, ...]
    axes: tuple[tuple[str, str], ...]
    target_measurements: int
    control_measurements: int
    positive_control_effects: tuple[int, ...]
    timeout: int

    def axis_for(self, harness: str) -> str:
        for name, axis in self.axes:
            if name == harness:
                return axis
        raise CampaignError(f"{self.id}: no frozen timing axis for harness {harness!r}")


@dataclass(frozen=True)
class CorpusAxisReplacement:
    target: str
    harness: str
    from_axis: str
    to_axis: str
    rationale: str


@dataclass(frozen=True)
class CampaignSpec:
    schema_version: str
    campaign_id: str
    description: str
    coverage_mode: str
    corpus_axis_replacements: tuple[CorpusAxisReplacement, ...]
    host: dict[str, Any]
    protocol: ProtocolSpec
    targets: tuple[TargetSpec, ...]
    manifest_path: Path
    manifest_sha256: str


@dataclass
class TargetValidation:
    target: TargetSpec
    report_dir: Path
    complete: bool = False
    promotion_ready: bool = False
    errors: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    harnesses: list[dict[str, Any]] = field(default_factory=list)
    artifact_sha256: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.id,
            "family": self.target.family,
            "report_dir": f"{self.target.id}/reports",
            "complete": self.complete,
            "promotion_ready": self.promotion_ready,
            "errors": self.errors,
            "blockers": self.blockers,
            "harnesses": self.harnesses,
            "artifact_sha256": self.artifact_sha256,
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CampaignError(f"{label} must be a mapping")
    return value


def _require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise CampaignError(f"{label} must be a list")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise CampaignError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CampaignError(f"{label} must be a non-negative integer")
    return value


def _positive_float(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or float(value) <= 0:
        raise CampaignError(f"{label} must be a positive number")
    result = float(value)
    if result == float("inf") or result != result:
        raise CampaignError(f"{label} must be finite")
    return result


def _forbid_unknown(data: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise CampaignError(f"{label} contains unknown keys: {unknown}")


def _repo_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise CampaignError(f"{label} must be a non-empty repository-relative path")
    candidate = (ROOT / value).resolve()
    try:
        candidate.relative_to(ROOT)
    except ValueError as exc:
        raise CampaignError(f"{label} escapes the repository: {value!r}") from exc
    return candidate


def load_campaign(path: Path = DEFAULT_MANIFEST) -> CampaignSpec:
    manifest_path = path.resolve()
    try:
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CampaignError(f"campaign manifest unreadable: {manifest_path}: {exc}") from exc
    root = _require_mapping(raw, "campaign manifest")
    _forbid_unknown(
        root,
        {
            "schema_version",
            "campaign_id",
            "description",
            "coverage_mode",
            "corpus_axis_replacements",
            "host",
            "protocol",
            "targets",
        },
        "campaign manifest",
    )
    if root.get("schema_version") != "1.0":
        raise CampaignError("campaign schema_version must be '1.0'")
    campaign_id = root.get("campaign_id")
    if not isinstance(campaign_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]+", campaign_id):
        raise CampaignError("campaign_id must match [a-z0-9][a-z0-9._-]+")
    coverage_mode = root.get("coverage_mode")
    if coverage_mode not in {"committed-timing-rows", "manifest-only"}:
        raise CampaignError("coverage_mode must be committed-timing-rows or manifest-only")

    axis_names = {"sk", "valid_tuple", "ct", "fo", "msg", "chosen_ct", "operand_bin"}
    replacements: list[CorpusAxisReplacement] = []
    replacement_keys: set[tuple[str, str]] = set()
    raw_replacements = root.get("corpus_axis_replacements", [])
    for index, item in enumerate(_require_list(raw_replacements, "corpus_axis_replacements")):
        data = _require_mapping(item, f"corpus_axis_replacements[{index}]")
        _forbid_unknown(
            data,
            {"target", "harness", "from_axis", "to_axis", "rationale"},
            f"corpus_axis_replacements[{index}]",
        )
        target = data.get("target")
        harness = data.get("harness")
        from_axis = data.get("from_axis")
        to_axis = data.get("to_axis")
        rationale = data.get("rationale")
        if not isinstance(target, str) or not target:
            raise CampaignError(f"corpus_axis_replacements[{index}].target must be non-empty")
        if not isinstance(harness, str) or not harness:
            raise CampaignError(f"corpus_axis_replacements[{index}].harness must be non-empty")
        if from_axis not in axis_names or to_axis not in axis_names:
            raise CampaignError(f"corpus_axis_replacements[{index}] axes must be known timing axes")
        if from_axis == to_axis:
            raise CampaignError(f"corpus_axis_replacements[{index}] must change the timing axis")
        if not isinstance(rationale, str) or not rationale.strip():
            raise CampaignError(f"corpus_axis_replacements[{index}].rationale must be non-empty")
        key = (target, harness)
        if key in replacement_keys:
            raise CampaignError(f"duplicate corpus axis replacement for {target}/{harness}")
        replacement_keys.add(key)
        replacements.append(
            CorpusAxisReplacement(
                target=target,
                harness=harness,
                from_axis=str(from_axis),
                to_axis=str(to_axis),
                rationale=rationale,
            )
        )
    if replacements and coverage_mode != "committed-timing-rows":
        raise CampaignError("corpus_axis_replacements require coverage_mode=committed-timing-rows")

    host = _require_mapping(root.get("host"), "host")
    _forbid_unknown(
        host,
        {
            "system",
            "machines",
            "require_single_cpu_affinity",
            "reject_emulation",
            "reject_virtualization",
            "recommended_governor",
        },
        "host",
    )
    protocol_raw = _require_mapping(root.get("protocol"), "protocol")
    _forbid_unknown(
        protocol_raw,
        {
            "backend",
            "clock",
            "seed",
            "warmup",
            "batches",
            "process_repeats",
            "pool_size",
            "aa_abs_t_limit",
            "positive_abs_t_threshold",
            "aa_max_failures",
            "target_power",
            "power_alpha",
            "compiler",
            "compile_timeout",
            "backend_timeout",
        },
        "protocol",
    )
    protocol = ProtocolSpec(
        backend=str(protocol_raw.get("backend", "")),
        clock=str(protocol_raw.get("clock", "")),
        seed=_positive_int(protocol_raw.get("seed"), "protocol.seed"),
        warmup=_nonnegative_int(protocol_raw.get("warmup"), "protocol.warmup"),
        batches=_positive_int(protocol_raw.get("batches"), "protocol.batches"),
        process_repeats=_positive_int(
            protocol_raw.get("process_repeats"), "protocol.process_repeats"
        ),
        pool_size=_positive_int(protocol_raw.get("pool_size"), "protocol.pool_size"),
        aa_abs_t_limit=_positive_float(
            protocol_raw.get("aa_abs_t_limit"), "protocol.aa_abs_t_limit"
        ),
        positive_abs_t_threshold=_positive_float(
            protocol_raw.get("positive_abs_t_threshold"),
            "protocol.positive_abs_t_threshold",
        ),
        aa_max_failures=_nonnegative_int(
            protocol_raw.get("aa_max_failures"), "protocol.aa_max_failures"
        ),
        target_power=_positive_float(protocol_raw.get("target_power"), "protocol.target_power"),
        power_alpha=_positive_float(protocol_raw.get("power_alpha"), "protocol.power_alpha"),
        compiler=str(protocol_raw.get("compiler", "")),
        compile_timeout=_positive_int(
            protocol_raw.get("compile_timeout"), "protocol.compile_timeout"
        ),
        backend_timeout=_positive_int(
            protocol_raw.get("backend_timeout"), "protocol.backend_timeout"
        ),
    )

    targets: list[TargetSpec] = []
    for index, item in enumerate(_require_list(root.get("targets"), "targets")):
        data = _require_mapping(item, f"targets[{index}]")
        _forbid_unknown(
            data,
            {
                "id",
                "family",
                "config",
                "harnesses",
                "axes",
                "target_measurements",
                "control_measurements",
                "positive_control_effects",
                "timeout",
            },
            f"targets[{index}]",
        )
        target_id = data.get("id")
        if not isinstance(target_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]+", target_id):
            raise CampaignError(f"targets[{index}].id is invalid")
        family = data.get("family")
        if not isinstance(family, str) or not family:
            raise CampaignError(f"targets[{index}].family must be non-empty")
        harnesses_raw = _require_list(data.get("harnesses"), f"targets[{index}].harnesses")
        if not harnesses_raw or any(
            not isinstance(name, str) or not name for name in harnesses_raw
        ):
            raise CampaignError(f"targets[{index}].harnesses must contain names")
        axes_raw = _require_mapping(data.get("axes"), f"targets[{index}].axes")
        if set(axes_raw) != set(harnesses_raw):
            raise CampaignError(f"targets[{index}].axes keys must exactly match harnesses")
        if any(not isinstance(axis, str) or axis not in axis_names for axis in axes_raw.values()):
            raise CampaignError(
                "targets["
                f"{index}].axes values must be one of "
                "sk/valid_tuple/ct/fo/msg/chosen_ct/operand_bin"
            )
        effects_raw = _require_list(
            data.get("positive_control_effects"),
            f"targets[{index}].positive_control_effects",
        )
        effects = tuple(
            _positive_int(value, f"targets[{index}].positive_control_effects")
            for value in effects_raw
        )
        targets.append(
            TargetSpec(
                id=target_id,
                family=family,
                config=_repo_path(data.get("config"), f"targets[{index}].config"),
                harnesses=tuple(harnesses_raw),
                axes=tuple((name, axes_raw[name]) for name in harnesses_raw),
                target_measurements=_positive_int(
                    data.get("target_measurements"),
                    f"targets[{index}].target_measurements",
                ),
                control_measurements=_positive_int(
                    data.get("control_measurements"),
                    f"targets[{index}].control_measurements",
                ),
                positive_control_effects=effects,
                timeout=_positive_int(data.get("timeout"), f"targets[{index}].timeout"),
            )
        )

    return CampaignSpec(
        schema_version="1.0",
        campaign_id=campaign_id,
        description=str(root.get("description", "")),
        coverage_mode=str(coverage_mode),
        corpus_axis_replacements=tuple(replacements),
        host=dict(host),
        protocol=protocol,
        targets=tuple(targets),
        manifest_path=manifest_path,
        manifest_sha256=_sha256(manifest_path),
    )


def _corpus_timing_pairs() -> set[tuple[str, str]]:
    return {(target, harness) for target, harness, _axis in _corpus_timing_axes()}


def _corpus_timing_axes() -> set[tuple[str, str, str]]:
    with CORPUS_SUMMARY.open(newline="", encoding="utf-8") as handle:
        return {
            (row["target"], row["harness"], row["timing_leak_target"])
            for row in csv.DictReader(handle)
            if row.get("timing_raw_status")
        }


def _resolve_from_config(config_path: Path, value: Path) -> Path:
    return value if value.is_absolute() else (config_path.parent / value).resolve()


def static_check(campaign: CampaignSpec) -> list[str]:
    errors: list[str] = []
    protocol = campaign.protocol
    for flag in (
        "require_single_cpu_affinity",
        "reject_emulation",
        "reject_virtualization",
    ):
        if not isinstance(campaign.host.get(flag), bool):
            errors.append(f"host.{flag} must be a boolean")
        elif campaign.host[flag] is not True:
            errors.append(f"host.{flag} must be true for the corpus campaign")
    if campaign.host.get("system") != "Linux":
        errors.append("host.system must be Linux")
    machines = campaign.host.get("machines")
    if not isinstance(machines, list) or {str(machine).lower() for machine in machines} != {
        "x86_64",
        "amd64",
    }:
        errors.append("host.machines must contain x86_64 and AMD64")
    if campaign.host.get("recommended_governor") != "performance":
        errors.append("host.recommended_governor must be performance")
    if protocol.backend != "official-dudect":
        errors.append("protocol.backend must be official-dudect")
    if protocol.compiler != "gcc":
        errors.append("protocol.compiler must be gcc")
    if protocol.clock != "rdtsc":
        errors.append("native corpus campaign must use clock=rdtsc for AUX migration checks")
    if not 0 < protocol.seed <= 0xFFFFFFFFFFFFFFFF:
        errors.append("protocol.seed must fit nonzero uint64")
    if protocol.warmup < 1_000:
        errors.append("protocol.warmup must be at least 1000")
    if protocol.batches < 10:
        errors.append("protocol.batches must be at least 10")
    if protocol.process_repeats < 3:
        errors.append("protocol.process_repeats must be at least 3")
    if protocol.pool_size < 2:
        errors.append("protocol.pool_size must be at least 2")
    if protocol.aa_max_failures < 0 or protocol.aa_max_failures >= protocol.process_repeats:
        errors.append("protocol.aa_max_failures must be in [0, process_repeats)")
    if not 0.5 < protocol.target_power < 1:
        errors.append("protocol.target_power must be between 0.5 and 1")
    if not 0 < protocol.power_alpha < 0.5:
        errors.append("protocol.power_alpha must be between 0 and 0.5")
    if protocol.positive_abs_t_threshold <= protocol.aa_abs_t_limit:
        errors.append("positive_abs_t_threshold must exceed aa_abs_t_limit")
    if not campaign.targets:
        errors.append("campaign must contain at least one target")

    ids: set[str] = set()
    manifest_axes: set[tuple[str, str, str]] = set()
    for target in campaign.targets:
        if target.id in ids:
            errors.append(f"duplicate target id: {target.id}")
        ids.add(target.id)
        if len(set(target.harnesses)) != len(target.harnesses):
            errors.append(f"{target.id}: duplicate harness name")
        effects = target.positive_control_effects
        if len(effects) != 3 or tuple(sorted(set(effects))) != effects:
            errors.append(
                f"{target.id}: positive_control_effects must be three unique increasing values"
            )
        minimum_total = 2 * OFFICIAL_DUDECT_MIN_CLASS0 + 1_000
        if target.target_measurements < minimum_total:
            errors.append(
                f"{target.id}: target_measurements={target.target_measurements} lacks "
                f"margin above official class-0 minimum; require >= {minimum_total}"
            )
        if target.control_measurements < 1_000:
            errors.append(f"{target.id}: control_measurements must be >= 1000")
        if target.control_measurements > target.target_measurements:
            errors.append(f"{target.id}: control_measurements cannot exceed target_measurements")
        if not target.config.is_file():
            errors.append(f"{target.id}: config missing: {target.config.relative_to(ROOT)}")
            continue
        try:
            cfg = load_config(target.config)
        except Exception as exc:
            errors.append(f"{target.id}: config does not load: {exc}")
            continue
        if cfg.project.name != target.id:
            errors.append(
                f"{target.id}: config project.name={cfg.project.name!r} does not match id"
            )
        dudect = cfg.dudect
        if dudect is None or not dudect.enabled:
            errors.append(f"{target.id}: dudect must be enabled")
            continue
        if dudect.backend != "official-dudect":
            errors.append(f"{target.id}: config backend must be official-dudect")
        if dudect.compiler.cc != protocol.compiler:
            errors.append(
                f"{target.id}: compiler drift: manifest={protocol.compiler!r}, "
                f"config={dudect.compiler.cc!r}"
            )
        required_cflags = {"-fno-lto", "-fno-omit-frame-pointer"}
        actual_cflags = set(dudect.compiler.cflags)
        if not required_cflags <= actual_cflags:
            errors.append(
                f"{target.id}: timing compiler cflags must include {sorted(required_cflags)}"
            )
        if any(
            flag == "-fomit-frame-pointer" or (flag.startswith("-flto") and flag != "-fno-lto")
            for flag in dudect.compiler.cflags
        ):
            errors.append(f"{target.id}: timing compiler cflags re-enable LTO/frame omission")
        optimization_flags = [
            flag for flag in dudect.compiler.cflags if re.fullmatch(r"-O\S*", flag)
        ]
        if len(optimization_flags) != 1:
            errors.append(f"{target.id}: timing compiler must have one optimization flag")
        configured = tuple(harness.name for harness in dudect.harnesses)
        if configured != target.harnesses:
            errors.append(
                f"{target.id}: harness order/set drift: manifest={target.harnesses}, "
                f"config={configured}"
            )
        for harness in dudect.harnesses:
            configured_axis = (
                harness.leak_target
                if harness.template == "kem"
                else harness.sign_leak_target
                if harness.template == "sign"
                else ""
            )
            frozen_axis = target.axis_for(harness.name)
            manifest_axes.add((target.id, harness.name, frozen_axis))
            if harness.template not in {"kem", "sign"}:
                errors.append(f"{target.id}/{harness.name}: campaign supports only KEM/sign v2")
            if configured_axis != frozen_axis:
                errors.append(
                    f"{target.id}/{harness.name}: timing axis drift: "
                    f"manifest={frozen_axis!r}, config={configured_axis!r}"
                )
            if (
                campaign.campaign_id == "kyberslash-native-v3"
                and frozen_axis == "operand_bin"
                and harness.operand_setup_contract != OPERAND_V3_SETUP_CONTRACT
            ):
                errors.append(
                    f"{target.id}/{harness.name}: KyberSlash v3 operand axis must use "
                    f"{OPERAND_V3_SETUP_CONTRACT}"
                )
            if harness.binary_contract is None:
                if optimization_flags != ["-O2"]:
                    errors.append(
                        f"{target.id}/{harness.name}: timing compiler must use exactly -O2 "
                        "unless an exact linked-binary contract freezes another cell"
                    )
            else:
                contract_path = _resolve_from_config(
                    target.config,
                    harness.binary_contract.manifest,
                )
                try:
                    _contract_root, contract_rule = load_timing_binary_contract(
                        contract_path,
                        harness.binary_contract.target,
                    )
                except (OSError, TimingBinaryContractError) as exc:
                    errors.append(f"{target.id}/{harness.name}: binary contract cannot load: {exc}")
                else:
                    if contract_rule.get("compiler") != dudect.compiler.cc:
                        errors.append(f"{target.id}/{harness.name}: binary contract compiler drift")
                    if contract_rule.get("cflags") != dudect.compiler.cflags:
                        errors.append(f"{target.id}/{harness.name}: binary contract cflags drift")
                    if harness.operand_setup_contract == OPERAND_V3_SETUP_CONTRACT:
                        wrapper_rule = contract_rule.get("symbols", {}).get(
                            f"{harness.prefix}crypto_kem_dec", {}
                        )
                        if wrapper_rule.get("required_call_targets") != [
                            "ctkat_kyberslash_site_operation"
                        ]:
                            errors.append(
                                f"{target.id}/{harness.name}: operand-v3 binary contract "
                                "must bind the decapsulation wrapper to the arithmetic site"
                            )
            if any(Path(source).name == "randombytes.c" for source in harness.sources):
                errors.append(
                    f"{target.id}/{harness.name}: strong randombytes.c would shadow "
                    "the seeded interpose"
                )
            for source in harness.sources:
                resolved = _resolve_from_config(target.config, source)
                if not resolved.is_file():
                    errors.append(
                        f"{target.id}/{harness.name}: source missing: {resolved.relative_to(ROOT)}"
                    )
            include_dirs = [
                _resolve_from_config(target.config, include_dir)
                for include_dir in harness.include_dirs
            ]
            for include_dir in include_dirs:
                if not include_dir.is_dir():
                    errors.append(
                        f"{target.id}/{harness.name}: include dir missing: "
                        f"{include_dir.relative_to(ROOT)}"
                    )
            if (
                harness.header
                and include_dirs
                and not any(
                    (include_dir / harness.header).is_file() for include_dir in include_dirs
                )
            ):
                errors.append(
                    f"{target.id}/{harness.name}: header {harness.header!r} not found "
                    "under configured include dirs"
                )

    if campaign.coverage_mode == "committed-timing-rows":
        corpus_axes = _corpus_timing_axes()
        expected_axes = set(corpus_axes)
        for replacement in campaign.corpus_axis_replacements:
            old = (replacement.target, replacement.harness, replacement.from_axis)
            new = (replacement.target, replacement.harness, replacement.to_axis)
            if old not in corpus_axes:
                errors.append(f"corpus axis replacement source is not committed: {old!r}")
                continue
            expected_axes.remove(old)
            expected_axes.add(new)
        if manifest_axes != expected_axes:
            missing = sorted(expected_axes - manifest_axes)
            extra = sorted(manifest_axes - expected_axes)
            errors.append(
                f"campaign/corpus timing-axis drift: missing={missing or 'none'}, "
                f"extra={extra or 'none'}"
            )
    return errors


def _command_version(command: str) -> str:
    executable = shutil.which(command)
    if executable is None:
        return ""
    try:
        result = subprocess.run(
            [executable, "--version"],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.splitlines()[0].strip() if result.stdout else ""


def _detect_container_marker() -> str:
    if Path("/.dockerenv").is_file():
        return "docker"
    if Path("/run/.containerenv").is_file():
        return "podman"
    cgroup = _read_text(Path("/proc/1/cgroup")).lower()
    for marker, label in (
        ("docker", "docker"),
        ("kubepods", "kubernetes"),
        ("containerd", "containerd"),
        ("libpod", "podman"),
        ("lxc", "lxc"),
    ):
        if marker in cgroup:
            return label
    return ""


def _detect_virtualization() -> dict[str, str]:
    result = {"vm": "", "container": _detect_container_marker()}
    detector = shutil.which("systemd-detect-virt")
    if detector:
        for kind, option in (("vm", "--vm"), ("container", "--container")):
            try:
                proc = subprocess.run(
                    [detector, option],
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=10,
                )
            except (OSError, subprocess.SubprocessError):
                continue
            value = proc.stdout.strip()
            if proc.returncode == 0 and value and value != "none":
                result[kind] = value
    if result["vm"]:
        return result
    dmi = " ".join(
        _read_text(path)
        for path in (
            Path("/sys/class/dmi/id/sys_vendor"),
            Path("/sys/class/dmi/id/product_name"),
            Path("/sys/class/dmi/id/board_vendor"),
        )
    ).lower()
    markers = {
        "amazon": "amazon-ec2",
        "google compute": "gce",
        "microsoft corporation": "microsoft-hyperv",
        "vmware": "vmware",
        "virtualbox": "virtualbox",
        "openstack": "openstack",
        "kvm": "kvm",
        "qemu": "qemu",
    }
    for needle, label in markers.items():
        if needle in dmi:
            result["vm"] = label
            break
    if not result["vm"]:
        cpuinfo = _read_text(Path("/proc/cpuinfo")).lower()
        if any(
            " hypervisor " in f" {line.strip()} "
            for line in cpuinfo.splitlines()
            if line.lstrip().startswith(("flags", "features"))
        ):
            result["vm"] = "cpuid-hypervisor"
    if not result["vm"]:
        hypervisor_type = _read_text(Path("/sys/hypervisor/type")).lower()
        if hypervisor_type:
            result["vm"] = hypervisor_type
    return result


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _git_state() -> tuple[str, bool]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain", "--untracked-files=normal"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=True,
                timeout=10,
            ).stdout.strip()
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CampaignError(f"cannot resolve git provenance: {exc}") from exc
    return commit, dirty


def _compiler_executable_identity(command: str) -> dict[str, str] | None:
    executable = shutil.which(command)
    if executable is None:
        return None
    resolved = Path(executable).resolve()
    try:
        digest = _sha256(resolved)
    except OSError:
        return None
    return {"resolved_path": str(resolved), "sha256": digest}


def pin_current_process(cpu: int) -> None:
    if platform.system() != "Linux" or not hasattr(os, "sched_setaffinity"):
        raise CampaignError("--cpu requires Linux sched_setaffinity")
    available = set(os.sched_getaffinity(0))
    if cpu not in available:
        raise CampaignError(f"--cpu {cpu} is not in current affinity {sorted(available)}")
    try:
        os.sched_setaffinity(0, {cpu})
    except OSError as exc:
        raise CampaignError(f"could not pin campaign to CPU {cpu}: {exc}") from exc


def preflight(
    campaign: CampaignSpec,
    *,
    allow_dirty: bool,
    allow_virtualized: bool,
    build_adapter: bool,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    emulated = detect_qemu_emulation()
    environment = collect_timing_environment(emulated=emulated, clock=campaign.protocol.clock)
    system = platform.system()
    machine = platform.machine()
    accepted_machines = {str(value).lower() for value in campaign.host.get("machines", [])}
    if system != campaign.host.get("system"):
        errors.append(f"requires {campaign.host.get('system')}, got {system}")
    if machine.lower() not in accepted_machines:
        errors.append(f"requires x86_64 machine, got {machine or 'unknown'}")
    if emulated and campaign.host.get("reject_emulation", True):
        errors.append("cross-architecture emulation detected")
    affinity = environment.get("cpu_affinity") or []
    if campaign.host.get("require_single_cpu_affinity", True) and len(affinity) != 1:
        errors.append(f"requires exactly one eligible CPU, got {affinity or 'unavailable'}")
    cpu_model = environment.get("cpu_model")
    if not isinstance(cpu_model, str) or not cpu_model.strip():
        errors.append("exact CPU model metadata is unavailable")
    machine_id_sha256 = environment.get("machine_id_sha256")
    if not isinstance(machine_id_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", machine_id_sha256
    ):
        errors.append("hashed physical host identity is unavailable")
    boot_id_sha256 = environment.get("boot_id_sha256")
    if not isinstance(boot_id_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", boot_id_sha256):
        errors.append("hashed boot identity is unavailable")
    timing_cpu_flags = environment.get("timing_cpu_flags")
    required_timing_flags = ("constant_tsc", "nonstop_tsc", "rdtscp")
    if not isinstance(timing_cpu_flags, dict) or any(
        timing_cpu_flags.get(flag) is not True for flag in required_timing_flags
    ):
        errors.append(
            "invariant-TSC/RDTSCP capability is unavailable "
            f"(requires {', '.join(required_timing_flags)})"
        )

    virtualization = _detect_virtualization()
    virtualized = bool(virtualization["vm"] or virtualization["container"])
    if virtualized and campaign.host.get("reject_virtualization", True):
        message = (
            f"virtualized host detected: vm={virtualization['vm'] or 'none'}, "
            f"container={virtualization['container'] or 'none'}"
        )
        if allow_virtualized:
            warnings.append(message + " (engineering-only override)")
        else:
            errors.append(message)

    commit, dirty = _git_state()
    if dirty:
        message = "git worktree has tracked or untracked changes"
        if allow_dirty:
            warnings.append(message + " (engineering-only override)")
        else:
            errors.append(message)

    compiler = _command_version("gcc")
    compiler_executable = _compiler_executable_identity("gcc")
    if not compiler or compiler_executable is None:
        errors.append("gcc is unavailable")
    selected_cpu = affinity[0] if len(affinity) == 1 else None
    governor = ""
    if selected_cpu is not None:
        governor = _read_text(
            Path(f"/sys/devices/system/cpu/cpu{selected_cpu}/cpufreq/scaling_governor")
        )
    recommended = str(campaign.host.get("recommended_governor", ""))
    if governor and recommended and governor != recommended:
        warnings.append(f"CPU {selected_cpu} governor is {governor!r}, recommended {recommended!r}")
    if not governor:
        warnings.append("CPU governor metadata unavailable")

    adapter_ok = False
    if build_adapter and not any(
        reason.startswith(("requires ", "cross-architecture", "gcc is")) for reason in errors
    ):
        try:
            with tempfile.TemporaryDirectory(prefix="ctkat-native-preflight-") as temp_dir:
                build_official_dudect_adapter(
                    cc="gcc",
                    output_dir=Path(temp_dir),
                    timeout=120,
                )
            adapter_ok = True
        except Exception as exc:
            errors.append(f"official dudect adapter preflight failed: {exc}")

    governor_eligible = not recommended or governor == recommended
    paper_eligible = (
        not errors and not emulated and not virtualized and not dirty and governor_eligible
    )
    return {
        "checked_at": _utc_now(),
        "ok": not errors,
        "paper_eligible": paper_eligible,
        "errors": errors,
        "warnings": warnings,
        "git_commit": commit,
        "git_dirty": dirty,
        "compiler": compiler or None,
        "compiler_executable": compiler_executable,
        "official_adapter_built": adapter_ok,
        "virtualization": virtualization,
        "environment": environment,
        "governor_selected_cpu": governor or None,
    }


def validate_preflight_report(
    campaign: CampaignSpec,
    report: Any,
    *,
    expected_commit: str,
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not isinstance(report, dict):
        return False, ["host_preflight must be an object"]
    if report.get("ok") is not True or report.get("errors") != []:
        errors.append("host preflight was not a successful executable-host check")
    if report.get("git_commit") != expected_commit:
        errors.append("host preflight git commit differs from campaign report")
    dirty = report.get("git_dirty")
    if not isinstance(dirty, bool):
        errors.append("host preflight git_dirty must be boolean")
        dirty = True
    if not isinstance(report.get("compiler"), str) or not report.get("compiler"):
        errors.append("host preflight compiler identity is missing")
    compiler_executable = report.get("compiler_executable")
    if (
        not isinstance(compiler_executable, dict)
        or set(compiler_executable) != {"resolved_path", "sha256"}
        or not isinstance(compiler_executable.get("resolved_path"), str)
        or not Path(compiler_executable.get("resolved_path", "")).is_absolute()
        or not isinstance(compiler_executable.get("sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", compiler_executable.get("sha256", ""))
    ):
        errors.append("host preflight compiler executable identity is missing")
    if report.get("official_adapter_built") is not True:
        errors.append("host preflight did not build the official adapter")

    virtualization = report.get("virtualization")
    if not isinstance(virtualization, dict) or any(
        not isinstance(virtualization.get(field), str) for field in ("vm", "container")
    ):
        errors.append("host preflight virtualization metadata is malformed")
        virtualized = True
    else:
        virtualized = bool(virtualization["vm"] or virtualization["container"])

    environment = report.get("environment")
    if not isinstance(environment, dict):
        errors.append("host preflight environment metadata is malformed")
    else:
        accepted_machines = {str(value).lower() for value in campaign.host.get("machines", [])}
        if environment.get("system") != campaign.host.get("system"):
            errors.append("host preflight environment is not Linux")
        if str(environment.get("machine", "")).lower() not in accepted_machines:
            errors.append("host preflight environment is not x86_64")
        if environment.get("clock") != campaign.protocol.clock:
            errors.append("host preflight clock differs from the campaign")
        if environment.get("emulated") is not False:
            errors.append("host preflight reports emulation")
        cpu_model = environment.get("cpu_model")
        if not isinstance(cpu_model, str) or not cpu_model.strip():
            errors.append("host preflight exact CPU model is missing")
        machine_id_sha256 = environment.get("machine_id_sha256")
        if not isinstance(machine_id_sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", machine_id_sha256
        ):
            errors.append("host preflight hashed physical identity is missing")
        boot_id_sha256 = environment.get("boot_id_sha256")
        if not isinstance(boot_id_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", boot_id_sha256):
            errors.append("host preflight hashed boot identity is missing")
        timing_cpu_flags = environment.get("timing_cpu_flags")
        required_timing_flags = ("constant_tsc", "nonstop_tsc", "rdtscp")
        if not isinstance(timing_cpu_flags, dict) or any(
            timing_cpu_flags.get(flag) is not True for flag in required_timing_flags
        ):
            errors.append("host preflight lacks invariant-TSC/RDTSCP capability")
        affinity = environment.get("cpu_affinity")
        if (
            not isinstance(affinity, list)
            or len(affinity) != 1
            or isinstance(affinity[0], bool)
            or not isinstance(affinity[0], int)
            or affinity[0] < 0
        ):
            errors.append("host preflight does not record one pinned logical CPU")
        if environment.get("rejected") is not False:
            errors.append("host timing environment was rejected")

    warnings = report.get("warnings")
    if not isinstance(warnings, list) or any(not isinstance(value, str) for value in warnings):
        errors.append("host preflight warnings must be a string list")
        warnings = []
    if dirty and not any("git worktree" in warning for warning in warnings):
        errors.append("dirty-host override is not recorded in warnings")
    if virtualized and not any("engineering-only override" in warning for warning in warnings):
        errors.append("virtualized-host override is not recorded in warnings")

    selected_governor = report.get("governor_selected_cpu")
    recommended_governor = str(campaign.host.get("recommended_governor", ""))
    governor_eligible = not recommended_governor or selected_governor == recommended_governor
    if not governor_eligible and not any("governor" in warning for warning in warnings):
        errors.append("non-performance governor is not recorded in warnings")

    recomputed_eligible = not errors and not dirty and not virtualized and governor_eligible
    if report.get("paper_eligible") is not recomputed_eligible:
        errors.append("host preflight paper_eligible does not match recorded host facts")
        recomputed_eligible = False
    return recomputed_eligible, errors


def campaign_dudect(
    cfg: CtkatConfig,
    campaign: CampaignSpec,
    target: TargetSpec,
    generated_dir: Path,
) -> DudectConfig:
    if cfg.dudect is None:
        raise CampaignError(f"{target.id}: dudect config missing")
    protocol = cfg.dudect.timing_protocol.model_copy(
        update={
            "process_repeats": campaign.protocol.process_repeats,
            "pool_size": campaign.protocol.pool_size,
            "control_measurements": target.control_measurements,
            "positive_control_effects": list(target.positive_control_effects),
            "aa_abs_t_limit": campaign.protocol.aa_abs_t_limit,
            "positive_abs_t_threshold": campaign.protocol.positive_abs_t_threshold,
            "aa_max_failures": campaign.protocol.aa_max_failures,
            "target_power": campaign.protocol.target_power,
            "power_alpha": campaign.protocol.power_alpha,
        }
    )
    compiler = cfg.dudect.compiler.model_copy(update={"cc": campaign.protocol.compiler})
    return cfg.dudect.model_copy(
        update={
            "backend": campaign.protocol.backend,
            "clock": campaign.protocol.clock,
            "seed": campaign.protocol.seed,
            "measurements": target.target_measurements,
            "warmup": campaign.protocol.warmup,
            "batches": campaign.protocol.batches,
            "timeout": target.timeout,
            "compile_timeout": campaign.protocol.compile_timeout,
            "backend_timeout": campaign.protocol.backend_timeout,
            "compiler": compiler,
            "generated_dir": generated_dir.resolve(),
            "timing_protocol": protocol,
        }
    )


def _expected_protocol_counts(
    campaign: CampaignSpec,
    target: TargetSpec,
) -> dict[tuple[str, str, int, int], int]:
    counts: dict[tuple[str, str, int, int], int] = {}
    for harness in target.harnesses:
        for process_index in range(campaign.protocol.process_repeats):
            counts[(harness, "target-calibration", process_index, 0)] = target.target_measurements
            counts[(harness, "target", process_index, 0)] = target.target_measurements
            counts[(harness, "aa", process_index, 0)] = target.control_measurements
            counts[(harness, "setup-placebo", process_index, 0)] = target.control_measurements
            for effect in target.positive_control_effects:
                counts[(harness, "positive", process_index, effect)] = target.control_measurements
    return counts


def _validate_protocol_csv(
    path: Path,
    campaign: CampaignSpec,
    target: TargetSpec,
    configured_harnesses: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    reported: set[str] = set()
    actual: dict[tuple[str, str, int, int], int] = {}
    seeds: dict[tuple[str, str, int, int], int] = {}
    signature_lengths: dict[str, set[int]] = {}

    def report_once(category: str, message: str) -> None:
        if category not in reported:
            errors.append(message)
            reported.add(category)

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != PROTOCOL_HEADER:
            return [
                f"{path.name}: header drift: expected={PROTOCOL_HEADER}, actual={reader.fieldnames}"
            ]
        for number, row in enumerate(reader, start=2):
            try:
                process_index = int(row["process_index"])
                effect = int(row["effect_ticks"])
                seed = int(row["seed"])
                sample_id = int(row["sample_id"])
                clazz = int(row["class"])
                cycles = float(row["cycles"])
                aux_start = int(row["aux_start"])
                aux_end = int(row["aux_end"])
                output_length = int(row["output_length"])
            except (TypeError, ValueError):
                report_once(
                    "numeric",
                    f"{path.name}:{number}: invalid numeric protocol field",
                )
                continue
            configured = configured_harnesses.get(row["harness"])
            signature_return_code = row["signature_return_code"]
            if configured is not None and configured.template == "sign":
                signature_lengths.setdefault(row["harness"], set()).add(output_length)
                if output_length < 1:
                    report_once(
                        "signature-output-length",
                        f"{path.name}:{number}: signature output length must be positive",
                    )
                try:
                    parsed_signature_return_code = int(signature_return_code)
                except (TypeError, ValueError):
                    report_once(
                        "signature-return-code",
                        f"{path.name}:{number}: signature row lacks an integer return code",
                    )
                else:
                    if parsed_signature_return_code != 0:
                        report_once(
                            "signature-failure",
                            f"{path.name}:{number}: signing returned "
                            f"{parsed_signature_return_code}, expected 0",
                        )
            elif signature_return_code != "":
                report_once(
                    "non-sign-return-code",
                    f"{path.name}:{number}: non-sign row has a signature return code",
                )
            if row["project"] != target.id:
                report_once(
                    "project",
                    f"{path.name}:{number}: project={row['project']!r}, expected={target.id!r}",
                )
            if row["protocol"] != "timing-harness-v2":
                report_once(
                    "protocol",
                    f"{path.name}:{number}: protocol is not timing-harness-v2",
                )
            key = (row["harness"], row["role"], process_index, effect)
            expected_sample_id = actual.get(key, 0)
            if sample_id != expected_sample_id:
                report_once(
                    "sample-id",
                    f"{path.name}:{number}: non-contiguous sample_id={sample_id} "
                    f"for {key}, expected={expected_sample_id}",
                )
            if clazz not in {0, 1}:
                report_once(
                    "class",
                    f"{path.name}:{number}: class must be 0 or 1",
                )
            if not 0 < seed <= 0xFFFFFFFFFFFFFFFF:
                report_once(
                    "seed-range",
                    f"{path.name}:{number}: seed must be a nonzero uint64",
                )
            previous_seed = seeds.setdefault(key, seed)
            if previous_seed != seed:
                report_once(
                    "seed-stability",
                    f"{path.name}:{number}: seed changed within trace {key}",
                )
            if (
                not math.isfinite(cycles)
                or cycles < 0
                or min(aux_start, aux_end, output_length) < 0
            ):
                report_once(
                    "numeric-range",
                    f"{path.name}:{number}: negative/non-finite trace value",
                )
            drop_reason = row["drop_reason"]
            if drop_reason not in {"", "clock-anomaly", "cpu-migration"}:
                report_once(
                    "drop-reason",
                    f"{path.name}:{number}: invalid drop_reason={drop_reason!r}",
                )
            if not drop_reason and (cycles == 0 or aux_start != aux_end):
                report_once(
                    "unmarked-drop",
                    f"{path.name}:{number}: retained row contains a clock/AUX anomaly",
                )
            if drop_reason == "cpu-migration" and aux_start == aux_end:
                report_once(
                    "migration",
                    f"{path.name}:{number}: cpu-migration row has unchanged AUX",
                )
            actual[key] = actual.get(key, 0) + 1
    for harness_name, lengths in signature_lengths.items():
        configured = configured_harnesses[harness_name]
        if configured.signature_length_contract == "fixed" and len(lengths) != 1:
            errors.append(
                f"{path.name}: {harness_name} fixed signature contract has lengths "
                f"{sorted(lengths)}"
            )
    expected = _expected_protocol_counts(campaign, target)
    for harness in target.harnesses:
        harness_seeds = [seed for key, seed in seeds.items() if key[0] == harness]
        if len(set(harness_seeds)) != len(harness_seeds):
            errors.append(
                f"{path.name}: {harness} trace seeds are not domain-separated "
                "across roles/repeats/effects"
            )
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        wrong = sorted(
            (key, expected[key], actual[key])
            for key in set(expected).intersection(actual)
            if expected[key] != actual[key]
        )
        errors.append(
            f"{path.name}: trace count drift: missing={missing or 'none'}, "
            f"extra={extra or 'none'}, wrong={wrong or 'none'}"
        )
    return errors


def _load_summary(path: Path) -> tuple[dict[str, dict[str, str]], list[str]]:
    errors: list[str] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or [])
        missing = SUMMARY_REQUIRED_COLUMNS - fields
        if missing:
            errors.append(f"{path.name}: missing columns {sorted(missing)}")
        rows = list(reader)
    by_harness: dict[str, dict[str, str]] = {}
    for row in rows:
        harness = row.get("harness", "")
        if not harness or harness in by_harness:
            errors.append(f"{path.name}: empty/duplicate harness {harness!r}")
            continue
        by_harness[harness] = row
    return by_harness, errors


def _nested_artifact(root: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise CampaignError(f"{label} must be a non-empty relative path")
    raw = Path(relative)
    if raw.is_absolute() or ".." in raw.parts:
        raise CampaignError(f"{label} is not a safe relative path: {relative!r}")
    resolved_root = root.resolve()
    candidate = resolved_root / raw
    if candidate.is_symlink() or any(
        parent.is_symlink()
        for parent in candidate.parents
        if parent != resolved_root and parent.is_relative_to(resolved_root)
    ):
        raise CampaignError(f"{label} contains a symlink: {relative!r}")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(resolved_root) or not resolved.is_file():
        raise CampaignError(f"{label} is missing or escapes its artifact root: {relative!r}")
    return resolved


def _recorded_sha256(value: Any, label: str, errors: list[str]) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        errors.append(f"{label} is not a SHA-256 digest")
        return ""
    return value


def _run_offline_tool(
    command: list[str],
    *,
    label: str,
    errors: list[str],
) -> subprocess.CompletedProcess[str] | None:
    """Run an operator-selected local tool without trusting report-supplied argv."""

    try:
        return subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        errors.append(f"{label} could not execute: {exc}")
        return None


def _current_tool_matching_record(
    *,
    requested_command: Any,
    record: Any,
    recorded_version: Any,
    label: str,
    errors: list[str],
) -> Path | None:
    """Resolve a trusted current tool and require exact recorded provenance.

    The executable path embedded in an artifact is untrusted input and is never
    executed directly.  PATH resolution starts from the committed contract;
    the resulting regular file must then match the recorded absolute path,
    SHA-256, byte size, and first ``--version`` line.
    """

    start_error_count = len(errors)
    if not isinstance(requested_command, str) or not requested_command:
        errors.append(f"{label} requested command is missing")
        return None
    if not isinstance(record, dict):
        errors.append(f"{label} executable provenance is missing")
        return None
    resolved_value = shutil.which(requested_command)
    if not resolved_value:
        errors.append(f"{label} is unavailable: {requested_command}")
        return None
    current = Path(resolved_value).resolve()
    if current.is_symlink() or not current.is_file():
        errors.append(f"{label} current executable is not a regular file: {current}")
        return None

    recorded_path = record.get("path")
    if not isinstance(recorded_path, str) or not Path(recorded_path).is_absolute():
        errors.append(f"{label} recorded path is not absolute")
    elif recorded_path != str(current):
        errors.append(
            f"{label} current path differs from recorded provenance: "
            f"current={current}, recorded={recorded_path}"
        )
    recorded_hash = _recorded_sha256(record.get("sha256"), f"{label} executable", errors)
    if recorded_hash and _sha256(current) != recorded_hash:
        errors.append(f"{label} current executable hash differs from recorded provenance")
    recorded_bytes = record.get("bytes")
    if (
        isinstance(recorded_bytes, bool)
        or not isinstance(recorded_bytes, int)
        or recorded_bytes < 1
    ):
        errors.append(f"{label} recorded executable byte size is invalid")
    elif current.stat().st_size != recorded_bytes:
        errors.append(f"{label} current executable size differs from recorded provenance")

    if not isinstance(recorded_version, str) or not recorded_version.strip():
        errors.append(f"{label} recorded version is missing")
    version_command = [str(current), "--version"]
    recorded_version_command = record.get("version_command")
    if recorded_version_command != version_command:
        errors.append(f"{label} recorded version command drift")
    version_proc = _run_offline_tool(version_command, label=f"{label} --version", errors=errors)
    if version_proc is None:
        return None
    if version_proc.returncode != 0 or not version_proc.stdout.strip():
        errors.append(f"{label} --version failed: {version_proc.stderr.strip()}")
    else:
        current_version = version_proc.stdout.splitlines()[0]
        if current_version != recorded_version:
            errors.append(
                f"{label} current version differs from recorded provenance: "
                f"current={current_version!r}, recorded={recorded_version!r}"
            )
    if len(errors) != start_error_count:
        return None
    return current


def _canonical_objdump_output(text: str) -> str:
    """Normalize only the artifact-local filename in GNU objdump headings."""

    lines = text.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    for index, line in enumerate(lines):
        marker = re.search(r":\s+file format\s+", line)
        if marker is not None:
            lines[index] = "<preserved-binary>" + line[marker.start() :]
            break
    return "\n".join(lines).rstrip()


def _fresh_objdump(
    *,
    contract_root: dict[str, Any],
    binary_path: Path,
    binary_record: Any,
    disassembly: dict[str, Any],
    label: str,
    errors: list[str],
) -> tuple[str, str] | None:
    """Re-run the recorded objdump identity over the preserved binary."""

    tool_record = disassembly.get("tool")
    recorded_version = tool_record.get("version") if isinstance(tool_record, dict) else None
    objdump = _current_tool_matching_record(
        requested_command=contract_root.get("disassembler"),
        record=tool_record,
        recorded_version=recorded_version,
        label=f"{label} objdump",
        errors=errors,
    )
    if objdump is None:
        return None

    recorded_binary_path = binary_record.get("path") if isinstance(binary_record, dict) else None
    recorded_tool_path = tool_record.get("path") if isinstance(tool_record, dict) else None
    for command_field, flag in (("file_header_command", "-f"), ("command", "-d")):
        expected = [recorded_tool_path, flag, recorded_binary_path]
        if disassembly.get(command_field) != expected:
            errors.append(f"{label} recorded {command_field} drift")

    header_command = [str(objdump), "-f", str(binary_path)]
    disassembly_command = [str(objdump), "-d", str(binary_path)]
    header_proc = _run_offline_tool(
        header_command,
        label=f"{label} fresh objdump -f",
        errors=errors,
    )
    full_proc = _run_offline_tool(
        disassembly_command,
        label=f"{label} fresh objdump -d",
        errors=errors,
    )
    if header_proc is None or full_proc is None:
        return None
    if header_proc.returncode != 0 or not header_proc.stdout.strip():
        errors.append(f"{label} fresh objdump -f failed: {header_proc.stderr.strip()}")
    if full_proc.returncode != 0 or not full_proc.stdout.strip():
        errors.append(f"{label} fresh objdump -d failed: {full_proc.stderr.strip()}")
    if header_proc.returncode != 0 or not header_proc.stdout.strip():
        return None
    if full_proc.returncode != 0 or not full_proc.stdout.strip():
        return None
    return header_proc.stdout, full_proc.stdout


def _recorded_path_matches_repo_input(recorded: Any, expected: Path) -> bool:
    """Match relocatable artifact paths by their exact repository suffix."""

    if not isinstance(recorded, str) or not Path(recorded).is_absolute():
        return False
    try:
        suffix = expected.resolve().relative_to(ROOT.resolve())
    except ValueError:
        suffix = Path(expected.name)
    recorded_parts = Path(recorded).parts
    suffix_parts = suffix.parts
    return (
        len(recorded_parts) >= len(suffix_parts)
        and tuple(recorded_parts[-len(suffix_parts) :]) == suffix_parts
    )


def _validate_build_provenance_artifacts(
    *,
    campaign: CampaignSpec,
    target: TargetSpec,
    harness: Any,
    protocol: dict[str, Any],
    report_dir: Path,
    artifact_sha256: dict[str, str],
    host_preflight: dict[str, Any],
) -> list[str]:
    """Bind every timing row to its pre-measurement source and binary seal."""

    errors: list[str] = []
    label = f"{target.id}/{harness.name}: build provenance"
    metadata = protocol.get("build_provenance")
    expected_metadata = {
        "passed",
        "captured_before_measurement",
        "report",
        "report_sha256",
        "generated_source_sha256",
        "binary_sha256",
        "config_sha256",
    }
    if not isinstance(metadata, dict):
        return [f"{label} metadata is missing"]
    if set(metadata) != expected_metadata:
        errors.append(f"{label} metadata field set drift")
    if metadata.get("passed") is not True:
        errors.append(f"{label} did not pass before measurement")
    if metadata.get("captured_before_measurement") is not True:
        errors.append(f"{label} was not captured before measurement")
    expected_report = f"build_provenance/timing_{harness.name}.build-seal.json"
    if metadata.get("report") != expected_report:
        errors.append(
            f"{label} report path={metadata.get('report')!r}, expected={expected_report!r}"
        )
    try:
        report_path = _nested_artifact(report_dir, metadata.get("report"), label)
    except CampaignError as exc:
        errors.append(str(exc))
        return errors
    report_relative = str(report_path.relative_to(report_dir.resolve()))
    report_hash = _sha256(report_path)
    artifact_sha256[report_relative] = report_hash
    recorded_report_hash = _recorded_sha256(
        metadata.get("report_sha256"), f"{label} report_sha256", errors
    )
    if recorded_report_hash and recorded_report_hash != report_hash:
        errors.append(f"{label} report hash mismatch")
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{label} report is unreadable: {exc}")
        return errors
    expected_payload_fields = {
        "schema_version",
        "kind",
        "captured_before_measurement",
        "config",
        "generated_source",
        "binary",
        "linked_sources",
        "include_dirs",
        "compiler",
        "reproduction_argv",
    }
    if not isinstance(payload, dict):
        return [*errors, f"{label} report root must be an object"]
    if set(payload) != expected_payload_fields:
        errors.append(f"{label} report field set drift")
    if payload.get("schema_version") != "1.0":
        errors.append(f"{label} schema version drift")
    if payload.get("kind") != "ctkat-timing-build-provenance":
        errors.append(f"{label} kind drift")
    if payload.get("captured_before_measurement") is not True:
        errors.append(f"{label} report was not captured before measurement")

    def validate_file_record(
        record: Any,
        *,
        field_label: str,
        expected_path: Path,
        path_policy: str,
    ) -> str:
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes"}:
            errors.append(f"{label} {field_label} record is malformed")
            return ""
        recorded_path = record.get("path")
        if path_policy == "repo":
            path_ok = _recorded_path_matches_repo_input(recorded_path, expected_path)
        else:
            path_ok = (
                isinstance(recorded_path, str)
                and Path(recorded_path).is_absolute()
                and Path(recorded_path).name == expected_path.name
            )
        if not path_ok:
            errors.append(f"{label} {field_label} path/name drift")
        digest = _recorded_sha256(record.get("sha256"), f"{label} {field_label}", errors)
        expected_hash = _sha256(expected_path)
        if digest and digest != expected_hash:
            errors.append(f"{label} {field_label} hash mismatch")
        byte_count = record.get("bytes")
        if (
            isinstance(byte_count, bool)
            or not isinstance(byte_count, int)
            or byte_count != expected_path.stat().st_size
        ):
            errors.append(f"{label} {field_label} byte size mismatch")
        return expected_hash

    config_record = payload.get("config")
    config_hash = validate_file_record(
        config_record,
        field_label="config",
        expected_path=target.config,
        path_policy="repo",
    )
    if metadata.get("config_sha256") != config_hash:
        errors.append(f"{label} backend config hash mismatch")

    generated_root = report_dir.parent / "generated"
    generated_records = (
        ("generated_source", f"timing_{harness.name}.c", "generated_source_sha256"),
        ("binary", f"timing_{harness.name}", "binary_sha256"),
    )
    for field_name, expected_name, metadata_field in generated_records:
        try:
            generated_path = _nested_artifact(
                generated_root,
                expected_name,
                f"{label} {field_name}",
            )
        except CampaignError as exc:
            errors.append(str(exc))
            continue
        generated_hash = validate_file_record(
            payload.get(field_name),
            field_label=field_name,
            expected_path=generated_path,
            path_policy="basename",
        )
        artifact_key = f"generated/{expected_name}"
        previous_hash = artifact_sha256.get(artifact_key)
        if previous_hash is not None and previous_hash != generated_hash:
            errors.append(f"{label} {artifact_key} conflicts with another provenance report")
        artifact_sha256[artifact_key] = generated_hash
        if metadata.get(metadata_field) != generated_hash:
            errors.append(f"{label} backend {field_name} hash mismatch")

    linked_records = payload.get("linked_sources")
    if not isinstance(linked_records, list) or len(linked_records) != len(harness.sources):
        errors.append(f"{label} linked source index drift")
        linked_records = []
    else:
        recorded_paths: list[Any] = []
        for index, (record, source) in enumerate(zip(linked_records, harness.sources, strict=True)):
            expected_source = _resolve_from_config(target.config, source)
            validate_file_record(
                record,
                field_label=f"linked_sources[{index}]",
                expected_path=expected_source,
                path_policy="repo",
            )
            recorded_paths.append(record.get("path") if isinstance(record, dict) else None)
        if len(recorded_paths) != len(set(recorded_paths)):
            errors.append(f"{label} linked source list contains duplicates")

    include_dirs = payload.get("include_dirs")
    if not isinstance(include_dirs, list) or len(include_dirs) != len(harness.include_dirs):
        errors.append(f"{label} include directory index drift")
        include_dirs = []
    else:
        for index, (recorded, directory) in enumerate(
            zip(include_dirs, harness.include_dirs, strict=True)
        ):
            expected_directory = _resolve_from_config(target.config, directory)
            if not _recorded_path_matches_repo_input(recorded, expected_directory):
                errors.append(f"{label} include_dirs[{index}] path drift")
        if len(include_dirs) != len(set(include_dirs)):
            errors.append(f"{label} include directory list contains duplicates")

    compiler = payload.get("compiler")
    expected_compiler_fields = {
        "requested_command",
        "executable",
        "version",
        "version_command",
        "cflags",
        "compile_command",
    }
    if not isinstance(compiler, dict) or set(compiler) != expected_compiler_fields:
        errors.append(f"{label} compiler provenance is malformed")
        compiler = {}
    if compiler.get("requested_command") != campaign.protocol.compiler:
        errors.append(f"{label} compiler command drift")
    configured_flags = load_config(target.config).dudect
    expected_flags = list(configured_flags.compiler.cflags) if configured_flags is not None else []
    if compiler.get("cflags") != expected_flags:
        errors.append(f"{label} compiler flags drift")
    if (
        not isinstance(compiler.get("compile_command"), str)
        or not compiler.get("compile_command", "").strip()
    ):
        errors.append(f"{label} compile command is missing")
    executable = compiler.get("executable")
    if not isinstance(executable, dict) or set(executable) != {"path", "sha256", "bytes"}:
        errors.append(f"{label} compiler executable record is malformed")
        executable = {}
    executable_path = executable.get("path")
    _recorded_sha256(executable.get("sha256"), f"{label} compiler executable", errors)
    executable_bytes = executable.get("bytes")
    if (
        isinstance(executable_bytes, bool)
        or not isinstance(executable_bytes, int)
        or executable_bytes < 1
    ):
        errors.append(f"{label} compiler executable byte size is invalid")
    expected_executable = host_preflight.get("compiler_executable")
    if not isinstance(expected_executable, dict):
        errors.append(f"{label} host preflight compiler executable is missing")
    else:
        if executable_path != expected_executable.get("resolved_path"):
            errors.append(f"{label} compiler path differs from host preflight")
        if executable.get("sha256") != expected_executable.get("sha256"):
            errors.append(f"{label} compiler hash differs from host preflight")
    if compiler.get("version") != host_preflight.get("compiler"):
        errors.append(f"{label} compiler version differs from host preflight")
    if compiler.get("version_command") != [executable_path, "--version"]:
        errors.append(f"{label} compiler version command drift")

    reproduction_argv = payload.get("reproduction_argv")
    linked_paths = [
        record.get("path") if isinstance(record, dict) else None for record in linked_records
    ]
    expected_reproduction = [
        executable_path,
        *expected_flags,
        *(f"-I{directory}" for directory in include_dirs),
        (
            payload.get("generated_source", {}).get("path")
            if isinstance(payload.get("generated_source"), dict)
            else None
        ),
        *linked_paths,
        "-o",
        (
            payload.get("binary", {}).get("path")
            if isinstance(payload.get("binary"), dict)
            else None
        ),
    ]
    if reproduction_argv != expected_reproduction or any(
        not isinstance(value, str) for value in reproduction_argv or []
    ):
        errors.append(f"{label} reproduction argv drift")
    return errors


def _validate_binary_contract_artifacts(
    *,
    target: TargetSpec,
    harness: Any,
    protocol: dict[str, Any],
    report_dir: Path,
    artifact_sha256: dict[str, str],
) -> list[str]:
    """Reparse and bind every post-link contract artifact.

    The backend JSON is not trusted as a self-attestation.  This validator
    resolves the nested files without symlinks, hashes the measured binary and
    generated source, reloads the committed contract, then runs the exact
    recorded compiler/objdump identities locally and compares fresh ``-f`` and
    ``-d`` output with both the preserved text and semantic observations.
    """

    errors: list[str] = []
    reference = harness.binary_contract
    metadata = protocol.get("binary_contract")
    label = f"{target.id}/{harness.name}: binary contract"
    if reference is None:
        if metadata is not None:
            errors.append(f"{label} metadata is present without a configured contract")
        return errors
    if not isinstance(metadata, dict):
        return [f"{label} metadata is missing"]
    expected_metadata = {
        "passed",
        "contract_id",
        "contract_target",
        "report",
        "report_sha256",
        "binary_sha256",
        "full_disassembly_sha256",
    }
    if set(metadata) != expected_metadata:
        errors.append(f"{label} metadata field set drift")
    if metadata.get("passed") is not True:
        errors.append(f"{label} did not pass before measurement")
    expected_report = f"binary_contract/timing_{harness.name}.binary-contract.json"
    if metadata.get("report") != expected_report:
        errors.append(
            f"{label} report path={metadata.get('report')!r}, expected={expected_report!r}"
        )
    try:
        report_path = _nested_artifact(report_dir, metadata.get("report"), label)
    except CampaignError as exc:
        errors.append(str(exc))
        return errors
    report_relative = str(report_path.relative_to(report_dir.resolve()))
    report_hash = _sha256(report_path)
    artifact_sha256[report_relative] = report_hash
    recorded_report_hash = _recorded_sha256(
        metadata.get("report_sha256"), f"{label} report_sha256", errors
    )
    if recorded_report_hash and report_hash != recorded_report_hash:
        errors.append(f"{label} report hash mismatch")
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{label} report is unreadable: {exc}")
        return errors
    if not isinstance(payload, dict):
        return [*errors, f"{label} report root must be an object"]
    if payload.get("schema_version") != "1.0" or payload.get("kind") != (
        "ctkat-timing-binary-contract-report"
    ):
        errors.append(f"{label} report identity/schema mismatch")
    if payload.get("passed") is not True or payload.get("errors") != []:
        errors.append(f"{label} report does not record an error-free pass")

    contract_path = _resolve_from_config(target.config, reference.manifest)
    try:
        contract_root, contract_rule = load_timing_binary_contract(
            contract_path,
            reference.target,
        )
    except (OSError, TimingBinaryContractError) as exc:
        errors.append(f"{label} committed manifest cannot load: {exc}")
        return errors
    if payload.get("contract_id") != contract_root.get("contract_id"):
        errors.append(f"{label} contract_id drift")
    if payload.get("contract_target") != reference.target:
        errors.append(f"{label} contract target drift")
    if metadata.get("contract_id") != contract_root.get("contract_id"):
        errors.append(f"{label} backend contract_id drift")
    if metadata.get("contract_target") != reference.target:
        errors.append(f"{label} backend contract target drift")
    manifest_record = payload.get("contract_manifest")
    if not isinstance(manifest_record, dict) or manifest_record.get("sha256") != _sha256(
        contract_path
    ):
        errors.append(f"{label} committed manifest hash mismatch")

    compiler = payload.get("compiler")
    if not isinstance(compiler, dict):
        errors.append(f"{label} compiler provenance is missing")
    else:
        if compiler.get("requested_command") != contract_rule.get("compiler"):
            errors.append(f"{label} compiler command drift")
        if compiler.get("cflags") != contract_rule.get("cflags"):
            errors.append(f"{label} compiler flags drift")
        if not isinstance(compiler.get("version"), str) or not compiler["version"].strip():
            errors.append(f"{label} compiler version is missing")
        if (
            not isinstance(compiler.get("compile_command"), str)
            or not compiler["compile_command"].strip()
        ):
            errors.append(f"{label} compile command is missing")
        executable = compiler.get("executable")
        if not isinstance(executable, dict):
            errors.append(f"{label} compiler executable record is missing")
        else:
            _recorded_sha256(executable.get("sha256"), f"{label} compiler executable", errors)
            _current_tool_matching_record(
                requested_command=contract_rule.get("compiler"),
                record=executable,
                recorded_version=compiler.get("version"),
                label=f"{label} compiler",
                errors=errors,
            )

    config_record = payload.get("config")
    if not isinstance(config_record, dict) or config_record.get("sha256") != _sha256(target.config):
        errors.append(f"{label} config hash is missing or mismatched")
    linked_records = payload.get("linked_sources")
    if not isinstance(linked_records, list) or len(linked_records) != len(harness.sources):
        errors.append(f"{label} linked source index drift")
    else:
        for index, (record, source) in enumerate(zip(linked_records, harness.sources, strict=True)):
            resolved_source = _resolve_from_config(target.config, source)
            if not isinstance(record, dict) or record.get("sha256") != _sha256(resolved_source):
                errors.append(f"{label} linked_sources[{index}] hash mismatch")

    generated_root = report_dir.parent / "generated"
    generated_records = (
        ("binary", payload.get("binary"), f"timing_{harness.name}"),
        ("generated_source", payload.get("generated_source"), f"timing_{harness.name}.c"),
    )
    preserved_binary: Path | None = None
    binary_record = payload.get("binary")
    for record_field, record, expected_name in generated_records:
        if not isinstance(record, dict) or Path(str(record.get("path", ""))).name != expected_name:
            errors.append(f"{label} {record_field} record/name drift")
            continue
        try:
            path = _nested_artifact(generated_root, expected_name, f"{label} {record_field}")
        except CampaignError as exc:
            errors.append(str(exc))
            continue
        actual_hash = _sha256(path)
        artifact_sha256[f"generated/{expected_name}"] = actual_hash
        if record.get("sha256") != actual_hash:
            errors.append(f"{label} {record_field} hash mismatch")
        if record_field == "binary" and metadata.get("binary_sha256") != actual_hash:
            errors.append(f"{label} backend binary hash mismatch")
        if record_field == "binary":
            preserved_binary = path

    disassembly = payload.get("disassembly")
    if not isinstance(disassembly, dict):
        errors.append(f"{label} disassembly provenance is missing")
        return errors
    nested_records = (
        (
            "full_artifact",
            "full_sha256",
            metadata.get("full_disassembly_sha256"),
        ),
        ("file_header_artifact", "file_header_sha256", None),
    )
    full_text = ""
    header_text = ""
    for artifact_field, hash_field, backend_hash in nested_records:
        artifact_name = disassembly.get(artifact_field)
        if not isinstance(artifact_name, str) or Path(artifact_name).name != artifact_name:
            errors.append(f"{label} {artifact_field} is unsafe")
            continue
        relative = f"binary_contract/{artifact_name}"
        try:
            artifact = _nested_artifact(report_dir, relative, f"{label} {artifact_field}")
        except CampaignError as exc:
            errors.append(str(exc))
            continue
        actual_hash = _sha256(artifact)
        artifact_sha256[relative] = actual_hash
        if disassembly.get(hash_field) != actual_hash:
            errors.append(f"{label} {hash_field} mismatch")
        if backend_hash is not None and backend_hash != actual_hash:
            errors.append(f"{label} backend disassembly hash mismatch")
        if artifact_field == "full_artifact":
            full_text = artifact.read_text(encoding="utf-8", errors="replace")
        else:
            header_text = artifact.read_text(encoding="utf-8", errors="replace")
    stored_observations: dict[str, Any] | None = None
    if full_text:
        observations, disassembly_errors = evaluate_disassembly(
            full_text,
            contract_rule["symbols"],
        )
        stored_observations = observations
        if disassembly_errors:
            errors.extend(f"{label} reparse: {error}" for error in disassembly_errors)
        if observations != disassembly.get("symbols"):
            errors.append(f"{label} recorded symbol observations differ from reparse")
    if preserved_binary is None:
        errors.append(f"{label} preserved binary is unavailable for fresh disassembly")
        return errors

    fresh = _fresh_objdump(
        contract_root=contract_root,
        binary_path=preserved_binary,
        binary_record=binary_record,
        disassembly=disassembly,
        label=label,
        errors=errors,
    )
    if fresh is None:
        return errors
    fresh_header, fresh_full = fresh
    post_objdump_binary_hash = _sha256(preserved_binary)
    if post_objdump_binary_hash != artifact_sha256.get(f"generated/{preserved_binary.name}"):
        errors.append(f"{label} preserved binary changed during fresh disassembly")
    if isinstance(binary_record, dict) and binary_record.get("sha256") != post_objdump_binary_hash:
        errors.append(f"{label} post-objdump binary hash differs from recorded report")
    if metadata.get("binary_sha256") != post_objdump_binary_hash:
        errors.append(f"{label} post-objdump binary hash differs from backend metadata")
    format_pattern = str(contract_root.get("file_format_pattern", ""))
    if re.search(format_pattern, fresh_header) is None:
        errors.append(f"{label} fresh file header does not match /{format_pattern}/")
    if header_text and _canonical_objdump_output(fresh_header) != _canonical_objdump_output(
        header_text
    ):
        errors.append(f"{label} fresh file header differs from recorded artifact")
    if full_text and _canonical_objdump_output(fresh_full) != _canonical_objdump_output(full_text):
        errors.append(f"{label} fresh disassembly differs from recorded artifact")
    fresh_observations, fresh_errors = evaluate_disassembly(
        fresh_full,
        contract_rule["symbols"],
    )
    if fresh_errors:
        errors.extend(f"{label} fresh reparse: {error}" for error in fresh_errors)
    if fresh_observations != disassembly.get("symbols"):
        errors.append(f"{label} fresh symbol observations differ from recorded report")
    if stored_observations is not None and fresh_observations != stored_observations:
        errors.append(f"{label} fresh symbol observations differ from recorded artifact")
    return errors


def validate_target_artifacts(
    campaign: CampaignSpec,
    target: TargetSpec,
    report_dir: Path,
    *,
    host_paper_eligible: bool,
    host_preflight: dict[str, Any],
    run_kind: str = "final",
) -> TargetValidation:
    result = TargetValidation(target=target, report_dir=report_dir)
    cfg = load_config(target.config)
    if cfg.dudect is None:
        result.errors.append(f"{target.id}: dudect config missing")
        return result
    configured_harnesses = {harness.name: harness for harness in cfg.dudect.harnesses}
    for name in REQUIRED_ARTIFACTS:
        path = report_dir / name
        if path.is_symlink() or not path.is_file():
            result.errors.append(f"missing artifact: {path}")
        else:
            result.artifact_sha256[name] = _sha256(path)
    if result.errors:
        return result

    backend_path = report_dir / "dudect_backend_report.json"
    try:
        backend = json.loads(backend_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result.errors.append(f"backend report unreadable: {exc}")
        return result
    if not isinstance(backend, dict):
        result.errors.append("backend report root must be an object")
        return result
    if backend.get("schema_version") != "2.0":
        result.errors.append("backend report schema_version must be 2.0")
    if backend.get("kind") != "timing-backend-report":
        result.errors.append("backend report kind must be timing-backend-report")
    if backend.get("project") != target.id:
        result.errors.append(
            f"backend report project={backend.get('project')!r}, expected={target.id!r}"
        )
    if backend.get("official_dudect_revision") != OFFICIAL_DUDECT_REVISION:
        result.errors.append("official dudect revision drift")
    hash_fields = {
        "raw_trace_sha256": "dudect_raw_timings.csv",
        "calibration_trace_sha256": "dudect_calibration_timings.csv",
        "protocol_trace_sha256": "dudect_protocol_timings.csv",
    }
    for field_name, artifact_name in hash_fields.items():
        if backend.get(field_name) != result.artifact_sha256[artifact_name]:
            result.errors.append(f"{field_name} does not match {artifact_name}")

    summary, summary_errors = _load_summary(report_dir / "dudect_summary.csv")
    result.errors.extend(summary_errors)
    backend_harnesses: dict[str, dict[str, Any]] = {}
    backend_items = backend.get("harnesses")
    if not isinstance(backend_items, list):
        result.errors.append("backend report harnesses must be a list")
        backend_items = []
    for item in backend_items:
        if not isinstance(item, dict):
            result.errors.append("backend report contains a non-object harness")
            continue
        name = str(item.get("harness", ""))
        if not name or name in backend_harnesses:
            result.errors.append(f"backend report contains empty/duplicate harness {name!r}")
            continue
        backend_harnesses[name] = item
    expected_harnesses = set(target.harnesses)
    if set(summary) != expected_harnesses:
        result.errors.append(
            f"summary harness drift: expected={sorted(expected_harnesses)}, "
            f"actual={sorted(summary)}"
        )
    if set(backend_harnesses) != expected_harnesses:
        result.errors.append(
            f"backend harness drift: expected={sorted(expected_harnesses)}, "
            f"actual={sorted(backend_harnesses)}"
        )

    result.errors.extend(
        _validate_protocol_csv(
            report_dir / "dudect_protocol_timings.csv",
            campaign,
            target,
            configured_harnesses,
        )
    )
    independent_dudect = verify_official_dudect_artifacts(
        raw_path=report_dir / "dudect_raw_timings.csv",
        calibration_path=report_dir / "dudect_calibration_timings.csv",
        protocol_path=report_dir / "dudect_protocol_timings.csv",
        backend_report=backend,
        expected_project=target.id,
        expected_harnesses=expected_harnesses,
        protocol_contract=OfficialDudectProtocolContract(
            base_seed=campaign.protocol.seed,
            process_repeats=campaign.protocol.process_repeats,
            target_measurements=target.target_measurements,
            control_measurements=target.control_measurements,
            positive_effects=target.positive_control_effects,
            aa_abs_t_limit=campaign.protocol.aa_abs_t_limit,
            positive_abs_t_threshold=campaign.protocol.positive_abs_t_threshold,
            aa_max_failures=campaign.protocol.aa_max_failures,
            target_power=campaign.protocol.target_power,
            power_alpha=campaign.protocol.power_alpha,
            expected_axes=target.axes,
        ),
    )
    result.errors.extend(
        f"official dudect independent verification: {error}" for error in independent_dudect.errors
    )

    for harness_name in target.harnesses:
        row = summary.get(harness_name)
        item = backend_harnesses.get(harness_name)
        if row is None or item is None:
            continue
        protocol = item.get("harness_protocol") or {}
        harness_errors: list[str] = []
        if not isinstance(protocol, dict):
            result.errors.append(f"{harness_name}: harness_protocol must be an object")
            continue
        if row.get("project") != target.id:
            harness_errors.append(f"summary project={row.get('project')!r}, expected={target.id!r}")
        configured_harness = configured_harnesses.get(harness_name)
        if configured_harness is None:
            harness_errors.append("harness is absent from the target config")
            continue
        if item.get("backend") != OFFICIAL_DUDECT_BACKEND:
            harness_errors.append(f"backend={item.get('backend')!r}")
        if item.get("upstream_revision") != OFFICIAL_DUDECT_REVISION:
            harness_errors.append("backend harness upstream revision drift")
        if row.get("upstream_revision") != OFFICIAL_DUDECT_REVISION:
            harness_errors.append("summary upstream revision drift")
        tests = item.get("tests")
        if (
            not isinstance(tests, list)
            or len(tests) != OFFICIAL_DUDECT_PROTOCOL_TESTS
            or any(not isinstance(test, dict) for test in tests)
            or [test.get("index") for test in tests] != list(range(OFFICIAL_DUDECT_PROTOCOL_TESTS))
        ):
            harness_errors.append(
                f"backend must preserve all {OFFICIAL_DUDECT_PROTOCOL_TESTS} ordered official tests"
            )
        if item.get("protocol_test_count") != OFFICIAL_DUDECT_PROTOCOL_TESTS:
            harness_errors.append("backend official protocol test count mismatch")
        try:
            summary_protocol_tests = int(row.get("protocol_test_count", ""))
        except (TypeError, ValueError):
            summary_protocol_tests = -1
        if summary_protocol_tests != OFFICIAL_DUDECT_PROTOCOL_TESTS:
            harness_errors.append("summary official protocol test count mismatch")
        if protocol.get("protocol") != "timing-harness-v2":
            harness_errors.append("protocol manifest missing")
        expected_axis = target.axis_for(harness_name)
        if protocol.get("axis") != expected_axis:
            harness_errors.append(
                f"harness_protocol.axis={protocol.get('axis')!r}, expected={expected_axis!r}"
            )
        if expected_axis == "valid_tuple":
            harness_errors.extend(
                validate_valid_tuple_harness_report(
                    item,
                    label=f"{target.id}.{harness_name}",
                )
            )
        if configured_harness.operand_setup_contract == OPERAND_V3_SETUP_CONTRACT:
            harness_errors.extend(
                validate_operand_v3_harness_report(
                    item,
                    base_seed=campaign.protocol.seed,
                    label=f"{target.id}.{harness_name}",
                )
            )
        elif (
            isinstance(protocol.get("input_contract"), dict)
            and protocol["input_contract"].get("setup_contract") == OPERAND_V3_SETUP_CONTRACT
        ):
            harness_errors.append(
                "operand-v3 input contract is present without the configured setup contract"
            )
        expected_protocol = {
            "schema_version": "1.0",
            "template": configured_harness.template,
            "common_work_buffer": True,
            "symmetric_setup": True,
            "timed_region_target_only": True,
            "rdtscp_aux_migration_filter": True,
            "pool_size": campaign.protocol.pool_size,
            "target_measurements": target.target_measurements,
            "control_measurements": target.control_measurements,
            "process_repeats_required": 3,
            "process_repeats_observed": campaign.protocol.process_repeats,
            "aa_abs_t_limit": campaign.protocol.aa_abs_t_limit,
            "aa_max_failures": campaign.protocol.aa_max_failures,
            "positive_abs_t_threshold": campaign.protocol.positive_abs_t_threshold,
            "target_power": campaign.protocol.target_power,
            "power_alpha": campaign.protocol.power_alpha,
        }
        for key, expected in expected_protocol.items():
            if protocol.get(key) != expected:
                harness_errors.append(
                    f"harness_protocol.{key}={protocol.get(key)!r}, expected={expected!r}"
                )
        signature_contract = protocol.get("signature_call_contract")
        if configured_harness.template == "sign":
            if not isinstance(signature_contract, dict):
                harness_errors.append("signature_call_contract must be an object")
            else:
                expected_signature_contract = {
                    "configured": configured_harness.signature_length_contract,
                    "return_code_column": "signature_return_code",
                    "return_code_success": 0,
                    "return_codes_recorded": True,
                    "correctness_round_trip_gate": True,
                    "measured_contract_failures": 0,
                    "traces_validated": (
                        campaign.protocol.process_repeats
                        * (4 + len(target.positive_control_effects))
                    ),
                    "passed": True,
                }
                for key, expected in expected_signature_contract.items():
                    if signature_contract.get(key) != expected:
                        harness_errors.append(
                            f"signature_call_contract.{key}="
                            f"{signature_contract.get(key)!r}, expected={expected!r}"
                        )
                resolved_min = signature_contract.get("resolved_min")
                resolved_max = signature_contract.get("resolved_max")
                if (
                    isinstance(resolved_min, bool)
                    or not isinstance(resolved_min, int)
                    or isinstance(resolved_max, bool)
                    or not isinstance(resolved_max, int)
                    or resolved_min < 1
                    or resolved_max < resolved_min
                ):
                    harness_errors.append("signature_call_contract resolved range is invalid")
                elif (
                    configured_harness.signature_length_contract == "fixed"
                    and resolved_min != resolved_max
                ):
                    harness_errors.append("fixed signature contract resolved range is not fixed")
                elif (
                    configured_harness.signature_length_contract == "bounded" and resolved_min != 1
                ):
                    harness_errors.append("bounded signature contract must resolve from length 1")
        elif signature_contract is not None:
            harness_errors.append("non-sign harness unexpectedly claims signature_call_contract")
        harness_errors.extend(
            _validate_build_provenance_artifacts(
                campaign=campaign,
                target=target,
                harness=configured_harness,
                protocol=protocol,
                report_dir=report_dir,
                artifact_sha256=result.artifact_sha256,
                host_preflight=host_preflight,
            )
        )
        harness_errors.extend(
            _validate_binary_contract_artifacts(
                target=target,
                harness=configured_harness,
                protocol=protocol,
                report_dir=report_dir,
                artifact_sha256=result.artifact_sha256,
            )
        )
        curve = protocol.get("positive_power_curve")
        if not isinstance(curve, list) or any(not isinstance(item, dict) for item in curve):
            harness_errors.append("positive_power_curve must be a list of objects")
            curve = []
        observed_effects = [item.get("effect_ticks") for item in curve]
        if observed_effects != list(target.positive_control_effects):
            harness_errors.append(
                f"positive effect curve={observed_effects}, "
                f"expected={list(target.positive_control_effects)}"
            )
        expected_list_lengths = {
            "target_repeats": campaign.protocol.process_repeats,
            "aa_controls": campaign.protocol.process_repeats,
            "setup_placebo_controls": campaign.protocol.process_repeats,
            "positive_controls": (
                campaign.protocol.process_repeats * len(target.positive_control_effects)
            ),
        }
        for field_name, expected_length in expected_list_lengths.items():
            value = protocol.get(field_name)
            if (
                not isinstance(value, list)
                or len(value) != expected_length
                or any(not isinstance(entry, dict) for entry in value)
            ):
                harness_errors.append(
                    f"{field_name} count/type mismatch; expected {expected_length} objects"
                )
        for field_name in (
            "target_status_consistent",
            "aa_budget_passed",
            "setup_placebo_passed",
            "positive_power_passed",
        ):
            if not isinstance(protocol.get(field_name), bool):
                harness_errors.append(f"{field_name} must be boolean")
        if protocol.get("randomness_policies_observed") != ["seeded-interpose"]:
            harness_errors.append(
                f"randomness policy={protocol.get('randomness_policies_observed')!r}"
            )
        try:
            raw_total = int(row.get("raw_n_total", ""))
        except (TypeError, ValueError):
            raw_total = -1
        if raw_total != target.target_measurements:
            harness_errors.append(
                f"summary raw_n_total={raw_total}, expected={target.target_measurements}"
            )
        if row.get("backend") != OFFICIAL_DUDECT_BACKEND:
            harness_errors.append(f"summary backend={row.get('backend')!r}")
        if row.get("status") != item.get("raw_status"):
            harness_errors.append("summary/backend raw status mismatch")
        if row.get("timing_validity") != item.get("timing_validity"):
            harness_errors.append("summary/backend timing_validity mismatch")
        try:
            summary_n0 = int(row.get("n0", ""))
            summary_n1 = int(row.get("n1", ""))
            summary_seed = int(row.get("analysis_seed", ""))
            summary_repeats = int(row.get("process_repeats", ""))
            summary_aa_failures = int(row.get("aa_failures", ""))
            summary_abs_t = float(row.get("abs_t_score", ""))
            backend_abs_t = float(item.get("abs_t_score"))
        except (TypeError, ValueError):
            harness_errors.append("summary/backend contains invalid numeric metadata")
        else:
            if summary_n0 != item.get("n0") or summary_n1 != item.get("n1"):
                harness_errors.append("summary/backend retained sample count mismatch")
            if summary_seed != item.get("analysis_seed"):
                harness_errors.append("summary/backend analysis seed mismatch")
            if summary_repeats != campaign.protocol.process_repeats:
                harness_errors.append("summary process repeat count mismatch")
            if summary_aa_failures != protocol.get("aa_failures"):
                harness_errors.append("summary/backend A/A failure count mismatch")
            if (
                not math.isfinite(summary_abs_t)
                or not math.isfinite(backend_abs_t)
                or not math.isclose(
                    summary_abs_t,
                    backend_abs_t,
                    rel_tol=0,
                    abs_tol=0.000_501,
                )
            ):
                harness_errors.append("summary/backend absolute t-score mismatch")
        expected_power = str(protocol.get("positive_power_passed")).lower()
        if row.get("positive_power_passed") != expected_power:
            harness_errors.append("summary/backend positive-power result mismatch")
        if item.get("analysis_raw_n_total") != target.target_measurements:
            harness_errors.append("backend analysis raw count mismatch")
        enough_measurements = item.get("enough_measurements")
        if not isinstance(enough_measurements, bool):
            harness_errors.append("backend enough_measurements must be boolean")
        elif item.get("timing_validity") == "valid" and not enough_measurements:
            harness_errors.append("valid timing contradicts insufficient retained measurements")
        if harness_errors:
            result.errors.extend(f"{harness_name}: {error}" for error in harness_errors)

        raw_status = str(item.get("raw_status", ""))
        validity = str(item.get("timing_validity", ""))
        try:
            _, signal = timing_from_raw(raw_status, validity)
            signal_value = signal.value
        except ValueError as exc:
            result.errors.append(f"{harness_name}: invalid timing state: {exc}")
            signal_value = "not-interpretable"
        validity_reasons = item.get("validity_reasons")
        if not isinstance(validity_reasons, list) or any(
            not isinstance(value, str) for value in validity_reasons
        ):
            result.errors.append(f"{harness_name}: validity_reasons must be a string list")
            validity_reasons = ["malformed validity_reasons"]
        blockers = list(validity_reasons)
        if validity != "valid":
            blockers.insert(0, f"timing_validity={validity or 'missing'}")
        environment = item.get("environment")
        if not isinstance(environment, dict):
            result.errors.append(f"{harness_name}: environment must be an object")
            environment = {"rejected": True}
        if environment.get("rejected"):
            blockers.append("target timing environment rejected")
        if not host_paper_eligible:
            blockers.append("campaign host is engineering-only")
        if run_kind != "final":
            blockers.append(f"run_kind={run_kind} is non-promotable")
        blockers = list(dict.fromkeys(blockers))
        result.blockers.extend(f"{harness_name}: {blocker}" for blocker in blockers)
        result.harnesses.append(
            {
                "harness": harness_name,
                "axis": expected_axis,
                "raw_status": raw_status,
                "timing_validity": validity,
                "timing_signal": signal_value,
                "abs_t_score": item.get("abs_t_score"),
                "analysis_seed": item.get("analysis_seed"),
                "n0": item.get("n0"),
                "n1": item.get("n1"),
                "promotion_ready": validity == "valid" and not blockers,
                "blockers": blockers,
            }
        )

    result.blockers = list(dict.fromkeys(result.blockers))
    result.complete = not result.errors
    result.promotion_ready = result.complete and all(
        harness["promotion_ready"] for harness in result.harnesses
    )
    return result


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _host_fingerprint(preflight_report: dict[str, Any]) -> str:
    environment = preflight_report.get("environment")
    virtualization = preflight_report.get("virtualization")
    if not isinstance(environment, dict) or not isinstance(virtualization, dict):
        raise CampaignError("cannot fingerprint malformed host preflight")
    identity = {
        "system": environment.get("system"),
        "machine": environment.get("machine"),
        "kernel": environment.get("kernel"),
        "cpu_model": environment.get("cpu_model"),
        "machine_id_sha256": environment.get("machine_id_sha256"),
        "boot_id_sha256": environment.get("boot_id_sha256"),
        "microcode": environment.get("microcode"),
        "cpu_affinity": environment.get("cpu_affinity"),
        "clock": environment.get("clock"),
        "timing_cpu_flags": environment.get("timing_cpu_flags"),
        "compiler": preflight_report.get("compiler"),
        "compiler_executable": preflight_report.get("compiler_executable"),
        "governor": preflight_report.get("governor_selected_cpu"),
        "virtualization": virtualization,
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _target_attestation_payload(
    *,
    campaign: CampaignSpec,
    target: TargetSpec,
    validation: TargetValidation,
    run_id: str,
    run_kind: str,
    commit: str,
    host_fingerprint_sha256: str,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "kind": "native-target-run-attestation",
        "campaign_id": campaign.campaign_id,
        "manifest_sha256": campaign.manifest_sha256,
        "target_id": target.id,
        "ctkat_commit": commit,
        "run_id": run_id,
        "run_kind": run_kind,
        "host_fingerprint_sha256": host_fingerprint_sha256,
        "artifact_sha256": dict(sorted(validation.artifact_sha256.items())),
    }


def _validate_target_attestation(
    path: Path,
    *,
    campaign: CampaignSpec,
    target: TargetSpec,
    validation: TargetValidation,
    run_id: str,
    run_kind: str,
    commit: str,
    host_fingerprint_sha256: str,
) -> tuple[str | None, list[str]]:
    if path.is_symlink() or not path.is_file():
        return None, [f"{target.id}: target run attestation is missing"]
    try:
        actual = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, [f"{target.id}: target run attestation is unreadable: {exc}"]
    expected = _target_attestation_payload(
        campaign=campaign,
        target=target,
        validation=validation,
        run_id=run_id,
        run_kind=run_kind,
        commit=commit,
        host_fingerprint_sha256=host_fingerprint_sha256,
    )
    if actual != expected:
        return None, [f"{target.id}: target run attestation does not match this run"]
    return _sha256(path), []


def _updates(validations: Iterable[TargetValidation]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for validation in validations:
        report_rel = f"{validation.target.id}/reports/dudect_backend_report.json"
        report_hash = validation.artifact_sha256.get("dudect_backend_report.json", "")
        for harness in validation.harnesses:
            rows.append(
                {
                    "target": validation.target.id,
                    "family": validation.target.family,
                    "harness": harness["harness"],
                    "timing_validity": harness["timing_validity"],
                    "timing_signal": harness["timing_signal"],
                    "timing_backend": OFFICIAL_DUDECT_BACKEND,
                    "timing_raw_status": harness["raw_status"],
                    "timing_abs_t": harness["abs_t_score"],
                    "timing_measurements": validation.target.target_measurements,
                    "timing_leak_target": harness["axis"],
                    "timing_seed": harness["analysis_seed"],
                    "timing_threshold": OFFICIAL_TIMING_THRESHOLD,
                    "report": report_rel,
                    "report_sha256": report_hash,
                    "promotion_ready": str(harness["promotion_ready"]).lower(),
                    "blockers": "; ".join(harness["blockers"]),
                }
            )
    return rows


def write_updates(
    path: Path,
    validations: Iterable[TargetValidation],
    *,
    merge: bool = False,
) -> None:
    materialized = list(validations)
    rows = _updates(materialized)
    if merge and path.is_file():
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames != UPDATE_FIELDS:
                raise CampaignError(f"cannot merge update CSV with a drifted header: {path}")
            replaced_targets = {validation.target.id for validation in materialized}
            previous = [row for row in reader if row.get("target") not in replaced_targets]
        rows = [*previous, *rows]
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=UPDATE_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)


def validate_updates(
    path: Path,
    validations: Iterable[TargetValidation],
) -> list[str]:
    materialized = list(validations)
    if not path.is_file():
        return [f"missing artifact: {path}"]
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != UPDATE_FIELDS:
            return [
                f"{path.name}: header drift: expected={UPDATE_FIELDS}, actual={reader.fieldnames}"
            ]
        rows = list(reader)

    selected_targets = {validation.target.id for validation in materialized}
    actual: dict[tuple[str, str], dict[str, str]] = {}
    errors: list[str] = []
    for row in rows:
        if row.get("target") not in selected_targets:
            continue
        key = (row.get("target", ""), row.get("harness", ""))
        if key in actual:
            errors.append(f"{path.name}: duplicate candidate row {key}")
        actual[key] = row
    expected = {
        (str(row["target"]), str(row["harness"])): {
            field: "" if row.get(field) is None else str(row.get(field, ""))
            for field in UPDATE_FIELDS
        }
        for row in _updates(materialized)
    }
    if set(actual) != set(expected):
        errors.append(
            f"{path.name}: selected candidate rows drift: "
            f"expected={sorted(expected)}, actual={sorted(actual)}"
        )
    for key in set(actual).intersection(expected):
        if actual[key] != expected[key]:
            mismatches = [
                field
                for field in UPDATE_FIELDS
                if actual[key].get(field, "") != expected[key].get(field, "")
            ]
            errors.append(
                f"{path.name}: candidate {key} differs from validated artifacts in {mismatches}"
            )
    return errors


def _safe_output_root(path: Path) -> Path:
    resolved = path.resolve()
    if resolved == ROOT or ROOT.is_relative_to(resolved):
        raise CampaignError(
            f"output root cannot be the repository or one of its ancestors: {resolved}"
        )
    local_campaign_root = (ROOT / "measurement_runs").resolve()
    if resolved.is_relative_to(ROOT) and not resolved.is_relative_to(local_campaign_root):
        raise CampaignError(
            "an in-repository output must live under the ignored measurement_runs/ "
            f"directory: {resolved}"
        )
    if resolved.exists() and not resolved.is_dir():
        raise CampaignError(f"output root exists but is not a directory: {resolved}")
    return resolved


def _select_targets(campaign: CampaignSpec, selected: list[str]) -> tuple[TargetSpec, ...]:
    if not selected:
        return campaign.targets
    known = {target.id: target for target in campaign.targets}
    unknown = sorted(set(selected) - set(known))
    if unknown:
        raise CampaignError(f"unknown --target value(s): {unknown}")
    return tuple(target for target in campaign.targets if target.id in set(selected))


def _human_premeasurement_gate_material(
    expected_commit: str,
    *,
    allow_review_only_head: bool = False,
) -> dict[str, Any]:
    from scripts.check_paper_reviews import DEFAULT_MANIFEST as REVIEW_MANIFEST
    from scripts.check_paper_reviews import evaluate_manifest

    current_commit, dirty = _git_state()
    if dirty:
        raise CampaignError("human review gate requires a clean git worktree")
    if current_commit != expected_commit:
        if not allow_review_only_head:
            raise CampaignError(
                "human review gate expected commit differs from current git HEAD: "
                f"{expected_commit} != {current_commit}"
            )
        try:
            ancestor = subprocess.run(
                ["git", "merge-base", "--is-ancestor", expected_commit, current_commit],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            )
            if ancestor.returncode != 0:
                raise CampaignError(
                    "measurement commit is not an ancestor of the validation checkout"
                )
            drift = subprocess.run(
                [
                    "git",
                    "diff",
                    "--name-only",
                    f"{expected_commit}..{current_commit}",
                    "--",
                    *MEASUREMENT_CRITICAL_PATHS,
                ],
                cwd=ROOT,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError) as exc:
            raise CampaignError(f"cannot validate review-only commit drift: {exc}") from exc
        if drift:
            raise CampaignError(
                "measurement-critical source changed after the recorded run: "
                + ", ".join(drift.splitlines())
            )
    review_report, review_errors = evaluate_manifest(REVIEW_MANIFEST)
    if review_errors:
        raise CampaignError("paper review packets are invalid: " + "; ".join(review_errors))
    if review_report.get("pre_measurement_ready") is not True:
        raise CampaignError(
            "human premeasurement review is incomplete; use --run-kind engineering "
            "until the real reviewer quorum is recorded"
        )
    reviewed_source_commits = review_report.get("pre_measurement_reviewed_source_commits")
    if (
        not isinstance(reviewed_source_commits, list)
        or len(reviewed_source_commits) != 1
        or not isinstance(reviewed_source_commits[0], str)
    ):
        raise CampaignError("human premeasurement packets must bind one frozen source commit")
    packet_hashes: dict[str, str] = {}
    for packet in review_report.get("packets", []):
        if not isinstance(packet, dict) or packet.get("required_before_measurement") is not True:
            continue
        value = packet.get("path")
        if not isinstance(value, str):
            raise CampaignError("paper review report contains a malformed packet path")
        path = (ROOT / value).resolve()
        if not path.is_file() or path.is_symlink():
            raise CampaignError(f"paper review packet is not a regular file: {value}")
        packet_hashes[value] = _sha256(path)
    return {
        "schema_version": "1.0",
        "kind": "human-premeasurement-review-gate",
        "ready": True,
        "ctkat_commit": expected_commit,
        "reviewed_source_commit": reviewed_source_commits[0],
        "plan_id": review_report.get("plan_id"),
        "minimum_reviewers": review_report.get("minimum_reviewers"),
        "review_manifest": _display_path(REVIEW_MANIFEST),
        "review_manifest_sha256": _sha256(REVIEW_MANIFEST),
        "packet_sha256": dict(sorted(packet_hashes.items())),
    }


def _human_premeasurement_gate(expected_commit: str) -> dict[str, Any]:
    return {
        **_human_premeasurement_gate_material(expected_commit),
        "checked_at": _utc_now(),
    }


SINGLE_HOST_PLAN = ROOT / "docs/measurement/paper_native_campaign_v6.yaml"
SINGLE_HOST_GATE_INPUTS = (
    ROOT / "docs/measurement/EXPERIMENT_PREREGISTRATION.md",
    ROOT / "docs/measurement/PAPER_NATIVE_ANALYSIS_V2.md",
    ROOT / "docs/measurement/native_timing_v3_campaign.yaml",
    ROOT / "docs/measurement/kyberslash_native_v3.yaml",
    ROOT / "docs/measurement/falcon_native_v2.yaml",
    ROOT / "docs/measurement/diverse_native_v2.yaml",
    ROOT / "docs/measurement/mlkem_asm_evidence_v1.yaml",
    ROOT / "docs/baselines/same_corpus_v1.yaml",
    ROOT / "docs/baselines/baseline-result-v1.schema.json",
    ROOT / "docs/artifact/measurement_bundle_single_host_template.yaml",
    ROOT / "scripts/check_paper_campaign.py",
    ROOT / "scripts/analyze_paper_native_results.py",
    ROOT / "scripts/build_asm_evidence.py",
    ROOT / "scripts/build_single_host_measurement_bundle.py",
    ROOT / "scripts/check_asm_evidence.py",
    ROOT / "scripts/hash_artifacts.py",
    ROOT / "scripts/run_native_timing_campaign.py",
    ROOT / "scripts/run_same_corpus_baselines.py",
    ROOT / "pyproject.toml",
    ROOT / "uv.lock",
)


def _single_host_premeasurement_gate_material(
    expected_commit: str,
    *,
    allow_governance_only_head: bool = False,
) -> dict[str, Any]:
    """Bind a clean commit and the complete single-host frozen input set.

    This gate is deliberately not described as review.  It replaces the unavailable
    reviewer quorum with deterministic integrity checks while preserving an explicit
    single-host/no-independent-validation scope boundary.
    """

    current_commit, dirty = _git_state()
    if dirty:
        raise CampaignError("single-host integrity gate requires a clean git worktree")
    if current_commit != expected_commit:
        if not allow_governance_only_head:
            raise CampaignError(
                "single-host integrity gate expected commit differs from current git HEAD: "
                f"{expected_commit} != {current_commit}"
            )
        try:
            ancestor = subprocess.run(
                ["git", "merge-base", "--is-ancestor", expected_commit, current_commit],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            )
            if ancestor.returncode != 0:
                raise CampaignError(
                    "measurement commit is not an ancestor of the validation checkout"
                )
            drift = subprocess.run(
                [
                    "git",
                    "diff",
                    "--name-only",
                    f"{expected_commit}..{current_commit}",
                    "--",
                    *MEASUREMENT_CRITICAL_PATHS,
                ],
                cwd=ROOT,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError) as exc:
            raise CampaignError(f"cannot validate post-measurement commit drift: {exc}") from exc
        if drift:
            raise CampaignError(
                "measurement-critical source changed after the recorded run: "
                + ", ".join(drift.splitlines())
            )
    try:
        plan = yaml.safe_load(SINGLE_HOST_PLAN.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CampaignError(f"single-host paper plan is unreadable: {exc}") from exc
    if not isinstance(plan, dict):
        raise CampaignError("single-host paper plan must be a mapping")
    policy = plan.get("execution_policy")
    promotion = plan.get("promotion")
    if (
        plan.get("schema_version") != 3
        or plan.get("campaign_id") != "ctkat-paper-native-v6-single-host"
        or plan.get("status") != "premeasurement-frozen"
        or not isinstance(policy, dict)
        or policy.get("minimum_physical_hosts") != 1
        or policy.get("independent_human_review_required") is not False
        or policy.get("cross_host_reproducibility_claimed") is not False
        or policy.get("premeasurement_gate") != "automated-frozen-input-integrity"
        or not isinstance(promotion, dict)
        or promotion.get("require_automated_premeasurement_gate") is not True
        or promotion.get("require_two_person_human_review") is not False
        or promotion.get("require_both_hosts") is not False
    ):
        raise CampaignError("single-host paper plan policy drift")
    components = plan.get("components")
    expected_manifests = {
        str(path.relative_to(ROOT))
        for path in SINGLE_HOST_GATE_INPUTS
        if path.name.endswith(".yaml")
    }
    component_manifests = {
        item.get("manifest")
        for item in components or []
        if isinstance(item, dict) and isinstance(item.get("manifest"), str)
    }
    required_components = {
        "docs/measurement/native_timing_v3_campaign.yaml",
        "docs/measurement/kyberslash_native_v3.yaml",
        "docs/measurement/falcon_native_v2.yaml",
        "docs/measurement/diverse_native_v2.yaml",
    }
    if component_manifests != required_components:
        raise CampaignError("single-host paper component set drift")
    for relative in sorted(component_manifests):
        frozen = load_campaign(ROOT / relative)
        errors = static_check(frozen)
        if errors:
            raise CampaignError(f"{relative}: frozen campaign invalid: " + "; ".join(errors))
    input_paths = (SINGLE_HOST_PLAN, *SINGLE_HOST_GATE_INPUTS)
    missing = [str(path.relative_to(ROOT)) for path in input_paths if not path.is_file()]
    if missing:
        raise CampaignError("single-host gate inputs are missing: " + ", ".join(missing))
    input_hashes = {
        str(path.relative_to(ROOT)): _sha256(path)
        for path in sorted(input_paths, key=lambda item: str(item.relative_to(ROOT)))
    }
    if not required_components <= expected_manifests:
        raise CampaignError("single-host gate manifest hash set drift")
    return {
        "schema_version": "1.0",
        "kind": "automated-frozen-input-integrity-gate",
        "ready": True,
        "ctkat_commit": expected_commit,
        "plan_id": plan["campaign_id"],
        "plan_sha256": _sha256(SINGLE_HOST_PLAN),
        "input_sha256": input_hashes,
        "physical_host_count": 1,
        "independent_human_review": False,
        "cross_host_reproducibility": False,
    }


def _single_host_premeasurement_gate(expected_commit: str) -> dict[str, Any]:
    return {
        **_single_host_premeasurement_gate_material(expected_commit),
        "checked_at": _utc_now(),
    }


def _validate_single_host_premeasurement_gate(
    gate: Any,
    *,
    expected_commit: str,
    allow_governance_only_head: bool = False,
) -> list[str]:
    if not isinstance(gate, dict):
        return ["final campaign lacks a single-host frozen-input integrity gate"]
    expected_material = _single_host_premeasurement_gate_material(
        expected_commit,
        allow_governance_only_head=allow_governance_only_head,
    )
    expected_keys = set(expected_material) | {"checked_at"}
    if set(gate) != expected_keys:
        return ["single-host final integrity gate field set drift"]
    checked_at = gate.get("checked_at")
    if not isinstance(checked_at, str):
        return ["single-host final integrity gate timestamp is missing"]
    try:
        parsed = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
    except ValueError:
        return ["single-host final integrity gate timestamp is malformed"]
    if parsed.tzinfo is None:
        return ["single-host final integrity gate timestamp lacks a timezone"]
    if gate != {**expected_material, "checked_at": checked_at}:
        return [
            "single-host final integrity gate no longer matches the exact frozen commit "
            "and input hashes"
        ]
    return []


def _validate_human_premeasurement_gate(
    gate: Any,
    *,
    expected_commit: str,
    allow_review_only_head: bool = False,
) -> list[str]:
    if not isinstance(gate, dict):
        return ["final campaign lacks a human premeasurement review gate"]
    expected_material = _human_premeasurement_gate_material(
        expected_commit,
        allow_review_only_head=allow_review_only_head,
    )
    expected_keys = set(expected_material) | {"checked_at"}
    if set(gate) != expected_keys:
        return ["final campaign human review gate field set drift"]
    checked_at = gate.get("checked_at")
    if not isinstance(checked_at, str):
        return ["final campaign human review gate timestamp is missing"]
    try:
        parsed = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
    except ValueError:
        return ["final campaign human review gate timestamp is malformed"]
    if parsed.tzinfo is None:
        return ["final campaign human review gate timestamp lacks a timezone"]
    expected = {
        **expected_material,
        "checked_at": checked_at,
    }
    if gate != expected:
        return [
            "final campaign human review gate no longer matches the exact current "
            "reviewed commit and packet hashes"
        ]
    return []


def _print_static_plan(campaign: CampaignSpec) -> None:
    print(
        f"[native-timing] OK: {campaign.campaign_id}, "
        f"{len(campaign.targets)} targets, "
        f"{sum(len(target.harnesses) for target in campaign.targets)} timing axes"
    )
    print(
        f"  protocol: backend={campaign.protocol.backend} "
        f"compiler={campaign.protocol.compiler} clock={campaign.protocol.clock} "
        f"warmup={campaign.protocol.warmup} repeats={campaign.protocol.process_repeats}"
    )
    for target in campaign.targets:
        rows_per_harness = campaign.protocol.process_repeats * (
            2 * target.target_measurements + 5 * target.control_measurements
        )
        print(
            f"  {target.id}: harnesses={','.join(target.harnesses)} "
            f"target={target.target_measurements} control={target.control_measurements} "
            f"protocol_rows={rows_per_harness * len(target.harnesses)}"
        )


def execute_campaign(
    campaign: CampaignSpec,
    output_root: Path,
    targets: tuple[TargetSpec, ...],
    *,
    preflight_report: dict[str, Any],
    run_kind: str,
    review_gate: dict[str, Any] | None,
    resume: bool,
    continue_on_error: bool,
    automated_gate: dict[str, Any] | None = None,
) -> int:
    output_root = _safe_output_root(output_root)
    if run_kind not in RUN_KINDS:
        raise CampaignError(f"invalid run_kind={run_kind!r}")
    if run_kind == "final" and resume:
        raise CampaignError("final runs cannot use --resume; start a fresh output root")
    commit = preflight_report.get("git_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise CampaignError("preflight report must contain a full git commit")
    host_paper_eligible, host_errors = validate_preflight_report(
        campaign,
        preflight_report,
        expected_commit=commit,
    )
    if host_errors:
        raise CampaignError("preflight report is invalid: " + "; ".join(host_errors))
    if run_kind in {"pilot", "final"} and not host_paper_eligible:
        raise CampaignError(f"{run_kind} requires a paper-eligible physical host")
    if run_kind == "final":
        if review_gate is not None and automated_gate is not None:
            raise CampaignError("final execution cannot claim both human and automated gates")
        gate_errors = (
            _validate_single_host_premeasurement_gate(
                automated_gate,
                expected_commit=commit,
            )
            if automated_gate is not None
            else _validate_human_premeasurement_gate(
                review_gate,
                expected_commit=commit,
            )
        )
        if gate_errors:
            raise CampaignError(
                "final execution requires a valid premeasurement gate: " + "; ".join(gate_errors)
            )
    elif review_gate is not None or automated_gate is not None:
        raise CampaignError("premeasurement gates are only valid for a final run")
    host_fingerprint_sha256 = _host_fingerprint(preflight_report)
    if output_root.exists() and any(output_root.iterdir()) and not resume:
        raise CampaignError(f"output root is non-empty; use --resume: {output_root}")
    output_root.mkdir(parents=True, exist_ok=True)
    report_path = output_root / "campaign_report.json"
    if resume:
        if not report_path.is_file() or report_path.is_symlink():
            raise CampaignError("cannot resume without an existing regular campaign report")
        try:
            previous = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CampaignError(f"cannot resume: campaign report unreadable: {exc}") from exc
        if not isinstance(previous, dict):
            raise CampaignError("cannot resume: campaign report root must be an object")
        if previous.get("schema_version") != "2.0":
            raise CampaignError("cannot resume: campaign report schema is not 2.0")
        if previous.get("kind") != "native-timing-campaign-report":
            raise CampaignError("cannot resume: campaign report kind changed")
        if previous.get("campaign_id") != campaign.campaign_id:
            raise CampaignError("cannot resume: campaign id changed")
        if previous.get("manifest_sha256") != campaign.manifest_sha256:
            raise CampaignError("cannot resume: campaign manifest hash changed")
        if previous.get("ctkat_commit") != preflight_report["git_commit"]:
            raise CampaignError("cannot resume: CT-KAT commit changed")
        if previous.get("run_kind") != run_kind:
            raise CampaignError("cannot resume: run kind changed")
        run_id = previous.get("run_id")
        if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id):
            raise CampaignError("cannot resume: run id is malformed")
        if previous.get("host_fingerprint_sha256") != host_fingerprint_sha256:
            raise CampaignError("cannot resume: host or boot identity changed")
        report = previous
        report["status"] = "running"
        report["finished_at"] = None
        previous_selected = previous.get("selected_targets") or []
        if not isinstance(previous_selected, list) or any(
            not isinstance(value, str) for value in previous_selected
        ):
            raise CampaignError("cannot resume: selected target index is malformed")
        known_targets = {target.id for target in campaign.targets}
        if not set(previous_selected) <= known_targets:
            raise CampaignError("cannot resume: selected target index contains unknown targets")
        report["selected_targets"] = list(
            dict.fromkeys(
                [
                    *previous_selected,
                    *(target.id for target in targets),
                ]
            )
        )
        previous_targets = previous.get("targets") or {}
        if not isinstance(previous_targets, dict) or any(
            not isinstance(value, dict) for value in previous_targets.values()
        ):
            raise CampaignError("cannot resume: campaign target index is malformed")
        if not set(previous_targets) <= known_targets:
            raise CampaignError("cannot resume: campaign target index contains unknown targets")
        report["targets"] = previous_targets
    else:
        run_id = uuid.uuid4().hex
        report = {
            "schema_version": "2.0",
            "kind": "native-timing-campaign-report",
            "campaign_id": campaign.campaign_id,
            "manifest": _display_path(campaign.manifest_path),
            "manifest_sha256": campaign.manifest_sha256,
            "ctkat_commit": commit,
            "run_id": run_id,
            "run_kind": run_kind,
            "host_fingerprint_sha256": host_fingerprint_sha256,
            "started_at": _utc_now(),
            "finished_at": None,
            "status": "running",
            "paper_promotion_ready": False,
            "selected_targets": [target.id for target in targets],
            "human_review_gate": review_gate,
            "automated_premeasurement_gate": automated_gate,
            "host_preflight": preflight_report,
            "targets": {},
        }
    _write_json_atomic(report_path, report)

    validations: list[TargetValidation] = []
    execution_failed = False
    for target in targets:
        target_root = output_root / target.id
        report_dir = target_root / "reports"
        existing = None
        if resume and all((report_dir / name).is_file() for name in REQUIRED_ARTIFACTS):
            existing = validate_target_artifacts(
                campaign,
                target,
                report_dir,
                host_paper_eligible=host_paper_eligible,
                host_preflight=preflight_report,
                run_kind=run_kind,
            )
            if existing.complete:
                attestation_hash, attestation_errors = _validate_target_attestation(
                    target_root / TARGET_ATTESTATION,
                    campaign=campaign,
                    target=target,
                    validation=existing,
                    run_id=run_id,
                    run_kind=run_kind,
                    commit=commit,
                    host_fingerprint_sha256=host_fingerprint_sha256,
                )
                previous_record = report["targets"].get(target.id)
                if not isinstance(previous_record, dict):
                    attestation_errors.append(
                        f"{target.id}: target is absent from the prior campaign index"
                    )
                elif previous_record.get("run_attestation_sha256") != attestation_hash:
                    attestation_errors.append(
                        f"{target.id}: campaign index attestation hash mismatch"
                    )
                if attestation_errors:
                    raise CampaignError(
                        f"cannot resume {target.id}: " + "; ".join(attestation_errors)
                    )
                print(f"[native-timing] resume: {target.id} artifacts already complete")
                validations.append(existing)
                record = existing.as_dict()
                record["run_attestation_sha256"] = attestation_hash
                report["targets"][target.id] = record
                _write_json_atomic(report_path, report)
                continue
            raise CampaignError(
                f"cannot resume {target.id}: existing artifacts are corrupt: {existing.errors}"
            )

        print(f"[native-timing] execute: {target.id} ({', '.join(target.harnesses)})")
        try:
            cfg = load_config(target.config)
            dudect = campaign_dudect(
                cfg,
                campaign,
                target,
                target_root / "generated",
            )
            _do_dudect(
                dudect,
                target.config.parent,
                cfg.project.name,
                report_dir,
                config_path=target.config,
            )
            validation = validate_target_artifacts(
                campaign,
                target,
                report_dir,
                host_paper_eligible=host_paper_eligible,
                host_preflight=preflight_report,
                run_kind=run_kind,
            )
        except BaseException as exc:
            if isinstance(exc, KeyboardInterrupt):
                report["status"] = "interrupted"
                report["finished_at"] = _utc_now()
                _write_json_atomic(report_path, report)
                raise
            validation = TargetValidation(target=target, report_dir=report_dir)
            validation.errors.append(f"execution failed: {exc}")
        validations.append(validation)
        attestation_hash = None
        if validation.complete:
            attestation_path = target_root / TARGET_ATTESTATION
            _write_json_atomic(
                attestation_path,
                _target_attestation_payload(
                    campaign=campaign,
                    target=target,
                    validation=validation,
                    run_id=run_id,
                    run_kind=run_kind,
                    commit=commit,
                    host_fingerprint_sha256=host_fingerprint_sha256,
                ),
            )
            attestation_hash = _sha256(attestation_path)
        record = validation.as_dict()
        record["run_attestation_sha256"] = attestation_hash
        report["targets"][target.id] = record
        _write_json_atomic(report_path, report)
        write_updates(
            output_root / "corpus_timing_updates.csv",
            [validation],
            merge=True,
        )
        if validation.errors:
            execution_failed = True
            print(
                f"[native-timing] ERROR {target.id}: " + "; ".join(validation.errors),
                file=sys.stderr,
            )
            if not continue_on_error:
                break
        elif validation.promotion_ready:
            print(f"[native-timing] {target.id}: promotion-ready")
        else:
            print(
                f"[native-timing] {target.id}: complete but non-promotable — "
                + "; ".join(validation.blockers)
            )

    report["finished_at"] = _utc_now()
    all_complete = all(
        bool(report["targets"].get(target_id, {}).get("complete"))
        for target_id in report["selected_targets"]
    )
    paper_promotion_ready = all_complete and all(
        bool(report["targets"][target_id].get("promotion_ready"))
        for target_id in report["selected_targets"]
    )
    report["paper_promotion_ready"] = paper_promotion_ready
    if execution_failed:
        report["status"] = "failed"
    elif not all_complete:
        report["status"] = "partial"
    else:
        report["status"] = "complete"
    _write_json_atomic(report_path, report)
    write_updates(
        output_root / "corpus_timing_updates.csv",
        validations,
        merge=resume,
    )
    if execution_failed:
        return 1
    if run_kind != "final":
        return 0 if all_complete else 1
    return 0 if paper_promotion_ready else 2


def validate_run(
    campaign: CampaignSpec,
    output_root: Path,
    selected: tuple[TargetSpec, ...],
    *,
    expected_commit: str | None = None,
    expected_run_kind: str | None = None,
) -> int:
    output_root = _safe_output_root(output_root)
    report_path = output_root / "campaign_report.json"
    if not report_path.is_file():
        raise CampaignError(f"campaign report missing: {report_path}")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CampaignError(f"campaign report unreadable: {exc}") from exc
    if not isinstance(report, dict):
        raise CampaignError("campaign report root must be an object")
    if report.get("schema_version") != "2.0" or report.get("campaign_id") != campaign.campaign_id:
        raise CampaignError("campaign report identity/schema mismatch")
    if report.get("kind") != "native-timing-campaign-report":
        raise CampaignError("campaign report kind mismatch")
    if report.get("manifest_sha256") != campaign.manifest_sha256:
        raise CampaignError("campaign report manifest hash does not match current manifest")
    run_kind = report.get("run_kind")
    if run_kind not in RUN_KINDS:
        raise CampaignError("campaign report run_kind is invalid")
    if expected_run_kind is not None and run_kind != expected_run_kind:
        raise CampaignError("campaign report run_kind differs from expected kind")
    run_id = report.get("run_id")
    if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise CampaignError("campaign report run_id is malformed")
    recorded_selected = report.get("selected_targets")
    if not isinstance(recorded_selected, list) or any(
        not isinstance(value, str) for value in recorded_selected
    ):
        raise CampaignError("campaign report selected_targets must be a string list")
    requested_ids = {target.id for target in selected}
    if not requested_ids <= set(recorded_selected):
        raise CampaignError(
            "selected validation targets were not recorded as executed by this campaign"
        )
    target_index = report.get("targets")
    if not isinstance(target_index, dict):
        raise CampaignError("campaign report targets must be an object")
    host_preflight = report.get("host_preflight")
    report_commit = report.get("ctkat_commit")
    if not isinstance(report_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", report_commit):
        raise CampaignError("campaign report ctkat_commit must be a full git hash")
    if expected_commit is not None and report_commit != expected_commit:
        raise CampaignError("campaign report ctkat_commit differs from expected frozen commit")
    host_eligible, host_errors = validate_preflight_report(
        campaign,
        host_preflight,
        expected_commit=report_commit,
    )
    if host_errors:
        raise CampaignError("campaign host preflight is invalid: " + "; ".join(host_errors))
    host_fingerprint_sha256 = _host_fingerprint(host_preflight)
    if report.get("host_fingerprint_sha256") != host_fingerprint_sha256:
        raise CampaignError("campaign host fingerprint does not match its preflight")
    if run_kind == "final":
        human_gate = report.get("human_review_gate")
        automated_gate = report.get("automated_premeasurement_gate")
        if human_gate is not None and automated_gate is not None:
            raise CampaignError("final campaign claims both human and automated gates")
        gate_errors = (
            _validate_single_host_premeasurement_gate(
                automated_gate,
                expected_commit=report_commit,
                allow_governance_only_head=True,
            )
            if automated_gate is not None
            else _validate_human_premeasurement_gate(
                human_gate,
                expected_commit=report_commit,
                allow_review_only_head=True,
            )
        )
        if gate_errors:
            raise CampaignError("; ".join(gate_errors))
    elif (
        report.get("human_review_gate") is not None
        or report.get("automated_premeasurement_gate") is not None
    ):
        raise CampaignError("non-final campaign must not claim a premeasurement gate")
    validations = [
        validate_target_artifacts(
            campaign,
            target,
            output_root / target.id / "reports",
            host_paper_eligible=host_eligible,
            host_preflight=host_preflight,
            run_kind=run_kind,
        )
        for target in selected
    ]
    attestation_errors: list[str] = []
    for target, validation in zip(selected, validations, strict=True):
        attestation_hash, current_errors = _validate_target_attestation(
            output_root / target.id / TARGET_ATTESTATION,
            campaign=campaign,
            target=target,
            validation=validation,
            run_id=run_id,
            run_kind=run_kind,
            commit=report_commit,
            host_fingerprint_sha256=host_fingerprint_sha256,
        )
        attestation_errors.extend(current_errors)
        recorded = target_index.get(target.id)
        if not isinstance(recorded, dict):
            attestation_errors.append(f"{target.id}: campaign target index entry is missing")
            continue
        if recorded.get("run_attestation_sha256") != attestation_hash:
            attestation_errors.append(f"{target.id}: recorded target attestation hash mismatch")
        if recorded.get("artifact_sha256") != validation.artifact_sha256:
            attestation_errors.append(f"{target.id}: recorded artifact hashes mismatch")
        if recorded.get("complete") is not validation.complete:
            attestation_errors.append(f"{target.id}: recorded completeness mismatch")
        if recorded.get("promotion_ready") is not validation.promotion_ready:
            attestation_errors.append(f"{target.id}: recorded promotion state mismatch")
    update_errors = validate_updates(
        output_root / "corpus_timing_updates.csv",
        validations,
    )
    for validation in validations:
        if validation.errors:
            print(
                f"[native-timing] ERROR {validation.target.id}: " + "; ".join(validation.errors),
                file=sys.stderr,
            )
        elif validation.promotion_ready:
            print(f"[native-timing] {validation.target.id}: artifacts valid, promotion-ready")
        else:
            print(
                f"[native-timing] {validation.target.id}: artifacts valid, non-promotable — "
                + "; ".join(validation.blockers)
            )
    if any(validation.errors for validation in validations):
        return 1
    for error in attestation_errors:
        print(f"[native-timing] ERROR: {error}", file=sys.stderr)
    if attestation_errors:
        return 1
    for error in update_errors:
        print(f"[native-timing] ERROR: {error}", file=sys.stderr)
    if update_errors:
        return 1
    all_complete = all(validation.complete for validation in validations)
    promotion_ready = all_complete and all(validation.promotion_ready for validation in validations)
    if report.get("status") != "complete":
        print("[native-timing] ERROR: campaign report status is not complete", file=sys.stderr)
        return 1
    if report.get("paper_promotion_ready") is not promotion_ready:
        print("[native-timing] ERROR: campaign promotion state mismatch", file=sys.stderr)
        return 1
    if run_kind != "final":
        return 0 if all_complete else 1
    return 0 if promotion_ready else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true", help="static manifest/config/corpus check")
    action.add_argument("--preflight", action="store_true", help="native host gate only")
    action.add_argument("--execute", action="store_true", help="run the selected campaign targets")
    action.add_argument(
        "--validate-run",
        type=Path,
        metavar="OUTPUT_ROOT",
        help="validate an existing campaign without executing targets",
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--cpu", type=int, help="explicitly pin this process and children")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--continue-on-error", action="store_true")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--allow-virtualized", action="store_true")
    parser.add_argument(
        "--expected-commit",
        help="require --validate-run evidence to match this frozen 40-hex commit",
    )
    parser.add_argument(
        "--run-kind",
        choices=RUN_KINDS,
        help="required for execution; engineering and pilot runs are never promotable",
    )
    parser.add_argument(
        "--expected-run-kind",
        choices=RUN_KINDS,
        help="require --validate-run evidence to have this run kind",
    )
    parser.add_argument(
        "--final-gate",
        choices=("human", "single-host"),
        default="human",
        help="final promotion gate; single-host is automated and claims no independent review",
    )
    args = parser.parse_args(argv)

    try:
        campaign = load_campaign(args.manifest)
        errors = static_check(campaign)
        if errors:
            for error in errors:
                print(f"[native-timing] ERROR: {error}", file=sys.stderr)
            return 1
        selected = _select_targets(campaign, args.target)
        if args.check:
            _print_static_plan(campaign)
            return 0
        if args.cpu is not None:
            pin_current_process(args.cpu)
        if args.validate_run is not None:
            if args.expected_commit is not None and not re.fullmatch(
                r"[0-9a-f]{40}", args.expected_commit
            ):
                parser.error("--expected-commit must be a full lowercase 40-hex commit")
            return validate_run(
                campaign,
                args.validate_run,
                selected,
                expected_commit=args.expected_commit,
                expected_run_kind=args.expected_run_kind,
            )

        host = preflight(
            campaign,
            allow_dirty=args.allow_dirty,
            allow_virtualized=args.allow_virtualized,
            build_adapter=True,
        )
        print(json.dumps(host, indent=2, sort_keys=True))
        if not host["ok"]:
            return 1
        if args.preflight:
            return 0
        if args.output_root is None:
            parser.error("--execute requires --output-root")
        if args.run_kind is None:
            parser.error("--execute requires --run-kind")
        review_gate = None
        automated_gate = None
        if args.run_kind == "final":
            if args.final_gate == "single-host":
                automated_gate = _single_host_premeasurement_gate(str(host["git_commit"]))
            else:
                review_gate = _human_premeasurement_gate(str(host["git_commit"]))
        return execute_campaign(
            campaign,
            args.output_root,
            selected,
            preflight_report=host,
            run_kind=args.run_kind,
            review_gate=review_gate,
            resume=args.resume,
            continue_on_error=args.continue_on_error,
            automated_gate=automated_gate,
        )
    except CampaignError as exc:
        print(f"[native-timing] ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
