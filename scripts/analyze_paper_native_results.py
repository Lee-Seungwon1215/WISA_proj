#!/usr/bin/env python3
"""Fail-closed, deterministic analysis of the native paper campaign.

The primary dudect decision is never replaced by the secondary analyses in
this file.  In particular, a valid finding on either physical host keeps the
combined axis at risk.  Pairwise, heterogeneity, and signature-length results
are reported as diagnostics only.
"""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import math
import os
import re
import statistics
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctkat.timing_input_contract import (  # noqa: E402
    validate_operand_v3_harness_report,
    validate_valid_tuple_harness_report,
)

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
POST_VERIFICATION_ALLOWED_PATH = "docs/reviews/paper/native-promotion-v2.yaml"


class AnalysisError(RuntimeError):
    """The final artifact or the frozen analysis contract is invalid."""


@dataclass(frozen=True, order=True)
class AxisKey:
    component: str
    target: str
    harness: str


@dataclass(frozen=True)
class ComponentPlan:
    component: str
    manifest: Path
    campaign_id: str


@dataclass(frozen=True)
class BlindingMap:
    bundle_id: str
    scope: str
    labels: tuple[tuple[str, str, str], ...]

    @property
    def by_pair(self) -> dict[tuple[str, str], str]:
        return {(component, target): opaque for opaque, component, target in self.labels}

    @property
    def sha256(self) -> str:
        canonical = [
            {"opaque_label": opaque, "component": component, "target": target}
            for opaque, component, target in sorted(self.labels)
        ]
        return hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()


@dataclass
class SignatureAssociation:
    n: int = 0
    minimum_length: int | None = None
    maximum_length: int | None = None
    unique_lengths: set[int] = field(default_factory=set)
    sum_x: float = 0.0
    sum_y: float = 0.0
    sum_xx: float = 0.0
    sum_yy: float = 0.0
    sum_xy: float = 0.0
    by_class: dict[int, list[float]] = field(default_factory=dict)
    mean_x: float = 0.0
    mean_y: float = 0.0
    m2_x: float = 0.0
    m2_y: float = 0.0
    co_moment: float = 0.0

    def add(self, length: int, cycles: float, clazz: int) -> None:
        self.n += 1
        self.minimum_length = (
            length if self.minimum_length is None else min(self.minimum_length, length)
        )
        self.maximum_length = (
            length if self.maximum_length is None else max(self.maximum_length, length)
        )
        self.unique_lengths.add(length)
        x = float(length)
        self.sum_x += x
        self.sum_y += cycles
        self.sum_xx += x * x
        self.sum_yy += cycles * cycles
        self.sum_xy += x * cycles
        delta_x = x - self.mean_x
        self.mean_x += delta_x / self.n
        delta_y = cycles - self.mean_y
        self.mean_y += delta_y / self.n
        self.m2_x += delta_x * (x - self.mean_x)
        self.m2_y += delta_y * (cycles - self.mean_y)
        self.co_moment += delta_x * (cycles - self.mean_y)
        bucket = self.by_class.setdefault(clazz, [0.0] * 6)
        bucket[0] += 1.0
        class_count = bucket[0]
        class_delta_x = x - bucket[1]
        bucket[1] += class_delta_x / class_count
        class_delta_y = cycles - bucket[2]
        bucket[2] += class_delta_y / class_count
        bucket[3] += class_delta_x * (x - bucket[1])
        bucket[4] += class_delta_y * (cycles - bucket[2])
        bucket[5] += class_delta_x * (cycles - bucket[2])

    def result(self) -> dict[str, Any]:
        base: dict[str, Any] = {
            "retained_samples": self.n,
            "minimum_output_length": self.minimum_length,
            "maximum_output_length": self.maximum_length,
            "unique_output_lengths": len(self.unique_lengths),
        }
        if self.n < 3:
            return {
                **base,
                "status": "insufficient-data",
                "pearson_r": None,
                "p_value": None,
                "slope_cycles_per_byte": None,
                "within_class_pearson_r": None,
                "within_class_p_value": None,
            }
        if len(self.unique_lengths) == 1:
            return {
                **base,
                "status": "constant-length",
                "pearson_r": None,
                "p_value": None,
                "slope_cycles_per_byte": None,
                "within_class_pearson_r": None,
                "within_class_p_value": None,
            }
        r = _correlation(self.co_moment, self.m2_x, self.m2_y)
        slope = self.co_moment / self.m2_x if self.m2_x > 0 else None
        centered_x_ss = sum(bucket[3] for bucket in self.by_class.values())
        centered_y_ss = sum(bucket[4] for bucket in self.by_class.values())
        centered_cov = sum(bucket[5] for bucket in self.by_class.values())
        within_r = _correlation(centered_cov, centered_x_ss, centered_y_ss)
        return {
            **base,
            "status": "variable-length",
            "pearson_r": r,
            "p_value": _correlation_p_value(r, self.n),
            "slope_cycles_per_byte": slope,
            "within_class_pearson_r": within_r,
            "within_class_p_value": _correlation_p_value(
                within_r,
                self.n,
                fitted_parameters=len(self.by_class) + 1,
            ),
        }


@dataclass(frozen=True)
class HostAxis:
    key: AxisKey
    family: str
    axis: str
    host_id: str
    cpu_model: str
    machine_id_sha256: str
    raw_status: str
    timing_validity: str
    timing_signal: str
    t_score: float | None
    abs_t_score: float
    n0: int
    n1: int
    repeat_deltas: tuple[float, ...]
    signature: dict[str, Any] | None


COMPONENT_PLANS = {
    "committed-corpus-refresh": ComponentPlan(
        "committed-corpus-refresh",
        ROOT / "docs/measurement/native_timing_v5_campaign.yaml",
        "corpus-native-timing-v5",
    ),
    "kyberslash-contrast": ComponentPlan(
        "kyberslash-contrast",
        ROOT / "docs/measurement/kyberslash_native_v5.yaml",
        "kyberslash-native-v5",
    ),
    "falcon-contrast": ComponentPlan(
        "falcon-contrast",
        ROOT / "docs/measurement/falcon_native_v4.yaml",
        "falcon-native-v4",
    ),
    "diverse-lineages": ComponentPlan(
        "diverse-lineages",
        ROOT / "docs/measurement/diverse_native_v4.yaml",
        "diverse-native-v4",
    ),
}

PAIRWISE_FAMILIES: dict[str, tuple[AxisKey, ...]] = {
    "kyberslash-full-kem-chosen-ct": tuple(
        AxisKey("kyberslash-contrast", target, "kem_dec_chosen_ct")
        for target in (
            "pqclean_mlkem768",
            "pqclean_mlkem768_kyberslash1",
            "pqclean_mlkem768_kyberslash2",
            "pqclean_mlkem768_kyberslash",
        )
    ),
    "kyberslash-ks1-operand": tuple(
        AxisKey("kyberslash-contrast", target, "operand_bin")
        for target in (
            "kyberslash_operand_ks1_vulnerable",
            "kyberslash_operand_ks1_patched",
        )
    ),
    "kyberslash-ks2-poly-operand": tuple(
        AxisKey("kyberslash-contrast", target, "operand_bin")
        for target in (
            "kyberslash_operand_ks2_poly_vulnerable",
            "kyberslash_operand_ks2_poly_patched",
        )
    ),
    "kyberslash-ks2-polyvec-operand": tuple(
        AxisKey("kyberslash-contrast", target, "operand_bin")
        for target in (
            "kyberslash_operand_ks2_polyvec_vulnerable",
            "kyberslash_operand_ks2_polyvec_patched",
        )
    ),
    "falcon-512": tuple(
        AxisKey("falcon-contrast", target, "sign")
        for target in (
            "pqclean_falcon512_reference",
            "c_fndsa512_native_fp",
            "c_fndsa512_fpr_emu",
        )
    ),
    "falcon-1024": tuple(
        AxisKey("falcon-contrast", target, "sign")
        for target in (
            "pqclean_falcon1024_reference",
            "c_fndsa1024_native_fp",
            "c_fndsa1024_fpr_emu",
        )
    ),
    "mlkem-native-valid-tuple": (
        AxisKey("diverse-lineages", "mlkem_native_768_portable", "kem_dec_valid_tuple"),
        AxisKey("diverse-lineages", "mlkem_native_768_x86_64", "kem_dec_valid_tuple"),
    ),
    "mldsa-native": (
        AxisKey("diverse-lineages", "mldsa_native_65_portable", "sign"),
        AxisKey("diverse-lineages", "mldsa_native_65_x86_64", "sign"),
    ),
}

REQUIRED_TARGET_ARTIFACTS = {
    "dudect_raw_timings.csv",
    "dudect_calibration_timings.csv",
    "dudect_protocol_timings.csv",
    "dudect_summary.csv",
    "dudect_backend_report.json",
}
RETURN_CODE_ALIASES = (
    "signature_return_code",
    "operation_return_code",
    "return_code",
    "sig_rc",
)
RISK_STATUSES = {"FAIL"}
RAW_STATUSES = {"PASS", "WARNING", "FAIL"}
HETEROGENEITY_I2_WARNING = 75.0


class InputLedger:
    def __init__(self) -> None:
        self._items: dict[str, dict[str, Any]] = {}

    def add(self, label: str, path: Path) -> str:
        digest = _sha256(path)
        record = {
            "label": label,
            "sha256": digest,
            "bytes": path.stat().st_size,
        }
        if label in self._items:
            if self._items[label] != record:
                raise AnalysisError(f"input ledger label changed content: {label}")
            return digest
        self._items[label] = record
        return digest

    def records(self) -> list[dict[str, Any]]:
        return [self._items[key] for key in sorted(self._items)]

    def aggregate_sha256(self) -> str:
        digest = hashlib.sha256()
        for item in self.records():
            digest.update(item["label"].encode("utf-8"))
            digest.update(b"\0")
            digest.update(item["sha256"].encode("ascii"))
            digest.update(b"\0")
            digest.update(str(item["bytes"]).encode("ascii"))
            digest.update(b"\n")
        return digest.hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalysisError(f"{label} is unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise AnalysisError(f"{label} must be a JSON object")
    return value


def _safe_child(root: Path, relative: Any, label: str, *, directory: bool) -> Path:
    if not isinstance(relative, str) or not relative:
        raise AnalysisError(f"{label} must be a non-empty relative path")
    raw = Path(relative)
    if raw.is_absolute() or ".." in raw.parts:
        raise AnalysisError(f"{label} must not escape its component root")
    root = root.resolve()
    candidate = root / raw
    if candidate.is_symlink() or any(
        parent.is_symlink()
        for parent in candidate.parents
        if parent != root and parent.is_relative_to(root)
    ):
        raise AnalysisError(f"{label} contains a symlink")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root):
        raise AnalysisError(f"{label} escapes its component root")
    valid = resolved.is_dir() if directory else resolved.is_file()
    if not valid:
        kind = "directory" if directory else "file"
        raise AnalysisError(f"{label} {kind} is missing")
    return resolved


def _safe_future_child(root: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise AnalysisError(f"{label} must be a non-empty relative path")
    raw = Path(relative)
    if raw.is_absolute() or ".." in raw.parts:
        raise AnalysisError(f"{label} must not escape the bundle root")
    root = root.resolve()
    candidate = root / raw
    if candidate.is_symlink() or any(
        parent.is_symlink()
        for parent in candidate.parents
        if parent != root and parent.is_relative_to(root)
    ):
        raise AnalysisError(f"{label} contains a symlink")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root):
        raise AnalysisError(f"{label} escapes the bundle root")
    return resolved


def _select_blinding_record(
    declared_path: Path,
    override: Path | None,
    *,
    allow_external_draft: bool,
) -> Path:
    """Select a regular record without letting final analysis change provenance."""

    if override is not None:
        selected = override.resolve()
        if override.is_symlink() or not selected.is_file():
            raise AnalysisError("--blinding-record is missing or is a symlink")
        if not allow_external_draft and selected != declared_path.resolve():
            raise AnalysisError(
                "unblinded --blinding-record must be the exact record frozen in the bundle"
            )
        return selected
    if declared_path.is_symlink() or not declared_path.is_file():
        raise AnalysisError("bundle blinding record is missing or is a symlink")
    return declared_path.resolve()


def _finite_float(value: Any, label: str, *, optional: bool = False) -> float | None:
    if value is None and optional:
        return None
    if isinstance(value, bool):
        raise AnalysisError(f"{label} must be a finite number")
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise AnalysisError(f"{label} must be a finite number") from exc
    if not math.isfinite(result):
        raise AnalysisError(f"{label} must be a finite number")
    return result


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool):
        raise AnalysisError(f"{label} must be an integer >= {minimum}")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise AnalysisError(f"{label} must be an integer >= {minimum}") from exc
    if str(result) != str(value).strip() and not isinstance(value, int):
        raise AnalysisError(f"{label} must be a canonical integer")
    if result < minimum:
        raise AnalysisError(f"{label} must be an integer >= {minimum}")
    return result


def _manifest_contract(plan: ComponentPlan) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = yaml.safe_load(plan.manifest.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("campaign_id") != plan.campaign_id:
        raise AnalysisError(f"{plan.component}: local campaign manifest identity drift")
    protocol = raw.get("protocol")
    targets = raw.get("targets")
    if not isinstance(protocol, dict) or not isinstance(targets, list):
        raise AnalysisError(f"{plan.component}: malformed local campaign manifest")
    target_index: dict[str, Any] = {}
    for entry in targets:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise AnalysisError(f"{plan.component}: malformed target entry")
        target_id = entry["id"]
        if target_id in target_index:
            raise AnalysisError(f"{plan.component}: duplicate target {target_id}")
        harnesses = entry.get("harnesses")
        axes = entry.get("axes")
        if not isinstance(harnesses, list) or not isinstance(axes, dict):
            raise AnalysisError(f"{plan.component}.{target_id}: malformed harness contract")
        target_index[target_id] = entry
    return protocol, target_index


def _signature_metadata(
    item: Mapping[str, Any],
    lengths: set[int],
    label: str,
) -> dict[str, Any]:
    protocol = item.get("harness_protocol")
    if not isinstance(protocol, dict):
        raise AnalysisError(f"{label}: harness_protocol is missing")
    repeats = protocol.get("target_repeats")
    if not isinstance(repeats, list) or not repeats:
        raise AnalysisError(f"{label}: signature target repeat metadata is missing")
    metadata_values: list[dict[str, Any]] = []
    for index, repeat in enumerate(repeats):
        metadata = repeat.get("runtime_metadata") if isinstance(repeat, dict) else None
        if not isinstance(metadata, dict):
            raise AnalysisError(f"{label}: target repeat {index} runtime metadata is missing")
        metadata_values.append(metadata)
    analysis_metadata = item.get("analysis_runtime_metadata")
    if not isinstance(analysis_metadata, dict):
        raise AnalysisError(f"{label}: analysis runtime metadata is missing")
    metadata_values.append(analysis_metadata)

    contracts: set[tuple[str, int, int]] = set()
    for index, metadata in enumerate(metadata_values):
        prefix = f"{label}: signature runtime metadata {index}"
        if metadata.get("signature_return_code_recorded") not in {True, "true"}:
            raise AnalysisError(f"{prefix} does not record return codes")
        if metadata.get("signature_correctness_gate") != "passed":
            raise AnalysisError(f"{prefix} correctness gate did not pass")
        if (
            _integer(
                metadata.get("measured_signature_contract_failures"),
                f"{prefix}.measured_signature_contract_failures",
            )
            != 0
        ):
            raise AnalysisError(f"{prefix} recorded a signature contract failure")
        contract = metadata.get("signature_length_contract")
        if contract not in {"fixed", "bounded"}:
            raise AnalysisError(f"{prefix} length contract is invalid")
        minimum = _integer(
            metadata.get("signature_length_min"),
            f"{prefix}.signature_length_min",
            minimum=1,
        )
        maximum = _integer(
            metadata.get("signature_length_max"),
            f"{prefix}.signature_length_max",
            minimum=1,
        )
        if maximum < minimum or (contract == "fixed" and maximum != minimum):
            raise AnalysisError(f"{prefix} length bounds contradict the contract")
        contracts.add((contract, minimum, maximum))
    if len(contracts) != 1:
        raise AnalysisError(f"{label}: signature contract differs across process repeats")
    contract, minimum, maximum = next(iter(contracts))
    if not lengths or any(length < minimum or length > maximum for length in lengths):
        raise AnalysisError(f"{label}: observed output length violates runtime bounds")
    if contract == "fixed" and lengths != {minimum}:
        raise AnalysisError(f"{label}: fixed-length signature trace varied")
    aggregate = protocol.get("signature_call_contract")
    if not isinstance(aggregate, dict):
        raise AnalysisError(f"{label}: aggregate signature call contract is missing")
    if (
        aggregate.get("configured") != contract
        or aggregate.get("return_code_column") != "signature_return_code"
        or aggregate.get("return_code_success") != 0
        or aggregate.get("return_codes_recorded") is not True
        or aggregate.get("correctness_round_trip_gate") is not True
        or aggregate.get("measured_contract_failures") != 0
        or aggregate.get("resolved_min") != minimum
        or aggregate.get("resolved_max") != maximum
        or aggregate.get("passed") is not True
    ):
        raise AnalysisError(f"{label}: aggregate signature call contract did not pass")
    return {"contract": contract, "minimum": minimum, "maximum": maximum}


def _parse_protocol(
    path: Path,
    *,
    project: str,
    harnesses: Sequence[str],
    sign_harnesses: set[str],
    process_repeats: int,
    target_measurements: int,
) -> tuple[dict[str, tuple[float, ...]], dict[str, SignatureAssociation], str | None]:
    class_sums: dict[tuple[str, int, int], list[float]] = {}
    target_rows: dict[tuple[str, int], int] = {}
    signatures = {name: SignatureAssociation() for name in sign_harnesses}
    return_column: str | None = None
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or [])
        required = {
            "project",
            "harness",
            "role",
            "process_index",
            "class",
            "cycles",
            "drop_reason",
            "output_length",
            "protocol",
        }
        if not required <= fields:
            raise AnalysisError(
                f"{path.name}: missing protocol columns {sorted(required - fields)}"
            )
        if sign_harnesses:
            return_column = next((name for name in RETURN_CODE_ALIASES if name in fields), None)
            if return_column is None:
                raise AnalysisError(f"{path.name}: signature return-code column is missing")
        expected_harnesses = set(harnesses)
        for number, row in enumerate(reader, start=2):
            harness = row["harness"]
            if row["project"] != project or harness not in expected_harnesses:
                raise AnalysisError(f"{path.name}:{number}: project/harness identity drift")
            if row["protocol"] != "timing-harness-v2":
                raise AnalysisError(f"{path.name}:{number}: protocol identity drift")
            process_index = _integer(row["process_index"], f"{path.name}:{number}.process_index")
            if process_index >= process_repeats:
                raise AnalysisError(f"{path.name}:{number}: process index is outside the plan")
            clazz = _integer(row["class"], f"{path.name}:{number}.class")
            if clazz not in {0, 1}:
                raise AnalysisError(f"{path.name}:{number}: class must be 0 or 1")
            if harness in sign_harnesses:
                assert return_column is not None
                rc = _integer(
                    row[return_column],
                    f"{path.name}:{number}.{return_column}",
                    minimum=-(2**31),
                )
                if rc != 0:
                    raise AnalysisError(
                        f"{path.name}:{number}: signature API returned nonzero ({rc})"
                    )
            if row["role"] != "target":
                continue
            target_key = (harness, process_index)
            target_rows[target_key] = target_rows.get(target_key, 0) + 1
            if row["drop_reason"]:
                continue
            cycles = _finite_float(row["cycles"], f"{path.name}:{number}.cycles")
            assert cycles is not None
            if cycles <= 0:
                raise AnalysisError(f"{path.name}:{number}: retained cycles must be positive")
            bucket = class_sums.setdefault((harness, process_index, clazz), [0.0, 0.0])
            bucket[0] += 1.0
            bucket[1] += cycles
            if harness in sign_harnesses:
                length = _integer(
                    row["output_length"],
                    f"{path.name}:{number}.output_length",
                    minimum=1,
                )
                signatures[harness].add(length, cycles, clazz)

    expected_keys = {
        (harness, process_index)
        for harness in harnesses
        for process_index in range(process_repeats)
    }
    if set(target_rows) != expected_keys or any(
        target_rows[key] != target_measurements for key in expected_keys
    ):
        raise AnalysisError(f"{path.name}: target repeat row counts differ from the manifest")
    deltas: dict[str, tuple[float, ...]] = {}
    for harness in harnesses:
        values: list[float] = []
        for process_index in range(process_repeats):
            zero = class_sums.get((harness, process_index, 0))
            one = class_sums.get((harness, process_index, 1))
            if zero is None or one is None or zero[0] < 2 or one[0] < 2:
                raise AnalysisError(
                    f"{path.name}: {harness} repeat {process_index} lacks retained classes"
                )
            values.append(one[1] / one[0] - zero[1] / zero[0])
        deltas[harness] = tuple(values)
    return deltas, signatures, return_column


def _signal(raw_status: str) -> str:
    return {
        "PASS": "no-signal-observed",
        "WARNING": "warning",
        "FAIL": "signal",
    }[raw_status]


def _single_host_qualification_fingerprint(
    gate: Mapping[str, Any],
    *,
    expected_commit: str,
    label: str,
) -> str:
    qualification = gate.get("control_qualification")
    run_ids = qualification.get("rehearsal_run_ids") if isinstance(qualification, dict) else None
    report_hashes = (
        qualification.get("rehearsal_report_sha256") if isinstance(qualification, dict) else None
    )
    if (
        gate.get("ctkat_commit") != expected_commit
        or gate.get("plan_id") != "ctkat-paper-native-v10-single-host"
        or not isinstance(qualification, dict)
        or qualification.get("kind") != "two-clean-control-rehearsal-qualification"
        or qualification.get("ready") is not True
        or qualification.get("profile_id") != "ctkat-paper-control-rehearsal-v3"
        or any(
            not isinstance(qualification.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", qualification.get(field, ""))
            for field in ("sha256", "profile_sha256", "calibration_sha256")
        )
        or not isinstance(run_ids, list)
        or len(run_ids) != 2
        or len(set(run_ids)) != 2
        or any(
            not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id)
            for run_id in run_ids
        )
        or not isinstance(report_hashes, dict)
        or len(report_hashes) != 2
        or any(
            not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
            for value in report_hashes.values()
        )
    ):
        raise AnalysisError(f"{label}: V10 control qualification is missing or malformed")
    return json.dumps(qualification, sort_keys=True, separators=(",", ":"))


def load_host_axes(
    host: Mapping[str, Any],
    expected_commit: str,
    ledger: InputLedger,
    *,
    component_plans: Mapping[str, ComponentPlan] = COMPONENT_PLANS,
    required_gate_kind: str = "human-premeasurement-review-gate",
) -> list[HostAxis]:
    host_id = host.get("id")
    cpu_model = host.get("cpu_model")
    machine_id = host.get("machine_id_sha256")
    component_roots = host.get("components")
    if not isinstance(host_id, str) or not host_id:
        raise AnalysisError("host id is missing")
    if not isinstance(cpu_model, str) or not cpu_model:
        raise AnalysisError(f"{host_id}: CPU model is missing")
    if not isinstance(machine_id, str) or not re.fullmatch(r"[0-9a-f]{64}", machine_id):
        raise AnalysisError(f"{host_id}: machine identity is missing")
    if not isinstance(component_roots, dict) or set(component_roots) != set(component_plans):
        raise AnalysisError(f"{host_id}: component set differs from the analysis plan")

    observations: list[HostAxis] = []
    qualification_fingerprints: set[str] = set()
    for component in sorted(component_plans):
        plan = component_plans[component]
        component_root = Path(str(component_roots[component])).resolve()
        if not component_root.is_dir() or component_root.is_symlink():
            raise AnalysisError(f"{host_id}.{component}: component root is invalid")
        manifest_protocol, manifest_targets = _manifest_contract(plan)
        ledger.add(f"plan/{component}/manifest", plan.manifest)
        report_path = _safe_child(
            component_root, "campaign_report.json", f"{host_id}.{component}.report", directory=False
        )
        ledger.add(f"{host_id}/{component}/campaign_report.json", report_path)
        report = _read_json(report_path, f"{host_id}.{component}.campaign_report")
        if (
            report.get("schema_version") != "2.0"
            or report.get("kind") != "native-timing-campaign-report"
        ):
            raise AnalysisError(f"{host_id}.{component}: campaign report kind drift")
        if report.get("campaign_id") != plan.campaign_id:
            raise AnalysisError(f"{host_id}.{component}: campaign id drift")
        if report.get("manifest_sha256") != _sha256(plan.manifest):
            raise AnalysisError(f"{host_id}.{component}: campaign manifest hash drift")
        if report.get("ctkat_commit") != expected_commit:
            raise AnalysisError(f"{host_id}.{component}: CT-KAT commit mismatch")
        if report.get("run_kind") != "final":
            raise AnalysisError(f"{host_id}.{component}: only run_kind=final is admissible")
        if report.get("status") != "complete":
            raise AnalysisError(f"{host_id}.{component}: campaign is not complete")
        if report.get("paper_promotion_ready") is not True:
            raise AnalysisError(f"{host_id}.{component}: campaign is not paper-promotion ready")
        if not isinstance(report.get("run_id"), str) or not re.fullmatch(
            r"[0-9a-f]{32}", report["run_id"]
        ):
            raise AnalysisError(f"{host_id}.{component}: campaign run id is invalid")
        gate_field = (
            "automated_premeasurement_gate"
            if required_gate_kind == "automated-frozen-input-integrity-gate"
            else "human_review_gate"
        )
        gate = report.get(gate_field)
        if (
            not isinstance(gate, dict)
            or gate.get("kind") != required_gate_kind
            or gate.get("ready") is not True
        ):
            raise AnalysisError(f"{host_id}.{component}: required premeasurement gate is missing")
        if required_gate_kind == "automated-frozen-input-integrity-gate" and (
            gate.get("physical_host_count") != 1
            or gate.get("independent_human_review") is not False
            or gate.get("cross_host_reproducibility") is not False
            or report.get("human_review_gate") is not None
        ):
            raise AnalysisError(f"{host_id}.{component}: single-host scope boundary drift")
        if required_gate_kind == "automated-frozen-input-integrity-gate":
            qualification_fingerprints.add(
                _single_host_qualification_fingerprint(
                    gate,
                    expected_commit=expected_commit,
                    label=f"{host_id}.{component}",
                )
            )
        selected = report.get("selected_targets")
        target_index = report.get("targets")
        if set(selected or []) != set(manifest_targets) or not isinstance(target_index, dict):
            raise AnalysisError(f"{host_id}.{component}: target set differs from the manifest")
        if set(target_index) != set(manifest_targets):
            raise AnalysisError(f"{host_id}.{component}: target report set drift")
        preflight = report.get("host_preflight")
        if not isinstance(preflight, dict) or preflight.get("paper_eligible") is not True:
            raise AnalysisError(f"{host_id}.{component}: final paper-eligible preflight is missing")
        environment = preflight.get("environment")
        virtualization = preflight.get("virtualization")
        if not isinstance(environment, dict) or not isinstance(virtualization, dict):
            raise AnalysisError(f"{host_id}.{component}: host preflight is malformed")
        affinity = environment.get("cpu_affinity")
        boot_id = environment.get("boot_id_sha256")
        if (
            preflight.get("git_commit") != expected_commit
            or preflight.get("git_dirty") is not False
            or environment.get("cpu_model") != cpu_model
            or environment.get("machine_id_sha256") != machine_id
            or environment.get("system") != "Linux"
            or str(environment.get("machine", "")).lower() not in {"x86_64", "amd64"}
            or environment.get("emulated") is not False
            or environment.get("rejected") is not False
            or not isinstance(boot_id, str)
            or not re.fullmatch(r"[0-9a-f]{64}", boot_id)
            or not isinstance(affinity, list)
            or len(affinity) != 1
            or isinstance(affinity[0], bool)
            or not isinstance(affinity[0], int)
            or affinity[0] < 0
            or virtualization.get("vm")
            or virtualization.get("container")
        ):
            raise AnalysisError(f"{host_id}.{component}: physical host identity/preflight drift")

        process_repeats = _integer(
            manifest_protocol.get("process_repeats"), f"{component}.process_repeats", minimum=1
        )
        for target_id in sorted(manifest_targets):
            contract = manifest_targets[target_id]
            target_report = target_index[target_id]
            if not isinstance(target_report, dict):
                raise AnalysisError(
                    f"{host_id}.{component}.{target_id}: target report is malformed"
                )
            if (
                target_report.get("target") != target_id
                or target_report.get("complete") is not True
                or target_report.get("promotion_ready") is not True
                or target_report.get("errors") != []
                or target_report.get("blockers") != []
            ):
                raise AnalysisError(
                    f"{host_id}.{component}.{target_id}: target is not a clean promotion candidate"
                )
            report_dir = _safe_child(
                component_root,
                target_report.get("report_dir"),
                f"{host_id}.{component}.{target_id}.report_dir",
                directory=True,
            )
            artifact_hashes = target_report.get("artifact_sha256")
            if not isinstance(artifact_hashes, dict) or not REQUIRED_TARGET_ARTIFACTS <= set(
                artifact_hashes
            ):
                raise AnalysisError(
                    f"{host_id}.{component}.{target_id}: target artifact hashes are incomplete"
                )
            artifact_paths: dict[str, Path] = {}
            for name, expected_hash in sorted(artifact_hashes.items()):
                if not isinstance(name, str):
                    raise AnalysisError(f"{host_id}.{component}.{target_id}: unsafe artifact name")
                relative = Path(name)
                if relative.is_absolute() or ".." in relative.parts:
                    raise AnalysisError(f"{host_id}.{component}.{target_id}: unsafe artifact name")
                if relative.parts and relative.parts[0] == "generated":
                    if len(relative.parts) != 2:
                        raise AnalysisError(
                            f"{host_id}.{component}.{target_id}: generated artifact depth drift"
                        )
                    artifact_root = report_dir.parent
                elif relative.parts and relative.parts[0] == "binary_contract":
                    if len(relative.parts) != 2:
                        raise AnalysisError(
                            f"{host_id}.{component}.{target_id}: contract artifact depth drift"
                        )
                    artifact_root = report_dir
                elif relative.parts and relative.parts[0] == "build_provenance":
                    if len(relative.parts) != 2:
                        raise AnalysisError(
                            f"{host_id}.{component}.{target_id}: build seal depth drift"
                        )
                    artifact_root = report_dir
                elif len(relative.parts) == 1:
                    artifact_root = report_dir
                else:
                    raise AnalysisError(
                        f"{host_id}.{component}.{target_id}: unrecognized artifact namespace"
                    )
                path = _safe_child(
                    artifact_root,
                    name,
                    f"{host_id}.{component}.{target_id}.{name}",
                    directory=False,
                )
                actual_hash = ledger.add(f"{host_id}/{component}/{target_id}/{name}", path)
                if expected_hash != actual_hash:
                    raise AnalysisError(f"{host_id}.{component}.{target_id}: {name} hash mismatch")
                artifact_paths[name] = path
            backend = _read_json(
                artifact_paths["dudect_backend_report.json"],
                f"{host_id}.{component}.{target_id}.backend",
            )
            if (
                backend.get("kind") != "timing-backend-report"
                or backend.get("project") != target_id
                or backend.get("protocol_trace_sha256")
                != artifact_hashes["dudect_protocol_timings.csv"]
            ):
                raise AnalysisError(
                    f"{host_id}.{component}.{target_id}: backend identity/hash drift"
                )
            harnesses = contract["harnesses"]
            if not isinstance(harnesses, list) or any(
                not isinstance(name, str) for name in harnesses
            ):
                raise AnalysisError(f"{component}.{target_id}: malformed harness list")
            backend_items = backend.get("harnesses")
            if not isinstance(backend_items, list):
                raise AnalysisError(f"{host_id}.{component}.{target_id}: backend harnesses missing")
            by_harness = {
                item.get("harness"): item for item in backend_items if isinstance(item, dict)
            }
            if set(by_harness) != set(harnesses) or len(by_harness) != len(backend_items):
                raise AnalysisError(f"{host_id}.{component}.{target_id}: harness set drift")
            recorded_harnesses = target_report.get("harnesses")
            if not isinstance(recorded_harnesses, list) or any(
                not isinstance(item, dict) for item in recorded_harnesses
            ):
                raise AnalysisError(
                    f"{host_id}.{component}.{target_id}: campaign harness index is malformed"
                )
            campaign_by_harness = {item.get("harness"): item for item in recorded_harnesses}
            if set(campaign_by_harness) != set(harnesses) or len(campaign_by_harness) != len(
                recorded_harnesses
            ):
                raise AnalysisError(
                    f"{host_id}.{component}.{target_id}: campaign harness set drift"
                )
            sign_harnesses = {
                name
                for name in harnesses
                if name == "sign"
                or (
                    isinstance(by_harness[name].get("harness_protocol"), dict)
                    and by_harness[name]["harness_protocol"].get("template") == "sign"
                )
            }
            deltas, signature_accumulators, return_column = _parse_protocol(
                artifact_paths["dudect_protocol_timings.csv"],
                project=target_id,
                harnesses=harnesses,
                sign_harnesses=sign_harnesses,
                process_repeats=process_repeats,
                target_measurements=_integer(
                    contract.get("target_measurements"),
                    f"{component}.{target_id}.target_measurements",
                    minimum=1,
                ),
            )
            axes = contract.get("axes")
            assert isinstance(axes, dict)
            for harness in sorted(harnesses):
                item = by_harness[harness]
                raw_status = item.get("raw_status")
                timing_validity = item.get("timing_validity")
                if raw_status not in RAW_STATUSES or timing_validity != "valid":
                    raise AnalysisError(
                        f"{host_id}.{component}.{target_id}.{harness}: invalid primary result"
                    )
                protocol = item.get("harness_protocol")
                axis = axes.get(harness)
                if not isinstance(protocol, dict) or protocol.get("axis") != axis:
                    raise AnalysisError(f"{host_id}.{component}.{target_id}.{harness}: axis drift")
                build_provenance = protocol.get("build_provenance")
                if not isinstance(build_provenance, dict) or set(build_provenance) != {
                    "passed",
                    "captured_before_measurement",
                    "report",
                    "report_sha256",
                    "generated_source_sha256",
                    "binary_sha256",
                    "config_sha256",
                }:
                    raise AnalysisError(
                        f"{host_id}.{component}.{target_id}.{harness}: "
                        "build provenance metadata drift"
                    )
                seal_relative = build_provenance.get("report")
                if (
                    build_provenance.get("passed") is not True
                    or build_provenance.get("captured_before_measurement") is not True
                    or not isinstance(seal_relative, str)
                    or artifact_hashes.get(seal_relative) != build_provenance.get("report_sha256")
                    or artifact_hashes.get(f"generated/timing_{harness}.c")
                    != build_provenance.get("generated_source_sha256")
                    or artifact_hashes.get(f"generated/timing_{harness}")
                    != build_provenance.get("binary_sha256")
                ):
                    raise AnalysisError(
                        f"{host_id}.{component}.{target_id}.{harness}: "
                        "build provenance hashes are not bound to target artifacts"
                    )
                if axis == "valid_tuple":
                    contract_errors = validate_valid_tuple_harness_report(
                        item,
                        label=f"{host_id}.{component}.{target_id}.{harness}",
                    )
                    if contract_errors:
                        raise AnalysisError(contract_errors[0])
                if component == "kyberslash-contrast" and axis == "operand_bin":
                    contract_errors = validate_operand_v3_harness_report(
                        item,
                        base_seed=_integer(
                            manifest_protocol.get("seed"),
                            f"{component}.seed",
                            minimum=1,
                        ),
                        label=f"{host_id}.{component}.{target_id}.{harness}",
                    )
                    if contract_errors:
                        raise AnalysisError(contract_errors[0])
                target_harness = campaign_by_harness[harness]
                backend_environment = item.get("environment")
                if (
                    target_harness.get("axis") != axis
                    or target_harness.get("raw_status") != raw_status
                    or target_harness.get("timing_validity") != timing_validity
                    or target_harness.get("timing_signal") != _signal(str(raw_status))
                    or target_harness.get("n0") != item.get("n0")
                    or target_harness.get("n1") != item.get("n1")
                    or target_harness.get("promotion_ready") is not True
                    or target_harness.get("blockers") != []
                    or not isinstance(backend_environment, dict)
                    or backend_environment.get("cpu_model") != cpu_model
                    or backend_environment.get("machine_id_sha256") != machine_id
                    or backend_environment.get("rejected") is not False
                ):
                    raise AnalysisError(
                        f"{host_id}.{component}.{target_id}.{harness}: "
                        "campaign/backend/host provenance mismatch"
                    )
                recorded_abs_t = _finite_float(
                    target_harness.get("abs_t_score"),
                    f"{host_id}.{component}.{target_id}.{harness}.recorded_abs_t_score",
                )
                backend_abs_t = _finite_float(
                    item.get("abs_t_score"),
                    f"{host_id}.{component}.{target_id}.{harness}.abs_t_score",
                )
                if recorded_abs_t != backend_abs_t:
                    raise AnalysisError(
                        f"{host_id}.{component}.{target_id}.{harness}: t-score provenance mismatch"
                    )
                assert backend_abs_t is not None
                signature: dict[str, Any] | None = None
                if harness in sign_harnesses:
                    accumulator = signature_accumulators[harness]
                    signature = accumulator.result()
                    signature["return_code_column"] = return_column
                    signature["runtime_contract"] = _signature_metadata(
                        item,
                        accumulator.unique_lengths,
                        f"{host_id}.{component}.{target_id}.{harness}",
                    )
                observations.append(
                    HostAxis(
                        key=AxisKey(component, target_id, harness),
                        family=str(contract.get("family", "")),
                        axis=str(axis),
                        host_id=host_id,
                        cpu_model=cpu_model,
                        machine_id_sha256=machine_id,
                        raw_status=str(raw_status),
                        timing_validity="valid",
                        timing_signal=_signal(str(raw_status)),
                        t_score=_finite_float(
                            item.get("t_score"),
                            f"{host_id}.{component}.{target_id}.{harness}.t_score",
                            optional=True,
                        ),
                        abs_t_score=float(backend_abs_t),
                        n0=_integer(
                            item.get("n0"),
                            f"{host_id}.{component}.{target_id}.{harness}.n0",
                            minimum=1,
                        ),
                        n1=_integer(
                            item.get("n1"),
                            f"{host_id}.{component}.{target_id}.{harness}.n1",
                            minimum=1,
                        ),
                        repeat_deltas=deltas[harness],
                        signature=signature,
                    )
                )
    if (
        required_gate_kind == "automated-frozen-input-integrity-gate"
        and len(qualification_fingerprints) != 1
    ):
        raise AnalysisError(f"{host_id}: components do not share one V10 control qualification")
    return observations


def _betacf(a: float, b: float, x: float) -> float:
    maximum_iterations = 300
    epsilon = 3e-14
    floor = 1e-300
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < floor:
        d = floor
    d = 1.0 / d
    result = d
    for index in range(1, maximum_iterations + 1):
        twice = 2 * index
        numerator = index * (b - index) * x / ((qam + twice) * (a + twice))
        d = 1.0 + numerator * d
        if abs(d) < floor:
            d = floor
        c = 1.0 + numerator / c
        if abs(c) < floor:
            c = floor
        d = 1.0 / d
        result *= d * c
        numerator = -(a + index) * (qab + index) * x / ((a + twice) * (qap + twice))
        d = 1.0 + numerator * d
        if abs(d) < floor:
            d = floor
        c = 1.0 + numerator / c
        if abs(c) < floor:
            c = floor
        d = 1.0 / d
        delta = d * c
        result *= delta
        if abs(delta - 1.0) < epsilon:
            return result
    raise AnalysisError("incomplete-beta continued fraction did not converge")


def _regularized_beta(x: float, a: float, b: float) -> float:
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    front = math.exp(
        math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log1p(-x)
    )
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def _student_t_two_sided_p(t_score: float, degrees_of_freedom: float) -> float:
    if degrees_of_freedom <= 0 or math.isnan(t_score):
        raise AnalysisError("Student t p-value requires finite positive degrees of freedom")
    if math.isinf(t_score):
        return 0.0
    x = degrees_of_freedom / (degrees_of_freedom + t_score * t_score)
    return min(1.0, max(0.0, _regularized_beta(x, degrees_of_freedom / 2.0, 0.5)))


def _welch(values_a: Sequence[float], values_b: Sequence[float]) -> dict[str, Any]:
    if len(values_a) < 2 or len(values_b) < 2:
        raise AnalysisError("Welch contrast requires at least two values per target")
    mean_a = statistics.fmean(values_a)
    mean_b = statistics.fmean(values_b)
    variance_a = statistics.variance(values_a)
    variance_b = statistics.variance(values_b)
    term_a = variance_a / len(values_a)
    term_b = variance_b / len(values_b)
    denominator = math.sqrt(term_a + term_b)
    difference = mean_a - mean_b
    if denominator == 0.0:
        t_score = 0.0 if difference == 0.0 else math.copysign(math.inf, difference)
        degrees = float(len(values_a) + len(values_b) - 2)
    else:
        t_score = difference / denominator
        degrees_denominator = 0.0
        if term_a:
            degrees_denominator += term_a * term_a / (len(values_a) - 1)
        if term_b:
            degrees_denominator += term_b * term_b / (len(values_b) - 1)
        degrees = (term_a + term_b) ** 2 / degrees_denominator
    return {
        "mean_left": mean_a,
        "mean_right": mean_b,
        "estimate_difference": difference,
        "t_score": t_score if math.isfinite(t_score) else None,
        "t_nonfinite": not math.isfinite(t_score),
        "t_direction": 0 if t_score == 0 else (1 if t_score > 0 else -1),
        "degrees_of_freedom": degrees,
        "p_value": _student_t_two_sided_p(t_score, degrees),
    }


def _holm_adjust(records: list[dict[str, Any]]) -> None:
    ordered = sorted(records, key=lambda item: (item["p_value_raw"], item["contrast_id"]))
    running = 0.0
    total = len(ordered)
    for rank, item in enumerate(ordered):
        running = max(running, min(1.0, (total - rank) * item["p_value_raw"]))
        item["p_value_holm"] = running
        item["holm_significant_0_05"] = running <= 0.05


def _correlation(covariance: float, x_ss: float, y_ss: float) -> float | None:
    if x_ss <= 0 or y_ss <= 0:
        return None
    return max(-1.0, min(1.0, covariance / math.sqrt(x_ss * y_ss)))


def _correlation_p_value(
    value: float | None,
    sample_count: int,
    *,
    fitted_parameters: int = 2,
) -> float | None:
    degrees = sample_count - fitted_parameters
    if value is None or degrees <= 0:
        return None
    if abs(value) >= 1.0:
        return 0.0
    t_score = value * math.sqrt(degrees / (1.0 - value * value))
    return _student_t_two_sided_p(t_score, float(degrees))


def _host_heterogeneity(hosts: Sequence[HostAxis]) -> dict[str, Any]:
    if len(hosts) == 1:
        item = hosts[0]
        return {
            "effect_metric": "class1-minus-class0-mean-cycles-per-process-repeat",
            "host_mean_effects": {
                item.host_id: statistics.fmean(item.repeat_deltas),
            },
            "cochran_q": None,
            "degrees_of_freedom": 0,
            "q_p_value": None,
            "i2_percent": None,
            "warning": False,
            "warning_reasons": [],
            "applicability": "not-applicable-single-host",
        }
    reasons: list[str] = []
    effects = [statistics.fmean(item.repeat_deltas) for item in hosts]
    variances = [
        statistics.variance(item.repeat_deltas) / len(item.repeat_deltas) for item in hosts
    ]
    q_value: float | None = None
    i2: float | None = None
    p_value: float | None = None
    if all(value > 0 for value in variances):
        weights = [1.0 / value for value in variances]
        fixed = sum(weight * effect for weight, effect in zip(weights, effects)) / sum(weights)
        q_value = sum(weight * (effect - fixed) ** 2 for weight, effect in zip(weights, effects))
        i2 = 0.0 if q_value <= 0 else max(0.0, (q_value - 1.0) / q_value * 100.0)
        p_value = math.erfc(math.sqrt(q_value / 2.0))
        if i2 >= HETEROGENEITY_I2_WARNING:
            reasons.append(f"I2>={HETEROGENEITY_I2_WARNING:g}%")
    else:
        reasons.append("heterogeneity-unavailable-zero-within-host-variance")
    if len({item.raw_status for item in hosts}) > 1:
        reasons.append("raw-status-disagreement")
    nonzero_signs = {math.copysign(1.0, effect) for effect in effects if effect != 0}
    if len(nonzero_signs) > 1:
        reasons.append("effect-direction-disagreement")
    return {
        "effect_metric": "class1-minus-class0-mean-cycles-per-process-repeat",
        "host_mean_effects": {item.host_id: effect for item, effect in zip(hosts, effects)},
        "cochran_q": q_value,
        "degrees_of_freedom": 1,
        "q_p_value": p_value,
        "i2_percent": i2,
        "warning": bool(reasons),
        "warning_reasons": reasons,
        "applicability": "available",
    }


def _combined_status(hosts: Sequence[HostAxis]) -> str:
    if any(item.timing_validity == "valid" and item.raw_status in RISK_STATUSES for item in hosts):
        return "risk-detected"
    if any(item.timing_validity != "valid" for item in hosts):
        return "inconclusive"
    if any(item.raw_status == "WARNING" for item in hosts):
        return "needs-review"
    return "no-finding-observed"


def _pairwise_contrasts(
    by_key: Mapping[AxisKey, Sequence[HostAxis]],
    families: Mapping[str, Sequence[AxisKey]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for family in sorted(families):
        keys = tuple(families[family])
        missing = [key for key in keys if key not in by_key]
        if missing:
            raise AnalysisError(f"pairwise family {family} is missing axes: {missing}")
        family_rows: list[dict[str, Any]] = []
        for left_index, left in enumerate(keys):
            for right in keys[left_index + 1 :]:
                left_values = [
                    value
                    for host in sorted(by_key[left], key=lambda item: item.host_id)
                    for value in host.repeat_deltas
                ]
                right_values = [
                    value
                    for host in sorted(by_key[right], key=lambda item: item.host_id)
                    for value in host.repeat_deltas
                ]
                welch = _welch(left_values, right_values)
                contrast_id = f"{left.target}:{left.harness}__vs__{right.target}:{right.harness}"
                family_rows.append(
                    {
                        "family": family,
                        "contrast_id": contrast_id,
                        "left": {
                            "component": left.component,
                            "target": left.target,
                            "harness": left.harness,
                        },
                        "right": {
                            "component": right.component,
                            "target": right.target,
                            "harness": right.harness,
                        },
                        "method": "welch-two-sided-on-process-repeat-class-mean-deltas",
                        "effect_metric": "class1-minus-class0-mean-cycles",
                        "n_left": len(left_values),
                        "n_right": len(right_values),
                        "mean_left": welch["mean_left"],
                        "mean_right": welch["mean_right"],
                        "estimate_difference": welch["estimate_difference"],
                        "t_score": welch["t_score"],
                        "t_nonfinite": welch["t_nonfinite"],
                        "t_direction": welch["t_direction"],
                        "degrees_of_freedom": welch["degrees_of_freedom"],
                        "p_value_raw": welch["p_value"],
                    }
                )
        _holm_adjust(family_rows)
        result.extend(sorted(family_rows, key=lambda item: item["contrast_id"]))
    return result


def build_analysis(
    observations: Sequence[HostAxis],
    *,
    expected_commit: str,
    verification_commit: str | None = None,
    bundle_id: str,
    input_records: Sequence[dict[str, Any]],
    input_aggregate_sha256: str,
    pairwise_families: Mapping[str, Sequence[AxisKey]] = PAIRWISE_FAMILIES,
    expected_host_count: int = 2,
) -> dict[str, Any]:
    host_ids = sorted({item.host_id for item in observations})
    cpu_models = {item.cpu_model for item in observations}
    machine_ids = {item.machine_id_sha256 for item in observations}
    if expected_host_count not in {1, 2}:
        raise AnalysisError("analysis supports exactly one or two physical hosts")
    if (
        len(host_ids) != expected_host_count
        or len(cpu_models) != expected_host_count
        or len(machine_ids) != expected_host_count
    ):
        raise AnalysisError(
            f"analysis requires {expected_host_count} distinct physical host and CPU identities"
        )
    by_key: dict[AxisKey, list[HostAxis]] = {}
    for item in observations:
        by_key.setdefault(item.key, []).append(item)
    primary: list[dict[str, Any]] = []
    signatures: list[dict[str, Any]] = []
    for key in sorted(by_key):
        hosts = sorted(by_key[key], key=lambda item: item.host_id)
        if [item.host_id for item in hosts] != host_ids:
            raise AnalysisError(f"axis {key} does not contain every frozen host")
        combined = _combined_status(hosts)
        heterogeneity = _host_heterogeneity(hosts)
        primary_record = {
            "component": key.component,
            "target": key.target,
            "family": hosts[0].family,
            "harness": key.harness,
            "axis": hosts[0].axis,
            "combined_status": combined,
            "risk_on_any_measured_host": combined == "risk-detected",
            "host_results": [
                {
                    "host_id": item.host_id,
                    "cpu_model": item.cpu_model,
                    "machine_id_sha256": item.machine_id_sha256,
                    "raw_status": item.raw_status,
                    "timing_validity": item.timing_validity,
                    "timing_signal": item.timing_signal,
                    "t_score": item.t_score,
                    "abs_t_score": item.abs_t_score,
                    "n0": item.n0,
                    "n1": item.n1,
                    "repeat_class_mean_deltas": list(item.repeat_deltas),
                }
                for item in hosts
            ],
            "host_heterogeneity": heterogeneity,
        }
        if expected_host_count == 2:
            primary_record["risk_on_either_host"] = combined == "risk-detected"
        primary.append(primary_record)
        for item in hosts:
            if item.signature is not None:
                signatures.append(
                    {
                        "component": key.component,
                        "target": key.target,
                        "harness": key.harness,
                        "host_id": item.host_id,
                        **item.signature,
                    }
                )
    pairwise = _pairwise_contrasts(by_key, pairwise_families)
    counts = {
        status: sum(item["combined_status"] == status for item in primary)
        for status in (
            "risk-detected",
            "needs-review",
            "inconclusive",
            "no-finding-observed",
        )
    }
    return {
        "schema_version": "1.0",
        "kind": (
            "paper-native-single-host-analysis"
            if expected_host_count == 1
            else "paper-native-two-host-analysis"
        ),
        "bundle_id": bundle_id,
        "ctkat_commit": expected_commit,
        "measurement_commit": expected_commit,
        "verification_commit": verification_commit or expected_commit,
        "input_aggregate_sha256": input_aggregate_sha256,
        "inputs": list(input_records),
        "analysis_policy": {
            "primary_combination": (
                "single valid host result is retained without cross-host generalization"
                if expected_host_count == 1
                else "risk on either valid host remains risk"
            ),
            "pairwise_method": "Welch two-sided test on per-process class-mean deltas",
            "multiplicity": "Holm within each preregistered family",
            "heterogeneity": (
                "not applicable to the preregistered single-host scope"
                if expected_host_count == 1
                else "Cochran Q and I2 across host mean effects"
            ),
            "heterogeneity_i2_warning_percent": HETEROGENEITY_I2_WARNING,
            "signature_association": (
                "Pearson duration/output-length, plus within-class-centered Pearson"
            ),
            "secondary_can_override_primary": False,
        },
        "hosts": [
            {
                "id": host_id,
                "cpu_model": next(
                    item.cpu_model for item in observations if item.host_id == host_id
                ),
                "machine_id_sha256": next(
                    item.machine_id_sha256 for item in observations if item.host_id == host_id
                ),
            }
            for host_id in host_ids
        ],
        "summary": {
            "axis_count": len(primary),
            "pairwise_contrast_count": len(pairwise),
            "signature_host_axis_count": len(signatures),
            "combined_status_counts": counts,
            "heterogeneity_warning_count": sum(
                item["host_heterogeneity"]["warning"] for item in primary
            ),
        },
        "primary_axes": primary,
        "pairwise_contrasts": pairwise,
        "signature_length_associations": sorted(
            signatures,
            key=lambda item: (item["component"], item["target"], item["harness"], item["host_id"]),
        ),
    }


def load_blinding_map(
    path: Path,
    *,
    expected_bundle_id: str,
    expected_pairs: set[tuple[str, str]],
) -> tuple[BlindingMap, dict[str, Any]]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise AnalysisError(f"blinding/unblinding record is unreadable: {exc}") from exc
    if not isinstance(raw, dict):
        raise AnalysisError("blinding/unblinding record must be a mapping")
    if raw.get("bundle_id") != expected_bundle_id:
        raise AnalysisError("blinding map bundle identity mismatch")
    scope = raw.get("scope")
    if scope != "result-analyst-label-blinding":
        raise AnalysisError("blinding map scope mismatch")
    label_map = raw.get("label_map")
    if not isinstance(label_map, list) or not label_map:
        raise AnalysisError("blinding map label_map must be a non-empty list")
    labels: list[tuple[str, str, str]] = []
    opaque_seen: set[str] = set()
    pair_seen: set[tuple[str, str]] = set()
    for index, item in enumerate(label_map):
        if not isinstance(item, dict) or set(item) != {"opaque_label", "component", "target"}:
            raise AnalysisError(f"blinding map label_map[{index}] is malformed")
        opaque = item["opaque_label"]
        component = item["component"]
        target = item["target"]
        pair = (component, target)
        if (
            not isinstance(opaque, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}", opaque)
            or not isinstance(component, str)
            or not component
            or not isinstance(target, str)
            or not target
            or opaque in opaque_seen
            or pair in pair_seen
        ):
            raise AnalysisError(f"blinding map label_map[{index}] has invalid/duplicate values")
        opaque_seen.add(opaque)
        pair_seen.add(pair)
        labels.append((opaque, component, target))
    if pair_seen != expected_pairs:
        raise AnalysisError("blinding map does not exactly cover the analyzed targets")
    return (
        BlindingMap(
            bundle_id=expected_bundle_id,
            scope=scope,
            labels=tuple(sorted(labels)),
        ),
        raw,
    )


def blind_analysis(named: Mapping[str, Any], blinding: BlindingMap) -> dict[str, Any]:
    """Remove real implementation labels while retaining frozen group structure."""
    result = copy.deepcopy(dict(named))
    pair_to_label = blinding.by_pair
    primary = result["primary_axes"]
    axis_labels: dict[tuple[str, str, str], str] = {}
    per_target_axes: dict[tuple[str, str], list[str]] = {}
    for item in primary:
        pair = (item["component"], item["target"])
        per_target_axes.setdefault(pair, []).append(item["harness"])
    for pair, harnesses in per_target_axes.items():
        opaque = pair_to_label[pair]
        for index, harness in enumerate(sorted(harnesses), start=1):
            axis_labels[(pair[0], pair[1], harness)] = f"{opaque}-axis-{index:02d}"
    primary_families = {
        value: f"group-{index:03d}"
        for index, value in enumerate(
            sorted({item["family"] for item in primary}),
            start=1,
        )
    }
    for item in primary:
        component = item["component"]
        target = item["target"]
        harness = item["harness"]
        item["component"] = "opaque-component"
        item["target"] = pair_to_label[(component, target)]
        item["family"] = primary_families[item["family"]]
        item["harness"] = axis_labels[(component, target, harness)]
        item["axis"] = "opaque-axis"

    pairwise_families = {
        value: f"contrast-family-{index:03d}"
        for index, value in enumerate(
            sorted({item["family"] for item in result["pairwise_contrasts"]}),
            start=1,
        )
    }
    for item in result["pairwise_contrasts"]:
        left = item["left"]
        right = item["right"]
        left_key = (left["component"], left["target"], left["harness"])
        right_key = (right["component"], right["target"], right["harness"])
        left_label = pair_to_label[left_key[:2]]
        right_label = pair_to_label[right_key[:2]]
        item["family"] = pairwise_families[item["family"]]
        item["contrast_id"] = f"{left_label}__vs__{right_label}"
        item["left"] = {
            "component": "opaque-component",
            "target": left_label,
            "harness": axis_labels[left_key],
        }
        item["right"] = {
            "component": "opaque-component",
            "target": right_label,
            "harness": axis_labels[right_key],
        }
    for item in result["signature_length_associations"]:
        key = (item["component"], item["target"], item["harness"])
        item["component"] = "opaque-component"
        item["target"] = pair_to_label[key[:2]]
        item["harness"] = axis_labels[key]

    input_count = len(result.get("inputs", []))
    result["inputs"] = []
    result["kind"] = "paper-native-two-host-analysis-blinded"
    result["blinding"] = {
        "state": "blinded",
        "scope": blinding.scope,
        "label_map_sha256": blinding.sha256,
        "opaque_target_count": len(blinding.labels),
        "redacted_input_record_count": input_count,
        "real_component_or_target_labels_present": False,
    }
    serialized = json.dumps(result, sort_keys=True, allow_nan=False)
    forbidden = {component for _, component, _ in blinding.labels} | {
        target for _, _, target in blinding.labels
    }
    leaked = sorted(value for value in forbidden if value and value in serialized)
    if leaked:
        raise AnalysisError(f"blinded analysis leaked real labels: {leaked}")
    return result


def unblinded_analysis(
    named: Mapping[str, Any],
    blinding: BlindingMap,
    unblinding_record: Mapping[str, Any],
    *,
    unblinding_record_sha256: str,
) -> dict[str, Any]:
    result = copy.deepcopy(dict(named))
    result["blinding"] = {
        "state": "unblinded",
        "scope": blinding.scope,
        "label_map_sha256": blinding.sha256,
        "blinded_analysis_manifest_sha256": unblinding_record.get(
            "blinded_analysis_manifest_sha256"
        ),
        "blinded_analysis_completed_at": unblinding_record.get("blinded_analysis_completed_at"),
        "unblinded_at": unblinding_record.get("unblinded_at"),
        "unblinding_record_sha256": unblinding_record_sha256,
        "blinded_byte_parity_verified": True,
    }
    return result


def _format_csv(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, float):
        if math.isinf(value):
            return "inf" if value > 0 else "-inf"
        return format(value, ".17g")
    return str(value)


def _csv_bytes(fieldnames: Sequence[str], rows: Iterable[Mapping[str, Any]]) -> bytes:
    import io

    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: _format_csv(row.get(key)) for key in fieldnames})
    return handle.getvalue().encode("utf-8")


def _axis_csv(analysis: Mapping[str, Any]) -> bytes:
    fields = (
        "component",
        "target",
        "family",
        "harness",
        "axis",
        "host_id",
        "cpu_model",
        "raw_status",
        "timing_validity",
        "timing_signal",
        "t_score",
        "abs_t_score",
        "n0",
        "n1",
        "mean_repeat_delta_cycles",
        "combined_status",
        "heterogeneity_i2_percent",
        "heterogeneity_warning",
    )
    rows = []
    for axis in analysis["primary_axes"]:
        for host in axis["host_results"]:
            rows.append(
                {
                    **{
                        key: axis[key]
                        for key in ("component", "target", "family", "harness", "axis")
                    },
                    **{
                        key: host[key]
                        for key in (
                            "host_id",
                            "cpu_model",
                            "raw_status",
                            "timing_validity",
                            "timing_signal",
                            "t_score",
                            "abs_t_score",
                            "n0",
                            "n1",
                        )
                    },
                    "mean_repeat_delta_cycles": statistics.fmean(host["repeat_class_mean_deltas"]),
                    "combined_status": axis["combined_status"],
                    "heterogeneity_i2_percent": axis["host_heterogeneity"]["i2_percent"],
                    "heterogeneity_warning": axis["host_heterogeneity"]["warning"],
                }
            )
    return _csv_bytes(fields, rows)


def _pairwise_csv(analysis: Mapping[str, Any]) -> bytes:
    fields = (
        "family",
        "contrast_id",
        "left_component",
        "left_target",
        "left_harness",
        "right_component",
        "right_target",
        "right_harness",
        "method",
        "n_left",
        "n_right",
        "mean_left",
        "mean_right",
        "estimate_difference",
        "t_score",
        "t_nonfinite",
        "t_direction",
        "degrees_of_freedom",
        "p_value_raw",
        "p_value_holm",
        "holm_significant_0_05",
    )
    rows = []
    for item in analysis["pairwise_contrasts"]:
        rows.append(
            {
                **{key: item[key] for key in fields if key in item},
                "left_component": item["left"]["component"],
                "left_target": item["left"]["target"],
                "left_harness": item["left"]["harness"],
                "right_component": item["right"]["component"],
                "right_target": item["right"]["target"],
                "right_harness": item["right"]["harness"],
            }
        )
    return _csv_bytes(fields, rows)


def _signature_csv(analysis: Mapping[str, Any]) -> bytes:
    fields = (
        "component",
        "target",
        "harness",
        "host_id",
        "retained_samples",
        "minimum_output_length",
        "maximum_output_length",
        "unique_output_lengths",
        "status",
        "pearson_r",
        "p_value",
        "slope_cycles_per_byte",
        "within_class_pearson_r",
        "within_class_p_value",
        "return_code_column",
        "runtime_contract",
    )
    rows = []
    for item in analysis["signature_length_associations"]:
        row = dict(item)
        row["runtime_contract"] = json.dumps(item["runtime_contract"], sort_keys=True)
        rows.append(row)
    return _csv_bytes(fields, rows)


def _markdown(analysis: Mapping[str, Any]) -> bytes:
    summary = analysis["summary"]
    counts = summary["combined_status_counts"]
    single_host = analysis.get("kind") == "paper-native-single-host-analysis"
    lines = [
        "# Single-host native timing analysis"
        if single_host
        else "# Two-host native timing analysis",
        "",
        f"- Bundle: `{analysis['bundle_id']}`",
        f"- CT-KAT commit: `{analysis['ctkat_commit']}`",
        f"- Input aggregate SHA-256: `{analysis['input_aggregate_sha256']}`",
        f"- Axes: {summary['axis_count']}",
        f"- Combined risk: {counts['risk-detected']}",
        f"- Needs review: {counts['needs-review']}",
        f"- Inconclusive: {counts['inconclusive']}",
        f"- No finding observed: {counts['no-finding-observed']}",
        f"- Heterogeneity warnings: {summary['heterogeneity_warning_count']}",
        "",
        (
            "Each valid result is scoped to this physical host; it is not evidence of "
            "cross-host reproducibility."
            if single_host
            else "A valid risk finding on either host remains `risk-detected`."
        ),
        "Secondary contrasts and output-length analyses never declassify a primary finding.",
        "",
        "## Primary axes",
        "",
        "| Component | Target | Harness/axis | Combined | Host results | I² |",
        "|---|---|---|---|---|---:|",
    ]
    for axis in analysis["primary_axes"]:
        host_results = ", ".join(
            f"{item['host_id']}={item['raw_status']} (|t|={item['abs_t_score']:.4g})"
            for item in axis["host_results"]
        )
        i2 = axis["host_heterogeneity"]["i2_percent"]
        i2_text = "unavailable" if i2 is None else f"{i2:.2f}%"
        lines.append(
            f"| {axis['component']} | {axis['target']} | "
            f"{axis['harness']}/{axis['axis']} | {axis['combined_status']} | "
            f"{host_results} | {i2_text} |"
        )
    lines.extend(
        [
            "",
            "## Secondary analyses",
            "",
            f"- Pairwise contrasts: {summary['pairwise_contrast_count']} "
            "(Holm-adjusted within preregistered family).",
            f"- Signature host/axes: {summary['signature_host_axis_count']}.",
            "- Machine-readable values are in the adjacent JSON and CSV files.",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def render_outputs(analysis: Mapping[str, Any]) -> dict[str, bytes]:
    return {
        "paper_native_analysis.json": (
            json.dumps(analysis, indent=2, sort_keys=True, allow_nan=False) + "\n"
        ).encode("utf-8"),
        "paper_native_axis_results.csv": _axis_csv(analysis),
        "paper_native_pairwise_contrasts.csv": _pairwise_csv(analysis),
        "paper_native_signature_length.csv": _signature_csv(analysis),
        "paper_native_analysis.md": _markdown(analysis),
    }


def render_blinded_outputs(analysis: Mapping[str, Any]) -> dict[str, bytes]:
    if analysis.get("kind") != "paper-native-two-host-analysis-blinded":
        raise AnalysisError("blinded renderer requires a blinded analysis payload")
    rendered = render_outputs(analysis)
    manifest = {
        "schema_version": "1.0",
        "kind": "paper-native-blinded-analysis-manifest",
        "bundle_id": analysis.get("bundle_id"),
        "measurement_commit": analysis.get("measurement_commit", analysis.get("ctkat_commit")),
        "verification_commit": analysis.get("verification_commit"),
        "input_aggregate_sha256": analysis.get("input_aggregate_sha256"),
        "label_map_sha256": analysis["blinding"]["label_map_sha256"],
        "outputs": {
            name: {
                "sha256": hashlib.sha256(content).hexdigest(),
                "bytes": len(content),
            }
            for name, content in sorted(rendered.items())
        },
    }
    rendered["analysis_manifest.json"] = (
        json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    return rendered


def _write_rendered(output_root: Path, rendered: Mapping[str, bytes], *, check: bool) -> None:
    output_root = output_root.resolve()
    if output_root == ROOT or ROOT.is_relative_to(output_root):
        raise AnalysisError("output root cannot be the repository or one of its ancestors")
    expected_names = set(rendered)
    if output_root.exists():
        if output_root.is_symlink() or not output_root.is_dir():
            raise AnalysisError("output root must be a regular directory")
        entries = list(output_root.iterdir())
        actual_names = {entry.name for entry in entries}
        if check:
            if actual_names != expected_names or any(
                entry.is_symlink() or not entry.is_file() for entry in entries
            ):
                raise AnalysisError(
                    "deterministic output file set drift: "
                    f"expected={sorted(expected_names)}, actual={sorted(actual_names)}"
                )
        elif entries:
            raise AnalysisError(
                "output root must be absent or empty; use --check-output for regeneration"
            )
    if check:
        for name, expected in rendered.items():
            path = output_root / name
            if not path.is_file() or path.read_bytes() != expected:
                raise AnalysisError(f"deterministic output drift: {path}")
        return
    output_root.mkdir(parents=True, exist_ok=True)
    for name, content in rendered.items():
        path = output_root / name
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_bytes(content)
        os.replace(temporary, path)


def write_outputs(output_root: Path, analysis: Mapping[str, Any], *, check: bool) -> None:
    _write_rendered(output_root, render_outputs(analysis), check=check)


def write_blinded_outputs(output_root: Path, analysis: Mapping[str, Any], *, check: bool) -> str:
    rendered = render_blinded_outputs(analysis)
    _write_rendered(output_root, rendered, check=check)
    return hashlib.sha256(rendered["analysis_manifest.json"]).hexdigest()


def verify_blinded_outputs(
    output_root: Path,
    expected_blinded: Mapping[str, Any],
    *,
    expected_manifest_sha256: str,
) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_manifest_sha256):
        raise AnalysisError("unblinding record has no valid blinded analysis manifest hash")
    rendered = render_blinded_outputs(expected_blinded)
    manifest = rendered["analysis_manifest.json"]
    if hashlib.sha256(manifest).hexdigest() != expected_manifest_sha256:
        raise AnalysisError("recomputed blinded analysis manifest hash differs from the record")
    _write_rendered(output_root, rendered, check=True)


def _git_head() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def _require_review_only_descendant(
    verification_commit: str,
    current_commit: str,
) -> None:
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", verification_commit, current_commit],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    changed_paths = subprocess.run(
        [
            "git",
            "diff",
            "--name-only",
            f"{verification_commit}..{current_commit}",
        ],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()
    unexpected = sorted(
        path
        for path in changed_paths.splitlines()
        if path and path != POST_VERIFICATION_ALLOWED_PATH
    )
    if unexpected:
        raise AnalysisError(
            "paper-ready descendant changed files outside the sole review packet: "
            + ", ".join(unexpected)
        )


def _tracked_worktree_dirty() -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return bool(result.stdout.strip())


def _prepare_blinded_bundle(
    bundle_path: Path,
    verification_commit: str,
) -> tuple[dict[str, Any], Path | None]:
    """Validate a schema-v4 blinded bundle or schema-v5 named single-host bundle."""
    try:
        raw = yaml.safe_load(bundle_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise AnalysisError(f"measurement bundle is unreadable: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") not in {4, 5}:
        raise AnalysisError("analysis requires a schema-v4 or schema-v5 measurement bundle")
    single_host = raw.get("schema_version") == 5
    if single_host and raw.get("evidence_scope") != "single-physical-host":
        raise AnalysisError("schema-v5 bundle must declare single-physical-host scope")
    measurement_commit = raw.get("measurement_commit")
    if not isinstance(measurement_commit, str) or not re.fullmatch(
        r"[0-9a-f]{40}", measurement_commit
    ):
        raise AnalysisError("measurement bundle has no valid measurement commit")
    if raw.get("verification_commit") != verification_commit:
        raise AnalysisError("measurement bundle verification commit differs from checkout HEAD")
    critical_paths = (
        "ctkat",
        "scripts",
        "examples",
        "docs/measurement",
        "docs/baselines",
        "docs/ground_truth",
        "pyproject.toml",
        "uv.lock",
    )
    drift = subprocess.run(
        [
            "git",
            "diff",
            "--name-only",
            f"{measurement_commit}..{verification_commit}",
            "--",
            *critical_paths,
        ],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()
    if drift:
        raise AnalysisError(
            "measurement-critical source changed after measurement: "
            + ", ".join(drift.splitlines())
        )
    bundle_id = raw.get("bundle_id")
    if not isinstance(bundle_id, str) or not bundle_id:
        raise AnalysisError("measurement bundle id is missing")
    hosts = raw.get("hosts")
    required_host_count = 1 if single_host else 2
    if not isinstance(hosts, list) or len(hosts) != required_host_count:
        raise AnalysisError(
            f"measurement bundle requires exactly {required_host_count} physical host(s)"
        )
    bundle_root = bundle_path.parent.resolve()
    records: list[dict[str, Any]] = []
    host_ids: set[str] = set()
    cpu_models: set[str] = set()
    machine_ids: set[str] = set()
    compiler_contracts: set[tuple[str, str]] = set()
    host_roots: list[Path] = []
    run_ids: set[str] = set()
    from scripts.hash_artifacts import build_manifest

    for index, host in enumerate(hosts):
        if not isinstance(host, dict):
            raise AnalysisError(f"hosts[{index}] must be a mapping")
        host_id = host.get("id")
        cpu_model = host.get("cpu_model")
        if (
            not isinstance(host_id, str)
            or not host_id
            or host_id in host_ids
            or not isinstance(cpu_model, str)
            or not cpu_model
            or cpu_model in cpu_models
            or host.get("physical") is not True
            or host.get("virtualization_detected") is not False
        ):
            raise AnalysisError("blinded bundle host identity/physical contract is invalid")
        host_ids.add(host_id)
        cpu_models.add(cpu_model)
        host_root = _safe_child(
            bundle_root,
            host.get("artifact_root"),
            f"{host_id}.artifact_root",
            directory=True,
        )
        if any(
            host_root == previous
            or host_root.is_relative_to(previous)
            or previous.is_relative_to(host_root)
            for previous in host_roots
        ):
            raise AnalysisError("host artifact roots must be distinct and non-overlapping")
        host_roots.append(host_root)
        hash_manifest = _safe_child(
            bundle_root,
            host.get("hash_manifest"),
            f"{host_id}.hash_manifest",
            directory=False,
        )
        if not hash_manifest.is_relative_to(host_root):
            raise AnalysisError(f"{host_id}: hash manifest escapes its host artifact root")
        host_hash_manifest = hash_manifest.read_text(encoding="utf-8")
        if host_hash_manifest != build_manifest(host_root, exclude=hash_manifest):
            raise AnalysisError(f"{host_id}: host SHA-256 manifest mismatch")
        raw_components = host.get("components")
        if not isinstance(raw_components, dict) or set(raw_components) != set(COMPONENT_PLANS):
            raise AnalysisError(f"{host_id}: component set differs from the frozen plan")
        components: dict[str, str] = {}
        observed_machine_ids: set[str] = set()
        qualification_fingerprints: set[str] = set()
        for component in sorted(COMPONENT_PLANS):
            component_root = _safe_child(
                bundle_root,
                raw_components[component],
                f"{host_id}.{component}",
                directory=True,
            )
            if not component_root.is_relative_to(host_root):
                raise AnalysisError(f"{host_id}.{component}: component escapes host root")
            report = _read_json(
                component_root / "campaign_report.json",
                f"{host_id}.{component}.campaign_report",
            )
            if single_host:
                gate = report.get("automated_premeasurement_gate")
                if not isinstance(gate, dict):
                    raise AnalysisError(f"{host_id}.{component}: automated final gate is missing")
                qualification_fingerprints.add(
                    _single_host_qualification_fingerprint(
                        gate,
                        expected_commit=measurement_commit,
                        label=f"{host_id}.{component}",
                    )
                )
            run_id = report.get("run_id")
            if (
                not isinstance(run_id, str)
                or not re.fullmatch(r"[0-9a-f]{32}", run_id)
                or run_id in run_ids
            ):
                raise AnalysisError(f"{host_id}.{component}: run id is missing or reused")
            run_ids.add(run_id)
            environment = (report.get("host_preflight") or {}).get("environment")
            preflight = report.get("host_preflight") or {}
            if not isinstance(environment, dict):
                raise AnalysisError(f"{host_id}.{component}: preflight identity is missing")
            machine_id = environment.get("machine_id_sha256")
            if not isinstance(machine_id, str) or not re.fullmatch(r"[0-9a-f]{64}", machine_id):
                raise AnalysisError(f"{host_id}.{component}: machine identity is missing")
            observed_machine_ids.add(machine_id)
            compiler_version = preflight.get("compiler")
            compiler_executable = preflight.get("compiler_executable")
            if (
                not isinstance(compiler_version, str)
                or not compiler_version
                or not isinstance(compiler_executable, dict)
                or not isinstance(compiler_executable.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", compiler_executable.get("sha256", ""))
            ):
                raise AnalysisError(
                    f"{host_id}.{component}: compiler executable provenance is missing"
                )
            compiler_contracts.add((compiler_version, str(compiler_executable["sha256"])))
            components[component] = str(component_root)
        if len(observed_machine_ids) != 1:
            raise AnalysisError(f"{host_id}: component machine identities disagree")
        machine_id = next(iter(observed_machine_ids))
        if machine_id in machine_ids:
            raise AnalysisError("final bundle reuses a physical machine identity")
        machine_ids.add(machine_id)
        raw_baselines = host.get("same_corpus_results")
        if not isinstance(raw_baselines, dict) or set(raw_baselines) != {
            "official_dudect",
            "timecop",
            "microwalk_pin",
        }:
            raise AnalysisError(f"{host_id}: same-corpus tool set is incomplete")
        baselines: dict[str, str] = {}
        for tool_id in sorted(raw_baselines):
            baseline = _safe_child(
                bundle_root,
                raw_baselines[tool_id],
                f"{host_id}.same_corpus_results.{tool_id}",
                directory=False,
            )
            if not baseline.is_relative_to(host_root):
                raise AnalysisError(f"{host_id}.{tool_id}: baseline escapes host root")
            baseline_report = _read_json(baseline, f"{host_id}.{tool_id}.baseline")
            baseline_run_id = baseline_report.get("run_id")
            baseline_host = baseline_report.get("host")
            baseline_gate = baseline_report.get(
                "automated_premeasurement_gate" if single_host else "human_review_gate"
            )
            required_gate_kind = (
                "automated-frozen-input-integrity-gate"
                if single_host
                else "human-premeasurement-review-gate"
            )
            if (
                baseline_report.get("ctkat_commit") != measurement_commit
                or baseline_report.get("run_kind") != "final"
                or baseline_report.get("promotion_ready") is not True
                or not isinstance(baseline_run_id, str)
                or not re.fullmatch(r"[0-9a-f]{32}", baseline_run_id)
                or baseline_run_id in run_ids
                or not isinstance(baseline_host, dict)
                or baseline_host.get("cpu_model") != cpu_model
                or baseline_host.get("machine_id_sha256") != machine_id
                or not isinstance(baseline_gate, dict)
                or baseline_gate.get("kind") != required_gate_kind
                or baseline_gate.get("ready") is not True
                or (
                    single_host
                    and (
                        baseline_gate.get("physical_host_count") != 1
                        or baseline_gate.get("independent_human_review") is not False
                        or baseline_gate.get("cross_host_reproducibility") is not False
                        or baseline_report.get("human_review_gate") is not None
                    )
                )
            ):
                raise AnalysisError(f"{host_id}.{tool_id}: final baseline provenance failed")
            if single_host:
                assert isinstance(baseline_gate, dict)
                qualification_fingerprints.add(
                    _single_host_qualification_fingerprint(
                        baseline_gate,
                        expected_commit=measurement_commit,
                        label=f"{host_id}.{tool_id}",
                    )
                )
            run_ids.add(baseline_run_id)
            baselines[tool_id] = str(baseline)
        if single_host and len(qualification_fingerprints) != 1:
            raise AnalysisError(
                f"{host_id}: final results do not share one V10 control qualification"
            )
        if single_host:
            qualification = json.loads(next(iter(qualification_fingerprints)))
            required_qualification_hashes = {
                qualification["sha256"],
                *qualification["rehearsal_report_sha256"].values(),
            }
            manifest_hashes = [
                line.split("  ", maxsplit=1)[0]
                for line in host_hash_manifest.splitlines()
                if "  " in line
            ]
            missing_or_ambiguous = sorted(
                value
                for value in required_qualification_hashes
                if manifest_hashes.count(value) != 1
            )
            if missing_or_ambiguous:
                raise AnalysisError(
                    f"{host_id}: qualification or rehearsal source is not uniquely preserved "
                    "by the host SHA-256 manifest"
                )
        records.append(
            {
                "id": host_id,
                "cpu_model": cpu_model,
                "machine_id_sha256": machine_id,
                "artifact_root": str(host_root),
                "hash_manifest": str(hash_manifest),
                "components": components,
                "same_corpus_results": baselines,
            }
        )
    if len(compiler_contracts) != 1:
        raise AnalysisError("bundle must use one exact GCC version and executable hash")
    assembly = raw.get("assembly_evidence")
    if not isinstance(assembly, dict) or set(assembly) != {"mlkem_public_attribution"}:
        raise AnalysisError("bundle lacks the frozen ML-KEM assembly evidence")
    mlkem_assembly = assembly["mlkem_public_attribution"]
    if not isinstance(mlkem_assembly, dict) or set(mlkem_assembly) != {"host_id", "bundle"}:
        raise AnalysisError("ML-KEM assembly evidence entry field set drift")
    assembly_host_id = mlkem_assembly.get("host_id")
    host_roots_by_id = {record["id"]: Path(record["artifact_root"]) for record in records}
    if assembly_host_id not in host_roots_by_id:
        raise AnalysisError("ML-KEM assembly evidence references an unknown host")
    assembly_bundle = _safe_child(
        bundle_root,
        mlkem_assembly.get("bundle"),
        "assembly_evidence.mlkem_public_attribution.bundle",
        directory=False,
    )
    if not assembly_bundle.is_relative_to(host_roots_by_id[str(assembly_host_id)]):
        raise AnalysisError("ML-KEM assembly evidence escapes its recorded host root")
    assembly_payload = _read_json(assembly_bundle, "ML-KEM assembly evidence")
    if (
        assembly_payload.get("kind") != "ctkat-asm-evidence-bundle"
        or assembly_payload.get("paper_eligible") is not True
        or (assembly_payload.get("source_revision") or {}).get("commit") != measurement_commit
    ):
        raise AnalysisError("ML-KEM assembly evidence identity/commit/eligibility mismatch")
    assembly_record = {
        "mlkem_public_attribution": {
            "host_id": assembly_host_id,
            "bundle": str(assembly_bundle),
        }
    }
    if single_host:
        named = raw.get("analysis")
        if not isinstance(named, dict) or set(named) != {"scope", "output_root"}:
            raise AnalysisError("schema-v5 bundle named analysis contract is malformed")
        if named.get("scope") != "named-single-host":
            raise AnalysisError("schema-v5 bundle analysis scope drift")
        named_root = _safe_future_child(
            bundle_root,
            named.get("output_root"),
            "analysis.output_root",
        )
        return {
            "bundle_id": bundle_id,
            "evidence_scope": "single-physical-host",
            "measurement_commit": measurement_commit,
            "verification_commit": verification_commit,
            "named_analysis_root": str(named_root),
            "hosts": records,
            "assembly_evidence": assembly_record,
        }, None

    blind = raw.get("blind_rerun")
    if not isinstance(blind, dict) or blind.get("scope") != "result-analyst-label-blinding":
        raise AnalysisError("bundle does not declare result-analyst label blinding")
    blinded_root = _safe_future_child(
        bundle_root,
        blind.get("blinded_analysis_root"),
        "blind_rerun.blinded_analysis_root",
    )
    blinded_manifest = _safe_future_child(
        bundle_root,
        blind.get("blinded_analysis_manifest"),
        "blind_rerun.blinded_analysis_manifest",
    )
    if blinded_manifest != blinded_root / "analysis_manifest.json":
        raise AnalysisError("bundle blinded manifest path/name differs from the analysis contract")
    record_path = _safe_future_child(
        bundle_root,
        blind.get("unblinding_record"),
        "blind_rerun.unblinding_record",
    )
    return {
        "bundle_id": bundle_id,
        "measurement_commit": measurement_commit,
        "verification_commit": verification_commit,
        "blinded_analysis_root": str(blinded_root),
        "blinded_analysis_manifest": str(blinded_manifest),
        "hosts": records,
        "assembly_evidence": assembly_record,
    }, record_path


def _record_outer_inputs(
    ledger: InputLedger,
    hosts: Sequence[Mapping[str, Any]],
    assembly_evidence: Mapping[str, Any],
) -> None:
    for host in hosts:
        host_id = str(host["id"])
        ledger.add(f"{host_id}/SHA256SUMS", Path(str(host["hash_manifest"])))
        baselines = host.get("same_corpus_results")
        if not isinstance(baselines, dict):
            raise AnalysisError(f"{host_id}: same-corpus result index is malformed")
        for tool_id in sorted(baselines):
            ledger.add(
                f"{host_id}/same-corpus/{tool_id}.json",
                Path(str(baselines[tool_id])),
            )
    mlkem = assembly_evidence.get("mlkem_public_attribution")
    if not isinstance(mlkem, Mapping) or not isinstance(mlkem.get("bundle"), str):
        raise AnalysisError("ML-KEM assembly evidence index is malformed")
    ledger.add("assembly/mlkem_public_attribution.json", Path(str(mlkem["bundle"])))


def _measurement_validation_commands(
    bundle: Mapping[str, Any],
) -> list[list[str]]:
    measurement_commit = str(bundle["measurement_commit"])
    commands: list[list[str]] = []
    for host in bundle["hosts"]:
        components = host["components"]
        for component in sorted(COMPONENT_PLANS):
            commands.append(
                [
                    sys.executable,
                    str(ROOT / "scripts/run_native_timing_campaign.py"),
                    "--manifest",
                    str(COMPONENT_PLANS[component].manifest),
                    "--validate-run",
                    str(components[component]),
                    "--expected-commit",
                    measurement_commit,
                    "--expected-run-kind",
                    "final",
                ]
            )
        for tool_id in sorted(host["same_corpus_results"]):
            commands.append(
                [
                    sys.executable,
                    str(ROOT / "scripts/run_same_corpus_baselines.py"),
                    "--validate-result",
                    str(host["same_corpus_results"][tool_id]),
                    "--expected-commit",
                    measurement_commit,
                    "--expected-run-kind",
                    "final",
                ]
            )
    assembly = bundle.get("assembly_evidence")
    mlkem = assembly.get("mlkem_public_attribution") if isinstance(assembly, Mapping) else None
    if not isinstance(mlkem, Mapping) or not isinstance(mlkem.get("bundle"), str):
        raise AnalysisError("ML-KEM assembly evidence command index is malformed")
    commands.append(
        [
            sys.executable,
            str(ROOT / "scripts/check_asm_evidence.py"),
            "--bundle",
            str(mlkem["bundle"]),
            "--no-current-commit",
            "--expected-commit",
            measurement_commit,
        ]
    )
    return commands


def _run_validators(commands: Sequence[Sequence[str]]) -> None:
    for command in commands:
        result = subprocess.run(
            list(command),
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            display = " ".join(command)
            details = (result.stderr or result.stdout).strip()[-2000:]
            raise AnalysisError(f"upstream artifact validator failed: {display}\n{details}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument(
        "--verification-commit",
        "--expected-commit",
        dest="verification_commit",
        required=True,
        help="clean checkout HEAD used to verify the frozen measurement commit",
    )
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--output-mode",
        choices=("named", "blinded", "unblinded"),
        required=True,
        help="emit scoped named results, or run the legacy blinded two-host workflow",
    )
    parser.add_argument(
        "--blinding-record",
        type=Path,
        help=(
            "custodian-held draft for blinded mode; unblinded mode accepts only "
            "the exact record path frozen in the validated bundle"
        ),
    )
    parser.add_argument(
        "--blinded-output-root",
        type=Path,
        help="unblinded-mode override; must equal the bundle's frozen opaque-output path",
    )
    parser.add_argument(
        "--check-output",
        action="store_true",
        help="compare regenerated deterministic output instead of writing it",
    )
    parser.add_argument(
        "--allow-review-only-descendant",
        action="store_true",
        help=(
            "allow HEAD to descend from --verification-commit only when the "
            "native-promotion review packet is the sole changed file"
        ),
    )
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40}", args.verification_commit):
        parser.error("--verification-commit must be a lowercase 40-hex commit")
    if args.output_mode == "blinded" and args.blinded_output_root is not None:
        parser.error("--blinded-output-root applies only to unblinded mode")
    if args.output_mode == "named" and (
        args.blinding_record is not None or args.blinded_output_root is not None
    ):
        parser.error("named mode does not accept blinding arguments")
    try:
        current_commit = _git_head()
        if current_commit != args.verification_commit:
            if not args.allow_review_only_descendant:
                raise AnalysisError("analysis checkout HEAD differs from --verification-commit")
            _require_review_only_descendant(args.verification_commit, current_commit)
        if _tracked_worktree_dirty():
            raise AnalysisError("analysis checkout has tracked changes")
        bundle_path = args.bundle.resolve()
        if args.output_mode in {"named", "blinded"}:
            bundle, record_path = _prepare_blinded_bundle(
                bundle_path,
                args.verification_commit,
            )
            _run_validators(_measurement_validation_commands(bundle))
            if args.output_mode == "named":
                if bundle.get("evidence_scope") != "single-physical-host":
                    raise AnalysisError("named mode requires a schema-v5 single-host bundle")
                declared_named_root = Path(str(bundle["named_analysis_root"]))
                declared_blinded_root = None
            else:
                if bundle.get("evidence_scope") == "single-physical-host":
                    raise AnalysisError("blinded mode requires the schema-v4 two-host bundle")
                declared_blinded_root = Path(str(bundle["blinded_analysis_root"]))
        else:
            from scripts.reproduce_artifact import validate_bundle

            bundle, commands = validate_bundle(bundle_path, args.verification_commit)
            _run_validators(commands)
            raw_bundle = yaml.safe_load(bundle_path.read_text(encoding="utf-8"))
            if not isinstance(raw_bundle, dict) or not isinstance(
                raw_bundle.get("blind_rerun"), dict
            ):
                raise AnalysisError("validated bundle lost its blinding record index")
            record_path = _safe_child(
                bundle_path.parent,
                raw_bundle["blind_rerun"].get("unblinding_record"),
                "blind_rerun.unblinding_record",
                directory=False,
            )
            declared_blinded_root = _safe_child(
                bundle_path.parent,
                raw_bundle["blind_rerun"].get("blinded_analysis_root"),
                "blind_rerun.blinded_analysis_root",
                directory=True,
            )
        if args.output_mode != "named":
            if record_path is None:
                raise AnalysisError("blinded workflow lost its unblinding record path")
            record_path = _select_blinding_record(
                record_path,
                args.blinding_record,
                allow_external_draft=args.output_mode == "blinded",
            )
        measurement_commit = bundle.get("measurement_commit")
        if not isinstance(measurement_commit, str) or not re.fullmatch(
            r"[0-9a-f]{40}", measurement_commit
        ):
            raise AnalysisError("validated bundle has no measurement commit")
        ledger = InputLedger()
        ledger.add("measurement_bundle", bundle_path)
        _record_outer_inputs(ledger, bundle["hosts"], bundle["assembly_evidence"])
        observations: list[HostAxis] = []
        single_host = bundle.get("evidence_scope") == "single-physical-host"
        for host in bundle["hosts"]:
            observations.extend(
                load_host_axes(
                    host,
                    measurement_commit,
                    ledger,
                    required_gate_kind=(
                        "automated-frozen-input-integrity-gate"
                        if single_host
                        else "human-premeasurement-review-gate"
                    ),
                )
            )
        named = build_analysis(
            observations,
            expected_commit=measurement_commit,
            verification_commit=args.verification_commit,
            bundle_id=str(bundle.get("bundle_id") or ""),
            input_records=ledger.records(),
            input_aggregate_sha256=ledger.aggregate_sha256(),
            expected_host_count=1 if single_host else 2,
        )
        if args.output_mode == "named":
            if args.output_root.resolve() != declared_named_root.resolve():
                raise AnalysisError(
                    "named --output-root differs from the path frozen in the bundle"
                )
            write_outputs(args.output_root, named, check=args.check_output)
            record_path = None
        else:
            assert record_path is not None
            expected_pairs = {(item.key.component, item.key.target) for item in observations}
            blinding, record = load_blinding_map(
                record_path,
                expected_bundle_id=str(bundle.get("bundle_id") or ""),
                expected_pairs=expected_pairs,
            )
            blinded = blind_analysis(named, blinding)
        if args.output_mode == "blinded":
            if args.output_root.resolve() != declared_blinded_root.resolve():
                raise AnalysisError(
                    "blinded --output-root differs from the path frozen in the bundle"
                )
            manifest_hash = write_blinded_outputs(
                args.output_root,
                blinded,
                check=args.check_output,
            )
            print(f"[paper-analysis] blinded manifest SHA-256: {manifest_hash}")
        elif args.output_mode == "unblinded":
            expected_manifest = record.get("blinded_analysis_manifest_sha256")
            if not isinstance(expected_manifest, str):
                raise AnalysisError("unblinding record lacks the blinded manifest hash")
            blinded_output_root = (
                args.blinded_output_root.resolve()
                if args.blinded_output_root is not None
                else declared_blinded_root.resolve()  # type: ignore[union-attr]
            )
            if blinded_output_root != declared_blinded_root.resolve():  # type: ignore[union-attr]
                raise AnalysisError(
                    "--blinded-output-root differs from the path frozen in the bundle"
                )
            verify_blinded_outputs(
                blinded_output_root,
                blinded,
                expected_manifest_sha256=expected_manifest,
            )
            unblinded = unblinded_analysis(
                named,
                blinding,
                record,
                unblinding_record_sha256=_sha256(record_path),
            )
            write_outputs(args.output_root, unblinded, check=args.check_output)
    except (AnalysisError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"[paper-analysis] ERROR: {exc}", file=sys.stderr)
        return 1
    verb = "verified" if args.check_output else "wrote"
    print(
        f"[paper-analysis] OK: {verb} deterministic native analysis at {args.output_root.resolve()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
