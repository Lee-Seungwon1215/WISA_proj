"""Independent verification of preserved official-dudect timing artifacts.

The measurement process and its JSON summary are not trusted as their own
attestation.  This module strictly parses the preserved analysis/calibration
CSVs, reimplements the pinned upstream ``dudect.h`` update order in Python,
and compares every one of the 102 tests with the backend report.  When a
protocol CSV is supplied, it also binds the selected raw traces to the exact
seeded process traces from which they were exported.
"""

from __future__ import annotations

import csv
import math
import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from statistics import NormalDist, mean, variance
from typing import Any, Mapping, Sequence

from .official_dudect import (
    OFFICIAL_DUDECT_BACKEND,
    OFFICIAL_DUDECT_MIN_CLASS0,
    OFFICIAL_DUDECT_PERCENTILE_TESTS,
    OFFICIAL_DUDECT_PROTOCOL_TESTS,
    OFFICIAL_DUDECT_REVISION,
    OfficialDudectAnalysis,
    OfficialProtocolTest,
)
from .timing_input_contract import validate_valid_tuple_harness_report

RAW_TIMING_HEADER = (
    "project",
    "harness",
    "sample_id",
    "class",
    "cycles",
    "aux_start",
    "aux_end",
    "drop_reason",
    "output_length",
    "signature_return_code",
    "protocol",
)
PROTOCOL_TIMING_HEADER = (
    "project",
    "harness",
    "role",
    "process_index",
    "seed",
    "effect_ticks",
    *RAW_TIMING_HEADER[2:],
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.-]+$")
_UNSIGNED_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)$")
_SIGNED_DECIMAL = re.compile(r"^(?:0|-?[1-9][0-9]*)$")
_INTEGER_NUMBER = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.0+)?(?:[eE][+-]?(?:0|[1-9][0-9]*))?$")
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1
_UINT32_MAX = 2**32 - 1
_UINT64_MAX = 2**64 - 1
_FLOAT_REL_TOLERANCE = 1e-12
_FLOAT_ABS_TOLERANCE = 1e-12
_PROTOCOL_ROLES = {"target-calibration", "target", "aa", "setup-placebo", "positive"}
_CALIBRATION_SEED_DOMAIN = 0x9E3779B97F4A7C15
_UINT64_MASK = 0xFFFFFFFFFFFFFFFF
_TIMING_SEED_DOMAINS = {
    "target": 0x5441524745545632,
    "calibration": 0x43414C4942525632,
    "aa": 0x41415F434E54525632,
    "placebo": 0x504C414345425632,
    "positive": 0x504F534954495632,
}


class OfficialDudectVerificationError(RuntimeError):
    """A preserved raw artifact is malformed or contradicts the protocol."""


@dataclass(frozen=True)
class TimingArtifactSample:
    sample_id: int
    clazz: int
    cycles: int
    aux_start: int | None
    aux_end: int | None
    drop_reason: str
    output_length: int | None
    signature_return_code: int | None
    protocol: str

    @property
    def retained(self) -> bool:
        return self.drop_reason == ""


@dataclass(frozen=True)
class TimingArtifactTrace:
    project: str
    harness: str
    rows: tuple[TimingArtifactSample, ...]

    @property
    def retained_rows(self) -> tuple[TimingArtifactSample, ...]:
        return tuple(row for row in self.rows if row.retained)


@dataclass(frozen=True)
class ProtocolArtifactTrace:
    project: str
    harness: str
    role: str
    process_index: int
    seed: int
    effect_ticks: int
    rows: tuple[TimingArtifactSample, ...]


@dataclass
class OfficialDudectArtifactVerification:
    analyses: dict[str, OfficialDudectAnalysis] = field(default_factory=dict)
    analysis_traces: dict[str, TimingArtifactTrace] = field(default_factory=dict)
    calibration_traces: dict[str, TimingArtifactTrace] = field(default_factory=dict)
    protocol_summaries: dict[str, dict[str, Any]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.errors


@dataclass
class _OnlineTest:
    mean: list[float] = field(default_factory=lambda: [0.0, 0.0])
    m2: list[float] = field(default_factory=lambda: [0.0, 0.0])
    n: list[int] = field(default_factory=lambda: [0, 0])

    def push(self, value: float, clazz: int) -> None:
        self.n[clazz] += 1
        delta = value - self.mean[clazz]
        self.mean[clazz] = self.mean[clazz] + delta / self.n[clazz]
        self.m2[clazz] = self.m2[clazz] + delta * (value - self.mean[clazz])

    def variance(self, clazz: int) -> float:
        if self.n[clazz] < 2:
            return math.nan
        return self.m2[clazz] / (self.n[clazz] - 1)

    def t_score(self) -> float:
        # C's IEEE-754 divisions yield NaN for an under-populated class;
        # Python would raise ZeroDivisionError instead. Preserve the pinned
        # backend's value semantics explicitly.
        if self.n[0] < 2 or self.n[1] < 2:
            return math.nan
        variance0 = self.variance(0)
        variance1 = self.variance(1)
        denominator_squared = variance0 / self.n[0] + variance1 / self.n[1]
        denominator = math.sqrt(denominator_squared) if denominator_squared >= 0 else math.nan
        numerator = self.mean[0] - self.mean[1]
        if denominator == 0.0:
            if numerator == 0.0:
                return math.nan
            return math.copysign(math.inf, numerator)
        return numerator / denominator


@dataclass(frozen=True)
class OfficialDudectProtocolContract:
    """Frozen physical-control contract used to authenticate protocol CSV rows."""

    base_seed: int
    process_repeats: int
    target_measurements: int
    control_measurements: int
    positive_effects: tuple[int, ...]
    aa_abs_t_limit: float
    positive_abs_t_threshold: float
    aa_max_failures: int
    target_power: float
    power_alpha: float
    expected_axes: tuple[tuple[str, str], ...] = ()


def _timing_domain_seed(base: int, role: str, process_index: int, subindex: int = 0) -> int:
    x = (
        base
        ^ _TIMING_SEED_DOMAINS[role]
        ^ ((process_index + 1) * _CALIBRATION_SEED_DOMAIN)
        ^ ((subindex + 1) * 0xD1B54A32D192ED03)
    ) & _UINT64_MASK
    x = (x + _CALIBRATION_SEED_DOMAIN) & _UINT64_MASK
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & _UINT64_MASK
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & _UINT64_MASK
    x ^= x >> 31
    return x or _TIMING_SEED_DOMAINS[role]


def _parse_uint(value: str, *, label: str, maximum: int = _UINT64_MAX) -> int:
    if _UNSIGNED_DECIMAL.fullmatch(value) is None:
        raise OfficialDudectVerificationError(f"{label} is not canonical unsigned decimal")
    parsed = int(value)
    if parsed > maximum:
        raise OfficialDudectVerificationError(f"{label} exceeds {maximum}")
    return parsed


def _parse_int(
    value: str,
    *,
    label: str,
    minimum: int,
    maximum: int,
) -> int:
    if _SIGNED_DECIMAL.fullmatch(value) is None:
        raise OfficialDudectVerificationError(f"{label} is not canonical signed decimal")
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise OfficialDudectVerificationError(f"{label} is outside [{minimum},{maximum}]")
    return parsed


def _parse_cycles(value: str, *, label: str) -> int:
    if _INTEGER_NUMBER.fullmatch(value) is None:
        raise OfficialDudectVerificationError(
            f"{label} is not a canonical integer-valued cycle count"
        )
    try:
        decimal = Decimal(value)
    except InvalidOperation as exc:
        raise OfficialDudectVerificationError(f"{label} is invalid") from exc
    if not decimal.is_finite() or decimal != decimal.to_integral_value():
        raise OfficialDudectVerificationError(f"{label} is not a finite integer")
    parsed = int(decimal)
    if not _INT64_MIN <= parsed <= _INT64_MAX:
        raise OfficialDudectVerificationError(f"{label} is outside signed int64")
    return parsed


def _optional_uint(value: str, *, label: str, maximum: int) -> int | None:
    return None if value == "" else _parse_uint(value, label=label, maximum=maximum)


def _parse_sample(values: Sequence[str], *, label: str) -> TimingArtifactSample:
    if len(values) != len(RAW_TIMING_HEADER) - 2:
        raise OfficialDudectVerificationError(f"{label} has the wrong field count")
    (
        sample_id_raw,
        class_raw,
        cycles_raw,
        aux_start_raw,
        aux_end_raw,
        drop_reason,
        output_length_raw,
        signature_return_code_raw,
        protocol,
    ) = values
    sample_id = _parse_uint(sample_id_raw, label=f"{label}.sample_id")
    clazz = _parse_uint(class_raw, label=f"{label}.class", maximum=1)
    cycles = _parse_cycles(cycles_raw, label=f"{label}.cycles")
    aux_start = _optional_uint(aux_start_raw, label=f"{label}.aux_start", maximum=_UINT32_MAX)
    aux_end = _optional_uint(aux_end_raw, label=f"{label}.aux_end", maximum=_UINT32_MAX)
    output_length = _optional_uint(
        output_length_raw,
        label=f"{label}.output_length",
        maximum=_UINT64_MAX,
    )
    signature_return_code = (
        None
        if signature_return_code_raw == ""
        else _parse_int(
            signature_return_code_raw,
            label=f"{label}.signature_return_code",
            minimum=-(2**31),
            maximum=2**31 - 1,
        )
    )
    if drop_reason not in {"", "clock-anomaly", "cpu-migration"}:
        raise OfficialDudectVerificationError(f"{label}.drop_reason is invalid: {drop_reason!r}")
    if protocol not in {"timing-harness-v1", "timing-harness-v2"}:
        raise OfficialDudectVerificationError(f"{label}.protocol is invalid: {protocol!r}")
    if protocol == "timing-harness-v1":
        if (
            any(
                value is not None
                for value in (aux_start, aux_end, output_length, signature_return_code)
            )
            or drop_reason
        ):
            raise OfficialDudectVerificationError(
                f"{label}: timing-harness-v1 carries v2-only fields"
            )
    else:
        if aux_start is None or aux_end is None or output_length is None:
            raise OfficialDudectVerificationError(f"{label}: v2 row lacks AUX/output metadata")
        if not drop_reason and (cycles == 0 or aux_start != aux_end):
            raise OfficialDudectVerificationError(
                f"{label}: retained row contains an unmarked clock/AUX anomaly"
            )
        if drop_reason == "cpu-migration" and aux_start == aux_end:
            raise OfficialDudectVerificationError(f"{label}: cpu-migration row has unchanged AUX")
    return TimingArtifactSample(
        sample_id=sample_id,
        clazz=clazz,
        cycles=cycles,
        aux_start=aux_start,
        aux_end=aux_end,
        drop_reason=drop_reason,
        output_length=output_length,
        signature_return_code=signature_return_code,
        protocol=protocol,
    )


def parse_official_timing_csv(
    path: Path,
    *,
    expected_project: str,
) -> dict[str, TimingArtifactTrace]:
    """Strictly parse one exported analysis or calibration CSV."""

    if path.is_symlink() or not path.is_file():
        raise OfficialDudectVerificationError(f"artifact is missing or symlinked: {path}")
    rows: dict[str, list[TimingArtifactSample]] = {}
    protocols: dict[str, str] = {}
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.reader(handle, strict=True)
            header = next(reader, None)
            if header != list(RAW_TIMING_HEADER):
                raise OfficialDudectVerificationError(
                    f"{path.name}: exact header mismatch: {header!r}"
                )
            for line_number, raw in enumerate(reader, start=2):
                if len(raw) != len(RAW_TIMING_HEADER):
                    raise OfficialDudectVerificationError(
                        f"{path.name}:{line_number}: expected "
                        f"{len(RAW_TIMING_HEADER)} fields, got {len(raw)}"
                    )
                project, harness = raw[:2]
                if project != expected_project:
                    raise OfficialDudectVerificationError(
                        f"{path.name}:{line_number}: project={project!r}, "
                        f"expected={expected_project!r}"
                    )
                if _IDENTIFIER.fullmatch(harness) is None:
                    raise OfficialDudectVerificationError(
                        f"{path.name}:{line_number}: invalid harness {harness!r}"
                    )
                sample = _parse_sample(raw[2:], label=f"{path.name}:{line_number}")
                trace_rows = rows.setdefault(harness, [])
                if sample.sample_id != len(trace_rows):
                    raise OfficialDudectVerificationError(
                        f"{path.name}:{line_number}: {harness} sample_id="
                        f"{sample.sample_id}, expected={len(trace_rows)}"
                    )
                prior_protocol = protocols.setdefault(harness, sample.protocol)
                if prior_protocol != sample.protocol:
                    raise OfficialDudectVerificationError(
                        f"{path.name}:{line_number}: {harness} protocol changed within trace"
                    )
                trace_rows.append(sample)
    except (OSError, UnicodeError, csv.Error) as exc:
        raise OfficialDudectVerificationError(f"cannot parse {path}: {exc}") from exc
    if not rows:
        raise OfficialDudectVerificationError(f"{path.name}: contains no timing rows")
    return {
        harness: TimingArtifactTrace(expected_project, harness, tuple(trace_rows))
        for harness, trace_rows in rows.items()
    }


def parse_official_protocol_csv(
    path: Path,
    *,
    expected_project: str,
) -> dict[tuple[str, str, int, int], ProtocolArtifactTrace]:
    """Strictly parse all process traces used to select the exported raw trace."""

    if path.is_symlink() or not path.is_file():
        raise OfficialDudectVerificationError(f"artifact is missing or symlinked: {path}")
    rows: dict[tuple[str, str, int, int], list[TimingArtifactSample]] = {}
    seeds: dict[tuple[str, str, int, int], int] = {}
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.reader(handle, strict=True)
            header = next(reader, None)
            if header != list(PROTOCOL_TIMING_HEADER):
                raise OfficialDudectVerificationError(
                    f"{path.name}: exact header mismatch: {header!r}"
                )
            for line_number, raw in enumerate(reader, start=2):
                if len(raw) != len(PROTOCOL_TIMING_HEADER):
                    raise OfficialDudectVerificationError(
                        f"{path.name}:{line_number}: wrong protocol field count"
                    )
                project, harness, role = raw[:3]
                if project != expected_project or _IDENTIFIER.fullmatch(harness) is None:
                    raise OfficialDudectVerificationError(
                        f"{path.name}:{line_number}: project/harness identity mismatch"
                    )
                if role not in _PROTOCOL_ROLES:
                    raise OfficialDudectVerificationError(
                        f"{path.name}:{line_number}: invalid role {role!r}"
                    )
                process_index = _parse_uint(
                    raw[3], label=f"{path.name}:{line_number}.process_index"
                )
                seed = _parse_uint(raw[4], label=f"{path.name}:{line_number}.seed")
                effect_ticks = _parse_uint(raw[5], label=f"{path.name}:{line_number}.effect_ticks")
                if seed == 0:
                    raise OfficialDudectVerificationError(
                        f"{path.name}:{line_number}: seed must be nonzero"
                    )
                if (role == "positive") != (effect_ticks > 0):
                    raise OfficialDudectVerificationError(
                        f"{path.name}:{line_number}: role/effect mismatch"
                    )
                sample = _parse_sample(raw[6:], label=f"{path.name}:{line_number}")
                if sample.protocol != "timing-harness-v2":
                    raise OfficialDudectVerificationError(
                        f"{path.name}:{line_number}: protocol trace is not v2"
                    )
                key = (harness, role, process_index, effect_ticks)
                trace_rows = rows.setdefault(key, [])
                if sample.sample_id != len(trace_rows):
                    raise OfficialDudectVerificationError(
                        f"{path.name}:{line_number}: sample_id={sample.sample_id}, "
                        f"expected={len(trace_rows)} for {key}"
                    )
                prior_seed = seeds.setdefault(key, seed)
                if prior_seed != seed:
                    raise OfficialDudectVerificationError(
                        f"{path.name}:{line_number}: seed changed within {key}"
                    )
                trace_rows.append(sample)
    except (OSError, UnicodeError, csv.Error) as exc:
        raise OfficialDudectVerificationError(f"cannot parse {path}: {exc}") from exc
    if not rows:
        raise OfficialDudectVerificationError(f"{path.name}: contains no protocol rows")
    return {
        key: ProtocolArtifactTrace(
            expected_project,
            key[0],
            key[1],
            key[2],
            seeds[key],
            key[3],
            tuple(trace_rows),
        )
        for key, trace_rows in rows.items()
    }


def _test_kind(index: int) -> str:
    if index == 0:
        return "first-order-uncropped"
    if index <= OFFICIAL_DUDECT_PERCENTILE_TESTS:
        return "first-order-cropped"
    return "second-order"


def recompute_pinned_official_dudect(
    calibration: Sequence[TimingArtifactSample],
    analysis: Sequence[TimingArtifactSample],
) -> OfficialDudectAnalysis:
    """Recompute the pinned C update order without invoking its adapter."""

    calibration_retained = [row for row in calibration if row.retained]
    analysis_retained = [row for row in analysis if row.retained]
    if not calibration_retained or not analysis_retained:
        raise OfficialDudectVerificationError(
            "official dudect calibration and analysis traces must retain at least one row"
        )

    calibration_values = sorted([row.cycles for row in calibration_retained] + [0])
    percentile_values: list[int] = []
    for index in range(OFFICIAL_DUDECT_PERCENTILE_TESTS):
        which = 1.0 - math.pow(
            0.5,
            10.0 * float(index + 1) / float(OFFICIAL_DUDECT_PERCENTILE_TESTS),
        )
        position = int(float(len(calibration_values)) * which)
        if not 0 <= position < len(calibration_values):
            raise OfficialDudectVerificationError("pinned percentile index is out of range")
        percentile_values.append(calibration_values[position])

    contexts = [_OnlineTest() for _ in range(OFFICIAL_DUDECT_PROTOCOL_TESTS)]
    dropped_negative = 0
    for row in analysis_retained[10:]:
        difference = row.cycles
        if difference < 0:
            dropped_negative += 1
            continue
        value = float(difference)
        contexts[0].push(value, row.clazz)
        for crop_index, threshold in enumerate(percentile_values):
            if difference < threshold:
                contexts[crop_index + 1].push(value, row.clazz)
        if contexts[0].n[0] > 10_000:
            centered = value - contexts[0].mean[row.clazz]
            contexts[1 + OFFICIAL_DUDECT_PERCENTILE_TESTS].push(
                centered * centered,
                row.clazz,
            )

    winning_index = 0
    maximum = 0.0
    for index, context in enumerate(contexts):
        if context.n[0] > 10_000:
            candidate = abs(context.t_score())
            if maximum < candidate:
                maximum = candidate
                winning_index = index
    enough = any(context.n[0] > 10_000 and context.n[1] >= 2 for context in contexts)
    winning = contexts[winning_index]
    winning_t = winning.t_score() if winning.n[0] >= 2 and winning.n[1] >= 2 else math.nan
    max_abs_t = abs(winning_t)
    winning_n = winning.n[0] + winning.n[1]
    if winning_n > 0 and math.isfinite(max_abs_t):
        max_tau = max_abs_t / math.sqrt(winning_n)
    elif math.isinf(max_abs_t):
        max_tau = math.inf
    else:
        max_tau = math.nan
    if max_tau > 0 and math.isfinite(max_tau):
        detection_estimate = 25.0 / (max_tau * max_tau)
    elif max_tau == 0:
        detection_estimate = math.inf
    else:
        detection_estimate = math.nan
    status = "INSUFFICIENT" if not enough else ("FAIL" if max_abs_t > 10.0 else "PASS")

    tests: list[OfficialProtocolTest] = []
    for index, context in enumerate(contexts):
        t_value = context.t_score() if context.n[0] >= 2 and context.n[1] >= 2 else math.nan
        variance0 = context.variance(0)
        variance1 = context.variance(1)
        tests.append(
            OfficialProtocolTest(
                index=index,
                kind=_test_kind(index),
                crop_index=(index - 1 if 0 < index <= OFFICIAL_DUDECT_PERCENTILE_TESTS else None),
                crop_threshold=(
                    percentile_values[index - 1]
                    if 0 < index <= OFFICIAL_DUDECT_PERCENTILE_TESTS
                    else None
                ),
                n0=context.n[0],
                n1=context.n[1],
                mean0=context.mean[0],
                mean1=context.mean[1],
                var0=variance0 if math.isfinite(variance0) else None,
                var1=variance1 if math.isfinite(variance1) else None,
                t_score=t_value if math.isfinite(t_value) else None,
                abs_t_score=abs(t_value) if math.isfinite(t_value) else None,
                t_nonfinite=not math.isfinite(t_value),
                eligible=(context.n[0] > 10_000 and context.n[1] >= 2 and not math.isnan(t_value)),
            )
        )
    return OfficialDudectAnalysis(
        status=status,
        enough_measurements=enough,
        minimum_class0_measurements=OFFICIAL_DUDECT_MIN_CLASS0,
        calibration_input_count=len(calibration_retained),
        analysis_input_count=len(analysis_retained),
        discarded_initial_count=min(10, len(analysis_retained)),
        dropped_negative_count=dropped_negative,
        max_test_index=winning_index,
        max_test_kind=_test_kind(winning_index),
        max_abs_t=max_abs_t,
        max_tau=max_tau,
        detection_estimate=detection_estimate,
        tests=tuple(tests),
    )


def _same_number(expected: Any, actual: Any) -> bool:
    if expected is None:
        return actual is None
    if isinstance(expected, bool) or not isinstance(expected, (int, float)):
        return expected == actual
    if isinstance(actual, bool) or not isinstance(actual, (int, float)):
        return False
    if isinstance(expected, int):
        return isinstance(actual, int) and actual == expected
    return math.isfinite(float(actual)) and math.isclose(
        float(expected),
        float(actual),
        rel_tol=_FLOAT_REL_TOLERANCE,
        abs_tol=_FLOAT_ABS_TOLERANCE,
    )


def _compare_backend(
    harness: str,
    analysis: OfficialDudectAnalysis,
    item: Mapping[str, Any],
    raw_row_count: int,
    calibration_row_count: int,
) -> list[str]:
    errors: list[str] = []
    winning = analysis.winning_test
    uncropped = analysis.uncropped_test
    expected_fields: dict[str, Any] = {
        "backend": OFFICIAL_DUDECT_BACKEND,
        "upstream_revision": OFFICIAL_DUDECT_REVISION,
        "raw_status": analysis.status,
        "test_kind": analysis.max_test_kind,
        "test_index": analysis.max_test_index,
        "protocol_test_count": OFFICIAL_DUDECT_PROTOCOL_TESTS,
        "n0": winning.n0,
        "n1": winning.n1,
        "t_score": winning.t_score,
        "abs_t_score": (analysis.max_abs_t if math.isfinite(analysis.max_abs_t) else None),
        "t_score_uncropped": uncropped.t_score,
        "abs_t_score_uncropped": uncropped.abs_t_score,
        "max_tau": analysis.max_tau
        if analysis.max_tau is not None and math.isfinite(analysis.max_tau)
        else None,
        "detection_estimate": (
            analysis.detection_estimate
            if analysis.detection_estimate is not None
            and math.isfinite(analysis.detection_estimate)
            else None
        ),
        "enough_measurements": analysis.enough_measurements,
        "analysis_raw_n_total": raw_row_count,
        "calibration_raw_n_total": calibration_row_count,
    }
    for field_name, expected in expected_fields.items():
        actual = item.get(field_name)
        if not _same_number(expected, actual):
            errors.append(
                f"{harness}: backend {field_name}={actual!r}, independently recomputed={expected!r}"
            )

    raw_tests = item.get("tests")
    if not isinstance(raw_tests, list) or len(raw_tests) != OFFICIAL_DUDECT_PROTOCOL_TESTS:
        return errors + [
            f"{harness}: backend must contain exactly {OFFICIAL_DUDECT_PROTOCOL_TESTS} tests"
        ]
    expected_test_fields = set(analysis.tests[0].as_dict())
    for index, (expected_test, actual_test) in enumerate(
        zip(analysis.tests, raw_tests, strict=True)
    ):
        if not isinstance(actual_test, dict):
            errors.append(f"{harness}: backend test[{index}] is not an object")
            continue
        if set(actual_test) != expected_test_fields:
            errors.append(f"{harness}: backend test[{index}] field set drift")
            continue
        for field_name, expected in expected_test.as_dict().items():
            if not _same_number(expected, actual_test.get(field_name)):
                errors.append(
                    f"{harness}: backend test[{index}].{field_name}="
                    f"{actual_test.get(field_name)!r}, independently recomputed={expected!r}"
                )
    return errors


def _selected_protocol_trace(
    traces: Mapping[tuple[str, str, int, int], ProtocolArtifactTrace],
    *,
    harness: str,
    role: str,
    seed: Any,
) -> ProtocolArtifactTrace | None:
    if isinstance(seed, bool) or not isinstance(seed, int):
        return None
    matches = [
        trace
        for trace in traces.values()
        if trace.harness == harness and trace.role == role and trace.seed == seed
    ]
    return matches[0] if len(matches) == 1 else None


def _expected_protocol_traces(
    harness: str,
    contract: OfficialDudectProtocolContract,
) -> dict[tuple[str, str, int, int], tuple[int, int]]:
    expected: dict[tuple[str, str, int, int], tuple[int, int]] = {}
    for process_index in range(contract.process_repeats):
        target_seed = (
            contract.base_seed
            if process_index == 0
            else _timing_domain_seed(contract.base_seed, "target", process_index)
        )
        expected[(harness, "target", process_index, 0)] = (
            contract.target_measurements,
            target_seed,
        )
        expected[(harness, "target-calibration", process_index, 0)] = (
            contract.target_measurements,
            _timing_domain_seed(contract.base_seed, "calibration", process_index),
        )
        expected[(harness, "aa", process_index, 0)] = (
            contract.control_measurements,
            _timing_domain_seed(contract.base_seed, "aa", process_index),
        )
        expected[(harness, "setup-placebo", process_index, 0)] = (
            contract.control_measurements,
            _timing_domain_seed(contract.base_seed, "placebo", process_index),
        )
        for effect_index, effect in enumerate(contract.positive_effects):
            expected[(harness, "positive", process_index, effect)] = (
                contract.control_measurements,
                _timing_domain_seed(
                    contract.base_seed,
                    "positive",
                    process_index,
                    effect_index,
                ),
            )
    return expected


def _control_payload(
    trace: ProtocolArtifactTrace,
    *,
    warning_threshold: float,
    fail_threshold: float,
    power_alpha: float | None = None,
    target_power: float | None = None,
) -> dict[str, Any]:
    retained = trace.rows
    class0 = [row.cycles for row in retained if row.retained and row.clazz == 0]
    class1 = [row.cycles for row in retained if row.retained and row.clazz == 1]
    if len(class0) < 2 or len(class1) < 2:
        raise OfficialDudectVerificationError(
            f"{trace.harness}/{trace.role}/{trace.process_index}/{trace.effect_ticks}: "
            "control retained fewer than two rows in a class"
        )
    n0, n1 = len(class0), len(class1)
    # ``TimingSamples`` stores cycles as floats, so the producer serializes
    # control means as JSON numbers such as ``1699595.0``.  The independent
    # artifact parser intentionally restores cycle counts to integers, and
    # ``statistics.mean`` returns an ``int`` when that mean is exact.  Keep
    # statistical quantities in the real-valued domain here; otherwise the
    # strict integer-field branch in ``_same_number`` rejects a numerically
    # identical producer value solely because JSON preserved its ``.0``.
    mean0, mean1 = float(mean(class0)), float(mean(class1))
    var0, var1 = variance(class0), variance(class1)
    denominator = math.sqrt(var0 / n0 + var1 / n1)
    numerator = mean0 - mean1
    t_score = (
        0.0
        if denominator == 0.0 and numerator == 0.0
        else (math.copysign(math.inf, numerator) if denominator == 0.0 else numerator / denominator)
    )
    abs_t_score = abs(t_score)
    status = (
        "FAIL"
        if not math.isfinite(abs_t_score) or abs_t_score >= fail_threshold
        else "WARNING"
        if abs_t_score >= warning_threshold
        else "PASS"
    )
    payload: dict[str, Any] = {
        "role": trace.role,
        "process_index": trace.process_index,
        "seed": trace.seed,
        "effect_ticks": trace.effect_ticks,
        "raw_n_total": len(trace.rows),
        "n0": n0,
        "n1": n1,
        "mean0": mean0,
        "mean1": mean1,
        "mean_delta": mean1 - mean0,
        "t_score": t_score,
        "abs_t_score": abs_t_score,
        "status": status,
        "dropped_clock_n0": sum(
            row.drop_reason == "clock-anomaly" and row.clazz == 0 for row in trace.rows
        ),
        "dropped_clock_n1": sum(
            row.drop_reason == "clock-anomaly" and row.clazz == 1 for row in trace.rows
        ),
        "dropped_migration_n0": sum(
            row.drop_reason == "cpu-migration" and row.clazz == 0 for row in trace.rows
        ),
        "dropped_migration_n1": sum(
            row.drop_reason == "cpu-migration" and row.clazz == 1 for row in trace.rows
        ),
        "malformed_count": 0,
    }
    if power_alpha is not None and target_power is not None:
        standard_error = math.sqrt(var0 / n0 + var1 / n1)
        payload["minimum_detectable_effect"] = (
            NormalDist().inv_cdf(1.0 - power_alpha / 2.0) + NormalDist().inv_cdf(target_power)
        ) * standard_error
        payload["positive_detection_effect_at_target_power"] = (
            fail_threshold + NormalDist().inv_cdf(target_power)
        ) * standard_error
    return payload


def _positive_control_detected(
    payload: Mapping[str, Any],
    *,
    abs_t_threshold: float,
) -> bool:
    """Independently enforce the seeded delay's known class-1-slower direction."""

    return payload["mean_delta"] > 0.0 and payload["t_score"] <= -abs_t_threshold


def _compare_payload(
    harness: str,
    label: str,
    expected: Mapping[str, Any],
    actual: Any,
) -> list[str]:
    if not isinstance(actual, dict):
        return [f"{harness}: backend {label} is not an object"]
    errors: list[str] = []
    for field_name, expected_value in expected.items():
        if not _same_number(expected_value, actual.get(field_name)):
            errors.append(
                f"{harness}: backend {label}.{field_name}={actual.get(field_name)!r}, "
                f"raw protocol={expected_value!r}"
            )
    return errors


def _verify_protocol_contract(
    *,
    harness: str,
    traces: Mapping[tuple[str, str, int, int], ProtocolArtifactTrace],
    backend: Mapping[str, Any],
    contract: OfficialDudectProtocolContract,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    expected_index = _expected_protocol_traces(harness, contract)
    actual_index = {key: value for key, value in traces.items() if key[0] == harness}
    if set(actual_index) != set(expected_index):
        errors.append(
            f"{harness}: protocol trace matrix mismatch: "
            f"missing={sorted(set(expected_index) - set(actual_index))}, "
            f"extra={sorted(set(actual_index) - set(expected_index))}"
        )
    for key in sorted(set(actual_index).intersection(expected_index)):
        expected_count, expected_seed = expected_index[key]
        trace = actual_index[key]
        if len(trace.rows) != expected_count:
            errors.append(
                f"{harness}: protocol {key[1:]} row count={len(trace.rows)}, "
                f"expected={expected_count}"
            )
        if trace.seed != expected_seed:
            errors.append(
                f"{harness}: protocol {key[1:]} seed={trace.seed}, expected={expected_seed}"
            )
    if errors:
        return {}, errors

    protocol = backend.get("harness_protocol")
    if not isinstance(protocol, dict):
        return {}, [f"{harness}: backend harness_protocol is not an object"]
    expected_axis = dict(contract.expected_axes).get(harness)
    if expected_axis is not None and protocol.get("axis") != expected_axis:
        errors.append(
            f"{harness}: backend harness_protocol.axis={protocol.get('axis')!r}, "
            f"expected={expected_axis!r}"
        )
    if expected_axis == "valid_tuple":
        errors.extend(
            validate_valid_tuple_harness_report(
                backend,
                label=f"{harness}: backend",
            )
        )

    target_payloads: list[dict[str, Any]] = []
    target_analyses: list[
        tuple[OfficialDudectAnalysis, ProtocolArtifactTrace, ProtocolArtifactTrace]
    ] = []
    aa_payloads: list[dict[str, Any]] = []
    placebo_payloads: list[dict[str, Any]] = []
    positive_payloads: list[dict[str, Any]] = []
    try:
        for process_index in range(contract.process_repeats):
            target_trace = actual_index[(harness, "target", process_index, 0)]
            calibration_trace = actual_index[(harness, "target-calibration", process_index, 0)]
            target_analysis = recompute_pinned_official_dudect(
                calibration_trace.rows,
                target_trace.rows,
            )
            target_analyses.append((target_analysis, target_trace, calibration_trace))
            target_payloads.append(
                {
                    "process_index": process_index,
                    "analysis_seed": target_trace.seed,
                    "calibration_seed": calibration_trace.seed,
                    "status": target_analysis.status,
                    "abs_t_score": (
                        target_analysis.max_abs_t
                        if math.isfinite(target_analysis.max_abs_t)
                        else None
                    ),
                    "test_kind": target_analysis.max_test_kind,
                    "test_index": target_analysis.max_test_index,
                    "n0": target_analysis.winning_test.n0,
                    "n1": target_analysis.winning_test.n1,
                    "enough_measurements": target_analysis.enough_measurements,
                }
            )
            aa_payloads.append(
                _control_payload(
                    actual_index[(harness, "aa", process_index, 0)],
                    warning_threshold=contract.aa_abs_t_limit,
                    fail_threshold=contract.positive_abs_t_threshold,
                    power_alpha=contract.power_alpha,
                    target_power=contract.target_power,
                )
            )
            placebo_payloads.append(
                _control_payload(
                    actual_index[(harness, "setup-placebo", process_index, 0)],
                    warning_threshold=contract.aa_abs_t_limit,
                    fail_threshold=contract.positive_abs_t_threshold,
                )
            )
            for effect in contract.positive_effects:
                positive_payloads.append(
                    _control_payload(
                        actual_index[(harness, "positive", process_index, effect)],
                        warning_threshold=contract.aa_abs_t_limit,
                        fail_threshold=contract.positive_abs_t_threshold,
                    )
                )
    except OfficialDudectVerificationError as exc:
        return {}, [str(exc)]

    winning_index = max(
        range(len(target_analyses)),
        key=lambda index: target_analyses[index][0].max_abs_t,
    )
    winning_analysis, winning_trace, winning_calibration = target_analyses[winning_index]
    if backend.get("analysis_seed") != winning_trace.seed:
        errors.append(f"{harness}: backend did not select the raw maximum-|t| target repeat")
    if backend.get("calibration_seed") != winning_calibration.seed:
        errors.append(f"{harness}: backend calibration seed does not match winning target repeat")

    for field_name, expected_payloads in (
        ("target_repeats", target_payloads),
        ("aa_controls", aa_payloads),
        ("setup_placebo_controls", placebo_payloads),
        ("positive_controls", positive_payloads),
    ):
        actual_payloads = protocol.get(field_name)
        if not isinstance(actual_payloads, list) or len(actual_payloads) != len(expected_payloads):
            errors.append(f"{harness}: backend {field_name} count differs from raw protocol")
            continue
        for index, (expected_payload, actual_payload) in enumerate(
            zip(expected_payloads, actual_payloads, strict=True)
        ):
            errors.extend(
                _compare_payload(
                    harness,
                    f"{field_name}[{index}]",
                    expected_payload,
                    actual_payload,
                )
            )

    target_status_consistent = len({item["status"] for item in target_payloads}) == 1
    aa_failures = sum(item["abs_t_score"] >= contract.aa_abs_t_limit for item in aa_payloads)
    placebo_failures = sum(
        item["abs_t_score"] >= contract.aa_abs_t_limit for item in placebo_payloads
    )
    required_detections = math.ceil(contract.target_power * contract.process_repeats)
    power_curve: list[dict[str, Any]] = []
    for effect in contract.positive_effects:
        effect_runs = [item for item in positive_payloads if item["effect_ticks"] == effect]
        detections = sum(
            _positive_control_detected(
                item,
                abs_t_threshold=contract.positive_abs_t_threshold,
            )
            for item in effect_runs
        )
        power_curve.append(
            {
                "effect_ticks": effect,
                "detections": detections,
                "runs": len(effect_runs),
                "detection_rate": detections / len(effect_runs),
                "mean_observed_delta": mean(item["mean_delta"] for item in effect_runs),
            }
        )
    summary = {
        "target_status_consistent": target_status_consistent,
        "aa_failures": aa_failures,
        "aa_budget_passed": aa_failures <= contract.aa_max_failures,
        "setup_placebo_failures": placebo_failures,
        "setup_placebo_passed": placebo_failures == 0,
        "required_positive_detections": required_detections,
        "positive_power_passed": power_curve[-1]["detections"] >= required_detections,
        "minimum_detectable_effects": [item["minimum_detectable_effect"] for item in aa_payloads],
        "positive_detection_effects_at_target_power": [
            item["positive_detection_effect_at_target_power"] for item in aa_payloads
        ],
        "positive_power_curve": power_curve,
        "winning_analysis": winning_analysis,
    }
    for field_name in (
        "target_status_consistent",
        "aa_failures",
        "aa_budget_passed",
        "setup_placebo_failures",
        "setup_placebo_passed",
        "required_positive_detections",
        "positive_power_passed",
        "minimum_detectable_effects",
        "positive_detection_effects_at_target_power",
    ):
        if not _same_number(summary[field_name], protocol.get(field_name)):
            errors.append(
                f"{harness}: backend harness_protocol.{field_name}="
                f"{protocol.get(field_name)!r}, raw protocol={summary[field_name]!r}"
            )
    actual_curve = protocol.get("positive_power_curve")
    if not isinstance(actual_curve, list) or len(actual_curve) != len(power_curve):
        errors.append(f"{harness}: backend positive_power_curve count differs from raw protocol")
    else:
        for index, (expected_item, actual_item) in enumerate(
            zip(power_curve, actual_curve, strict=True)
        ):
            errors.extend(
                _compare_payload(
                    harness,
                    f"positive_power_curve[{index}]",
                    expected_item,
                    actual_item,
                )
            )
    if backend.get("timing_validity") == "valid" and not all(
        (
            summary["target_status_consistent"],
            summary["aa_budget_passed"],
            summary["setup_placebo_passed"],
            summary["positive_power_passed"],
            all(item["enough_measurements"] for item in target_payloads),
        )
    ):
        errors.append(f"{harness}: backend timing_validity=valid contradicts raw protocol controls")
    return summary, errors


def verify_official_dudect_artifacts(
    *,
    raw_path: Path,
    calibration_path: Path,
    backend_report: Mapping[str, Any],
    expected_project: str,
    expected_harnesses: set[str],
    protocol_path: Path | None = None,
    protocol_contract: OfficialDudectProtocolContract | None = None,
) -> OfficialDudectArtifactVerification:
    """Strictly reparse, recompute, and cross-bind one backend artifact set."""

    result = OfficialDudectArtifactVerification()
    try:
        result.analysis_traces = parse_official_timing_csv(
            raw_path, expected_project=expected_project
        )
        result.calibration_traces = parse_official_timing_csv(
            calibration_path, expected_project=expected_project
        )
    except OfficialDudectVerificationError as exc:
        result.errors.append(str(exc))
        return result

    if set(result.analysis_traces) != expected_harnesses:
        result.errors.append(
            "analysis raw harness set mismatch: "
            f"actual={sorted(result.analysis_traces)}, expected={sorted(expected_harnesses)}"
        )
    if set(result.calibration_traces) != expected_harnesses:
        result.errors.append(
            "calibration raw harness set mismatch: "
            f"actual={sorted(result.calibration_traces)}, expected={sorted(expected_harnesses)}"
        )

    backend_items = backend_report.get("harnesses")
    backend_by_harness: dict[str, Mapping[str, Any]] = {}
    if not isinstance(backend_items, list):
        result.errors.append("backend harnesses must be a list")
    else:
        for item in backend_items:
            if not isinstance(item, dict):
                result.errors.append("backend contains a non-object harness")
                continue
            harness = item.get("harness")
            if not isinstance(harness, str) or harness in backend_by_harness:
                result.errors.append(f"backend has invalid/duplicate harness {harness!r}")
                continue
            backend_by_harness[harness] = item
    if set(backend_by_harness) != expected_harnesses:
        result.errors.append(
            "backend harness set mismatch: "
            f"actual={sorted(backend_by_harness)}, expected={sorted(expected_harnesses)}"
        )

    protocol_traces: dict[tuple[str, str, int, int], ProtocolArtifactTrace] | None = None
    if protocol_path is not None:
        try:
            protocol_traces = parse_official_protocol_csv(
                protocol_path, expected_project=expected_project
            )
        except OfficialDudectVerificationError as exc:
            result.errors.append(str(exc))

    for harness in sorted(expected_harnesses):
        raw = result.analysis_traces.get(harness)
        calibration = result.calibration_traces.get(harness)
        backend = backend_by_harness.get(harness)
        if raw is None or calibration is None or backend is None:
            continue
        try:
            analysis = recompute_pinned_official_dudect(calibration.rows, raw.rows)
        except OfficialDudectVerificationError as exc:
            result.errors.append(f"{harness}: {exc}")
            continue
        result.analyses[harness] = analysis
        result.errors.extend(
            _compare_backend(
                harness,
                analysis,
                backend,
                len(raw.rows),
                len(calibration.rows),
            )
        )
        if protocol_traces is not None:
            if protocol_contract is not None:
                protocol_summary, protocol_errors = _verify_protocol_contract(
                    harness=harness,
                    traces=protocol_traces,
                    backend=backend,
                    contract=protocol_contract,
                )
                if protocol_summary:
                    result.protocol_summaries[harness] = protocol_summary
                result.errors.extend(protocol_errors)
            selected_analysis = _selected_protocol_trace(
                protocol_traces,
                harness=harness,
                role="target",
                seed=backend.get("analysis_seed"),
            )
            selected_calibration = _selected_protocol_trace(
                protocol_traces,
                harness=harness,
                role="target-calibration",
                seed=backend.get("calibration_seed"),
            )
            if selected_analysis is None:
                result.errors.append(
                    f"{harness}: analysis_seed does not select exactly one protocol trace"
                )
            elif selected_analysis.rows != raw.rows:
                result.errors.append(
                    f"{harness}: analysis raw rows differ from selected protocol trace"
                )
            if selected_calibration is None:
                result.errors.append(
                    f"{harness}: calibration_seed does not select exactly one protocol trace"
                )
            elif selected_calibration.rows != calibration.rows:
                result.errors.append(
                    f"{harness}: calibration raw rows differ from selected protocol trace"
                )
            if (
                selected_analysis is not None
                and selected_calibration is not None
                and selected_analysis.process_index != selected_calibration.process_index
            ):
                result.errors.append(
                    f"{harness}: selected analysis/calibration process indexes differ"
                )
    return result
