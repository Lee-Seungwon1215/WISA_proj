"""Pinned official-dudect statistical backend.

CT-KAT still owns input generation and timing measurement.  This module builds
a small adapter that feeds two raw traces into the *unmodified* upstream
``dudect.h`` implementation:

* trace 1 is the first, discarded batch used to establish 100 crop thresholds;
* trace 2 is passed through upstream ``update_statistics()``;
* upstream raw first-order, 100 cropped first-order, second-order, minimum
  measurement, max-|t|, tau, and detection-estimate semantics are preserved.

The adapter is deliberately a separate process.  That makes the backend
boundary auditable and prevents a future Python refactor from silently
becoming "official dudect" in name only.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from .dudect_runner import TimingSamples

OFFICIAL_DUDECT_REVISION = "dc269651fb2567e46755cfb2a13d3875592968b5"
OFFICIAL_DUDECT_BACKEND = "official-dudect-dc269651"
OFFICIAL_DUDECT_HEADER_SHA256 = "3fb3b2bd7f9e17ae34b7c92518c1311c67342c56facc80da925d85f121b649da"
OFFICIAL_DUDECT_PROTOCOL_TESTS = 102
OFFICIAL_DUDECT_PERCENTILE_TESTS = 100
OFFICIAL_DUDECT_MIN_CLASS0 = 10_001
_SUPPORTED_ARCHES = frozenset({"x86_64", "amd64"})
_MAX_ADAPTER_STDOUT = 4 * 1024 * 1024
_MAX_ADAPTER_STDERR = 1024 * 1024
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1


class OfficialDudectError(RuntimeError):
    """Base error for adapter build, execution, or contract failures."""


class OfficialDudectUnavailable(OfficialDudectError):
    """The pinned upstream engine cannot be built on this host."""


@dataclass(frozen=True)
class OfficialProtocolTest:
    index: int
    kind: str
    crop_index: Optional[int]
    crop_threshold: Optional[int]
    n0: int
    n1: int
    mean0: Optional[float]
    mean1: Optional[float]
    var0: Optional[float]
    var1: Optional[float]
    t_score: Optional[float]
    abs_t_score: Optional[float]
    t_nonfinite: bool
    eligible: bool

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> OfficialProtocolTest:
        return cls(
            index=int(value["index"]),
            kind=str(value["kind"]),
            crop_index=_optional_int(value.get("crop_index")),
            crop_threshold=_optional_int(value.get("crop_threshold")),
            n0=int(value["n0"]),
            n1=int(value["n1"]),
            mean0=_optional_float(value.get("mean0")),
            mean1=_optional_float(value.get("mean1")),
            var0=_optional_float(value.get("var0")),
            var1=_optional_float(value.get("var1")),
            t_score=_optional_float(value.get("t_score")),
            abs_t_score=_optional_float(value.get("abs_t_score")),
            t_nonfinite=bool(value["t_nonfinite"]),
            eligible=bool(value["eligible"]),
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "kind": self.kind,
            "crop_index": self.crop_index,
            "crop_threshold": self.crop_threshold,
            "n0": self.n0,
            "n1": self.n1,
            "mean0": self.mean0,
            "mean1": self.mean1,
            "var0": self.var0,
            "var1": self.var1,
            "t_score": self.t_score,
            "abs_t_score": self.abs_t_score,
            "t_nonfinite": self.t_nonfinite,
            "eligible": self.eligible,
        }


@dataclass(frozen=True)
class OfficialDudectAnalysis:
    status: str
    enough_measurements: bool
    minimum_class0_measurements: int
    calibration_input_count: int
    analysis_input_count: int
    discarded_initial_count: int
    dropped_negative_count: int
    max_test_index: int
    max_test_kind: str
    max_abs_t: float
    max_tau: Optional[float]
    detection_estimate: Optional[float]
    tests: tuple[OfficialProtocolTest, ...]
    upstream_revision: str = OFFICIAL_DUDECT_REVISION

    @property
    def winning_test(self) -> OfficialProtocolTest:
        return self.tests[self.max_test_index]

    @property
    def uncropped_test(self) -> OfficialProtocolTest:
        return self.tests[0]

    def as_dict(self) -> dict[str, object]:
        return {
            "backend": OFFICIAL_DUDECT_BACKEND,
            "upstream_revision": self.upstream_revision,
            "status": self.status,
            "enough_measurements": self.enough_measurements,
            "minimum_class0_measurements": self.minimum_class0_measurements,
            "protocol_test_count": len(self.tests),
            "percentile_test_count": OFFICIAL_DUDECT_PERCENTILE_TESTS,
            "calibration_input_count": self.calibration_input_count,
            "analysis_input_count": self.analysis_input_count,
            "discarded_initial_count": self.discarded_initial_count,
            "dropped_negative_count": self.dropped_negative_count,
            "max_test_index": self.max_test_index,
            "max_test_kind": self.max_test_kind,
            "max_abs_t": _finite_or_none(self.max_abs_t),
            "max_abs_t_nonfinite": not math.isfinite(self.max_abs_t),
            "max_tau": _finite_or_none(self.max_tau),
            "detection_estimate": _finite_or_none(self.detection_estimate),
            "tests": [test.as_dict() for test in self.tests],
        }


def _optional_int(value: Any) -> Optional[int]:
    return None if value is None else int(value)


def _optional_float(value: Any) -> Optional[float]:
    return None if value is None else float(value)


def _finite_or_none(value: Optional[float]) -> Optional[float]:
    if value is None or not math.isfinite(value):
        return None
    return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _resource_bytes(relative: str) -> bytes:
    return files("ctkat").joinpath(relative).read_bytes()


def assert_official_source_integrity() -> None:
    """Refuse to call a locally modified header under the upstream name."""

    try:
        actual = _sha256_bytes(_resource_bytes("_vendor/dudect/dudect.h"))
    except (FileNotFoundError, OSError) as exc:
        raise OfficialDudectError(
            "vendored official dudect header is missing or unreadable"
        ) from exc
    if actual != OFFICIAL_DUDECT_HEADER_SHA256:
        raise OfficialDudectError(
            "vendored official dudect header hash drift: "
            f"expected {OFFICIAL_DUDECT_HEADER_SHA256}, got {actual}"
        )


def build_official_dudect_adapter(
    *,
    cc: str,
    output_dir: Path,
    timeout: int = 120,
) -> Path:
    """Compile the raw-trace adapter against the pinned upstream header."""

    machine = platform.machine().lower()
    if machine not in _SUPPORTED_ARCHES:
        raise OfficialDudectUnavailable(
            "official dudect's pinned C engine is x86_64-only "
            f"(current host: {platform.machine() or 'unknown'}). "
            "Run it on native x86_64 Linux/macOS or explicitly select "
            "`backend: experimental-first-order`."
        )
    compiler = shutil.which(cc)
    if compiler is None:
        raise OfficialDudectUnavailable(f"official dudect adapter compiler not found: {cc!r}")
    assert_official_source_integrity()

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OfficialDudectUnavailable(
            f"cannot create official dudect adapter directory {output_dir}: {exc}"
        ) from exc
    binary = output_dir / "ctkat_official_dudect_adapter"
    native = files("ctkat").joinpath("native/official_dudect_adapter.c")
    header = files("ctkat").joinpath("_vendor/dudect/dudect.h")
    with as_file(native) as source_path, as_file(header) as header_path:
        vendor_dir = header_path.parent
        try:
            fd, temporary_name = tempfile.mkstemp(
                prefix=".ctkat_official_dudect_adapter.",
                dir=output_dir,
            )
        except OSError as exc:
            raise OfficialDudectUnavailable(
                f"cannot create official dudect adapter output in {output_dir}: {exc}"
            ) from exc
        os.close(fd)
        temporary = Path(temporary_name)
        temporary.unlink()
        command = [
            compiler,
            "-O2",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-I",
            str(vendor_dir),
            str(source_path),
            "-lm",
            "-o",
            str(temporary),
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            temporary.unlink(missing_ok=True)
            raise OfficialDudectUnavailable(
                f"could not compile official dudect adapter with {cc!r}: {exc}"
            ) from exc
        stderr = completed.stderr[:_MAX_ADAPTER_STDERR].decode("utf-8", errors="replace")
        if completed.returncode != 0:
            temporary.unlink(missing_ok=True)
            raise OfficialDudectUnavailable(
                f"official dudect adapter compile failed (rc={completed.returncode}):\n{stderr}"
            )
        try:
            temporary.chmod(0o755)
            os.replace(temporary, binary)
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            raise OfficialDudectUnavailable(
                f"cannot install official dudect adapter at {binary}: {exc}"
            ) from exc
    return binary


def _integer_cycles(cycles: Sequence[float], *, label: str) -> list[int]:
    result: list[int] = []
    for index, raw in enumerate(cycles):
        value = float(raw)
        if not math.isfinite(value) or not value.is_integer():
            raise OfficialDudectError(
                f"{label} timing row {index} is not a finite integer cycle count: {raw!r}"
            )
        integer = int(value)
        if not _INT64_MIN <= integer <= _INT64_MAX:
            raise OfficialDudectError(
                f"{label} timing row {index} is outside signed int64: {integer}"
            )
        result.append(integer)
    return result


def _write_trace(path: Path, samples: TimingSamples, *, label: str) -> None:
    if len(samples.classes) != len(samples.cycles):
        raise OfficialDudectError(f"{label} classes/cycles length mismatch")
    if not samples.cycles:
        raise OfficialDudectError(f"{label} trace is empty")
    cycles = _integer_cycles(samples.cycles, label=label)
    with path.open("w", encoding="ascii", newline="\n") as handle:
        handle.write(f"CTKAT-DUDECT-TRACE-V1 {len(cycles)}\n")
        for index, (clazz, value) in enumerate(zip(samples.classes, cycles)):
            if clazz not in (0, 1):
                raise OfficialDudectError(f"{label} timing row {index} has invalid class {clazz!r}")
            handle.write(f"{clazz},{value}\n")


def _parse_analysis(payload: Mapping[str, Any]) -> OfficialDudectAnalysis:
    if payload.get("schema_version") != "1.0":
        raise OfficialDudectError(
            f"official dudect adapter schema mismatch: {payload.get('schema_version')!r}"
        )
    revision = str(payload.get("upstream_revision", ""))
    if revision != OFFICIAL_DUDECT_REVISION:
        raise OfficialDudectError(f"official dudect adapter revision mismatch: {revision!r}")
    tests_raw = payload.get("tests")
    if not isinstance(tests_raw, list) or len(tests_raw) != OFFICIAL_DUDECT_PROTOCOL_TESTS:
        raise OfficialDudectError(
            "official dudect adapter must return exactly "
            f"{OFFICIAL_DUDECT_PROTOCOL_TESTS} protocol tests"
        )
    tests = tuple(OfficialProtocolTest.from_mapping(test) for test in tests_raw)
    if [test.index for test in tests] != list(range(OFFICIAL_DUDECT_PROTOCOL_TESTS)):
        raise OfficialDudectError("official dudect protocol test indexes are not contiguous")
    max_index = int(payload["max_test_index"])
    if not 0 <= max_index < len(tests):
        raise OfficialDudectError(f"official dudect max_test_index out of range: {max_index}")
    status = str(payload["status"])
    if status not in {"PASS", "FAIL", "INSUFFICIENT"}:
        raise OfficialDudectError(f"official dudect returned invalid status: {status!r}")

    max_abs_raw = payload.get("max_abs_t")
    if max_abs_raw is None and payload.get("max_abs_t_nonfinite"):
        max_abs_t = math.inf
    elif max_abs_raw is None:
        max_abs_t = math.nan
    else:
        max_abs_t = float(max_abs_raw)
    return OfficialDudectAnalysis(
        status=status,
        enough_measurements=bool(payload["enough_measurements"]),
        minimum_class0_measurements=int(payload["minimum_class0_measurements"]),
        calibration_input_count=int(payload["calibration_input_count"]),
        analysis_input_count=int(payload["analysis_input_count"]),
        discarded_initial_count=int(payload["discarded_initial_count"]),
        dropped_negative_count=int(payload["dropped_negative_count"]),
        max_test_index=max_index,
        max_test_kind=str(payload["max_test_kind"]),
        max_abs_t=max_abs_t,
        max_tau=_optional_float(payload.get("max_tau")),
        detection_estimate=_optional_float(payload.get("detection_estimate")),
        tests=tests,
        upstream_revision=revision,
    )


def analyze_with_official_dudect(
    calibration: TimingSamples,
    analysis: TimingSamples,
    *,
    adapter_binary: Path,
    workdir: Path,
    timeout: int = 120,
) -> OfficialDudectAnalysis:
    """Analyze raw traces by executing the compiled upstream-backed adapter."""

    try:
        with tempfile.TemporaryDirectory(prefix="ctkat-dudect-traces-", dir=workdir) as temp:
            temp_dir = Path(temp)
            calibration_path = temp_dir / "calibration.trace"
            analysis_path = temp_dir / "analysis.trace"
            _write_trace(calibration_path, calibration, label="calibration")
            _write_trace(analysis_path, analysis, label="analysis")
            completed = subprocess.run(
                [str(adapter_binary), str(calibration_path), str(analysis_path)],
                cwd=workdir,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OfficialDudectError(f"official dudect adapter execution failed: {exc}") from exc

    if len(completed.stdout) > _MAX_ADAPTER_STDOUT:
        raise OfficialDudectError(
            f"official dudect adapter stdout exceeded {_MAX_ADAPTER_STDOUT} bytes"
        )
    stderr = completed.stderr[:_MAX_ADAPTER_STDERR].decode("utf-8", errors="replace")
    if completed.returncode != 0:
        raise OfficialDudectError(
            f"official dudect adapter failed (rc={completed.returncode}):\n{stderr}"
        )
    try:
        payload = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OfficialDudectError(f"official dudect adapter emitted invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise OfficialDudectError("official dudect adapter JSON root must be an object")
    try:
        return _parse_analysis(payload)
    except OfficialDudectError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise OfficialDudectError(
            f"official dudect adapter returned an invalid result schema: {exc}"
        ) from exc
