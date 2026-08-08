import math
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console

# If more than this fraction of timing rows fail to parse we warn — large
# drop rates usually mean stdout/stderr got interleaved or the harness died
# mid-run, both of which silently corrupt downstream statistics.
_MALFORMED_WARN_THRESHOLD = 0.05

# Zero-cycle rows are sentinel values from the C harness's underflow clamp
# (`(t1 < t0) ? 0 : t1 - t0`). They indicate a clock anomaly (TSC skew,
# preemption between rdtscp pairs, etc.) and should not enter the t-test.
# Above this fraction we warn — many zeros usually mean the host is too
# noisy (no CPU pin, thermal throttling, ...) for reliable timing.
_ZERO_CYCLE_WARN_THRESHOLD = 0.01

# Bundle F (F4/S2): per-class zero-drop disparity is the *interesting* signal.
# When one class loses ≥5% of its samples and the other doesn't, the
# remaining samples are not a random subset — they're the slow tail of
# one class measured against the full distribution of the other, which
# biases the Welch t-test in non-obvious ways. Separate threshold so the
# warning fires even when the total drop rate stays below 1%.
_PER_CLASS_ZERO_WARN_THRESHOLD = 0.05

# The timing harness emits one CSV row per measurement on stdout. Keep the
# parent process bounded even when a user raises measurements to the configured
# maximum or a buggy harness writes forever before timeout.
MAX_TIMING_STDOUT_BYTES = 512 * 1024 * 1024
MAX_TIMING_STDERR_BYTES = 1024 * 1024

# Module-local rich Console so warnings match the formatting used by cli.py
# without creating a circular import (cli depends on us, not vice versa).
_console = Console(stderr=True)


@dataclass(frozen=True)
class DroppedTimingSample:
    sample_id: int
    clazz: int
    cycles: float
    aux_start: Optional[int]
    aux_end: Optional[int]
    reason: str
    output_length: Optional[int] = None
    signature_return_code: Optional[int] = None


@dataclass
class TimingProtocolTrace:
    """One physical process trace attached to a timing-harness-v2 run."""

    role: str
    process_index: int
    seed: int
    samples: "TimingSamples"
    effect_ticks: int = 0


@dataclass
class TimingSamples:
    classes: List[int] = field(default_factory=list)
    # `float` (not `int`) so this type is compatible with
    # `statistics.welch_t_test`, which is declared as `Sequence[float]`.
    # The harness emits whole-number cycle counts, but treating them as
    # floats lets the variance math (and downstream type checkers) flow
    # without `int → float` covariance gymnastics.
    cycles: List[float] = field(default_factory=list)
    # v2 retains the emitted identifiers and RDTSCP AUX values so the raw
    # artifact can show exactly which rows survived.  v1 inputs populate
    # sample_ids but leave AUX/output metadata as None.
    sample_ids: List[int] = field(default_factory=list)
    aux_start: List[Optional[int]] = field(default_factory=list)
    aux_end: List[Optional[int]] = field(default_factory=list)
    output_lengths: List[Optional[int]] = field(default_factory=list)
    # Signature timing traces extend the v2 CSV with one return code per
    # measured call.  Non-sign v1/v2 traces keep this list empty; a sign trace
    # must have exactly one entry for every retained row, while dropped rows
    # retain their code in DroppedTimingSample.
    signature_return_codes: List[int] = field(default_factory=list)
    signature_trace: bool = False
    # Bundle F (S1): expose raw-measurement bookkeeping so the user can
    # audit the filter pipeline from the CSV alone. Without these, "n0=10924,
    # n1=18705 from measurements=50000" gives no clue where the missing
    # ~20k samples went.
    raw_n_total: int = 0  # rows emitted by the C harness (pre-filter)
    dropped_zero_n0: int = 0  # class-0 rows dropped by the zero-cycle filter
    dropped_zero_n1: int = 0  # class-1 rows dropped by the zero-cycle filter
    dropped_migration_n0: int = 0
    dropped_migration_n1: int = 0
    malformed_count: int = 0
    dropped_samples: List[DroppedTimingSample] = field(default_factory=list)
    protocol_version: str = "timing-harness-v1"
    runtime_metadata: Dict[str, str] = field(default_factory=dict)
    # The official backend follows upstream's two-batch lifecycle: the first
    # run establishes crop thresholds and is discarded, while this object's
    # primary classes/cycles are the independently measured analysis batch.
    # Legacy/experimental runs leave this as None.
    calibration: Optional["TimingSamples"] = None
    # Root analysis trace only: all independent target/control process traces.
    # Child traces leave this empty, avoiding recursive payloads.
    protocol_traces: List[TimingProtocolTrace] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.cycles)


def parse_timing_csv(text: str) -> TimingSamples:
    lines = text.strip().splitlines()
    if not lines:
        raise ValueError("empty timing harness output")
    header = lines[0].strip()
    v1_header = "sample_id,class,cycles"
    v2_header = "sample_id,class,cycles,aux_start,aux_end,drop_reason,output_length"
    sign_v2_header = f"{v2_header},signature_return_code"
    if header not in {v1_header, v2_header, sign_v2_header}:
        raise ValueError(f"unexpected CSV header: {lines[0]!r}")

    is_v2 = header in {v2_header, sign_v2_header}
    is_signature_v2 = header == sign_v2_header
    samples = TimingSamples(
        protocol_version=("timing-harness-v2" if is_v2 else "timing-harness-v1"),
        signature_trace=is_signature_v2,
    )
    total = 0
    skipped_malformed = 0
    skipped_zero = 0
    # F4/S1: per-class zero tracking. raw counts also feed S1 CSV columns.
    raw_n0 = 0
    raw_n1 = 0
    for line in lines[1:]:
        total += 1
        parts = line.strip().split(",")
        expected_parts = 8 if is_signature_v2 else (7 if is_v2 else 3)
        if len(parts) != expected_parts:
            skipped_malformed += 1
            continue
        try:
            sample_id = int(parts[0])
            cls = int(parts[1])
            cyc = float(parts[2])  # see TimingSamples.cycles type comment
            aux_start = int(parts[3]) if is_v2 else None
            aux_end = int(parts[4]) if is_v2 else None
            drop_reason = parts[5] if is_v2 else ""
            output_length = int(parts[6]) if is_v2 else None
            signature_return_code = int(parts[7]) if is_signature_v2 else None
        except ValueError:
            skipped_malformed += 1
            continue
        if (
            sample_id < 0
            or (output_length is not None and output_length < 0)
            or (
                signature_return_code is not None
                and not -(1 << 31) <= signature_return_code < (1 << 31)
            )
        ):
            skipped_malformed += 1
            continue
        if not math.isfinite(cyc):
            # S6 (fail-open guard): `float("nan")` / `float("inf")` do NOT raise
            # in the parse above, and the `cyc == 0.0` zero-filter below is
            # False for both, so a non-finite cycle used to slip into `samples`
            # and poison Welch's t-test — abs(nan) is < every threshold, so the
            # harness silently reported status=PASS, i.e. a CLEAN verdict on
            # corrupt / overflowed timing data (interleaved stderr token like
            # "inf", a div-by-zero in a buggy custom harness, ...). Count it as
            # malformed so it's both dropped and surfaced by the malformed-rate
            # warning instead of read as "no leak".
            skipped_malformed += 1
            continue
        if cls not in (0, 1):
            # S5: the harness only ever emits class 0 or 1. A row with any
            # other class is corrupt output (interleaved stdout, truncated
            # write). Count it as malformed so the malformed-rate warning can
            # fire — otherwise it was appended to samples and then silently
            # dropped by the downstream `if cls == 0/1` t-test filtering,
            # inflating raw_n_total with no trace.
            skipped_malformed += 1
            continue
        if cls == 0:
            raw_n0 += 1
        elif cls == 1:
            raw_n1 += 1
        if is_v2:
            if drop_reason not in {"", "clock-anomaly", "cpu-migration"}:
                skipped_malformed += 1
                continue
            # Fail closed if a buggy/custom v2 harness forgot to label a
            # detectable migration or clock anomaly.
            if not drop_reason and aux_start != aux_end:
                drop_reason = "cpu-migration"
            if not drop_reason and cyc == 0.0:
                drop_reason = "clock-anomaly"

        if drop_reason == "cpu-migration":
            if cls == 0:
                samples.dropped_migration_n0 += 1
            else:
                samples.dropped_migration_n1 += 1
            samples.dropped_samples.append(
                DroppedTimingSample(
                    sample_id,
                    cls,
                    cyc,
                    aux_start,
                    aux_end,
                    drop_reason,
                    output_length,
                    signature_return_code,
                )
            )
            continue
        if drop_reason == "clock-anomaly" or cyc == 0.0:
            # Underflow sentinel from the C harness — drop, don't let it
            # drag the mean down or count as a real measurement.
            skipped_zero += 1
            if cls == 0:
                samples.dropped_zero_n0 += 1
            elif cls == 1:
                samples.dropped_zero_n1 += 1
            samples.dropped_samples.append(
                DroppedTimingSample(
                    sample_id,
                    cls,
                    cyc,
                    aux_start,
                    aux_end,
                    "clock-anomaly",
                    output_length,
                    signature_return_code,
                )
            )
            continue
        samples.classes.append(cls)
        samples.cycles.append(cyc)
        samples.sample_ids.append(sample_id)
        samples.aux_start.append(aux_start)
        samples.aux_end.append(aux_end)
        samples.output_lengths.append(output_length)
        if signature_return_code is not None:
            samples.signature_return_codes.append(signature_return_code)

    samples.raw_n_total = total
    samples.malformed_count = skipped_malformed

    if total > 0 and (skipped_malformed / total) > _MALFORMED_WARN_THRESHOLD:
        _console.print(
            f"[bold yellow][CTKAT] warning:[/] dropped {skipped_malformed}/"
            f"{total} malformed timing rows "
            f"({skipped_malformed / total:.1%}). The harness may have crashed "
            f"mid-run or its stdout was mixed with stderr — the resulting "
            f"t-score may be unreliable."
        )
    if total > 0 and (skipped_zero / total) > _ZERO_CYCLE_WARN_THRESHOLD:
        _console.print(
            f"[bold yellow][CTKAT] warning:[/] dropped {skipped_zero}/{total} "
            f"zero-cycle samples ({skipped_zero / total:.1%}). The C harness "
            f"clamps (t1 < t0) to 0; a high rate suggests TSC skew or "
            f"preemption — consider pinning to one CPU (`taskset -c 0`) and "
            f"disabling frequency scaling."
        )
    # F4/S2: per-class drop disparity. Only meaningful when both classes
    # got at least some samples — a one-sided harness (only class 0 or
    # only class 1) would otherwise trip the threshold trivially.
    if raw_n0 > 0 and raw_n1 > 0:
        rate0 = samples.dropped_zero_n0 / raw_n0
        rate1 = samples.dropped_zero_n1 / raw_n1
        # Trip if either side exceeds the threshold AND the gap is large
        # enough to suggest bias (not symmetric noise both above 5%).
        max_rate = max(rate0, rate1)
        gap = abs(rate0 - rate1)
        if max_rate > _PER_CLASS_ZERO_WARN_THRESHOLD and gap > _PER_CLASS_ZERO_WARN_THRESHOLD:
            _console.print(
                f"[bold yellow][CTKAT] warning:[/] zero-cycle filter "
                f"asymmetric — dropped {rate0:.1%} of class-0 vs {rate1:.1%} "
                f"of class-1 samples. Surviving samples are likely a biased "
                f"subset (the slow tail of one class), so the t-score should "
                f"be treated skeptically. (F4/S2)"
            )
    skipped_migration = samples.dropped_migration_n0 + samples.dropped_migration_n1
    if skipped_migration:
        _console.print(
            f"[bold yellow][CTKAT] warning:[/] discarded {skipped_migration}/{total} "
            "timing samples because RDTSCP AUX changed across the target call "
            "(CPU migration). Pin the process to one logical CPU."
        )
    return samples


def signature_trace_contract_errors(
    samples: TimingSamples,
    expected_contract: Optional[str] = None,
) -> List[str]:
    """Return fail-closed detached-signature trace contract violations.

    The generated C performs the same checks before and during measurement,
    but the report consumer independently verifies the emitted row/metadata
    evidence.  This catches stale/custom harness binaries as well as a broken
    generator.  ``fixed`` means exactly CRYPTO_BYTES; ``bounded`` means the
    nonzero range through CRYPTO_BYTES recorded by the generated binary.
    """

    errors: List[str] = []
    if not samples.signature_trace:
        return ["signature trace lacks the signature_return_code CSV column"]
    if expected_contract is not None and expected_contract not in {"fixed", "bounded"}:
        return [f"unknown expected signature length contract {expected_contract!r}"]

    metadata = samples.runtime_metadata
    observed_contract = metadata.get("signature_length_contract")
    if observed_contract not in {"fixed", "bounded"}:
        errors.append("runtime metadata lacks a valid signature_length_contract")
    elif expected_contract is not None and observed_contract != expected_contract:
        errors.append(
            "signature length contract mismatch: "
            f"config={expected_contract} runtime={observed_contract}"
        )

    def metadata_uint(name: str) -> Optional[int]:
        value = metadata.get(name)
        if value is None or not value.isdigit():
            errors.append(f"runtime metadata lacks decimal {name}")
            return None
        parsed = int(value)
        if parsed > (1 << 64) - 1:
            errors.append(f"runtime metadata {name} exceeds uint64")
            return None
        return parsed

    length_min = metadata_uint("signature_length_min")
    length_max = metadata_uint("signature_length_max")
    failure_count = metadata_uint("measured_signature_contract_failures")
    if metadata.get("signature_correctness_gate") != "passed":
        errors.append("pre-measurement signature correctness gate did not report passed")
    if metadata.get("signature_return_code_recorded") != "true":
        errors.append("runtime metadata does not confirm signature return-code recording")
    if failure_count is not None and failure_count != 0:
        errors.append(
            f"generated harness reported {failure_count} measured signature contract failures"
        )

    if length_min is not None and length_max is not None:
        if length_min < 1 or length_max < length_min:
            errors.append(f"invalid signature length range [{length_min},{length_max}]")
        if observed_contract == "fixed" and length_min != length_max:
            errors.append("fixed signature contract metadata has unequal min/max")
        if observed_contract == "bounded" and length_min != 1:
            errors.append("bounded signature contract metadata must start at one byte")

    retained_count = len(samples.classes)
    if len(samples.output_lengths) != retained_count:
        errors.append("retained signature output-length count does not match sample count")
    if len(samples.signature_return_codes) != retained_count:
        errors.append("retained signature return-code count does not match sample count")
    if samples.malformed_count:
        errors.append(
            f"signature trace contains {samples.malformed_count} malformed/unverifiable rows"
        )
    accounted = retained_count + len(samples.dropped_samples) + samples.malformed_count
    if samples.raw_n_total != accounted:
        errors.append(
            "signature trace row bookkeeping mismatch: "
            f"raw={samples.raw_n_total} accounted={accounted}"
        )

    rows: List[tuple[int, Optional[int], Optional[int]]] = []
    for index in range(min(retained_count, len(samples.output_lengths))):
        sample_id = samples.sample_ids[index] if index < len(samples.sample_ids) else index
        return_code = (
            samples.signature_return_codes[index]
            if index < len(samples.signature_return_codes)
            else None
        )
        rows.append((sample_id, samples.output_lengths[index], return_code))
    rows.extend(
        (item.sample_id, item.output_length, item.signature_return_code)
        for item in samples.dropped_samples
    )
    for sample_id, output_length, return_code in rows:
        if return_code is None:
            errors.append(f"sample {sample_id} lacks a signature return code")
        elif return_code != 0:
            errors.append(f"sample {sample_id} signature call returned {return_code}")
        if output_length is None:
            errors.append(f"sample {sample_id} lacks a signature output length")
        elif (
            length_min is not None
            and length_max is not None
            and not (length_min <= output_length <= length_max)
        ):
            errors.append(
                f"sample {sample_id} signature output length {output_length} "
                f"is outside [{length_min},{length_max}]"
            )

    return list(dict.fromkeys(errors))


def validate_signature_trace(
    samples: TimingSamples,
    expected_contract: Optional[str] = None,
) -> None:
    errors = signature_trace_contract_errors(samples, expected_contract)
    if errors:
        raise ValueError("signature timing contract rejected trace: " + "; ".join(errors))


def run_timing_harness(
    binary: Path,
    workdir: Path,
    timeout: int = 600,
    seed_override: Optional[int] = None,
    mode: Optional[str] = None,
    effect_ticks: int = 0,
    measurements_override: Optional[int] = None,
    signature_length_contract: Optional[str] = None,
) -> TimingSamples:
    # The dudect harness emits one CSV row per measurement. Capturing that with
    # subprocess.PIPE makes the parent allocate the entire raw timing corpus in
    # memory; use temp files and read only after enforcing a hard byte cap.
    #
    # Bundle Q (FN-1): the binary was just compiled so it normally exists, but
    # a noexec /tmp mount, an ETXTBSY race, or a silent toolchain stub can make
    # it unrunnable. Convert OSError (FileNotFoundError/PermissionError/...) to
    # RuntimeError so `_do_dudect`'s existing `except RuntimeError -> ERROR`
    # handler catches it (status=ERROR -> INCONCLUSIVE) instead of a raw
    # traceback. The T6 comment in cli._do_dudect promised "every uncaught
    # failure mode -> ERROR"; this closes the executable-missing gap it left.
    if seed_override is not None and not 0 < seed_override <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("timing harness seed override must be a nonzero uint64")
    if mode is not None and mode not in {"target", "aa", "placebo", "positive"}:
        raise ValueError(f"unsupported timing harness mode: {mode!r}")
    if mode is not None and seed_override is None:
        raise ValueError("timing harness v2 mode requires an explicit seed")
    if effect_ticks < 0 or effect_ticks > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("effect_ticks must be a uint64")
    if mode != "positive" and effect_ticks:
        raise ValueError("effect_ticks is only valid for mode='positive'")
    if measurements_override is not None and measurements_override < 1:
        raise ValueError("measurements_override must be positive")
    if signature_length_contract not in {None, "fixed", "bounded"}:
        raise ValueError("signature_length_contract must be one of: fixed, bounded")
    command = [str(binary)]
    if seed_override is not None:
        command.append(str(seed_override))
    if mode is not None:
        command.extend(
            [
                mode,
                str(effect_ticks),
                str(measurements_override or 0),
            ]
        )
    try:
        with tempfile.TemporaryFile() as stdout_f, tempfile.TemporaryFile() as stderr_f:
            proc = subprocess.run(
                command,
                cwd=str(workdir),
                stdout=stdout_f,
                stderr=stderr_f,
                timeout=timeout,
                check=False,
            )
            stdout_size = stdout_f.tell()
            if stdout_size > MAX_TIMING_STDOUT_BYTES:
                raise RuntimeError(
                    f"timing harness stdout exceeded "
                    f"{MAX_TIMING_STDOUT_BYTES} bytes ({stdout_size}); "
                    "reduce dudect.measurements or write a smaller harness output."
                )
            stderr_f.seek(0)
            stderr = stderr_f.read(MAX_TIMING_STDERR_BYTES + 1)
            stderr_text = stderr[:MAX_TIMING_STDERR_BYTES].decode("utf-8", errors="replace")
            if len(stderr) > MAX_TIMING_STDERR_BYTES:
                stderr_text += "\n[ctkat] stderr truncated"
            if proc.returncode != 0:
                raise RuntimeError(
                    f"timing harness {binary} failed (rc={proc.returncode}):\n"
                    f"stderr:\n{stderr_text}"
                )
            stdout_f.seek(0)
            text = stdout_f.read().decode("utf-8", errors="replace")
    except OSError as e:
        raise RuntimeError(f"timing harness {binary} could not be executed: {e}") from e
    # Metadata is deliberately emitted on stderr so stdout remains a strict
    # machine-readable trace.  Unknown keys are retained for forward-compatible
    # manifests; malformed metadata is ignored rather than corrupting samples.
    metadata: Dict[str, str] = {}
    for line in stderr_text.splitlines():
        if not line.startswith("CTKAT-HARNESS-META "):
            continue
        for key, value in re.findall(r"([A-Za-z0-9_-]+)=([^ ]+)", line):
            metadata[key] = value
    samples = parse_timing_csv(text)
    samples.runtime_metadata = metadata
    if samples.signature_trace or signature_length_contract is not None:
        validate_signature_trace(samples, signature_length_contract)
    return samples
