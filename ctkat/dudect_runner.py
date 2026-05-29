from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from rich.console import Console

from ._proc import run_text


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

# Module-local rich Console so warnings match the formatting used by cli.py
# without creating a circular import (cli depends on us, not vice versa).
_console = Console(stderr=True)


@dataclass
class TimingSamples:
    classes: List[int] = field(default_factory=list)
    # `float` (not `int`) so this type is compatible with
    # `statistics.welch_t_test`, which is declared as `Sequence[float]`.
    # The harness emits whole-number cycle counts, but treating them as
    # floats lets the variance math (and downstream type checkers) flow
    # without `int → float` covariance gymnastics.
    cycles: List[float] = field(default_factory=list)
    # Bundle F (S1): expose raw-measurement bookkeeping so the user can
    # audit the filter pipeline from the CSV alone. Without these, "n0=10924,
    # n1=18705 from measurements=50000" gives no clue where the missing
    # ~20k samples went.
    raw_n_total: int = 0       # rows emitted by the C harness (pre-filter)
    dropped_zero_n0: int = 0   # class-0 rows dropped by the zero-cycle filter
    dropped_zero_n1: int = 0   # class-1 rows dropped by the zero-cycle filter

    def __len__(self) -> int:
        return len(self.cycles)


def parse_timing_csv(text: str) -> TimingSamples:
    lines = text.strip().splitlines()
    if not lines:
        raise ValueError("empty timing harness output")
    if lines[0].strip() != "sample_id,class,cycles":
        raise ValueError(f"unexpected CSV header: {lines[0]!r}")

    samples = TimingSamples()
    total = 0
    skipped_malformed = 0
    skipped_zero = 0
    # F4/S1: per-class zero tracking. raw counts also feed S1 CSV columns.
    raw_n0 = 0
    raw_n1 = 0
    for line in lines[1:]:
        total += 1
        parts = line.strip().split(",")
        if len(parts) != 3:
            skipped_malformed += 1
            continue
        try:
            cls = int(parts[1])
            cyc = float(parts[2])  # see TimingSamples.cycles type comment
        except ValueError:
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
        if cyc == 0.0:
            # Underflow sentinel from the C harness — drop, don't let it
            # drag the mean down or count as a real measurement.
            skipped_zero += 1
            if cls == 0:
                samples.dropped_zero_n0 += 1
            elif cls == 1:
                samples.dropped_zero_n1 += 1
            continue
        samples.classes.append(cls)
        samples.cycles.append(cyc)

    samples.raw_n_total = total

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
    return samples


def run_timing_harness(
    binary: Path,
    workdir: Path,
    timeout: int = 600,
) -> TimingSamples:
    # Bundle N (T18): routes through `_proc.run_text` for utf-8 +
    # errors='replace'. The dudect harness emits CSV (ASCII), but a crashed
    # one can write garbage stderr before dying; `errors='replace'` keeps
    # that diagnostic visible instead of erroring out the parent.
    proc = run_text([str(binary)], cwd=workdir, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(
            f"timing harness {binary} failed (rc={proc.returncode}):\n"
            f"stderr:\n{proc.stderr}"
        )
    return parse_timing_csv(proc.stdout)
