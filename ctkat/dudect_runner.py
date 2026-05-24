import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from rich.console import Console


# If more than this fraction of timing rows fail to parse we warn — large
# drop rates usually mean stdout/stderr got interleaved or the harness died
# mid-run, both of which silently corrupt downstream statistics.
_MALFORMED_WARN_THRESHOLD = 0.05

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
    skipped = 0
    for line in lines[1:]:
        total += 1
        parts = line.strip().split(",")
        if len(parts) != 3:
            skipped += 1
            continue
        try:
            cls = int(parts[1])
            cyc = float(parts[2])  # see TimingSamples.cycles type comment
        except ValueError:
            skipped += 1
            continue
        samples.classes.append(cls)
        samples.cycles.append(cyc)

    if total > 0 and (skipped / total) > _MALFORMED_WARN_THRESHOLD:
        _console.print(
            f"[bold yellow][CTKAT] warning:[/] dropped {skipped}/{total} "
            f"malformed timing rows ({skipped / total:.1%}). The harness may "
            f"have crashed mid-run or its stdout was mixed with stderr — the "
            f"resulting t-score may be unreliable."
        )
    return samples


def run_timing_harness(
    binary: Path,
    workdir: Path,
    timeout: int = 600,
) -> TimingSamples:
    proc = subprocess.run(
        [str(binary)],
        cwd=str(workdir),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"timing harness {binary} failed (rc={proc.returncode}):\n"
            f"stderr:\n{proc.stderr}"
        )
    return parse_timing_csv(proc.stdout)
