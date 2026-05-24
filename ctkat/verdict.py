"""Combined verdict from Valgrind CT findings and dudect timing results.

Doc §17.11 proposed a verdict matrix using labels (PASS/WARNING/MEDIUM/HIGH/
CRITICAL) that collide with the per-finding `Severity` enum (HIGH/MEDIUM/LOW).
We use distinct labels here so the user can tell at a glance whether a
table cell describes a single finding or a combined verdict.

Inputs are normalized to:
    valgrind_status: PASS | FAIL | NONE   ("NONE" = no CT stage ran)
    dudect_status:   PASS | WARNING | FAIL | NONE
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Verdict(str, Enum):
    CLEAN = "CLEAN"          # both stages clean (or only one stage ran and it passed)
    LOW_RISK = "LOW_RISK"    # structural finding only — Valgrind FAIL, dudect PASS (or absent)
    SUSPECT = "SUSPECT"      # weak statistical signal — dudect WARNING, Valgrind clean (or absent)
    RISKY = "RISKY"          # one strong signal: either dudect FAIL alone, or Valgrind FAIL + dudect WARNING
    CRITICAL = "CRITICAL"    # both stages flag the harness


# Style hints for terminal rendering (rich markup).
VERDICT_STYLES = {
    Verdict.CLEAN:    "bold green",
    Verdict.LOW_RISK: "yellow",
    Verdict.SUSPECT:  "yellow",
    Verdict.RISKY:    "bold red",
    Verdict.CRITICAL: "bold red on white",
}


@dataclass
class HarnessVerdict:
    name: str
    valgrind_status: str       # "PASS" | "FAIL" | "NONE"
    dudect_status: str         # "PASS" | "WARNING" | "FAIL" | "NONE"
    verdict: Verdict
    valgrind_finding_count: int = 0
    dudect_abs_t: Optional[float] = None


# Full (valgrind, dudect) → verdict matrix. "NONE" means the stage didn't
# run for this harness; a single-stage harness is judged by whichever side
# ran. Keeping every legal combination in one table (instead of nested
# if-ladders) makes the policy auditable at a glance.
_MATRIX: dict[tuple[str, str], Verdict] = {
    # Both stages ran
    ("PASS", "PASS"):    Verdict.CLEAN,
    ("FAIL", "PASS"):    Verdict.LOW_RISK,
    ("PASS", "WARNING"): Verdict.SUSPECT,
    ("PASS", "FAIL"):    Verdict.RISKY,
    ("FAIL", "WARNING"): Verdict.RISKY,
    ("FAIL", "FAIL"):    Verdict.CRITICAL,
    # Only valgrind ran (dudect absent)
    ("PASS", "NONE"):    Verdict.CLEAN,
    ("FAIL", "NONE"):    Verdict.LOW_RISK,
    # Only dudect ran (valgrind absent)
    ("NONE", "PASS"):    Verdict.CLEAN,
    ("NONE", "WARNING"): Verdict.SUSPECT,
    ("NONE", "FAIL"):    Verdict.RISKY,
    # Neither stage ran — vacuous, treated as clean
    ("NONE", "NONE"):    Verdict.CLEAN,
}


def combine(valgrind_status: str, dudect_status: str) -> Verdict:
    """Map a (valgrind, dudect) status pair to a single verdict.

    Both inputs accept the literal "NONE" meaning the stage didn't run for
    this harness. Anything outside `_MATRIX` raises — fail-safe default
    (CLEAN on unknown input would silently mark a confused harness as safe).
    """
    key = (valgrind_status.upper(), dudect_status.upper())
    if key not in _MATRIX:
        raise ValueError(
            f"verdict.combine: unrecognized (valgrind, dudect) status pair: "
            f"({valgrind_status!r}, {dudect_status!r})"
        )
    return _MATRIX[key]
