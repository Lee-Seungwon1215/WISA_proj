"""Combined verdict from Valgrind CT findings and dudect timing results.

Doc §17.11 proposed a verdict matrix using labels (PASS/WARNING/MEDIUM/HIGH/
CRITICAL) that collide with the per-finding `Severity` enum (HIGH/MEDIUM/LOW).
We use distinct labels here so the user can tell at a glance whether a
table cell describes a single finding or a combined verdict.

Inputs are normalized to:
    kat_status:      PASS | FAIL | NONE             ("NONE" = no KAT stage ran)
    valgrind_status: PASS | FAIL | ERROR | NONE     ("ERROR" = crashed/incomplete)
    dudect_status:   PASS | WARNING | FAIL | ERROR | NONE

Bundle E-1 adds the INCONCLUSIVE verdict and the ERROR per-stage status, so
"we couldn't actually verify this" stops being silently folded into CLEAN
(F2/F5/T6) and so KAT failures propagate into the combined verdict even
when --continue-on-kat-fail keeps the pipeline running (F11).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Verdict(str, Enum):
    CLEAN = "CLEAN"               # both stages clean (or only one stage ran and it passed)
    LOW_RISK = "LOW_RISK"         # structural finding only — Valgrind FAIL, dudect PASS (or absent)
    SUSPECT = "SUSPECT"           # weak statistical signal — dudect WARNING, Valgrind clean (or absent)
    RISKY = "RISKY"               # one strong signal: either dudect FAIL alone, or Valgrind FAIL + dudect WARNING
    CRITICAL = "CRITICAL"         # both stages flag the harness
    INCONCLUSIVE = "INCONCLUSIVE" # at least one stage couldn't complete (crash/timeout/KAT FAIL)


# Style hints for terminal rendering (rich markup).
VERDICT_STYLES = {
    Verdict.CLEAN:        "bold green",
    Verdict.LOW_RISK:     "yellow",
    Verdict.SUSPECT:      "yellow",
    Verdict.RISKY:        "bold red",
    Verdict.CRITICAL:     "bold red on white",
    Verdict.INCONCLUSIVE: "bold yellow on white",
}


@dataclass
class HarnessVerdict:
    name: str
    valgrind_status: str       # "PASS" | "FAIL" | "ERROR" | "NONE"
    dudect_status: str         # "PASS" | "WARNING" | "FAIL" | "ERROR" | "NONE"
    verdict: Verdict
    valgrind_finding_count: int = 0
    dudect_abs_t: Optional[float] = None


# Full (valgrind, dudect) → verdict matrix. "NONE" means the stage didn't
# run for this harness; "ERROR" means the stage attempted but couldn't
# complete (e.g., Valgrind crashed F2, sentinel missing F5, dudect harness
# timed out T6). Any ERROR pair maps to INCONCLUSIVE so the verdict CSV —
# the documented CI gate — never silently downgrades a broken run to CLEAN.
_MATRIX: dict[tuple[str, str], Verdict] = {
    # Both stages ran cleanly
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
    # Any ERROR — analysis incomplete, must not be silently green.
    ("ERROR", "PASS"):    Verdict.INCONCLUSIVE,
    ("ERROR", "WARNING"): Verdict.INCONCLUSIVE,
    ("ERROR", "FAIL"):    Verdict.INCONCLUSIVE,
    ("ERROR", "ERROR"):   Verdict.INCONCLUSIVE,
    ("ERROR", "NONE"):    Verdict.INCONCLUSIVE,
    ("PASS", "ERROR"):    Verdict.INCONCLUSIVE,
    ("FAIL", "ERROR"):    Verdict.INCONCLUSIVE,
    ("NONE", "ERROR"):    Verdict.INCONCLUSIVE,
}


def combine(
    valgrind_status: str,
    dudect_status: str,
    kat_status: str = "NONE",
) -> Verdict:
    """Map (kat, valgrind, dudect) status to a single verdict.

    `kat_status` is a *precondition*, not a third axis of the matrix:
    KAT FAIL means the build artifact didn't pass functional correctness,
    so the side-channel analyses ran on incorrect code — their PASS is
    meaningless. We pre-filter to INCONCLUSIVE before consulting the
    (valgrind, dudect) matrix. This handles F11 (`--continue-on-kat-fail`
    used to silently downgrade KAT FAIL to verdict=CLEAN).

    All three inputs accept "NONE" for "stage didn't run". `valgrind` and
    `dudect` additionally accept "ERROR" for "stage attempted but didn't
    complete" (F2/F5/T6). Anything outside the matrix raises — fail-safe
    default (CLEAN on unknown input would silently mark a confused harness
    as safe).
    """
    kat = kat_status.upper()
    if kat == "FAIL":
        return Verdict.INCONCLUSIVE
    if kat not in ("PASS", "NONE"):
        raise ValueError(
            f"verdict.combine: kat_status must be PASS/FAIL/NONE, got {kat_status!r}"
        )
    key = (valgrind_status.upper(), dudect_status.upper())
    if key not in _MATRIX:
        raise ValueError(
            f"verdict.combine: unrecognized (valgrind, dudect) status pair: "
            f"({valgrind_status!r}, {dudect_status!r})"
        )
    return _MATRIX[key]
