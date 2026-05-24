"""Welch's t-test and batch stability checks for dudect-style timing analysis.

Implements the formula from doc §17.3:
    t = (mean0 - mean1) / sqrt(var0/n0 + var1/n1)

Threshold defaults (§17.3):
    |t| < 4.5         => PASS
    4.5 <= |t| < 10   => WARNING
    |t| >= 10         => FAIL
"""

from __future__ import annotations

from dataclasses import dataclass
from math import sqrt
from statistics import mean, variance
from typing import List, Sequence


@dataclass
class WelchResult:
    n0: int
    n1: int
    mean0: float
    mean1: float
    var0: float
    var1: float
    t_score: float
    abs_t_score: float
    status: str  # "PASS" | "WARNING" | "FAIL"


def welch_t_test(
    class0: Sequence[float],
    class1: Sequence[float],
    warning_threshold: float = 4.5,
    fail_threshold: float = 10.0,
) -> WelchResult:
    if len(class0) < 2 or len(class1) < 2:
        raise ValueError("each class must have at least two samples")

    n0, n1 = len(class0), len(class1)
    m0, m1 = mean(class0), mean(class1)
    v0, v1 = variance(class0), variance(class1)

    denom = sqrt(v0 / n0 + v1 / n1)
    if denom == 0.0:
        t = 0.0 if m0 == m1 else float("inf")
    else:
        t = (m0 - m1) / denom

    abs_t = abs(t)
    if abs_t >= fail_threshold:
        status = "FAIL"
    elif abs_t >= warning_threshold:
        status = "WARNING"
    else:
        status = "PASS"

    return WelchResult(
        n0=n0, n1=n1,
        mean0=m0, mean1=m1,
        var0=v0, var1=v1,
        t_score=t, abs_t_score=abs_t,
        status=status,
    )


# Minimum chunk size below which we don't attempt per-batch t-tests.
#
# Welch's t-test requires variance(), which needs ≥2 samples per class.
# Class membership in our timing harnesses is assigned by a PRNG (~50/50),
# so a chunk of N samples gives on average N/2 per class — but the
# binomial spread means tiny chunks frequently end up with 0 or 1 samples
# in one class, producing either skipped batches or noisy variance.
#
# At chunk=16 (≈8 per class on average) the probability of either class
# getting <2 samples is ~1.5%, which is the smallest size where most
# batches will yield a stable t-score. Going lower (e.g. 4 ≈ 2 per class)
# is theoretically possible but variance estimates are too jumpy to
# usefully indicate measurement stability.
_MIN_BATCH_CHUNK = 16


def batch_t_scores(
    classes: Sequence[int],
    cycles: Sequence[float],
    batches: int = 10,
    warning_threshold: float = 4.5,
    fail_threshold: float = 10.0,
) -> List[WelchResult]:
    """Split samples into equal batches in arrival order; compute t per batch.

    Used to gauge stability of the overall t-score (doc §17.16 #6). If batch
    t-scores swing wildly, the measurement environment is noisy and the
    overall verdict should be treated with caution.
    """
    if len(classes) != len(cycles):
        raise ValueError("classes and cycles must have same length")
    if batches < 1:
        raise ValueError("batches must be >= 1")

    chunk = len(cycles) // batches
    if chunk < _MIN_BATCH_CHUNK:
        return []  # not enough samples per batch for stable variance estimates

    results: List[WelchResult] = []
    for b in range(batches):
        start = b * chunk
        end = start + chunk
        c0 = [cycles[i] for i in range(start, end) if classes[i] == 0]
        c1 = [cycles[i] for i in range(start, end) if classes[i] == 1]
        if len(c0) < 2 or len(c1) < 2:
            continue
        results.append(
            welch_t_test(c0, c1, warning_threshold, fail_threshold)
        )
    return results
