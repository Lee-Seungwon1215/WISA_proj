"""Welch's t-test and batch stability checks for dudect-style timing analysis.

Implements the formula from doc §17.3:
    t = (mean0 - mean1) / sqrt(var0/n0 + var1/n1)

Threshold defaults (§17.3):
    |t| < 4.5         => PASS
    4.5 <= |t| < 10   => WARNING
    |t| >= 10         => FAIL

`welch_with_cropping` implements dudect's percentile-cropping protocol
(Reparaz et al. 2017, §3): re-run the t-test at several upper-tail cutoffs
and report the max |t|. Outliers from preemption / cache-miss bursts inflate
variance and mask leak signal; cropping the top 1-5% typically recovers it.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import sqrt
from statistics import mean, variance
from typing import List, Optional, Sequence


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
    # Diagnostic fields populated only by `welch_with_cropping`. `None` on
    # results from plain `welch_t_test` so the dataclass stays backward
    # compatible — old callers ignore these, new callers read them.
    cropped_at: Optional[float] = None        # cutoff that produced max |t|
    t_score_uncropped: Optional[float] = None # t at cutoff=1.0 (no cropping)
    abs_t_score_uncropped: Optional[float] = None


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
        # batch t-scores deliberately skip cropping — they measure raw
        # stability of the environment; cropping would smooth that signal.
        results.append(
            welch_t_test(c0, c1, warning_threshold, fail_threshold)
        )
    return results


# --- upper-tail cropping -------------------------------------------------------

# Cutoffs biased toward the lightly-cropped end (where dudect concentrates its
# 100-cutoff scan). 1.0 is always first so the result is well-defined even
# when downstream cropping cutoffs end up with <2 samples per class.
CROP_PERCENTILES: List[float] = [1.0, 0.99, 0.95, 0.90, 0.75]


def upper_crop(samples: Sequence[float], cutoff: float) -> List[float]:
    """Keep the lowest `cutoff` fraction of samples (drop the upper tail).

    cutoff=1.0  => no cropping (full list)
    cutoff=0.95 => drop ≈top 5%
    cutoff<=0.0 => empty list (degenerate; caller should skip)
    """
    if cutoff >= 1.0:
        return list(samples)
    if cutoff <= 0.0:
        return []
    n = len(samples)
    if n == 0:
        return []
    # Clamp to n-1 so cutoff=1.0 corner cases never IndexError. Threshold
    # picks the sample value at that rank from the sorted list, and we
    # keep every sample <= threshold (ties included, so we may keep a
    # tiny fraction more than `cutoff` — acceptable for dudect).
    threshold_idx = min(int(n * cutoff), n - 1)
    threshold = sorted(samples)[threshold_idx]
    return [s for s in samples if s <= threshold]


def welch_with_cropping(
    class0: Sequence[float],
    class1: Sequence[float],
    warning_threshold: float = 4.5,
    fail_threshold: float = 10.0,
    cutoffs: Sequence[float] = CROP_PERCENTILES,
) -> WelchResult:
    """Run welch_t_test at each cutoff, return the result with the largest
    |t|. The returned WelchResult is annotated with `cropped_at` (the cutoff
    that won) and `*_uncropped` (the cutoff=1.0 result, for diagnostic).

    Caller must ensure cutoffs starts with 1.0 — otherwise the uncropped
    fields will be left as None and the all-cropping-fails fallback is lost.
    """
    best: Optional[WelchResult] = None
    best_at: Optional[float] = None
    uncropped_t: Optional[float] = None
    uncropped_abs_t: Optional[float] = None

    for p in cutoffs:
        c0 = upper_crop(class0, p)
        c1 = upper_crop(class1, p)
        if len(c0) < 2 or len(c1) < 2:
            continue
        r = welch_t_test(c0, c1, warning_threshold, fail_threshold)
        if p == 1.0:
            uncropped_t = r.t_score
            uncropped_abs_t = r.abs_t_score
        if best is None or r.abs_t_score > best.abs_t_score:
            best = r
            best_at = p

    if best is None:
        # Only reachable if every cutoff (including 1.0) had <2 samples
        # per class — same precondition welch_t_test would raise on.
        raise ValueError(
            "welch_with_cropping: every cutoff yielded <2 samples per class"
        )

    best.cropped_at = best_at
    best.t_score_uncropped = uncropped_t
    best.abs_t_score_uncropped = uncropped_abs_t
    return best
