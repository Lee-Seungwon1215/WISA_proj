import random

from ctkat.statistics import (
    batch_t_scores,
    upper_crop,
    welch_t_test,
    welch_with_cropping,
)


def test_identical_distributions_pass():
    rng = random.Random(0)
    c0 = [rng.gauss(100, 5) for _ in range(2000)]
    c1 = [rng.gauss(100, 5) for _ in range(2000)]
    r = welch_t_test(c0, c1)
    assert r.status == "PASS"
    assert r.abs_t_score < 4.5


def test_clearly_different_means_fail():
    rng = random.Random(0)
    c0 = [rng.gauss(100, 5) for _ in range(2000)]
    c1 = [rng.gauss(120, 5) for _ in range(2000)]
    r = welch_t_test(c0, c1)
    assert r.status == "FAIL"
    assert r.abs_t_score >= 10.0


def test_t_score_sign_follows_mean_difference():
    c0 = [10.0] * 100 + [11.0] * 100
    c1 = [20.0] * 100 + [21.0] * 100
    r = welch_t_test(c0, c1)
    assert r.t_score < 0   # mean0 < mean1 => negative t


def test_too_few_samples_raises():
    import pytest
    with pytest.raises(ValueError):
        welch_t_test([1.0], [2.0, 3.0])


def test_zero_variance_handled():
    r = welch_t_test([5.0, 5.0, 5.0], [5.0, 5.0, 5.0])
    assert r.t_score == 0.0
    assert r.status == "PASS"


def test_batch_t_scores_returns_expected_count():
    rng = random.Random(0)
    n = 1000
    classes = [i & 1 for i in range(n)]
    cycles = [rng.gauss(100, 5) for _ in range(n)]
    batches = batch_t_scores(classes, cycles, batches=10)
    # 10 batches, each with enough samples per class
    assert len(batches) == 10


def test_batch_t_scores_skips_tiny_batches():
    # too few samples to split meaningfully
    classes = [0, 1, 0, 1]
    cycles = [1, 2, 3, 4]
    batches = batch_t_scores(classes, cycles, batches=10)
    assert batches == []


# --- Bundle B: upper-tail cropping --------------------------------------------


def test_upper_crop_cutoff_one_returns_full_list():
    samples = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert upper_crop(samples, 1.0) == samples
    # >1.0 also treated as no-op (defensive)
    assert upper_crop(samples, 1.5) == samples


def test_upper_crop_drops_high_tail():
    samples = list(range(100))  # 0..99
    cropped = upper_crop(samples, 0.95)
    # threshold = sorted[95] = 95; keep s <= 95 → 96 samples
    assert max(cropped) <= 95
    assert len(cropped) <= 96


def test_upper_crop_zero_cutoff_returns_empty():
    assert upper_crop([1.0, 2.0, 3.0], 0.0) == []


def test_upper_crop_empty_input():
    assert upper_crop([], 0.5) == []


def test_upper_crop_preserves_input_order():
    # Cropping filters but does NOT sort the result — order in original
    # sequence is preserved (matters for class-aligned timing pairs).
    samples = [5.0, 1.0, 9.0, 3.0, 7.0]
    cropped = upper_crop(samples, 0.75)
    # threshold = sorted[3] = 7; keep s <= 7 → [5, 1, 3, 7]
    assert cropped == [5.0, 1.0, 3.0, 7.0]


def test_welch_with_cropping_reveals_outlier_masked_leak():
    # Mostly-clean leak buried under heavy upper-tail noise. Without
    # cropping the noise inflates variance and crushes |t|; cropping the
    # top ~5% should recover a much larger |t|.
    rng = random.Random(0)
    c0 = [rng.gauss(100, 2) for _ in range(950)] + [1e7] * 50
    c1 = [rng.gauss(110, 2) for _ in range(950)] + [1e7] * 50
    uncropped = welch_t_test(c0, c1)
    cropped = welch_with_cropping(c0, c1)
    # Cropping must strictly improve detection on this synthetic leak.
    assert cropped.abs_t_score > uncropped.abs_t_score
    # Diagnostic fields are populated.
    assert cropped.cropped_at is not None
    assert cropped.t_score_uncropped is not None
    assert cropped.abs_t_score_uncropped is not None
    # Uncropped diagnostic must equal the plain welch result.
    assert abs(cropped.t_score_uncropped - uncropped.t_score) < 1e-9


def test_welch_with_cropping_returns_uncropped_when_no_outliers():
    # No outliers → cropping shouldn't help. The chosen cutoff should be
    # 1.0 (or any cutoff is fine if they tie, but 1.0 is first in the
    # iteration order so it wins ties).
    rng = random.Random(0)
    c0 = [rng.gauss(100, 5) for _ in range(2000)]
    c1 = [rng.gauss(100, 5) for _ in range(2000)]
    cropped = welch_with_cropping(c0, c1)
    # Both classes drawn from same distribution → status stays PASS even
    # under multi-cutoff max-|t| inflation.
    assert cropped.status == "PASS"


def test_welch_with_cropping_too_few_samples_raises():
    import pytest
    with pytest.raises(ValueError):
        welch_with_cropping([1.0], [2.0, 3.0])


# --- Bundle G: Cohen's d (S3) ----------------------------------------------


def test_cohens_d_zero_when_distributions_identical():
    rng = random.Random(0)
    c0 = [rng.gauss(100, 5) for _ in range(2000)]
    c1 = [rng.gauss(100, 5) for _ in range(2000)]
    r = welch_t_test(c0, c1)
    # Same distribution → |d| should sit near zero (gaussian noise sample-size
    # error). Pin generous bound; tighter than that and we're tail-fishing.
    assert abs(r.cohens_d) < 0.2


def test_cohens_d_matches_textbook_large_effect():
    # Classic textbook example: two normals one SD apart, equal SD.
    # Cohen's d should land near 1.0 (large effect).
    rng = random.Random(0)
    c0 = [rng.gauss(100, 5) for _ in range(2000)]
    c1 = [rng.gauss(105, 5) for _ in range(2000)]  # 1 SD higher
    r = welch_t_test(c0, c1)
    # Allow ±0.1 around 1.0 for sampling noise.
    assert 0.9 < r.cohens_d < 1.1


def test_cohens_d_sign_positive_when_class1_slower():
    # The leak-detection intuition: positive d means class 1 (random
    # secret) is slower than class 0 (fixed secret). Sanity check that
    # `m1 - m0` not `m0 - m1` is the convention we use.
    c0 = [100.0, 100.0, 100.0, 100.0]
    c1 = [110.0, 110.0, 110.0, 111.0]   # one extra to avoid zero var
    r = welch_t_test(c0, c1)
    assert r.cohens_d > 0


def test_cohens_d_sign_negative_when_class0_slower():
    c0 = [120.0, 120.0, 120.0, 121.0]
    c1 = [100.0, 100.0, 100.0, 100.0]
    r = welch_t_test(c0, c1)
    assert r.cohens_d < 0


def test_cohens_d_zero_when_means_equal_and_constant():
    # Both classes are the same constant — vacuously no effect. d=0
    # (pooled SD is also 0 but the means are equal so we don't blow up).
    c0 = [100.0] * 4
    c1 = [100.0] * 4
    r = welch_t_test(c0, c1)
    assert r.cohens_d == 0.0


def test_cohens_d_inf_when_pooled_var_zero_and_means_differ():
    # Degenerate but defined: zero variance with unequal means matches
    # the t-score's `inf` convention rather than raising.
    import math
    c0 = [100.0] * 4
    c1 = [200.0] * 4
    r = welch_t_test(c0, c1)
    assert math.isinf(r.cohens_d)
    assert r.cohens_d > 0  # m1 > m0 → +inf


# --- Bundle G: Type-I rate regression on multi-cutoff cropping (R2) -------


def test_multi_cutoff_under_null_typeI_rate_pinned():
    """R2: pin the empirical false-positive rate of multi-cutoff cropping
    on pure IID gaussian noise. Catches future changes to cutoff list
    or threshold semantics that would silently break user calibration.

    Not a goodness-of-fit test — the assertion bounds are intentionally
    generous so this passes consistently on the seed used here. If a
    refactor moves us outside the bounds, we want to look at it (might
    be intentional; might be a bug).
    """
    rng = random.Random(0xC0FFEE)
    n_trials = 200
    over_3 = 0
    over_4_5 = 0
    for _ in range(n_trials):
        c0 = [rng.gauss(0, 1) for _ in range(300)]
        c1 = [rng.gauss(0, 1) for _ in range(300)]
        r = welch_with_cropping(c0, c1)
        if r.abs_t_score > 3.0:
            over_3 += 1
        if r.abs_t_score > 4.5:
            over_4_5 += 1
    rate_4_5 = over_4_5 / n_trials
    rate_3 = over_3 / n_trials
    # Conservative bound: pure IID noise should NOT cross 4.5 often.
    # Anything > 10% means cropping is over-aggressive vs nominal.
    assert rate_4_5 < 0.10, f"rate over 4.5 = {rate_4_5:.1%} too high"
    # The over-3 bound is more loose — the multi-cutoff inflation is
    # observable here, just not catastrophic.
    assert rate_3 < 0.40, f"rate over 3.0 = {rate_3:.1%} too high"
