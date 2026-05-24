import random

from ctkat.statistics import batch_t_scores, welch_t_test


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
