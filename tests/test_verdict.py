from ctkat.verdict import Verdict, combine


def test_both_clean():
    assert combine("PASS", "PASS") == Verdict.CLEAN


def test_valgrind_only_fail():
    # Structural finding with no timing evidence (or dudect didn't run)
    assert combine("FAIL", "NONE") == Verdict.LOW_RISK
    assert combine("FAIL", "PASS") == Verdict.LOW_RISK


def test_dudect_only_warning():
    assert combine("PASS", "WARNING") == Verdict.SUSPECT
    assert combine("NONE", "WARNING") == Verdict.SUSPECT


def test_dudect_only_fail_no_valgrind_finding():
    assert combine("PASS", "FAIL") == Verdict.RISKY
    assert combine("NONE", "FAIL") == Verdict.RISKY


def test_valgrind_fail_plus_dudect_warning_promotes_to_risky():
    assert combine("FAIL", "WARNING") == Verdict.RISKY


def test_both_fail_is_critical():
    assert combine("FAIL", "FAIL") == Verdict.CRITICAL


def test_none_none_is_clean():
    # No stages ran at all — vacuously clean
    assert combine("NONE", "NONE") == Verdict.CLEAN


def test_status_is_case_insensitive():
    assert combine("pass", "fail") == Verdict.RISKY
    assert combine("Fail", "Warning") == Verdict.RISKY


def test_unknown_dudect_status_raises():
    # Fail-safe policy: an unrecognized status pair must NOT silently default
    # to CLEAN (that would mark a harness "safe" because the tool got
    # confused). Raise instead so the caller notices.
    import pytest
    with pytest.raises(ValueError, match="unrecognized"):
        combine("PASS", "UNKNOWN")


def test_unknown_valgrind_status_also_raises():
    # Symmetric coverage — neither side should silently fall through.
    import pytest
    with pytest.raises(ValueError, match="unrecognized"):
        combine("MAYBE", "PASS")
