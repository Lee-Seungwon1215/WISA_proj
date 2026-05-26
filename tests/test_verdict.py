from ctkat.verdict import Verdict, combine


def test_both_clean():
    assert combine("PASS", "PASS") == Verdict.CLEAN


def test_valgrind_only_fail():
    # Structural finding with no timing evidence (or dudect didn't run).
    # Bundle I (U6 Option A): renamed from LOW_RISK to STRUCTURAL_LEAK.
    assert combine("FAIL", "NONE") == Verdict.STRUCTURAL_LEAK
    assert combine("FAIL", "PASS") == Verdict.STRUCTURAL_LEAK


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


# --- Bundle E-1: INCONCLUSIVE state + KAT pre-filter -----------------------


def test_valgrind_error_is_inconclusive():
    # F2: valgrind crash must not silently fold into CLEAN
    assert combine("ERROR", "PASS") == Verdict.INCONCLUSIVE
    assert combine("ERROR", "NONE") == Verdict.INCONCLUSIVE
    assert combine("ERROR", "FAIL") == Verdict.INCONCLUSIVE


def test_dudect_error_is_inconclusive():
    # T6: dudect harness crash/timeout must not silently fold into CLEAN
    assert combine("PASS", "ERROR") == Verdict.INCONCLUSIVE
    assert combine("FAIL", "ERROR") == Verdict.INCONCLUSIVE
    assert combine("NONE", "ERROR") == Verdict.INCONCLUSIVE


def test_both_error_is_inconclusive():
    assert combine("ERROR", "ERROR") == Verdict.INCONCLUSIVE


def test_kat_fail_pre_filters_to_inconclusive():
    # F11: --continue-on-kat-fail must not let a green ct/dudect produce
    # verdict=CLEAN. KAT FAIL means the analysed binary was functionally
    # broken; downstream PASSes are meaningless.
    assert combine("PASS", "PASS", kat_status="FAIL") == Verdict.INCONCLUSIVE
    assert combine("FAIL", "FAIL", kat_status="FAIL") == Verdict.INCONCLUSIVE
    assert combine("NONE", "NONE", kat_status="FAIL") == Verdict.INCONCLUSIVE


def test_kat_pass_does_not_affect_matrix():
    # KAT PASS is the precondition for the (valgrind, dudect) matrix to
    # mean anything — so it should NOT change verdicts compared to the
    # legacy NONE behavior.
    assert combine("PASS", "PASS", kat_status="PASS") == Verdict.CLEAN
    assert combine("FAIL", "PASS", kat_status="PASS") == Verdict.STRUCTURAL_LEAK
    assert combine("FAIL", "FAIL", kat_status="PASS") == Verdict.CRITICAL


def test_kat_none_is_default():
    # Backward compat: existing callers that don't pass kat_status keep
    # working — same as explicit NONE.
    assert combine("PASS", "PASS") == combine("PASS", "PASS", kat_status="NONE")


def test_kat_unknown_raises():
    import pytest
    with pytest.raises(ValueError, match="kat_status"):
        combine("PASS", "PASS", kat_status="MAYBE")
