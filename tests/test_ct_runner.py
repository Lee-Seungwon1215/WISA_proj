"""Phase C: the shared Valgrind run-and-classify helper (ctkat/ct_runner.py).

These lock the PASS/FAIL/ERROR mapping that BOTH `cli._do_ct` and the upcoming
`ct-matrix` sweep depend on — extracting it was pointless if the two could drift
(CLAUDE.md §3/§5)."""

from pathlib import Path

from ctkat.ct_runner import CtRunOutcome, classify_valgrind_run
from ctkat.valgrind_runner import ValgrindResult

FIXTURES = Path(__file__).parent / "fixtures"


def _result(rc: int, *, timed_out: bool = False, stderr: str = "") -> ValgrindResult:
    # `log_path` on the result is unused by classify (it takes log_path
    # separately); only `returncode`/`timed_out` matter here.
    return ValgrindResult(
        returncode=rc, log_path=Path("unused"), stdout="", stderr=stderr,
        timed_out=timed_out,
    )


def test_classify_pass_on_clean_log():
    out = classify_valgrind_run(_result(0), FIXTURES / "valgrind_safe.log")
    assert isinstance(out, CtRunOutcome)
    assert out.status == "PASS"
    assert out.findings == []
    assert out.error == ""


def test_classify_fail_on_findings():
    out = classify_valgrind_run(_result(99), FIXTURES / "valgrind_bad.log")
    assert out.status == "FAIL"
    assert out.findings  # >= 1 finding parsed
    assert out.error == ""


def test_classify_error_on_unexpected_returncode():
    # rc outside {0, 99} = crash / valgrind failure -> ERROR, not zero-findings.
    out = classify_valgrind_run(_result(137), FIXTURES / "valgrind_safe.log")
    assert out.status == "ERROR"
    assert "137" in out.error
    assert out.findings == []


def test_classify_error_marks_timeout():
    # run_valgrind returns rc=124 + timed_out=True on timeout.
    out = classify_valgrind_run(_result(124, timed_out=True), FIXTURES / "valgrind_safe.log")
    assert out.status == "ERROR"
    assert "timeout" in out.error


def test_classify_error_on_missing_log(tmp_path):
    out = classify_valgrind_run(_result(0), tmp_path / "nope.log")
    assert out.status == "ERROR"
    assert "no log file" in out.error


def test_classify_keys_on_log_not_exit_code():
    # rc 99 is the --error-exitcode convention, but we classify on the parsed
    # LOG, not the code: a 99 over a clean log is PASS. Mirrors _do_ct exactly.
    out = classify_valgrind_run(_result(99), FIXTURES / "valgrind_safe.log")
    assert out.status == "PASS"
