"""CLI-level smoke tests using typer's CliRunner.

We don't try to cover subprocess-heavy commands (`run`, `ct`, `dudect`) at
this layer — those are exercised end-to-end by scripts/run_phase4.sh against
a real Docker + Valgrind environment. What we cover here:

  * `ctkat infer`     — pure-Python, easy to drive in isolation.
  * `_compute_verdicts` — pure helper that combines ct + dudect outputs;
    its matrix coverage isn't reachable through verdict.combine() alone.
"""

from pathlib import Path
from typing import List, Tuple

from typer.testing import CliRunner

from ctkat.cli import _compute_verdicts, app
from ctkat.dudect_runner import TimingSamples
from ctkat.statistics import WelchResult
from ctkat.valgrind_parser import (
    Finding,
    FindingType,
    Severity,
    StackFrame,
)
from ctkat.verdict import Verdict


FIXTURES = Path(__file__).parent / "fixtures" / "headers"


# --- ctkat infer smoke tests ------------------------------------------------


def test_infer_on_kem_header_succeeds_and_mentions_profile():
    runner = CliRunner()
    result = runner.invoke(app, ["infer", "--header", str(FIXTURES / "kem.h")])
    assert result.exit_code == 0
    assert "crypto_kem_dec" in result.stdout
    assert "kem_dec" in result.stdout  # profile name


def test_infer_function_filter_narrows_output():
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "infer",
            "--header", str(FIXTURES / "kem.h"),
            "--function", "crypto_kem_dec",
        ],
    )
    assert result.exit_code == 0
    assert "crypto_kem_dec" in result.stdout
    # The keypair function exists in kem.h but should be filtered out.
    assert "crypto_kem_keypair" not in result.stdout


def test_infer_requires_header_or_project():
    runner = CliRunner()
    result = runner.invoke(app, ["infer"])
    assert result.exit_code == 2
    assert "header" in result.stdout.lower() or "project" in result.stdout.lower()


def test_infer_missing_header_file_errors_cleanly():
    runner = CliRunner()
    result = runner.invoke(app, ["infer", "--header", "/nonexistent/path.h"])
    assert result.exit_code == 2
    assert "not found" in result.stdout.lower()


# --- _compute_verdicts (the ct+dudect merger) -------------------------------


def _ct_finding(harness: str) -> Tuple[str, List[Finding]]:
    """A single placeholder finding so the ct side counts as FAIL."""
    f = Finding(
        type=FindingType.SECRET_DEPENDENT_BRANCH,
        severity=Severity.HIGH,
        message="Conditional jump",
        frames=[StackFrame(address="0x0", function="foo", file="f.c", line=1)],
    )
    return (harness, [f])


def _ct_clean(harness: str) -> Tuple[str, List[Finding]]:
    return (harness, [])


def _dudect_result(harness: str, status: str, abs_t: float = 5.0):
    r = WelchResult(
        n0=100, n1=100, mean0=1.0, mean1=2.0,
        var0=0.5, var1=0.5,
        t_score=-abs_t, abs_t_score=abs_t, status=status,
    )
    return (harness, TimingSamples(), r, [])


def test_compute_verdicts_pairs_ct_and_dudect_by_name():
    ct = [_ct_finding("a"), _ct_clean("b")]
    dud = [_dudect_result("a", "FAIL"), _dudect_result("b", "PASS")]
    vs = _compute_verdicts(ct, dud)
    by_name = {v.name: v for v in vs}
    assert by_name["a"].verdict == Verdict.CRITICAL
    assert by_name["b"].verdict == Verdict.CLEAN


def test_compute_verdicts_handles_ct_only_harness():
    ct = [_ct_finding("a")]
    dud: List = []
    vs = _compute_verdicts(ct, dud)
    assert len(vs) == 1
    assert vs[0].valgrind_status == "FAIL"
    assert vs[0].dudect_status == "NONE"
    assert vs[0].verdict == Verdict.LOW_RISK


def test_compute_verdicts_handles_dudect_only_harness():
    ct: List = []
    dud = [_dudect_result("a", "WARNING", abs_t=7.0)]
    vs = _compute_verdicts(ct, dud)
    assert len(vs) == 1
    assert vs[0].valgrind_status == "NONE"
    assert vs[0].dudect_status == "WARNING"
    assert vs[0].verdict == Verdict.SUSPECT
    assert vs[0].dudect_abs_t == 7.0


def test_fmt_drops_non_finite_floats():
    # Regression: previously `f"{x:.3f}"` for inf/nan produced literal "inf"
    # or "nan" strings in CSVs, which pandas/R treat inconsistently and which
    # blew up downstream R code on a colleague's analysis script.
    from ctkat.cli import _fmt
    import math
    assert _fmt(math.inf) == ""
    assert _fmt(-math.inf) == ""
    assert _fmt(math.nan) == ""
    # Finite values still format as before.
    assert _fmt(3.14159, digits=2) == "3.14"
    assert _fmt(0.0) == "0.000"


def test_valgrind_unexpected_returncode_emits_warning(monkeypatch, tmp_path):
    """Regression: previously _do_ct ignored the valgrind ValgrindResult
    entirely. A crashing harness (segfault, abort) or a Valgrind failure
    would leave an empty/missing log, which then parsed as 0 findings →
    silent PASS. Now we surface a loud warning for any unexpected exit code.
    """
    import textwrap
    from ctkat import cli as cli_module
    from ctkat.config import load_config
    from ctkat.valgrind_runner import ValgrindResult

    # Fake out the heavyweight steps: skip build/generate, and have
    # `run_valgrind` claim a bogus exit code (137 = SIGKILL by convention)
    # without producing any log file.
    captured_log_path = {}

    def fake_run_valgrind(binary, log_path, flags, workdir):
        captured_log_path["path"] = log_path
        # Deliberately do NOT write any log — simulates a crashed harness.
        return ValgrindResult(
            returncode=137,
            log_path=log_path,
            stdout="",
            stderr="harness died with SIGKILL",
        )

    monkeypatch.setattr(cli_module, "run_valgrind", fake_run_valgrind)
    monkeypatch.setattr(cli_module, "_do_generate", lambda *a, **k: {})

    yaml_text = textwrap.dedent("""
        project: {name: demo}
        build: {command: "true"}
        ct:
          harnesses:
            - name: crashy
              binary: ./not_actually_used
    """).strip()
    p = tmp_path / "ctkat.yaml"
    p.write_text(yaml_text)

    runner = CliRunner()
    result = runner.invoke(app, ["ct", "--config", str(p)])
    # Should still complete (we treat the missing log as 0 findings) but
    # the warning must be present in stdout.
    assert "WARNING" in result.stdout
    assert "137" in result.stdout
    # Also the missing-log warning should fire.
    assert "no log file" in result.stdout.lower() or "nothing to parse" in result.stdout.lower()


def test_compute_verdicts_unions_harness_names_across_stages():
    # ct knows about "a", dudect knows about "b" — both should appear.
    ct = [_ct_clean("a")]
    dud = [_dudect_result("b", "PASS")]
    vs = _compute_verdicts(ct, dud)
    names = {v.name for v in vs}
    assert names == {"a", "b"}
