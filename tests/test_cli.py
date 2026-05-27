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

from ctkat.cli import _compute_verdicts, _print_cflags_banner, app
from ctkat.config import (
    BuildConfig,
    CtConfig,
    CtkatConfig,
    DudectCompilerConfig,
    DudectConfig,
    HarnessConfig,
    ProjectConfig,
)
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


# --- ctkat parse smoke test (F12 regression) --------------------------------


def test_parse_subcommand_runs_on_valid_log(tmp_path):
    """F12 regression: `ctkat parse <log>` used to NameError because the
    cli.py:1223 call site referenced `parse_valgrind_log` which was no longer
    imported after Bundle I (T3) switched to `parse_valgrind_log_with_stats`.
    """
    log = tmp_path / "valgrind.log"
    log.write_text("==123== No findings here\n")
    runner = CliRunner()
    result = runner.invoke(app, ["parse", str(log)])
    assert result.exit_code == 0
    assert "no findings" in result.stdout.lower()


# --- _compute_verdicts (the ct+dudect merger) -------------------------------


def _ct_finding(harness: str) -> Tuple[str, str, List[Finding]]:
    """A single placeholder finding so the ct side counts as FAIL.

    Bundle E-2: 3-tuple (name, status, findings). status="FAIL" because
    findings is non-empty.
    """
    f = Finding(
        type=FindingType.SECRET_DEPENDENT_BRANCH,
        severity=Severity.HIGH,
        message="Conditional jump",
        frames=[StackFrame(address="0x0", function="foo", file="f.c", line=1)],
    )
    return (harness, "FAIL", [f])


def _ct_clean(harness: str) -> Tuple[str, str, List[Finding]]:
    return (harness, "PASS", [])


def _ct_error(harness: str) -> Tuple[str, str, List[Finding]]:
    """Bundle E-2: ct stage didn't complete (valgrind crash F2 or sentinel
    missing F5). Verdict matrix maps this to INCONCLUSIVE."""
    return (harness, "ERROR", [])


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
    assert vs[0].verdict == Verdict.STRUCTURAL_LEAK


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


def test_fmt_accepts_none():
    # Bundle B: diagnostic fields (cropped_at when --no-crop, etc.) can be
    # None — must serialize to empty string, not the literal "None".
    from ctkat.cli import _fmt
    assert _fmt(None) == ""


def test_dudect_summary_csv_preserves_status_column_position(tmp_path):
    # Regression: scripts/run_phase4.sh parses `dudect_summary.csv` via
    # awk -F',' '... {print $11}' to read the status column. New Bundle B
    # diagnostic columns must be appended AFTER position 14 so that
    # external awk-by-position parsers keep working.
    from ctkat.cli import _emit_dudect_report
    from ctkat.dudect_runner import TimingSamples
    from ctkat.statistics import WelchResult

    r = WelchResult(
        n0=100, n1=100, mean0=1.0, mean1=2.0,
        var0=0.5, var1=0.5,
        t_score=-5.0, abs_t_score=5.0, status="WARNING",
        cropped_at=0.95, t_score_uncropped=-3.0, abs_t_score_uncropped=3.0,
    )
    results = [("h1", TimingSamples(), r, [])]
    _emit_dudect_report("proj", tmp_path, results)
    summary = (tmp_path / "dudect_summary.csv").read_text().splitlines()
    header = summary[0].split(",")
    # awk's $1 == header[0] etc. — these positions are part of the public
    # CSV contract.
    assert header[10] == "status"          # awk $11
    assert header[0]  == "project"         # awk $1
    assert header[1]  == "harness"         # awk $2
    # New columns at the end (15-17 in 1-indexed awk, 14-16 in 0-indexed).
    assert header[14] == "cropped_at"
    assert header[15] == "t_score_uncropped"
    assert header[16] == "abs_t_score_uncropped"
    # Data row carries the values.
    row = summary[1].split(",")
    assert row[10] == "WARNING"
    assert row[14] == "0.950"


def test_valgrind_unexpected_returncode_yields_error(monkeypatch, tmp_path):
    """Bundle E-2 (F2): valgrind exiting with anything outside {0, 99}
    means the harness crashed or valgrind itself failed. Previously this
    parsed the missing log as 0 findings and reported PASS (a CLEAN
    verdict on a crashed run). Now it must surface status=ERROR with
    exit code 2 — verdict CSV consumers must see "couldn't verify"
    instead of green-light.
    """
    import textwrap
    from ctkat import cli as cli_module
    from ctkat.valgrind_runner import ValgrindResult

    def fake_run_valgrind(binary, log_path, flags, workdir, **kwargs):
        # Deliberately do NOT write any log — simulates a crashed harness.
        # **kwargs absorbs the new Bundle N `timeout=` keyword.
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
    assert "ct: ERROR" in result.stdout
    assert "137" in result.stdout
    assert "INCOMPLETE" in result.stdout  # subcommand summary line
    assert result.exit_code == 2          # E-2: ct ERROR also exits 2


def test_compute_verdicts_unions_harness_names_across_stages():
    # ct knows about "a", dudect knows about "b" — both should appear.
    ct = [_ct_clean("a")]
    dud = [_dudect_result("b", "PASS")]
    vs = _compute_verdicts(ct, dud)
    names = {v.name for v in vs}
    assert names == {"a", "b"}


# --- F9: cflags asymmetry banner (Bundle E-3) ------------------------------


def _cfg_with_cflags(ct_flags, dud_flags):
    """Build a minimal CtkatConfig with both stages and the given cflags."""
    return CtkatConfig(
        project=ProjectConfig(name="t"),
        build=BuildConfig(command="true"),
        ct=CtConfig(
            cflags=ct_flags,
            harnesses=[HarnessConfig(name="h", binary=Path("/tmp/x"))],
        ),
        dudect=DudectConfig(
            compiler=DudectCompilerConfig(cflags=dud_flags),
        ),
    )


def test_cflags_banner_warns_when_asymmetric(capsys):
    cfg = _cfg_with_cflags(["-O0", "-g"], ["-O2", "-g"])
    _print_cflags_banner(cfg)
    out = capsys.readouterr().out
    assert "ct stage cflags" in out
    assert "dudect stage cflags" in out
    assert "WARNING" in out
    assert "different cflags" in out


def test_cflags_banner_silent_when_symmetric(capsys):
    # Same flags in different order should NOT warn (set comparison).
    cfg = _cfg_with_cflags(["-O2", "-g"], ["-g", "-O2"])
    _print_cflags_banner(cfg)
    out = capsys.readouterr().out
    assert "ct stage cflags" in out
    assert "dudect stage cflags" in out
    assert "WARNING" not in out
    assert "different cflags" not in out


def test_cflags_banner_silent_when_dudect_missing(capsys):
    cfg = CtkatConfig(
        project=ProjectConfig(name="t"),
        build=BuildConfig(command="true"),
        ct=CtConfig(
            harnesses=[HarnessConfig(name="h", binary=Path("/tmp/x"))],
        ),
    )
    _print_cflags_banner(cfg)
    assert capsys.readouterr().out == ""


def test_cflags_banner_silent_when_dudect_disabled(capsys):
    cfg = _cfg_with_cflags(["-O0"], ["-O2"])
    cfg = cfg.model_copy(update={"dudect": cfg.dudect.model_copy(update={"enabled": False})})
    _print_cflags_banner(cfg)
    assert capsys.readouterr().out == ""


# --- Bundle E-1: F1 KAT expected_min, F10 build expected_artifacts ----------


def _kat_cfg(command: str, expected_min=None, pattern=None):
    from ctkat.config import KatConfig
    kwargs = dict(command=command)
    if expected_min is not None:
        kwargs["expected_min"] = expected_min
    if pattern is not None:
        kwargs["expected_pattern"] = pattern
    return CtkatConfig(
        project=ProjectConfig(name="t"),
        build=BuildConfig(command="true"),
        kat=KatConfig(**kwargs),
    )


def test_kat_passes_when_count_meets_expected_min(tmp_path, capsys):
    from ctkat.cli import _do_kat
    cfg = _kat_cfg('echo "PASSED: 100 tests"', expected_min=50)
    ok, count = _do_kat(cfg, tmp_path)
    assert ok is True
    assert count == 100
    assert "KAT: PASS" in capsys.readouterr().out


def test_kat_fails_when_count_below_expected_min(tmp_path, capsys):
    from ctkat.cli import _do_kat
    cfg = _kat_cfg('echo "PASSED: 3 tests"', expected_min=10)
    ok, count = _do_kat(cfg, tmp_path)
    assert ok is False
    assert count == 3
    out = capsys.readouterr().out
    assert "KAT: FAIL" in out
    assert "ran 3" in out


def test_kat_fails_when_pattern_does_not_match(tmp_path, capsys):
    from ctkat.cli import _do_kat
    cfg = _kat_cfg('echo "everything is fine"', expected_min=1)
    ok, count = _do_kat(cfg, tmp_path)
    assert ok is False
    assert count is None
    # Rich may wrap the message; collapse whitespace before checking.
    out = " ".join(capsys.readouterr().out.split())
    assert "did not match" in out


def test_kat_unset_expected_min_warns_but_passes(tmp_path, capsys):
    # F1 backward-compat: legacy yaml (no expected_min) still passes on rc=0
    # but emits a one-time note pointing users at the new field.
    from ctkat.cli import _do_kat
    cfg = _kat_cfg('echo "hi"')  # no expected_min
    ok, count = _do_kat(cfg, tmp_path)
    assert ok is True
    out = capsys.readouterr().out
    assert "expected_min unset" in out
    assert "KAT: PASS" in out


def test_kat_no_op_still_passes_without_expected_min(tmp_path, capsys):
    # F1: documenting the fail-open that motivates F1 — a no-op runner
    # (`true`) still PASSes when expected_min is unset. This test pins
    # current legacy behavior so a future change is intentional.
    from ctkat.cli import _do_kat
    cfg = _kat_cfg("true")  # no stdout at all
    ok, _ = _do_kat(cfg, tmp_path)
    assert ok is True


def test_kat_anchored_pattern_rejects_substring_in_error_line(tmp_path, capsys):
    """F18 regression: a runner that prints an error line containing the
    substring "PASSED: N" but exits 0 used to false-PASS because the
    default `expected_pattern` was `re.search`ed without anchoring. The
    fix anchors the default pattern with `^...` + re.MULTILINE, so the
    match only fires on a standalone summary line."""
    from ctkat.cli import _do_kat
    # Single-line stdout with "PASSED: 100" embedded inside an error msg.
    # `printf` keeps it on one line — the offending substring is mid-line,
    # not at the start, so the anchored default must not match.
    cfg = _kat_cfg('printf "ERROR vector 50 differs. PASSED: 100 prior\\n"',
                   expected_min=10)
    ok, count = _do_kat(cfg, tmp_path)
    assert ok is False
    assert count is None


def test_kat_anchored_pattern_still_matches_pqclean_style_line(tmp_path, capsys):
    """F18 must not regress the happy path. PQClean / NIST KAT runners
    emit a standalone `PASSED: 100 tests` summary line, which the anchored
    default still matches."""
    from ctkat.cli import _do_kat
    cfg = _kat_cfg('printf "running ML-KEM-768 KAT\\nPASSED: 100 tests\\n"',
                   expected_min=50)
    ok, count = _do_kat(cfg, tmp_path)
    assert ok is True
    assert count == 100


def test_build_passes_when_expected_artifacts_present(tmp_path, capsys):
    from ctkat.cli import _do_build
    artifact = tmp_path / "out.bin"
    cfg = CtkatConfig(
        project=ProjectConfig(name="t"),
        build=BuildConfig(
            command=f"touch {artifact.name}",
            workdir=tmp_path,
            expected_artifacts=[Path("out.bin")],
        ),
    )
    assert _do_build(cfg, tmp_path) is True
    assert "Build: PASS" in capsys.readouterr().out


def test_build_fails_when_expected_artifact_missing(tmp_path, capsys):
    from ctkat.cli import _do_build
    cfg = CtkatConfig(
        project=ProjectConfig(name="t"),
        build=BuildConfig(
            command="true",  # no-op build
            workdir=tmp_path,
            expected_artifacts=[Path("never_produced.bin")],
        ),
    )
    assert _do_build(cfg, tmp_path) is False
    out = capsys.readouterr().out
    assert "Build: FAIL" in out
    assert "missing" in out


def test_dudect_summary_error_row_hides_numeric_cells(monkeypatch):
    """T22 regression: an ERROR row used to render with `n0=0`, `mean=0.00`,
    `|t|=0.00` — visually indistinguishable from a real measurement that
    happened to be all zeros. The fix collapses every numeric cell to `-`
    so the magenta status badge carries the signal alone."""
    import io
    from rich.console import Console as _RichConsole
    from ctkat import cli as cli_module
    from ctkat.cli import _print_dudect_summary, _error_welch
    from ctkat.dudect_runner import TimingSamples
    # Rich's auto-attached terminal doesn't write through capsys; replace
    # the module-level console with one that writes to a StringIO so we
    # can inspect what would have hit the user's terminal.
    buf = io.StringIO()
    monkeypatch.setattr(
        cli_module, "console",
        _RichConsole(file=buf, force_terminal=False, width=120),
    )
    err_result = _error_welch()
    samples = TimingSamples()
    _print_dudect_summary([("crashed_harness", samples, err_result, [])])
    out = buf.getvalue()
    assert "ERROR" in out
    # The 0.00 / 0 sentinel values must NOT leak into the row body.
    body_lines = [line for line in out.splitlines() if "crashed_harness" in line]
    assert body_lines, f"crashed_harness row missing from rendered table:\n{out}"
    body = "\n".join(body_lines)
    assert "0.00" not in body
    assert "-" in body


def test_infer_surfaces_skipped_declaration_count(tmp_path, capsys):
    """T13 regression: `parse_functions_with_stats` was added in Bundle H2
    (T11) but the CLI `infer` subcommand still called `parse_header_file`
    (list-only), so users were never told how many function-pointer /
    variadic decls the strict regex skipped. Fix wires the stats path
    through and surfaces a dim note."""
    header = tmp_path / "tricky.h"
    header.write_text(
        # One parseable decl + one function-pointer parameter (skipped by
        # the strict regex).
        "int normal_fn(int x);\n"
        "int register_cb(int (*cb)(int));\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(app, ["infer", "--header", str(header)])
    assert result.exit_code == 0
    assert "normal_fn" in result.stdout
    # The skip-count note must appear (Rich may wrap; collapse first).
    collapsed = " ".join(result.stdout.split())
    assert "1 declaration(s) skipped" in collapsed


def test_build_timeout_yields_fail_not_hang(tmp_path, capsys):
    """Bundle N (T12) regression: a hung build script must surface as
    `Build: FAIL` (rc=124) instead of stalling. Use `sleep 5` with a
    0.1-second timeout to keep the test under a second."""
    from ctkat.cli import _do_build
    cfg = CtkatConfig(
        project=ProjectConfig(name="t"),
        build=BuildConfig(command="sleep 5", workdir=tmp_path, timeout=1),
    )
    # Note: BuildConfig.timeout has ge=1 — the smallest value the validator
    # accepts. We rely on `sleep 5` taking longer than 1 second.
    assert _do_build(cfg, tmp_path) is False
    out = capsys.readouterr().out
    assert "Build: FAIL" in out
    assert "timeout" in out.lower()


def test_build_unset_expected_artifacts_warns(tmp_path, capsys):
    # F10 backward-compat: legacy yaml (no expected_artifacts) still passes
    # on rc=0 but a one-time note is emitted.
    from ctkat.cli import _do_build
    cfg = CtkatConfig(
        project=ProjectConfig(name="t"),
        build=BuildConfig(command="true", workdir=tmp_path),
    )
    assert _do_build(cfg, tmp_path) is True
    assert "expected_artifacts unset" in capsys.readouterr().out


# --- F17: CLI override re-validates against pydantic Field bounds --------


def test_dudect_cli_measurements_override_rejects_above_cap(tmp_path):
    """F17 regression: `--measurements 100000000` used to bypass T8's
    `Field(le=10_000_000)` because `model_copy(update=...)` does not
    re-validate. The fix routes overrides through `model_validate`."""
    import textwrap
    yaml_text = textwrap.dedent("""
        project: {name: demo}
        build: {command: "true"}
        dudect:
          harnesses:
            - {name: h, template: generic, function: foo}
    """).strip()
    p = tmp_path / "ctkat.yaml"
    p.write_text(yaml_text)
    runner = CliRunner()
    # 10**8 is 10x the T8 cap of 10_000_000.
    result = runner.invoke(app, ["dudect", "--config", str(p), "--measurements", "100000000"])
    assert result.exit_code != 0
    # The actual surfacing is via pydantic ValidationError → typer error;
    # what matters is we do NOT proceed silently.


# --- Bundle E-1: F7/F8 subcommand exit code symmetry ----------------------


def test_ct_subcommand_exits_2_when_ct_section_missing(tmp_path):
    import textwrap
    yaml_text = textwrap.dedent("""
        project: {name: demo}
        build: {command: "true"}
    """).strip()
    p = tmp_path / "ctkat.yaml"
    p.write_text(yaml_text)
    runner = CliRunner()
    result = runner.invoke(app, ["ct", "--config", str(p)])
    assert result.exit_code == 2
    # F8 specifically: must NOT print bold-green PASS in this case.
    assert "Constant-Time Check: PASS" not in result.stdout


def test_kat_subcommand_exits_2_when_kat_section_missing(tmp_path):
    import textwrap
    yaml_text = textwrap.dedent("""
        project: {name: demo}
        build: {command: "true"}
    """).strip()
    p = tmp_path / "ctkat.yaml"
    p.write_text(yaml_text)
    runner = CliRunner()
    result = runner.invoke(app, ["kat", "--config", str(p)])
    # F7: previously this exited 0 — asymmetric with dudect subcommand.
    assert result.exit_code == 2


# --- Bundle E-1: F11 KAT FAIL pre-filters verdict to INCONCLUSIVE ----------


def test_compute_verdicts_kat_fail_forces_inconclusive():
    # All ct/dudect clean, but KAT failed — verdict must NOT be CLEAN.
    ct = [_ct_clean("a"), _ct_clean("b")]
    dud = [_dudect_result("a", "PASS"), _dudect_result("b", "PASS")]
    vs = _compute_verdicts(ct, dud, kat_status="FAIL")
    assert all(v.verdict == Verdict.INCONCLUSIVE for v in vs)


def test_compute_verdicts_kat_pass_unchanged_from_legacy():
    # Backward compat: kat_status="PASS" doesn't change the matrix outcome
    # compared to legacy kat_status="NONE".
    ct = [_ct_clean("a")]
    dud = [_dudect_result("a", "FAIL", abs_t=15.0)]
    vs_pass = _compute_verdicts(ct, dud, kat_status="PASS")
    vs_none = _compute_verdicts(ct, dud, kat_status="NONE")
    assert vs_pass[0].verdict == vs_none[0].verdict == Verdict.RISKY


# --- Bundle E-1: verdict CSV gets kat_status / kat_count appended ---------


def test_emit_verdicts_csv_includes_kat_columns(tmp_path):
    from ctkat.cli import _emit_verdicts
    from ctkat.verdict import HarnessVerdict
    v = HarnessVerdict(
        name="h1",
        valgrind_status="PASS",
        dudect_status="PASS",
        verdict=Verdict.CLEAN,
        valgrind_finding_count=0,
        dudect_abs_t=1.5,
    )
    path = _emit_verdicts(
        tmp_path, "proj", [v], kat_status="PASS", kat_count=100,
    )
    lines = path.read_text().splitlines()
    header = lines[0].split(",")
    assert header[6] == "verdict"          # awk $7 must stay stable
    assert header[7] == "kat_status"       # appended at end
    assert header[8] == "kat_count"
    row = lines[1].split(",")
    assert row[6] == "CLEAN"
    assert row[7] == "PASS"
    assert row[8] == "100"


# --- Bundle E-1: T6 dudect runner uncaught paths → status=ERROR ---------


def _stub_compile(name, **kwargs):
    """Pretend the timing harness compiled successfully — what we want to
    test is what happens when the binary itself misbehaves at run time,
    not the compile path."""
    from ctkat.timing_harness_generator import GeneratedTimingHarness
    return GeneratedTimingHarness(
        source_path=Path(f"/tmp/{name}.c"),
        binary_path=Path(f"/tmp/{name}"),
        compile_command="(stubbed)",
    )


def _dud_cfg_with_harness(timeout=600):
    from ctkat.config import DudectHarnessConfig
    return DudectConfig(
        timeout=timeout,
        clock="monotonic",
        harnesses=[
            DudectHarnessConfig(
                name="h1",
                template="generic",
                function="foo",
                return_type="int",
                args=["x"],
                buffers=[],
            ),
        ],
    )


def test_dudect_timeout_yields_error_status(tmp_path, monkeypatch, capsys):
    import subprocess
    import ctkat.cli as cli_module
    monkeypatch.setattr(cli_module, "generate_and_compile_timing", _stub_compile)

    def fake_run(binary, workdir, timeout):
        raise subprocess.TimeoutExpired(cmd=str(binary), timeout=timeout)
    monkeypatch.setattr(cli_module, "run_timing_harness", fake_run)

    dud = _dud_cfg_with_harness(timeout=1)
    results = cli_module._do_dudect(dud, tmp_path, "proj", tmp_path, crop=False)
    assert len(results) == 1
    name, _, welch, _ = results[0]
    assert name == "h1"
    assert welch.status == "ERROR"
    assert "ERROR" in capsys.readouterr().out


def test_dudect_crash_yields_error_status(tmp_path, monkeypatch, capsys):
    import ctkat.cli as cli_module
    monkeypatch.setattr(cli_module, "generate_and_compile_timing", _stub_compile)

    def fake_run(binary, workdir, timeout):
        raise RuntimeError(f"timing harness {binary} failed (rc=139)")
    monkeypatch.setattr(cli_module, "run_timing_harness", fake_run)

    dud = _dud_cfg_with_harness()
    results = cli_module._do_dudect(dud, tmp_path, "proj", tmp_path, crop=False)
    assert results[0][2].status == "ERROR"
    assert "crashed" in capsys.readouterr().out


def test_dudect_empty_output_yields_error_status(tmp_path, monkeypatch, capsys):
    import ctkat.cli as cli_module
    monkeypatch.setattr(cli_module, "generate_and_compile_timing", _stub_compile)

    def fake_run(binary, workdir, timeout):
        raise ValueError("empty timing harness output")
    monkeypatch.setattr(cli_module, "run_timing_harness", fake_run)

    dud = _dud_cfg_with_harness()
    results = cli_module._do_dudect(dud, tmp_path, "proj", tmp_path, crop=False)
    assert results[0][2].status == "ERROR"
    assert "unparseable" in capsys.readouterr().out


def test_dudect_error_flows_to_inconclusive_verdict(tmp_path, monkeypatch):
    import ctkat.cli as cli_module
    monkeypatch.setattr(cli_module, "generate_and_compile_timing", _stub_compile)
    monkeypatch.setattr(
        cli_module, "run_timing_harness",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("rc=139")),
    )
    dud = _dud_cfg_with_harness()
    results = cli_module._do_dudect(dud, tmp_path, "proj", tmp_path, crop=False)
    verdicts = _compute_verdicts([], results)
    assert verdicts[0].verdict == Verdict.INCONCLUSIVE


# --- Bundle E-2: F2 (valgrind ERROR) + F5 (sentinel) ----------------------


def _ctkat_yaml(extra_ct_keys: str = "", harness_block: str = "") -> str:
    import textwrap
    return textwrap.dedent(f"""
        project: {{name: demo}}
        build: {{command: "true"}}
        ct:
        {extra_ct_keys}
          harnesses:
        {harness_block}
    """).strip()


def _stub_ct_setup(monkeypatch, *, returncode: int, stdout: str, write_log: bool):
    """Common monkeypatching for _do_ct unit tests: stub generate_and_compile
    (so we don't need a real binary on disk) and run_valgrind (so we don't
    need real valgrind)."""
    from ctkat import cli as cli_module
    from ctkat.valgrind_runner import ValgrindResult

    def fake_run_valgrind(binary, log_path, flags, workdir, **kwargs):
        # **kwargs absorbs Bundle N's keyword-only `timeout=`.
        if write_log:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text("==1== ERROR SUMMARY: 0 errors from 0 contexts\n")
        return ValgrindResult(
            returncode=returncode, log_path=log_path,
            stdout=stdout, stderr="",
        )

    monkeypatch.setattr(cli_module, "run_valgrind", fake_run_valgrind)
    monkeypatch.setattr(cli_module, "_do_generate", lambda *a, **k: {})


def test_ct_missing_log_yields_error(monkeypatch, tmp_path):
    # F2: rc=0 but log file never appeared — must produce ERROR, not PASS.
    _stub_ct_setup(monkeypatch, returncode=0, stdout="x", write_log=False)
    yaml_text = _ctkat_yaml(harness_block="    - {name: h, binary: ./x}")
    p = tmp_path / "ctkat.yaml"
    p.write_text(yaml_text)
    result = CliRunner().invoke(app, ["ct", "--config", str(p)])
    assert "ct: ERROR" in result.stdout
    assert "no log file" in result.stdout.lower()
    assert result.exit_code == 2


def test_ct_sentinel_required_but_missing_yields_error(monkeypatch, tmp_path):
    # F5: require_sentinel=true + binary stdout has no sentinel → ERROR.
    _stub_ct_setup(monkeypatch, returncode=0, stdout="hello world", write_log=True)
    yaml_text = _ctkat_yaml(
        extra_ct_keys="  require_sentinel: true",
        harness_block="    - {name: h, binary: ./x}",
    )
    p = tmp_path / "ctkat.yaml"
    p.write_text(yaml_text)
    result = CliRunner().invoke(app, ["ct", "--config", str(p)])
    assert "ct: ERROR" in result.stdout
    assert "sentinel" in result.stdout.lower()
    assert result.exit_code == 2


def test_ct_sentinel_required_and_present_passes(monkeypatch, tmp_path):
    # F5: require_sentinel=true + sentinel present → normal PASS path.
    _stub_ct_setup(
        monkeypatch, returncode=0,
        stdout="CTKAT-HARNESS-RAN: h\nother output\n", write_log=True,
    )
    yaml_text = _ctkat_yaml(
        extra_ct_keys="  require_sentinel: true",
        harness_block="    - {name: h, binary: ./x}",
    )
    p = tmp_path / "ctkat.yaml"
    p.write_text(yaml_text)
    result = CliRunner().invoke(app, ["ct", "--config", str(p)])
    assert "Constant-Time Check: PASS" in result.stdout
    assert result.exit_code == 0


def test_ct_sentinel_skipped_when_require_false_emits_note(monkeypatch, tmp_path):
    # F5 backward-compat: require_sentinel=false → don't enforce, but
    # emit a per-run note pointing users at the new field.
    _stub_ct_setup(monkeypatch, returncode=0, stdout="no sentinel here", write_log=True)
    yaml_text = _ctkat_yaml(harness_block="    - {name: h, binary: ./x}")
    p = tmp_path / "ctkat.yaml"
    p.write_text(yaml_text)
    result = CliRunner().invoke(app, ["ct", "--config", str(p)])
    assert "Constant-Time Check: PASS" in result.stdout
    assert "require_sentinel" in result.stdout
    assert result.exit_code == 0


def test_ct_error_flows_to_inconclusive_verdict():
    # End-to-end via _compute_verdicts: ct ERROR (from either F2 or F5)
    # + dudect PASS must NOT yield CLEAN.
    ct = [_ct_error("h"), _ct_clean("safe")]
    dud = [_dudect_result("h", "PASS"), _dudect_result("safe", "PASS")]
    vs = _compute_verdicts(ct, dud)
    by_name = {v.name: v for v in vs}
    assert by_name["h"].verdict == Verdict.INCONCLUSIVE
    assert by_name["safe"].verdict == Verdict.CLEAN  # unaffected harness stays CLEAN


# --- Bundle F: S1 dudect_summary.csv raw-count columns (18-20) ------------


# --- Bundle H2: T10 dudect_summary.csv full-header snapshot --------------


def test_dudect_summary_csv_header_snapshot(tmp_path):
    """T10: pin the exact header line. New columns must be appended at
    the end with this test updated explicitly — silent reorders break
    awk-by-position consumers (scripts/run_phase4.sh)."""
    from ctkat.cli import _emit_dudect_report
    from ctkat.dudect_runner import TimingSamples
    from ctkat.statistics import WelchResult

    r = WelchResult(
        n0=1, n1=1, mean0=0.0, mean1=0.0, var0=0.0, var1=0.0,
        t_score=0.0, abs_t_score=0.0, status="PASS",
    )
    _emit_dudect_report("p", tmp_path, [("h", TimingSamples(), r, [])])
    header = (tmp_path / "dudect_summary.csv").read_text().splitlines()[0]
    expected = (
        "project,harness,n0,n1,mean0,mean1,var0,var1,t_score,"
        "abs_t_score,status,batch_t_mean,batch_t_max_abs,batches,"
        "cropped_at,t_score_uncropped,abs_t_score_uncropped,"
        "raw_n_total,dropped_zero_n0,dropped_zero_n1,cohens_d"
    )
    assert header == expected


def test_dudect_summary_csv_has_raw_count_columns(tmp_path):
    from ctkat.cli import _emit_dudect_report
    from ctkat.dudect_runner import TimingSamples
    from ctkat.statistics import WelchResult

    samples = TimingSamples(
        classes=[0, 1] * 50, cycles=[100.0, 200.0] * 50,
        raw_n_total=200, dropped_zero_n0=30, dropped_zero_n1=2,
    )
    r = WelchResult(
        n0=50, n1=50, mean0=100.0, mean1=200.0,
        var0=1.0, var1=1.0,
        t_score=5.0, abs_t_score=5.0, status="FAIL",
    )
    _emit_dudect_report("proj", tmp_path, [("h1", samples, r, [])])
    summary = (tmp_path / "dudect_summary.csv").read_text().splitlines()
    header = summary[0].split(",")
    # Existing positions still stable (E-1 / Bundle B contract).
    assert header[10] == "status"
    assert header[14] == "cropped_at"
    # New F columns appended at the end (1-indexed 18-20).
    assert header[17] == "raw_n_total"
    assert header[18] == "dropped_zero_n0"
    assert header[19] == "dropped_zero_n1"
    row = summary[1].split(",")
    assert row[17] == "200"
    assert row[18] == "30"
    assert row[19] == "2"


# --- Bundle G: Cohen's d CSV column (S3) + Bonferroni scaling (R2) -------


def test_dudect_summary_csv_has_cohens_d_column(tmp_path):
    from ctkat.cli import _emit_dudect_report
    from ctkat.dudect_runner import TimingSamples
    from ctkat.statistics import WelchResult

    r = WelchResult(
        n0=10, n1=10, mean0=100.0, mean1=110.0,
        var0=1.0, var1=1.0,
        t_score=5.0, abs_t_score=5.0, status="WARNING",
        cohens_d=2.5,
    )
    _emit_dudect_report("proj", tmp_path,
                       [("h1", TimingSamples(), r, [])])
    summary = (tmp_path / "dudect_summary.csv").read_text().splitlines()
    header = summary[0].split(",")
    # S3: col 21 (0-indexed 20). Existing positions still stable.
    assert header[20] == "cohens_d"
    assert header[10] == "status"          # E-1/B contract
    assert header[17] == "raw_n_total"     # Bundle F contract
    row = summary[1].split(",")
    assert row[20] == "2.500"


def test_bonferroni_correction_scales_thresholds(monkeypatch, tmp_path, capsys):
    """R2: when dud.bonferroni_correct=True, _do_dudect must pass scaled
    thresholds to welch_with_cropping / welch_t_test / batch_t_scores.
    We monkeypatch those to capture their threshold kwargs."""
    import ctkat.cli as cli_module
    monkeypatch.setattr(cli_module, "generate_and_compile_timing", _stub_compile)

    # Stub run_timing_harness to return enough samples for the t-test
    # to actually fire.
    def fake_run(binary, workdir, timeout):
        from ctkat.dudect_runner import TimingSamples
        s = TimingSamples()
        s.classes = [0, 1] * 50
        s.cycles = [100.0, 110.0] * 50
        s.raw_n_total = 100
        return s
    monkeypatch.setattr(cli_module, "run_timing_harness", fake_run)

    captured = {}

    def fake_welch_with_cropping(c0, c1, warning_threshold, fail_threshold):
        captured["warn"] = warning_threshold
        captured["fail"] = fail_threshold
        from ctkat.statistics import welch_t_test
        return welch_t_test(c0, c1, warning_threshold, fail_threshold)
    monkeypatch.setattr(cli_module, "welch_with_cropping", fake_welch_with_cropping)

    dud = _dud_cfg_with_harness()
    dud = dud.model_copy(update={"bonferroni_correct": True})
    cli_module._do_dudect(dud, tmp_path, "proj", tmp_path, crop=True)

    # 4.5 * sqrt(5) ≈ 10.06, 10.0 * sqrt(5) ≈ 22.36
    import math
    expected_warn = 4.5 * math.sqrt(5)
    expected_fail = 10.0 * math.sqrt(5)
    assert abs(captured["warn"] - expected_warn) < 1e-6
    assert abs(captured["fail"] - expected_fail) < 1e-6
    # Banner line must mention the scaling so the user knows it kicked in.
    assert "bonferroni" in capsys.readouterr().out.lower()


def test_bonferroni_off_leaves_thresholds_alone(monkeypatch, tmp_path):
    import ctkat.cli as cli_module
    monkeypatch.setattr(cli_module, "generate_and_compile_timing", _stub_compile)

    def fake_run(binary, workdir, timeout):
        from ctkat.dudect_runner import TimingSamples
        s = TimingSamples()
        s.classes = [0, 1] * 50
        s.cycles = [100.0, 110.0] * 50
        s.raw_n_total = 100
        return s
    monkeypatch.setattr(cli_module, "run_timing_harness", fake_run)

    captured = {}

    def fake_welch_with_cropping(c0, c1, warning_threshold, fail_threshold):
        captured["warn"] = warning_threshold
        captured["fail"] = fail_threshold
        from ctkat.statistics import welch_t_test
        return welch_t_test(c0, c1, warning_threshold, fail_threshold)
    monkeypatch.setattr(cli_module, "welch_with_cropping", fake_welch_with_cropping)

    dud = _dud_cfg_with_harness()  # bonferroni_correct=False default
    cli_module._do_dudect(dud, tmp_path, "proj", tmp_path, crop=True)

    assert captured["warn"] == 4.5
    assert captured["fail"] == 10.0


def test_dudect_summary_csv_error_harness_has_zero_raw_counts(tmp_path):
    # S4 + S1 interaction: an ERROR-status harness emits a row with all
    # raw-count columns at 0 (matching default-constructed TimingSamples).
    # Important: the row STILL exists — previously E-1 made the loop
    # `continue` instead of raise, but the CSV must reflect that.
    from ctkat.cli import _emit_dudect_report, _error_welch
    from ctkat.dudect_runner import TimingSamples
    welch = _error_welch()
    _emit_dudect_report(
        "proj", tmp_path,
        [("ok", TimingSamples(classes=[0, 1], cycles=[1.0, 2.0],
                              raw_n_total=10, dropped_zero_n0=1,
                              dropped_zero_n1=0),
          WelchResult(n0=1, n1=1, mean0=1.0, mean1=2.0, var0=0.0, var1=0.0,
                      t_score=0.0, abs_t_score=0.0, status="PASS"), []),
         ("crashed", TimingSamples(), welch, [])],
    )
    rows = (tmp_path / "dudect_summary.csv").read_text().splitlines()[1:]
    by_name = {r.split(",")[1]: r.split(",") for r in rows}
    # Both harnesses present (S4: no row dropped on error).
    assert set(by_name.keys()) == {"ok", "crashed"}
    assert by_name["ok"][17] == "10"
    assert by_name["crashed"][10] == "ERROR"
    assert by_name["crashed"][17] == "0"
    assert by_name["crashed"][18] == "0"
    assert by_name["crashed"][19] == "0"
