"""Phase C: ct_matrix core (combo expansion, per-cell sweep, artifact writers).

All host-runnable — the real compile+Valgrind path is exercised separately by a
Docker-guarded e2e. Here compile_harness / run_valgrind / classify_valgrind_run
are mocked so the orchestration (status per cell, ERROR-on-compile-fail, sweep
continues) is tested without a toolchain."""

import json
import shutil
import subprocess
import textwrap
from pathlib import Path
from unittest import mock

import pytest
from typer.testing import CliRunner

from ctkat import ct_matrix as m
from ctkat.cli import app
from ctkat.ct_matrix import (
    CT_MATRIX_CSV_FIELDS,
    Combo,
    CtMatrixRow,
    HarnessInputs,
    expand_combos,
    preprocessor_cflags,
    write_ct_matrix_csv,
    write_ct_matrix_json,
)
from ctkat.ct_runner import CtRunOutcome
from ctkat.harness_generator import HarnessGenerationError


# --- expand_combos ----------------------------------------------------------

def test_expand_combos_cartesian_and_dedup():
    combos = expand_combos(["gcc", "clang", "gcc"], {"debug": ["-O0"], "rel": ["-O2"]})
    # gcc de-duped (first-seen order); cflags order follows dict insertion.
    assert [c.label for c in combos] == ["gcc_debug", "gcc_rel", "clang_debug", "clang_rel"]
    assert combos[0].cflags == ("-O0",)
    assert combos[3].cc == "clang"


def test_combo_label():
    assert Combo("gcc", "release", ("-O2",)).label == "gcc_release"


# --- preprocessor_cflags (carry defines/includes into every combo) ----------

def test_preprocessor_cflags_extracts_defines_and_includes():
    flags = ["-O2", "-g", "-fno-inline", "-DFOO=1", "-DBAR", "-Iinc",
             "-isystem", "/sys", "-fno-lto"]
    pp = preprocessor_cflags(flags)
    assert pp == ["-DFOO=1", "-DBAR", "-Iinc", "-isystem", "/sys"]
    # -O/-g/codegen flags are NOT carried — the combo owns those.
    assert "-O2" not in pp and "-g" not in pp and "-fno-inline" not in pp


def test_scan_carries_harness_preprocessor_flags_into_every_combo(tmp_path, monkeypatch):
    # Regression for the dropped-define bug: a `-D...` in the harness cflags must
    # ride into EVERY combo's compile, else the matrix builds a different program
    # than the ct stage.
    seen = []
    monkeypatch.setattr(m, "compile_harness", lambda **k: seen.append(k["cflags"]) or "cmd")
    monkeypatch.setattr(m, "run_valgrind", lambda *a, **k: object())
    monkeypatch.setattr(m, "classify_valgrind_run", lambda *a, **k: CtRunOutcome("PASS"))

    src = tmp_path / "h.c"
    src.write_text("int main(void){return 0;}\n")
    h = HarnessInputs(name="kem", source_path=src, sources=[], include_dirs=[],
                      extra_cflags=["-DPQCLEAN_NO_GLIBC_RANDOMBYTES"])
    combos = expand_combos(["gcc"], {"debug": ["-O0", "-g"], "release": ["-O2"]})
    m.scan_ct_matrix([h], combos, workdir=tmp_path, binaries_dir=tmp_path / "b",
                     valgrind_flags=[], compile_timeout=10, valgrind_timeout=10)
    assert len(seen) == 2
    assert all("-DPQCLEAN_NO_GLIBC_RANDOMBYTES" in cf for cf in seen)
    assert seen[0][0] == "-O0"   # combo opt flags come first, define appended


# --- scan_ct_matrix (mocked) ------------------------------------------------

def _harness(tmp_path):
    src = tmp_path / "h.c"
    src.write_text("int main(void){return 0;}\n")
    return HarnessInputs(name="kem", source_path=src, sources=[], include_dirs=[])


def test_scan_records_status_per_combo(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "compile_harness", lambda **k: "cmd")
    monkeypatch.setattr(m, "run_valgrind", lambda *a, **k: object())
    outcomes = iter([
        CtRunOutcome("PASS"),
        CtRunOutcome("FAIL", findings=[object(), object()]),
        CtRunOutcome("PASS"),
    ])
    monkeypatch.setattr(m, "classify_valgrind_run", lambda *a, **k: next(outcomes))

    combos = expand_combos(["gcc"], {"debug": ["-O0"], "release": ["-O2"], "size": ["-Os"]})
    rows = m.scan_ct_matrix(
        [_harness(tmp_path)], combos,
        workdir=tmp_path, binaries_dir=tmp_path / "b",
        valgrind_flags=["--tool=memcheck"], compile_timeout=10, valgrind_timeout=10,
    )
    assert [r.combo for r in rows] == ["gcc_debug", "gcc_release", "gcc_size"]
    assert [r.valgrind_status for r in rows] == ["PASS", "FAIL", "PASS"]
    assert rows[1].findings == 2


def test_scan_compile_failure_becomes_error_row_and_continues(tmp_path, monkeypatch):
    def fake_compile(**k):
        if k["cc"] == "clang":
            raise HarnessGenerationError("failed to compile harness (clang ...):\nstderr: boom")
        return "cmd"

    monkeypatch.setattr(m, "compile_harness", fake_compile)
    monkeypatch.setattr(m, "run_valgrind", lambda *a, **k: object())
    monkeypatch.setattr(m, "classify_valgrind_run", lambda *a, **k: CtRunOutcome("PASS"))

    combos = expand_combos(["gcc", "clang"], {"debug": ["-O0"]})
    rows = m.scan_ct_matrix(
        [_harness(tmp_path)], combos,
        workdir=tmp_path, binaries_dir=tmp_path / "b",
        valgrind_flags=[], compile_timeout=10, valgrind_timeout=10,
    )
    by_combo = {r.combo: r for r in rows}
    assert by_combo["gcc_debug"].valgrind_status == "PASS"
    # the clang cell failed to build -> ERROR row, but the sweep still produced
    # the gcc cell (one bad build must not abort the matrix).
    assert by_combo["clang_debug"].valgrind_status == "ERROR"
    assert "compile failed" in by_combo["clang_debug"].error
    assert len(rows) == 2


def test_scan_valgrind_error_propagates_as_error_row(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "compile_harness", lambda **k: "cmd")
    monkeypatch.setattr(m, "run_valgrind", lambda *a, **k: object())
    monkeypatch.setattr(
        m, "classify_valgrind_run",
        lambda *a, **k: CtRunOutcome("ERROR", error="valgrind exited with code 124 (timeout)"),
    )
    combos = expand_combos(["gcc"], {"debug": ["-O0"]})
    rows = m.scan_ct_matrix(
        [_harness(tmp_path)], combos,
        workdir=tmp_path, binaries_dir=tmp_path / "b",
        valgrind_flags=[], compile_timeout=10, valgrind_timeout=10,
    )
    assert rows[0].valgrind_status == "ERROR"
    assert "timeout" in rows[0].error


# --- artifact writers -------------------------------------------------------

def test_write_ct_matrix_csv_columns_and_row(tmp_path):
    rows = [CtMatrixRow(harness="kem", combo="gcc_release", cc="gcc",
                        cflags=("-O2", "-g"), valgrind_status="FAIL", findings=2)]
    out = tmp_path / "m.csv"
    write_ct_matrix_csv("proj", rows, out)
    lines = out.read_text().splitlines()
    assert lines[0] == ",".join(CT_MATRIX_CSV_FIELDS)
    assert "gcc_release" in lines[1]
    assert "-O2 -g" in lines[1]      # cflags space-joined
    assert "FAIL" in lines[1]


def test_write_ct_matrix_json_marks_verdict_independent(tmp_path):
    rows = [CtMatrixRow("kem", "gcc_debug", "gcc", ("-O0",), "PASS", 0, "")]
    combos = expand_combos(["gcc", "clang"], {"debug": ["-O0"]})
    out = tmp_path / "m.json"
    write_ct_matrix_json("proj", rows, out, combos=combos, compilers=["gcc", "clang"])
    data = json.loads(out.read_text())
    assert data["kind"] == "ct_matrix"
    assert data["verdict_independent"] is True
    assert data["scanned_compilers"] == ["gcc", "clang"]
    assert data["combos"] == ["gcc_debug", "clang_debug"]
    assert data["rows"][0]["valgrind_status"] == "PASS"


# --- CLI surface (scan mocked: no toolchain / Valgrind needed) ---------------

_MATRIX_YAML = textwrap.dedent(
    """
    project: {name: testproj, language: c, root: .}
    build: {command: "true", workdir: .}
    ct:
      workdir: .
      generated_dir: ./_generated
      harnesses:
        - name: kem_dec
          template: kem
          header: api.h
          prefix: "P_"
          include_dirs: ["."]
          sources: ["foo.c"]
    report: {output_dir: ./reports}
    matrix:
      compilers: [gcc, clang]
      ct_cflags:
        debug: [-O0, -g]
        release: [-O2, -g]
    """
)


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "ctkat.yaml"
    p.write_text(text)
    return p


def test_ct_matrix_cli_writes_artifacts_and_exits_zero(tmp_path):
    yaml_path = _write(tmp_path, _MATRIX_YAML)
    fake_rows = [
        CtMatrixRow("kem_dec", "gcc_debug", "gcc", ("-O0", "-g"), "FAIL", 1, ""),
        CtMatrixRow("kem_dec", "gcc_release", "gcc", ("-O2", "-g"), "PASS", 0, ""),
    ]
    with mock.patch("ctkat.cli.shutil.which", return_value="/usr/bin/tool"), \
         mock.patch("ctkat.cli.render_harness", return_value="// code\n"), \
         mock.patch("ctkat.cli.scan_ct_matrix", return_value=fake_rows) as mscan:
        result = CliRunner().invoke(app, ["ct-matrix", "-c", str(yaml_path)])
    assert result.exit_code == 0, result.stdout
    assert mscan.called
    csv_path = tmp_path / "reports" / "ctkat_ct_matrix.csv"
    json_path = tmp_path / "reports" / "ctkat_ct_matrix.json"
    assert csv_path.exists() and json_path.exists()
    body = csv_path.read_text()
    assert "gcc_debug" in body and "FAIL" in body
    # headline: differing CT results across builds is surfaced loudly.
    assert "DIFFERENT CT results" in result.stdout


def test_ct_matrix_cli_error_cell_not_reported_as_ct_difference(tmp_path):
    # {PASS, ERROR} across builds must NOT print "DIFFERENT CT results" — ERROR
    # is "couldn't measure", not a verdict. It gets its own note instead.
    yaml_path = _write(tmp_path, _MATRIX_YAML)
    rows = [
        CtMatrixRow("kem_dec", "gcc_debug", "gcc", ("-O0",), "PASS", 0, ""),
        CtMatrixRow("kem_dec", "gcc_release", "gcc", ("-O2",), "ERROR", 0, "compile failed: x"),
    ]
    with mock.patch("ctkat.cli.shutil.which", return_value="/usr/bin/tool"), \
         mock.patch("ctkat.cli.render_harness", return_value="// code\n"), \
         mock.patch("ctkat.cli.scan_ct_matrix", return_value=rows):
        result = CliRunner().invoke(app, ["ct-matrix", "-c", str(yaml_path)])
    assert result.exit_code == 0, result.stdout
    assert "DIFFERENT CT results" not in result.stdout
    assert "couldn't measure" in result.stdout       # the ERROR-cell note


def test_ct_matrix_cli_missing_valgrind_exits_2(tmp_path):
    yaml_path = _write(tmp_path, _MATRIX_YAML)

    def which(tool):
        return None if tool == "valgrind" else "/usr/bin/" + tool

    with mock.patch("ctkat.cli.shutil.which", side_effect=which):
        result = CliRunner().invoke(app, ["ct-matrix", "-c", str(yaml_path)])
    assert result.exit_code == 2
    assert "valgrind" in result.stdout and "not found" in result.stdout


def test_ct_matrix_cli_no_template_harness_exits_2(tmp_path):
    yaml = textwrap.dedent(
        """
        project: {name: p, language: c, root: .}
        build: {command: "true", workdir: .}
        ct:
          harnesses:
            - {name: h1, binary: ./bin/h1}
        report: {output_dir: ./reports}
        """
    )
    result = CliRunner().invoke(app, ["ct-matrix", "-c", str(_write(tmp_path, yaml))])
    assert result.exit_code == 2
    assert "no template harnesses" in result.stdout


def test_ct_matrix_cli_no_ct_section_exits_2(tmp_path):
    yaml = textwrap.dedent(
        """
        project: {name: p, language: c, root: .}
        build: {command: "true", workdir: .}
        """
    )
    result = CliRunner().invoke(app, ["ct-matrix", "-c", str(_write(tmp_path, yaml))])
    assert result.exit_code == 2


def test_ct_matrix_cli_all_cells_error_exits_2(tmp_path):
    yaml_path = _write(tmp_path, _MATRIX_YAML)
    all_error = [
        CtMatrixRow("kem_dec", "gcc_debug", "gcc", ("-O0",), "ERROR", 0, "compile failed: x"),
    ]
    with mock.patch("ctkat.cli.shutil.which", return_value="/usr/bin/tool"), \
         mock.patch("ctkat.cli.render_harness", return_value="// code\n"), \
         mock.patch("ctkat.cli.scan_ct_matrix", return_value=all_error):
        result = CliRunner().invoke(app, ["ct-matrix", "-c", str(yaml_path)])
    assert result.exit_code == 2
    assert "every build cell ERROR" in result.stdout


def test_ct_matrix_cli_uses_default_matrix_when_absent(tmp_path):
    # No `matrix:` => default gcc × debug/release/size (3 combos), still runs.
    yaml = textwrap.dedent(
        """
        project: {name: p, language: c, root: .}
        build: {command: "true", workdir: .}
        ct:
          workdir: .
          generated_dir: ./_generated
          harnesses:
            - {name: kem_dec, template: kem, header: api.h, prefix: "P_", include_dirs: ["."], sources: ["foo.c"]}
        report: {output_dir: ./reports}
        """
    )
    captured = {}

    def fake_scan(harnesses, combos, **k):
        captured["combos"] = [c.label for c in combos]
        return [CtMatrixRow("kem_dec", combos[0].label, combos[0].cc, combos[0].cflags, "PASS", 0, "")]

    with mock.patch("ctkat.cli.shutil.which", return_value="/usr/bin/tool"), \
         mock.patch("ctkat.cli.render_harness", return_value="// code\n"), \
         mock.patch("ctkat.cli.scan_ct_matrix", side_effect=fake_scan):
        result = CliRunner().invoke(app, ["ct-matrix", "-c", str(_write(tmp_path, yaml))])
    assert result.exit_code == 0, result.stdout
    assert captured["combos"] == ["gcc_debug", "gcc_release", "gcc_size"]


# --- guarded end-to-end: the Phase C headline flip (real compile + Valgrind) -

def _have_valgrind_and_gnu_gcc() -> bool:
    if shutil.which("valgrind") is None or shutil.which("gcc") is None:
        return False
    try:
        out = subprocess.run(
            ["gcc", "--version"], capture_output=True, text=True, timeout=10
        ).stdout.lower()
    except Exception:
        return False
    return bool(out) and "clang" not in out


_needs_valgrind_gcc = pytest.mark.skipif(
    not _have_valgrind_and_gnu_gcc(),
    reason="needs Valgrind + real GNU gcc (Linux/Docker); the -O0->-O2 CT flip is "
           "gcc-specific and Valgrind doesn't run on macOS",
)

# A secret-dependent select: a conditional jump on tainted data at -O0 (Valgrind
# FAIL), which gcc optimizes into branch-free code at -O2/-Os so Valgrind no
# longer flags it (PASS). Measured on Docker amd64 gcc 13.3 — the empirical
# basis for this test (NOT assumed; cf. the KyberSlash Phase 0 lesson).
_FLIP_BRANCH_C = """\
#include <valgrind/memcheck.h>
int main(void){
    volatile unsigned char secret = 0;
    VALGRIND_MAKE_MEM_UNDEFINED((void*)&secret, 1);
    int r;
    if (secret & 1) r = 0x11; else r = 0x22;   /* secret-dependent control flow */
    volatile int sink = r; (void)sink;
    return 0;
}
"""


@_needs_valgrind_gcc
def test_ct_matrix_secret_branch_flips_fail_O0_to_pass_O2(tmp_path):
    # THE Phase C headline: the SAME source's structural-CT verdict CHANGES with
    # the build configuration — FAIL at -O0, PASS at -O2. This is the evidence
    # that "the binary you tested != the binary you ship" matters for CT.
    src = tmp_path / "flip.c"
    src.write_text(_FLIP_BRANCH_C)
    combos = expand_combos(["gcc"], {"O0": ["-O0", "-g"], "O2": ["-O2", "-g"]})
    rows = m.scan_ct_matrix(
        [HarnessInputs(name="flip", source_path=src, sources=[], include_dirs=[])],
        combos,
        workdir=tmp_path, binaries_dir=tmp_path / "m",
        valgrind_flags=["--tool=memcheck", "--track-origins=yes", "--error-exitcode=99"],
        compile_timeout=60, valgrind_timeout=180,
    )
    by = {r.combo: r.valgrind_status for r in rows}
    assert by["gcc_O0"] == "FAIL", f"secret branch must leak at -O0; got {by}"
    assert by["gcc_O2"] == "PASS", f"gcc should optimize the leak away at -O2; got {by}"
    # the headline, stated as an invariant: NOT the same verdict across builds.
    assert by["gcc_O0"] != by["gcc_O2"]

