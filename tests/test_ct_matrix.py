"""Phase C: ct_matrix core (combo expansion, per-cell sweep, artifact writers).

All host-runnable — the real compile+Valgrind path is exercised separately by a
Docker-guarded e2e. Here compile_harness / run_valgrind / classify_valgrind_run
are mocked so the orchestration (status per cell, ERROR-on-compile-fail, sweep
continues) is tested without a toolchain."""

import json
import textwrap
from pathlib import Path
from unittest import mock

from typer.testing import CliRunner

from ctkat import ct_matrix as m
from ctkat.cli import app
from ctkat.ct_matrix import (
    CT_MATRIX_CSV_FIELDS,
    Combo,
    CtMatrixRow,
    HarnessInputs,
    expand_combos,
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
