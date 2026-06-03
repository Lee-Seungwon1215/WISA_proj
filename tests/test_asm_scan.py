"""Tests for the warn-only multi-opt variable-latency scan (ctkat/asm_scan.py).

Layered so the bulk is deterministic and compiler-free:
  * parse_objdump() — pure text → divisions; covers the mnemonic whitelist
    across x86 / ARM / RISC-V and the FP/mul exclusions (CLAUDE.md §8: the
    corpus must not be just the one reference build).
  * parse_nm() / resolve_functions() — pure symbol-table remapping, so the
    Mach-O `ltmp0`→real-name fix is tested without a Mach-O toolchain.
  * note/row/artifact writers + extract_opt_level — pure, deterministic.
  * `ctkat asm-scan` CLI — driven via CliRunner with scan_harness mocked, so
    the user-visible surface (subcommand, CSV columns, console msg, exit code)
    is exercised without a toolchain (CLAUDE.md §1).
  * Two guarded end-to-end tests actually compile a fixture — skipped when no
    gcc/objdump — asserting the semantic invariant (CLAUDE.md §2): a variable
    divisor is caught, a reciprocal-multiply fix is not. The function-name
    assertion uses `endswith("leak")` so it holds on both ELF (`leak`) and
    Mach-O (resolved from `_leak`).
"""

import shutil
import textwrap
from pathlib import Path
from unittest import mock

import pytest
from typer.testing import CliRunner

from ctkat.asm_scan import (
    AsmScanError,
    Occurrence,
    VarLatCandidate,
    VARLAT_CSV_FIELDS,
    candidate_to_row,
    extract_opt_level,
    parse_nm,
    parse_objdump,
    resolve_functions,
    scan_harness,
    write_varlat_csv,
    write_varlat_json,
)
from ctkat.cli import app


def _cand(function, pairs, *, ct_opt="-O0", harness="h", source="x.c", compiler="gcc"):
    """pairs = [(opt, addr, mnemonic), ...]"""
    return VarLatCandidate(
        harness=harness,
        source_file=source,
        function=function,
        compiler=compiler,
        ct_opt=ct_opt,
        occurrences=[Occurrence(o, a, m) for o, a, m in pairs],
    )


# --- parse_objdump: x86 ------------------------------------------------------

X86_DISASM = """
0000000000000050 <leaky_div>:
  50:\tpush   %rbp
  62:\tidivl  -0x8(%rbp)
  6a:\tret

0000000000000070 <fixed_recip>:
  77:\timul   $0xffffffff9d7dbb41,%rdx,%rdx
  80:\tret

0000000000000090 <fp_div>:
  95:\tdivsd  %xmm1,%xmm0
  99:\tmulsd  %xmm1,%xmm0
  9d:\tret
"""


def test_parse_objdump_finds_x86_idiv_only():
    assert parse_objdump(X86_DISASM) == [("leaky_div", "62", "idivl")]


def test_parse_objdump_excludes_reciprocal_multiply():
    assert all(mnem != "imul" for _f, _a, mnem in parse_objdump(X86_DISASM))


def test_parse_objdump_excludes_sse_fp_divide():
    # `divsd` starts with "div" but is constant-time FP; the `$` anchor keeps it
    # out. A regression here would flood every SSE-using binary.
    assert not any(f == "fp_div" for f, _a, _m in parse_objdump(X86_DISASM))


# --- parse_objdump: multi-arch ----------------------------------------------

MULTIARCH_DISASM = """
0000000000000000 <arm_fn>:
   8:\tsdiv\tw0, w1, w2
   c:\tudiv\tw3, w4, w5
  10:\tmul\tw0, w1, w2

0000000000000020 <riscv_fn>:
  20:\tdiv\ta0,a1,a2
  24:\tdivu\ta3,a4,a5
  28:\trem\ta0,a1,a2
  2c:\tremu\ta3,a4,a5
  30:\tdivuw\ta0,a1,a2
  34:\tmulw\ta3,a4,a5
"""


def test_parse_objdump_multiarch_div_mnemonics():
    mnems = [m for _f, _a, m in parse_objdump(MULTIARCH_DISASM)]
    assert mnems == ["sdiv", "udiv", "div", "divu", "rem", "remu", "divuw"]
    assert "mul" not in mnems and "mulw" not in mnems


def test_parse_objdump_empty_on_no_divisions():
    assert parse_objdump("0000 <f>:\n  0:\tret\n") == []


# --- parse_nm / resolve_functions (Mach-O ltmp0 fix) ------------------------

NM_TEXT = """\
0000000000000000 T _leak
0000000000000000 t ltmp0
0000000000000020 T _other
                 U _imported
"""


def test_parse_nm_prefers_global_strips_underscore():
    # both _leak (global) and ltmp0 (local) sit at addr 0 — global, real name wins.
    assert parse_nm(NM_TEXT) == [(0, "leak"), (32, "other")]


def test_resolve_functions_maps_addr_to_enclosing_symbol():
    # objdump attributed the div to the linker-temp `ltmp0`; the symbol table
    # remaps address 0x8 to the enclosing real function `leak`.
    hits = [("ltmp0", "8", "sdiv")]
    syms = [(0, "leak"), (32, "other")]
    assert resolve_functions(hits, syms) == [("leak", "8", "sdiv")]


def test_resolve_functions_falls_back_without_symbols():
    hits = [("ltmp0", "8", "sdiv")]
    assert resolve_functions(hits, []) == hits


def test_resolve_functions_keeps_real_elf_label():
    # objdump already gave a real function name (ELF): do NOT overwrite it from
    # the symbol table, so a genuine `_foo` is never mangled by underscore-strip.
    hits = [("poly_tomsg", "8", "div")]
    assert resolve_functions(hits, [(0, "wrong_symbol")]) == hits


def test_resolve_functions_resolves_unknown_label():
    assert resolve_functions([("?", "8", "div")], [(0, "leak")]) == [("leak", "8", "div")]


# --- extract_opt_level -------------------------------------------------------

def test_extract_opt_level_picks_last_and_defaults_to_O0():
    assert extract_opt_level(["-O0", "-g", "-fno-inline"]) == "-O0"
    assert extract_opt_level(["-g", "-DX=1"]) == "-O0"          # none -> -O0
    assert extract_opt_level(["-O2", "-g", "-O0"]) == "-O0"     # gcc honours last
    assert extract_opt_level(["-Os"]) == "-Os"


# --- note / row logic --------------------------------------------------------

def test_note_flags_optimized_only_as_ct_stage_miss():
    row = candidate_to_row(_cand("poly_tomsg", [("-Os", "222", "div")], ct_opt="-O0"))
    assert "absent at the ct stage's -O0" in row["note"]
    assert "would miss" in row["note"]


def test_note_uses_actual_ct_opt_not_hardcoded_O0():
    # ct.cflags = -O2 case: the note must talk about -O2, not a hardcoded -O0.
    row = candidate_to_row(_cand("f", [("-Os", "10", "idiv")], ct_opt="-O2"))
    assert "-O2" in row["note"] and "-O0" not in row["note"]


def test_note_when_division_present_at_ct_opt():
    row = candidate_to_row(_cand("f", [("-O0", "10", "idiv")], ct_opt="-O0"))
    assert "even at the ct stage's -O0" in row["note"]


def test_candidate_row_has_count_and_addresses():
    c = _cand("f", [("-O0", "10", "idiv"), ("-O2", "20", "div"), ("-Os", "30", "div")])
    row = candidate_to_row(c)
    assert row["mnemonics"] == "div;idiv"
    assert row["opt_levels"] == "-O0;-O2;-Os"
    assert row["count"] == "3"
    assert row["addresses"] == "-O0@0x10;-O2@0x20;-Os@0x30"


def test_candidate_row_carries_compiler():
    # the compiler dimension (Phase B) must reach the row; default is gcc.
    assert candidate_to_row(_cand("f", [("-Os", "10", "div")]))["compiler"] == "gcc"
    row = candidate_to_row(_cand("f", [("-Os", "10", "div")], compiler="clang"))
    assert row["compiler"] == "clang"


def test_note_is_compiler_aware_and_conditionalizes_miss():
    # SEMANTIC INVARIANT (CLAUDE.md §2/§4): a division found only under `clang`
    # must NOT assert the (possibly gcc) ct/Valgrind stage misses it — the claim
    # is conditioned on the ct build using the same compiler.
    note = candidate_to_row(
        _cand("poly_tomsg", [("-Os", "222", "div")], ct_opt="-O0", compiler="clang")
    )["note"]
    assert "clang" in note
    assert "if the ct build also uses clang" in note
    # the unconditional old phrasing ("the ct/Valgrind stage would miss") must
    # never stand alone without the compiler-match condition in front of it.
    assert note.index("if the ct build also uses clang") < note.index("would miss")


# --- artifact writers --------------------------------------------------------

def test_write_varlat_csv_columns_and_rows(tmp_path: Path):
    cands = [_cand("poly_tomsg", [("-Os", "222", "div")], harness="kem_dec", source="clean/poly.c")]
    out = tmp_path / "ctkat_varlat_candidates.csv"
    write_varlat_csv(cands, out)
    lines = out.read_text().splitlines()
    assert lines[0] == ",".join(VARLAT_CSV_FIELDS)
    assert "poly_tomsg" in lines[1] and "-Os" in lines[1]
    assert "count" in lines[0] and "addresses" in lines[0]


def test_write_varlat_json_marks_warn_only(tmp_path: Path):
    import json

    cands = [_cand("poly_tomsg", [("-Os", "222", "div")], harness="kem_dec", source="clean/poly.c")]
    out = tmp_path / "v.json"
    write_varlat_json("proj", cands, out, opt_levels=("-O0", "-Os", "-O2"))
    data = json.loads(out.read_text())
    assert data["warn_only"] is True
    assert data["kind"] == "varlat_candidates"
    assert data["scanned_opt_levels"] == ["-O0", "-Os", "-O2"]
    assert data["candidates"][0]["function"] == "poly_tomsg"


def test_write_varlat_json_has_matrix_compilers_and_errors(tmp_path: Path):
    import json

    cands = [
        _cand("poly_tomsg", [("-Os", "222", "div")], source="clean/poly.c", compiler="gcc"),
        _cand("poly_tomsg", [("-O0", "40", "idiv"), ("-Os", "222", "idiv")],
              source="clean/poly.c", compiler="clang"),
    ]
    out = tmp_path / "v.json"
    write_varlat_json(
        "proj", cands, out,
        opt_levels=("-O0", "-Os", "-O2"),
        compilers=("gcc", "clang"),
        errors=[{"compiler": "icc", "error": "compiler not found on PATH"}],
    )
    data = json.loads(out.read_text())
    assert data["scanned_compilers"] == ["gcc", "clang"]
    assert data["errors"] == [{"compiler": "icc", "error": "compiler not found on PATH"}]
    # normalized matrix: one row per (compiler, opt, source, function, mnemonic),
    # so a script can compare which compiler x opt kept a division alive.
    m = data["matrix"]
    assert {"compiler": "gcc", "opt": "-Os", "source_file": "clean/poly.c",
            "function": "poly_tomsg", "mnemonic": "div", "count": 1} in m
    assert {"compiler": "clang", "opt": "-O0", "source_file": "clean/poly.c",
            "function": "poly_tomsg", "mnemonic": "idiv", "count": 1} in m
    gcc_opts = sorted(r["opt"] for r in m if r["compiler"] == "gcc")
    clang_opts = sorted(r["opt"] for r in m if r["compiler"] == "clang")
    assert gcc_opts == ["-Os"] and clang_opts == ["-O0", "-Os"]


# --- CLI smoke (scan mocked: no toolchain needed) ----------------------------

_MIN_YAML = textwrap.dedent(
    """
    project:
      name: testproj
      language: c
      root: .
    build:
      command: "true"
      workdir: .
    ct:
      workdir: .
      generated_dir: ./_generated
      harnesses:
        - name: h1
          template: kem
          header: api.h
          prefix: "P_"
          include_dirs: ["."]
          sources: ["foo.c"]
    report:
      output_dir: ./reports
    """
)


def _write_min_yaml(tmp_path: Path) -> Path:
    p = tmp_path / "ctkat.yaml"
    p.write_text(_MIN_YAML)
    return p


def test_asm_scan_cli_writes_artifact_and_exits_zero(tmp_path: Path):
    yaml_path = _write_min_yaml(tmp_path)
    fake = [_cand("leaky", [("-Os", "222", "div")], harness="h1", source="foo.c")]
    # mock which() so the test doesn't depend on gcc/objdump being installed.
    with mock.patch("ctkat.cli.shutil.which", return_value="/usr/bin/tool"), \
         mock.patch("ctkat.cli.scan_harness", return_value=fake) as m:
        result = CliRunner().invoke(app, ["asm-scan", "-c", str(yaml_path)])
    assert result.exit_code == 0, result.stdout
    assert m.called
    csv_path = tmp_path / "reports" / "ctkat_varlat_candidates.csv"
    json_path = tmp_path / "reports" / "ctkat_varlat_candidates.json"
    assert csv_path.exists() and json_path.exists()
    body = csv_path.read_text()
    assert "leaky" in body and "-Os" in body
    assert "candidate" in result.stdout
    assert "warn-only" in result.stdout or "NOT proven" in result.stdout


def test_asm_scan_cli_includes_ct_opt_and_custom_opts(tmp_path: Path):
    yaml_path = _write_min_yaml(tmp_path)
    with mock.patch("ctkat.cli.shutil.which", return_value="/usr/bin/clang"), \
         mock.patch("ctkat.cli.scan_harness", return_value=[]) as m:
        result = CliRunner().invoke(
            app, ["asm-scan", "-c", str(yaml_path), "--opt", "-O3", "--cc", "clang"]
        )
    assert result.exit_code == 0
    # ct stage default cflags are -O0, so -O0 is prepended to the -O3 the user asked for.
    assert m.call_args.kwargs["opt_levels"] == ("-O0", "-O3")
    assert m.call_args.kwargs["cc"] == "clang"


def test_asm_scan_cli_missing_compiler_exits_2(tmp_path: Path):
    # Fail-closed: a missing toolchain is a config error (exit 2), NOT a clean
    # "no candidates" exit 0. Regression guard for the --cc clang traceback.
    yaml_path = _write_min_yaml(tmp_path)
    result = CliRunner().invoke(
        app, ["asm-scan", "-c", str(yaml_path), "--cc", "definitely-not-a-compiler-xyz"]
    )
    assert result.exit_code == 2
    assert "not found" in result.stdout


def test_asm_scan_cli_disasm_error_exits_2(tmp_path: Path):
    # `--cc true`-style case: passes the which() preflight but objdump later
    # fails (no object produced). AsmScanError must be caught → clean exit 2,
    # not an escaping traceback (exit 1).
    yaml_path = _write_min_yaml(tmp_path)
    with mock.patch("ctkat.cli.shutil.which", return_value="/usr/bin/tool"), \
         mock.patch("ctkat.cli.scan_harness", side_effect=AsmScanError("objdump failed: boom")):
        result = CliRunner().invoke(app, ["asm-scan", "-c", str(yaml_path)])
    assert result.exit_code == 2
    assert "disassembly failed" in result.stdout


def test_asm_scan_cli_no_ct_section_exits_2(tmp_path: Path):
    p = tmp_path / "ctkat.yaml"
    p.write_text(textwrap.dedent(
        """
        project: {name: p, language: c, root: .}
        build: {command: "true", workdir: .}
        """
    ))
    result = CliRunner().invoke(app, ["asm-scan", "-c", str(p)])
    assert result.exit_code == 2


def test_asm_scan_cli_multiple_compilers_recorded(tmp_path: Path):
    # --cc gcc --cc clang scans each compiler: both appear in the artifact and in
    # JSON scanned_compilers, one scan_harness call per (compiler, harness).
    import json

    yaml_path = _write_min_yaml(tmp_path)

    def fake_scan(*_a, **k):
        cc = k["cc"]
        return [_cand("leaky", [("-Os", "222", "div")], harness="h1",
                      source="foo.c", compiler=cc)]

    with mock.patch("ctkat.cli.shutil.which", return_value="/usr/bin/tool"), \
         mock.patch("ctkat.cli.scan_harness", side_effect=fake_scan) as m:
        result = CliRunner().invoke(
            app, ["asm-scan", "-c", str(yaml_path), "--cc", "gcc", "--cc", "clang"]
        )
    assert result.exit_code == 0, result.stdout
    assert m.call_count == 2  # one harness x two compilers
    body = (tmp_path / "reports" / "ctkat_varlat_candidates.csv").read_text()
    assert "gcc" in body and "clang" in body
    data = json.loads((tmp_path / "reports" / "ctkat_varlat_candidates.json").read_text())
    assert data["scanned_compilers"] == ["gcc", "clang"]
    assert data["errors"] == []


def _which_only(*present):
    have = set(present)

    def which(tool):
        return ("/usr/bin/" + tool) if tool in have else None

    return which


def test_asm_scan_cli_partial_missing_compiler_continues(tmp_path: Path):
    # Decision (D1): a missing requested compiler is SKIPPED + recorded as ERROR,
    # the scan continues with the available ones, exit 0 (warn-only, PARTIAL).
    # gcc + objdump present, clang absent.
    import json

    yaml_path = _write_min_yaml(tmp_path)
    fake = [_cand("leaky", [("-Os", "222", "div")], harness="h1", source="foo.c")]
    with mock.patch("ctkat.cli.shutil.which", side_effect=_which_only("gcc", "objdump", "nm")), \
         mock.patch("ctkat.cli.scan_harness", return_value=fake) as m:
        result = CliRunner().invoke(
            app, ["asm-scan", "-c", str(yaml_path), "--cc", "gcc", "--cc", "clang"]
        )
    assert result.exit_code == 0, result.stdout
    assert m.call_count == 1  # only gcc ran
    assert "clang" in result.stdout and "skipped" in result.stdout
    data = json.loads((tmp_path / "reports" / "ctkat_varlat_candidates.json").read_text())
    assert data["scanned_compilers"] == ["gcc"]
    assert data["errors"] == [{"compiler": "clang", "error": "compiler not found on PATH"}]


def test_asm_scan_cli_all_requested_compilers_missing_exits_2(tmp_path: Path):
    # objdump present but BOTH requested compilers absent -> nothing to scan ->
    # hard exit 2 (a green empty result would be a lie).
    yaml_path = _write_min_yaml(tmp_path)
    with mock.patch("ctkat.cli.shutil.which", side_effect=_which_only("objdump", "nm")):
        result = CliRunner().invoke(
            app, ["asm-scan", "-c", str(yaml_path), "--cc", "gccx", "--cc", "clangx"]
        )
    assert result.exit_code == 2
    assert "not found" in result.stdout


_TWO_HARNESS_YAML = textwrap.dedent(
    """
    project: {name: testproj, language: c, root: .}
    build: {command: "true", workdir: .}
    ct:
      workdir: .
      generated_dir: ./_generated
      harnesses:
        - {name: h1, template: kem, header: api.h, prefix: "P_", include_dirs: ["."], sources: ["foo.c"]}
        - {name: h2, template: kem, header: api.h, prefix: "P_", include_dirs: ["."], sources: ["bar.c"]}
    report: {output_dir: ./reports}
    """
)


def test_asm_scan_cli_failed_compiler_discards_partial_candidates(tmp_path: Path):
    # A compiler that succeeds on h1 but errors on h2 must contribute NOTHING:
    # its partial h1 candidates are discarded and it is absent from
    # scanned_compilers (it only appears in errors). A healthy compiler still
    # produces full results. This is the regression the per-compiler-atomic merge
    # fixes — with a single harness the old code looked fine, so two are needed.
    import json

    p = tmp_path / "ctkat.yaml"
    p.write_text(_TWO_HARNESS_YAML)

    def fake_scan(*_a, **k):
        if k["cc"] == "gcc" and k["harness"] == "h2":
            raise AsmScanError("objdump failed: boom")  # gcc dies AFTER h1 succeeded
        return [_cand("leaky", [("-Os", "222", "div")], harness=k["harness"],
                      source="foo.c", compiler=k["cc"])]

    with mock.patch("ctkat.cli.shutil.which", return_value="/usr/bin/tool"), \
         mock.patch("ctkat.cli.scan_harness", side_effect=fake_scan):
        result = CliRunner().invoke(
            app, ["asm-scan", "-c", str(p), "--cc", "gcc", "--cc", "clang"]
        )
    assert result.exit_code == 0, result.stdout
    data = json.loads((tmp_path / "reports" / "ctkat_varlat_candidates.json").read_text())
    assert data["scanned_compilers"] == ["clang"]           # gcc dropped entirely
    assert [e["compiler"] for e in data["errors"]] == ["gcc"]
    # NO gcc rows survive (its partial h1 candidate was discarded); clang ran both.
    assert {c["compiler"] for c in data["candidates"]} == {"clang"}
    assert sorted(c["harness"] for c in data["candidates"]) == ["h1", "h2"]


# --- guarded end-to-end (real compile) --------------------------------------

_HAVE_TOOLCHAIN = shutil.which("gcc") is not None and shutil.which("objdump") is not None
_needs_cc = pytest.mark.skipif(not _HAVE_TOOLCHAIN, reason="gcc/objdump not available")


@_needs_cc
def test_scan_detects_variable_divisor(tmp_path: Path):
    # `s / d` with a runtime divisor cannot be strength-reduced — it is a real
    # `idiv`/`sdiv` on every compiler and opt level (the one robust cell from
    # the Phase 0 matrix, §8.7). Compiler-independent, so this is safe to assert.
    src = tmp_path / "pos.c"
    src.write_text("int leak(int s, int d) { return s / d; }\n")
    cands = scan_harness(
        harness="t",
        sources=[src],
        source_display=["pos.c"],
        include_dirs=[],
        base_cflags=["-g"],
        workdir=tmp_path,
        opt_levels=("-O0", "-O2"),
        timeout=60,
    )
    leaks = [c for c in cands if c.function.endswith("leak")]
    assert leaks, f"no 'leak' candidate (symbol resolution?); got {[c.function for c in cands]}"
    assert leaks[0].mnemonics  # at least one division mnemonic
    assert leaks[0].count >= 1


@_needs_cc
def test_scan_ignores_reciprocal_multiply_fix(tmp_path: Path):
    # The ML-KEM fix shape (`* recip >> shift`) has no division at any opt — the
    # negative control. A regression flagging this would break CI on every
    # fixed implementation.
    src = tmp_path / "neg.c"
    src.write_text("unsigned safe(unsigned x){ x *= 80635u; x >>= 28; return x & 1; }\n")
    cands = scan_harness(
        harness="t",
        sources=[src],
        source_display=["neg.c"],
        include_dirs=[],
        base_cflags=["-g"],
        workdir=tmp_path,
        opt_levels=("-O0", "-Os", "-O2"),
        timeout=60,
    )
    assert cands == []
