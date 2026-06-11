"""Tests for scripts/build_corpus_table.py — the corpus merge (locked schema).

Synthetic report CSVs so the merge logic (ct ⨝ asm join, verdict_class
derivation, dudect surfacing, ct_flips) is locked without depending on the
gitignored real reports."""

import csv
import importlib.util
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "build_corpus_table.py"
_spec = importlib.util.spec_from_file_location("build_corpus_table", _SCRIPT)
bct = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bct)


def _write_reports(tmp_path, ctm, varlat, dud):
    rep = tmp_path / "reports"
    rep.mkdir(parents=True, exist_ok=True)

    def w(name, fields, rows):
        with open(rep / name, "w", newline="", encoding="utf-8") as f:
            wr = csv.DictWriter(f, fieldnames=fields)
            wr.writeheader()
            for r in rows:
                wr.writerow(r)

    w("ctkat_ct_matrix.csv",
      ["project", "harness", "combo", "cc", "cflags", "valgrind_status", "findings",
       "finding_funcs", "error"], ctm)
    w("ctkat_varlat_candidates.csv",
      ["compiler", "harness", "source_file", "function", "mnemonics", "opt_levels", "count", "addresses", "note"], varlat)
    w("dudect_summary.csv",
      ["project", "harness", "n0", "n1", "abs_t_score", "status"], dud)


def _ctm(harness, combo, cc, cflags, status, findings="0"):
    return {"project": "p", "harness": harness, "combo": combo, "cc": cc,
            "cflags": cflags, "valgrind_status": status, "findings": findings, "error": ""}


def _vl(harness, cc, func, opts):
    return {"compiler": cc, "harness": harness, "source_file": "x.c", "function": func,
            "mnemonics": "div", "opt_levels": opts, "count": "1", "addresses": "", "note": ""}


def test_opt_of():
    assert bct.opt_of("-O0 -g -fno-inline") == "-O0"
    assert bct.opt_of("-O2 -g -fno-lto") == "-O2"
    assert bct.opt_of("-Os -g") == "-Os"
    assert bct.opt_of("-g -DX") == "-O0"   # no -O -> default -O0


def test_build_robust_with_public_varlat(tmp_path):
    # ct PASS across builds + a div candidate triaged public -> robust, and the
    # dudect WARNING must be surfaced (not hidden).
    _write_reports(
        tmp_path,
        [_ctm("kem_dec", "gcc_size", "gcc", "-Os -g", "PASS"),
         _ctm("kem_dec", "gcc_debug", "gcc", "-O0 -g", "PASS")],
        [_vl("kem_dec", "gcc", "shake128", "-Os")],
        [{"project": "p", "harness": "kem_dec", "n0": "100", "n1": "100",
          "abs_t_score": "5.470", "status": "WARNING"}],
    )
    cells, summary = bct.build(tmp_path, "ML-KEM", "t", {"gcc": "13.3.0"}, "x86_64", "abc",
                              {"kem_dec": "public"})
    by_combo = {c["combo"]: c for c in cells}
    assert by_combo["gcc_size"]["asm_div_count"] == "1"
    assert by_combo["gcc_size"]["asm_div_funcs"] == "shake128"
    assert by_combo["gcc_debug"]["asm_div_count"] == "0"
    assert by_combo["gcc_size"]["cc_version"] == "13.3.0"

    s = summary[0]
    assert s["verdict_class"] == "robust"
    assert s["basis"] == "review"
    assert s["ct_flips"] == "no"
    assert s["dudect_status"] == "WARNING"
    assert "WARNING" in s["notes"]            # surfaced, not hidden


def test_build_flip_is_build_sensitive(tmp_path):
    _write_reports(
        tmp_path,
        [_ctm("f", "gcc_debug", "gcc", "-O0 -g", "FAIL", findings="1"),
         _ctm("f", "gcc_release", "gcc", "-O2 -g", "PASS")],
        [], [],
    )
    _cells, summary = bct.build(tmp_path, "syn", "t", {}, "", "", {})
    assert summary[0]["ct_flips"] == "yes"
    assert summary[0]["verdict_class"] == "build-sensitive-ct"
    assert summary[0]["basis"] == "auto"


def test_build_untriaged_is_the_honest_default(tmp_path):
    # ct PASS but a candidate exists and was NOT triaged -> ct-clean-untriaged
    # (NOT robust). This is the trap the locked taxonomy exists to avoid.
    _write_reports(
        tmp_path,
        [_ctm("h", "gcc_size", "gcc", "-Os", "PASS")],
        [_vl("h", "gcc", "foo", "-Os")],
        [],
    )
    _cells, summary = bct.build(tmp_path, "f", "t", {}, "", "", {})  # no --triage
    assert summary[0]["varlat_triage"] == "untriaged"
    assert summary[0]["verdict_class"] == "ct-clean-untriaged"
    assert summary[0]["basis"] == "stop"


def test_build_pass_no_candidates_is_robust(tmp_path):
    # ct PASS with NO asm-scan candidates -> robust (nothing to triage), even
    # without an explicit --triage (regression for the ct-clean-untriaged trap).
    _write_reports(tmp_path, [_ctm("safe", "gcc_debug", "gcc", "-O0", "PASS")], [], [])
    _c, s = bct.build(tmp_path, "syn", "t", {}, "", "", {})
    assert s[0]["verdict_class"] == "robust"
    assert s[0]["basis"] == "auto"


def test_build_ct_fail_registry_accepted_vs_needs_analysis(tmp_path):
    # registry auto-classify (default-deny): ct FAIL whose leak-site functions are
    # ALL registered -> accepted-variable-time; ANY unregistered -> needs-analysis.
    reg = {"ML-DSA": {"poly_chknorm", "make_hint", "pack_sig"}}

    def _row(funcs):
        return {"project": "p", "harness": "sign", "combo": "gcc_debug", "cc": "gcc",
                "cflags": "-O0", "valgrind_status": "FAIL", "findings": "2",
                "finding_funcs": funcs, "error": ""}

    # suffix-match against PFX_-prefixed names; all registered -> accepted
    _write_reports(tmp_path, [_row("PFX_poly_chknorm;PFX_make_hint;PFX_pack_sig")], [], [])
    _c, s = bct.build(tmp_path, "ML-DSA", "t", {}, "", "", {}, registry=reg)
    assert s[0]["verdict_class"] == "accepted-variable-time"
    assert s[0]["basis"] == "auto"
    assert "registry" in s[0]["notes"]
    assert "poly_chknorm" in s[0]["ct_finding_funcs"]

    # one unregistered function -> needs-analysis, named in the note (default-deny)
    _write_reports(tmp_path, [_row("PFX_poly_chknorm;PFX_mystery_fn")], [], [])
    _c, s = bct.build(tmp_path, "ML-DSA", "t", {}, "", "", {}, registry=reg)
    assert s[0]["verdict_class"] == "needs-analysis"
    assert s[0]["basis"] == "stop"
    assert "mystery_fn" in s[0]["notes"]


def test_merge_write_is_idempotent_per_target(tmp_path):
    fields = ["target", "x"]
    rows_a = [{"target": "A", "x": "1"}]
    bct.merge_write(tmp_path, "A", rows_a, fields, "t.csv")
    bct.merge_write(tmp_path, "B", [{"target": "B", "x": "2"}], fields, "t.csv")
    # re-running A replaces A's rows, keeps B
    bct.merge_write(tmp_path, "A", [{"target": "A", "x": "9"}], fields, "t.csv")
    with open(tmp_path / "t.csv", newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    by_t = {r["target"]: r["x"] for r in rows}
    assert by_t == {"A": "9", "B": "2"}
    assert len(rows) == 2


def test_asm_error_from_varlat_json_is_surfaced(tmp_path):
    # N2: a compiler whose asm-scan errored (e.g. a source never compiled) must
    # NOT show a clean "0 divisions" — its asm_error must be surfaced in the
    # corpus cell. Before the fix asm_error was hardcoded "", so a partial scan
    # looked identical to a complete clean one.
    import json
    _write_reports(
        tmp_path,
        [_ctm("kem_dec", "gcc_o2", "gcc", "-O2 -g", "PASS"),
         _ctm("kem_dec", "clang_o2", "clang", "-O2 -g", "PASS")],
        [_vl("kem_dec", "gcc", "shake128", "-O2")],   # only gcc produced candidates
        [],
    )
    # asm-scan JSON: gcc scanned OK, clang errored (a source never compiled).
    (tmp_path / "reports" / "ctkat_varlat_candidates.json").write_text(json.dumps({
        "project": "p", "kind": "varlat_candidates", "warn_only": True,
        "scanned_opt_levels": ["-O2"], "scanned_compilers": ["gcc"],
        "errors": [{"compiler": "clang",
                    "error": "source(s) never compiled under cc='clang': poly.c"}],
        "candidates": [], "matrix": [],
    }))
    cells, summary = bct.build(tmp_path, "ML-KEM", "t", {}, "x86_64", "abc", {})
    by_cc = {c["cc"]: c for c in cells}
    assert by_cc["gcc"]["asm_error"] == ""                       # scanned OK
    assert "never compiled" in by_cc["clang"]["asm_error"]       # surfaced, not blank
    # and the clang cell is not a misleading clean "0 divisions" with no caveat
    assert by_cc["clang"]["asm_div_count"] == "0"
    assert by_cc["clang"]["asm_error"] != ""
    # N2 (verdict layer, the row a human reads): must NOT be the strongest clean
    # class 'robust' when an asm-scan errored, and must carry a loud caveat note.
    s = summary[0]
    assert s["verdict_class"] != "robust"
    assert s["verdict_class"] == "ct-clean-asm-incomplete"
    assert "asm-scan incomplete" in s["notes"]


def test_asm_error_not_flagged_for_uncovered_compiler(tmp_path):
    # Review issue #4: a matrix compiler that simply wasn't in asm-scan's --cc
    # set (the common matrix={gcc,clang} / asm-scan=gcc-only flow) is a COVERAGE
    # choice, not an error — it must NOT be labeled asm_error nor downgrade the
    # verdict. asm_error is reserved for genuine asm-scan errors (schema-locked).
    import json
    _write_reports(
        tmp_path,
        [_ctm("kem_dec", "gcc_o2", "gcc", "-O2 -g", "PASS"),
         _ctm("kem_dec", "clang_o2", "clang", "-O2 -g", "PASS")],
        [],   # no div candidates at all -> clean
        [],
    )
    # clang is NOT in scanned_compilers and NOT in errors — just not requested.
    (tmp_path / "reports" / "ctkat_varlat_candidates.json").write_text(json.dumps({
        "project": "p", "kind": "varlat_candidates", "warn_only": True,
        "scanned_opt_levels": ["-O2"], "scanned_compilers": ["gcc"],
        "errors": [], "candidates": [], "matrix": [],
    }))
    cells, summary = bct.build(tmp_path, "ML-KEM", "t", {}, "x86_64", "abc", {})
    by_cc = {c["cc"]: c for c in cells}
    assert by_cc["clang"]["asm_error"] == ""   # not an error — just not requested
    # a not-requested compiler must NOT downgrade the verdict: no genuine asm
    # error -> the ct-PASS / no-candidate harness stays 'robust'.
    assert summary[0]["verdict_class"] == "robust"


def test_asm_error_blank_when_no_asm_json(tmp_path):
    # Backward-compat: no varlat JSON (asm-scan not run / older artifact) -> no
    # spurious asm_error.
    _write_reports(
        tmp_path,
        [_ctm("kem_dec", "gcc_o2", "gcc", "-O2 -g", "PASS")],
        [_vl("kem_dec", "gcc", "shake128", "-O2")],
        [],
    )
    cells, _ = bct.build(tmp_path, "ML-KEM", "t", {}, "x86_64", "abc", {})
    assert cells[0]["asm_error"] == ""
