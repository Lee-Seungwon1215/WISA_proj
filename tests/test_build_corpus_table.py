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


def test_build_pass_no_candidates_is_robust(tmp_path):
    # ct PASS with NO asm-scan candidates -> robust (nothing to triage), even
    # without an explicit --triage (regression for the ct-clean-untriaged trap).
    _write_reports(tmp_path, [_ctm("safe", "gcc_debug", "gcc", "-O0", "PASS")], [], [])
    _c, s = bct.build(tmp_path, "syn", "t", {}, "", "", {})
    assert s[0]["verdict_class"] == "robust"


def test_build_ct_fail_registry_accepted_vs_needs_analysis(tmp_path):
    # registry auto-classify (default-deny): ct FAIL whose leak-site functions are
    # ALL registered -> accepted-variable-time; ANY unregistered -> needs-analysis.
    reg = {"ML-DSA": {"poly_chknorm", "make_hint"}}

    def _row(funcs):
        return {"project": "p", "harness": "sign", "combo": "gcc_debug", "cc": "gcc",
                "cflags": "-O0", "valgrind_status": "FAIL", "findings": "2",
                "finding_funcs": funcs, "error": ""}

    # suffix-match against PFX_-prefixed names; all registered -> accepted
    _write_reports(tmp_path, [_row("PFX_poly_chknorm;PFX_make_hint")], [], [])
    _c, s = bct.build(tmp_path, "ML-DSA", "t", {}, "", "", {}, registry=reg)
    assert s[0]["verdict_class"] == "accepted-variable-time"
    assert "registry" in s[0]["notes"]
    assert "poly_chknorm" in s[0]["ct_finding_funcs"]

    # one unregistered function -> needs-analysis, named in the note (default-deny)
    _write_reports(tmp_path, [_row("PFX_poly_chknorm;PFX_mystery_fn")], [], [])
    _c, s = bct.build(tmp_path, "ML-DSA", "t", {}, "", "", {}, registry=reg)
    assert s[0]["verdict_class"] == "needs-analysis"
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
