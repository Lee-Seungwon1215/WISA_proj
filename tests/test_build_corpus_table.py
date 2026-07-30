"""Tests for scripts/build_corpus_table.py — the corpus merge (locked schema).

Synthetic report CSVs so the merge logic (ct ⨝ asm join, verdict_class
derivation, dudect surfacing, ct_flips) is locked without depending on the
gitignored real reports."""

import csv
import importlib.util
import json
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "build_corpus_table.py"
_spec = importlib.util.spec_from_file_location("build_corpus_table", _SCRIPT)
bct = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bct)


def _write_reports(tmp_path, ctm, varlat, dud, *, asm_manifest=True):
    rep = tmp_path / "reports"
    rep.mkdir(parents=True, exist_ok=True)

    def w(name, fields, rows):
        with open(rep / name, "w", newline="", encoding="utf-8") as f:
            wr = csv.DictWriter(f, fieldnames=fields)
            wr.writeheader()
            for r in rows:
                wr.writerow(r)

    w(
        "ctkat_ct_matrix.csv",
        [
            "project",
            "harness",
            "combo",
            "cc",
            "cflags",
            "valgrind_status",
            "findings",
            "finding_funcs",
            "error",
        ],
        ctm,
    )
    w(
        "ctkat_varlat_candidates.csv",
        [
            "compiler",
            "harness",
            "source_file",
            "function",
            "mnemonics",
            "opt_levels",
            "count",
            "addresses",
            "note",
        ],
        varlat,
    )
    w("dudect_summary.csv", ["project", "harness", "n0", "n1", "abs_t_score", "status"], dud)
    if asm_manifest:
        (rep / "ctkat_varlat_candidates.json").write_text(
            json.dumps(
                {
                    "project": "p",
                    "kind": "varlat_candidates",
                    "warn_only": True,
                    "scanned_opt_levels": sorted(
                        {bct.opt_of(row.get("cflags", "")) for row in ctm}
                    ),
                    "scanned_compilers": sorted({row["cc"] for row in ctm}),
                    "errors": [],
                    "candidates": [],
                    "matrix": [],
                }
            )
        )


def _ctm(harness, combo, cc, cflags, status, findings="0"):
    return {
        "project": "p",
        "harness": harness,
        "combo": combo,
        "cc": cc,
        "cflags": cflags,
        "valgrind_status": status,
        "findings": findings,
        "error": "",
    }


def _vl(harness, cc, func, opts):
    return {
        "compiler": cc,
        "harness": harness,
        "source_file": "x.c",
        "function": func,
        "mnemonics": "div",
        "opt_levels": opts,
        "count": "1",
        "addresses": "",
        "note": "",
    }


def test_opt_of():
    assert bct.opt_of("-O0 -g -fno-inline") == "-O0"
    assert bct.opt_of("-O2 -g -fno-lto") == "-O2"
    assert bct.opt_of("-Os -g") == "-Os"
    assert bct.opt_of("-g -DX") == "-O0"  # no -O -> default -O0


def test_build_robust_with_public_varlat(tmp_path):
    # ct PASS across builds + a div candidate triaged public -> robust, and the
    # dudect WARNING must be surfaced (not hidden).
    _write_reports(
        tmp_path,
        [
            _ctm("kem_dec", "gcc_size", "gcc", "-Os -g", "PASS"),
            _ctm("kem_dec", "gcc_debug", "gcc", "-O0 -g", "PASS"),
        ],
        [_vl("kem_dec", "gcc", "shake128", "-Os")],
        [
            {
                "project": "p",
                "harness": "kem_dec",
                "n0": "100",
                "n1": "100",
                "abs_t_score": "5.470",
                "status": "WARNING",
            }
        ],
    )
    cells, summary = bct.build(
        tmp_path, "ML-KEM", "t", {"gcc": "13.3.0"}, "x86_64", "abc", {"kem_dec": "public"}
    )
    by_combo = {c["combo"]: c for c in cells}
    assert by_combo["gcc_size"]["asm_div_count"] == "1"
    assert by_combo["gcc_size"]["asm_div_funcs"] == "shake128"
    assert by_combo["gcc_debug"]["asm_div_count"] == "0"
    assert by_combo["gcc_size"]["cc_version"] == "13.3.0"

    s = summary[0]
    assert s["legacy_verdict_class"] == "robust"
    assert s["legacy_basis"] == "review"
    assert s["structural"] == "no-finding"
    assert s["asm"] == "candidate"
    assert s["asm_attribution"] == "public"
    # A v1 timing WARNING has no A/A or power calibration, and the public
    # attribution has no review artifact in this synthetic fixture.
    assert s["timing_validity"] == "insufficient-power"
    assert s["review"] == "pending"
    assert s["overall"] == "inconclusive"
    assert s["ct_flips"] == "no"
    assert s["timing_raw_status"] == "WARNING"
    assert "WARNING" in s["notes"]  # surfaced, not hidden


def test_build_flip_is_build_sensitive(tmp_path):
    _write_reports(
        tmp_path,
        [
            _ctm("f", "gcc_debug", "gcc", "-O0 -g", "FAIL", findings="1"),
            _ctm("f", "gcc_release", "gcc", "-O2 -g", "PASS"),
        ],
        [],
        [],
    )
    _cells, summary = bct.build(tmp_path, "syn", "t", {}, "", "", {})
    assert summary[0]["ct_flips"] == "yes"
    assert summary[0]["legacy_verdict_class"] == "build-sensitive-ct"
    assert summary[0]["legacy_basis"] == "auto"
    assert summary[0]["structural"] == "finding"
    assert summary[0]["overall"] == "risk-detected"


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
    assert summary[0]["legacy_verdict_class"] == "ct-clean-untriaged"
    assert summary[0]["legacy_basis"] == "stop"
    assert summary[0]["asm_attribution"] == "unresolved"
    assert summary[0]["review"] == "pending"
    assert summary[0]["overall"] == "needs-review"


def test_build_asm_candidates_are_scoped_by_harness(tmp_path):
    _write_reports(
        tmp_path,
        [
            _ctm("h1", "gcc_o2", "gcc", "-O2", "PASS"),
            _ctm("h2", "gcc_o2", "gcc", "-O2", "PASS"),
        ],
        [_vl("h2", "gcc", "only_h2", "-O2")],
        [],
    )
    cells, summary = bct.build(tmp_path, "f", "t", {}, "", "", {})
    by_harness = {cell["harness"]: cell for cell in cells}
    assert by_harness["h1"]["asm_div_count"] == "0"
    assert by_harness["h2"]["asm_div_funcs"] == "only_h2"
    by_summary = {row["harness"]: row for row in summary}
    assert by_summary["h1"]["asm"] == "no-candidate"
    assert by_summary["h2"]["asm"] == "candidate"


def test_build_preserves_asm_only_optimization_cell(tmp_path):
    _write_reports(
        tmp_path,
        [_ctm("h", "gcc_o0", "gcc", "-O0", "PASS")],
        [_vl("h", "gcc", "optimized_div", "-O2")],
        [],
    )
    manifest = tmp_path / "reports" / "ctkat_varlat_candidates.json"
    payload = json.loads(manifest.read_text())
    payload["scanned_opt_levels"] = ["-O0", "-O2"]
    manifest.write_text(json.dumps(payload))

    cells, summary = bct.build(tmp_path, "f", "t", {}, "", "", {})
    by_combo = {cell["combo"]: cell for cell in cells}
    assert by_combo["asm_only_gcc_O2"]["ct_status"] == "NA"
    assert by_combo["asm_only_gcc_O2"]["asm_div_funcs"] == "optimized_div"
    assert summary[0]["structural"] == "no-finding"
    assert summary[0]["asm"] == "candidate"


def test_build_pass_no_candidates_is_robust(tmp_path):
    # ct PASS with NO asm-scan candidates -> robust (nothing to triage), even
    # without an explicit --triage (regression for the ct-clean-untriaged trap).
    _write_reports(tmp_path, [_ctm("safe", "gcc_debug", "gcc", "-O0", "PASS")], [], [])
    _c, s = bct.build(tmp_path, "syn", "t", {}, "", "", {})
    assert s[0]["legacy_verdict_class"] == "robust"
    assert s[0]["legacy_basis"] == "auto"
    assert s[0]["overall"] == "no-finding-observed"


def test_build_ct_fail_registry_accepted_vs_needs_analysis(tmp_path):
    # registry auto-classify (default-deny): ct FAIL whose leak-site functions are
    # ALL registered -> accepted-variable-time; ANY unregistered -> needs-analysis.
    reg = {"ML-DSA": {"poly_chknorm", "make_hint", "pack_sig"}}

    def _row(funcs):
        return {
            "project": "p",
            "harness": "sign",
            "combo": "gcc_debug",
            "cc": "gcc",
            "cflags": "-O0",
            "valgrind_status": "FAIL",
            "findings": "2",
            "finding_funcs": funcs,
            "error": "",
        }

    # suffix-match against PFX_-prefixed names; all registered -> accepted
    _write_reports(tmp_path, [_row("PFX_poly_chknorm;PFX_make_hint;PFX_pack_sig")], [], [])
    _c, s = bct.build(tmp_path, "ML-DSA", "t", {}, "", "", {}, registry=reg)
    assert s[0]["legacy_verdict_class"] == "accepted-variable-time"
    assert s[0]["legacy_basis"] == "auto"
    assert s[0]["review"] == "pending"
    assert s[0]["overall"] == "needs-review"
    assert "registry" in s[0]["notes"]
    assert "poly_chknorm" in s[0]["ct_finding_funcs"]

    # one unregistered function -> needs-analysis, named in the note (default-deny)
    _write_reports(tmp_path, [_row("PFX_poly_chknorm;PFX_mystery_fn")], [], [])
    _c, s = bct.build(tmp_path, "ML-DSA", "t", {}, "", "", {}, registry=reg)
    assert s[0]["legacy_verdict_class"] == "needs-analysis"
    assert s[0]["legacy_basis"] == "stop"
    assert s[0]["overall"] == "needs-review"
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
    _write_reports(
        tmp_path,
        [
            _ctm("kem_dec", "gcc_o2", "gcc", "-O2 -g", "PASS"),
            _ctm("kem_dec", "clang_o2", "clang", "-O2 -g", "PASS"),
        ],
        [_vl("kem_dec", "gcc", "shake128", "-O2")],  # only gcc produced candidates
        [],
    )
    # asm-scan JSON: gcc scanned OK, clang errored (a source never compiled).
    (tmp_path / "reports" / "ctkat_varlat_candidates.json").write_text(
        json.dumps(
            {
                "project": "p",
                "kind": "varlat_candidates",
                "warn_only": True,
                "scanned_opt_levels": ["-O2"],
                "scanned_compilers": ["gcc"],
                "errors": [
                    {
                        "compiler": "clang",
                        "error": "source(s) never compiled under cc='clang': poly.c",
                    }
                ],
                "candidates": [],
                "matrix": [],
            }
        )
    )
    cells, summary = bct.build(tmp_path, "ML-KEM", "t", {}, "x86_64", "abc", {})
    by_cc = {c["cc"]: c for c in cells}
    assert by_cc["gcc"]["asm_error"] == ""  # scanned OK
    assert "never compiled" in by_cc["clang"]["asm_error"]  # surfaced, not blank
    # and the clang cell is not a misleading clean "0 divisions" with no caveat
    assert by_cc["clang"]["asm_div_count"] == "0"
    assert by_cc["clang"]["asm_error"] != ""
    # N2 (verdict layer, the row a human reads): must NOT be the strongest clean
    # class 'robust' when an asm-scan errored, and must carry a loud caveat note.
    s = summary[0]
    assert s["legacy_verdict_class"] != "robust"
    assert s["legacy_verdict_class"] == "ct-clean-asm-incomplete"
    assert s["asm"] == "incomplete"
    assert s["overall"] == "inconclusive"
    assert "asm-scan incomplete" in s["notes"]


def test_uncovered_asm_compiler_is_not_run_and_incomplete(tmp_path):
    # A matrix compiler outside asm-scan's recorded coverage is not an ERROR,
    # but it is also not a clean zero-candidate result.
    _write_reports(
        tmp_path,
        [
            _ctm("kem_dec", "gcc_o2", "gcc", "-O2 -g", "PASS"),
            _ctm("kem_dec", "clang_o2", "clang", "-O2 -g", "PASS"),
        ],
        [],  # no div candidates at all -> clean
        [],
    )
    # clang is NOT in scanned_compilers and NOT in errors — just not requested.
    (tmp_path / "reports" / "ctkat_varlat_candidates.json").write_text(
        json.dumps(
            {
                "project": "p",
                "kind": "varlat_candidates",
                "warn_only": True,
                "scanned_opt_levels": ["-O2"],
                "scanned_compilers": ["gcc"],
                "errors": [],
                "candidates": [],
                "matrix": [],
            }
        )
    )
    cells, summary = bct.build(tmp_path, "ML-KEM", "t", {}, "x86_64", "abc", {})
    by_cc = {c["cc"]: c for c in cells}
    assert by_cc["gcc"]["asm_status"] == "PASS"
    assert by_cc["clang"]["asm_status"] == "NOT_RUN"
    assert by_cc["clang"]["asm_error"] == ""
    assert summary[0]["legacy_verdict_class"] == "ct-clean-asm-incomplete"
    assert summary[0]["asm"] == "incomplete"
    assert summary[0]["overall"] == "inconclusive"
    assert "not run" in summary[0]["notes"]


def test_asm_error_blank_when_no_asm_json(tmp_path):
    # Backward-compat: no varlat JSON (asm-scan not run / older artifact) -> no
    # spurious asm_error.
    _write_reports(
        tmp_path,
        [_ctm("kem_dec", "gcc_o2", "gcc", "-O2 -g", "PASS")],
        [_vl("kem_dec", "gcc", "shake128", "-O2")],
        [],
        asm_manifest=False,
    )
    cells, _ = bct.build(tmp_path, "ML-KEM", "t", {}, "x86_64", "abc", {})
    assert cells[0]["asm_error"] == ""
    assert cells[0]["asm_status"] == "PASS"  # the candidate row proves this cell ran


def test_missing_asm_coverage_manifest_cannot_claim_no_candidate(tmp_path):
    _write_reports(
        tmp_path,
        [_ctm("safe", "gcc_o2", "gcc", "-O2", "PASS")],
        [],
        [],
        asm_manifest=False,
    )
    cells, summary = bct.build(tmp_path, "syn", "t", {}, "x86_64", "abc", {})
    assert cells[0]["asm_status"] == "NOT_RUN"
    assert summary[0]["asm"] == "not-run"
    assert summary[0]["overall"] == "needs-review"


def test_stale_asm_coverage_manifest_is_rejected(tmp_path):
    _write_reports(
        tmp_path,
        [_ctm("safe", "gcc_o2", "gcc", "-O2", "PASS")],
        [],
        [],
    )
    manifest = tmp_path / "reports" / "ctkat_varlat_candidates.json"
    payload = json.loads(manifest.read_text())
    payload["project"] = "different-project"
    manifest.write_text(json.dumps(payload))
    try:
        bct.build(tmp_path, "syn", "t", {}, "x86_64", "abc", {})
    except ValueError as exc:
        assert "does not match" in str(exc)
    else:
        raise AssertionError("stale asm coverage manifest was accepted")
