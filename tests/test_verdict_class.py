"""Bundle R (Phase 1): lock every branch of the extracted verdict_class
classifier DIRECTLY. Before extraction this taxonomy was only tested indirectly
through scripts/build_corpus_table.py; now `ctkat screen` and the corpus builder
share this code, so each branch + its note phrasing gets a direct test."""

from ctkat.verdict_class import (
    CLEAN_CLASSES,
    VERDICT_CLASSES,
    classify_harness,
    opt_of,
    summarize,
)

REG = {"ML-DSA": {"poly_chknorm", "make_hint"}}


def _cell(status, *, cc="gcc", opt="-O0", div="0", asm_error="", funcs=""):
    return {
        "ct_status": status, "cc": cc, "opt": opt,
        "asm_div_count": div, "asm_error": asm_error, "ct_finding_funcs": funcs,
    }


def test_robust_clean_no_candidates():
    vc, notes = classify_harness([_cell("PASS")], family="X")
    assert vc == "robust"
    assert notes == ""


def test_robust_candidates_triaged_public():
    vc, _ = classify_harness([_cell("PASS", div="1")], family="X", triage="public")
    assert vc == "robust"


def test_ct_clean_untriaged_when_candidate_present():
    vc, notes = classify_harness([_cell("PASS", div="2")], family="X", triage="untriaged")
    assert vc == "ct-clean-untriaged"
    assert "not yet triaged" in notes


def test_ct_clean_asm_incomplete_on_asm_error():
    vc, notes = classify_harness(
        [_cell("PASS", asm_error="source(s) never compiled under cc='clang': poly.c", cc="clang")],
        family="X",
    )
    assert vc == "ct-clean-asm-incomplete"
    assert "asm-scan incomplete" in notes


def test_varlat_secret_risk():
    vc, _ = classify_harness([_cell("PASS", div="1")], family="X", triage="secret-risk")
    assert vc == "varlat-secret-risk"


def test_build_sensitive_ct_on_status_flip():
    # same harness, PASS in one build cell and FAIL in another -> build-sensitive.
    vc, _ = classify_harness([_cell("PASS"), _cell("FAIL")], family="X")
    assert vc == "build-sensitive-ct"


def test_accepted_variable_time_when_all_funcs_registered():
    vc, notes = classify_harness(
        [_cell("FAIL", funcs="PQCLEAN_MLDSA65_CLEAN_poly_chknorm;PQCLEAN_MLDSA65_CLEAN_make_hint")],
        family="ML-DSA", registry=REG,
    )
    assert vc == "accepted-variable-time"
    assert "registry" in notes


def test_needs_analysis_on_unregistered_func():
    vc, notes = classify_harness(
        [_cell("FAIL", funcs="PFX_poly_chknorm;PFX_mystery_leak")],
        family="ML-DSA", registry=REG,
    )
    assert vc == "needs-analysis"
    assert "mystery_leak" in notes          # the unregistered func is named


def test_needs_analysis_when_no_registry():
    # default-deny: without a matching family/registry, a ct FAIL is needs-analysis,
    # never auto-accepted (the safe direction for `screen` when --family is absent).
    vc, _ = classify_harness([_cell("FAIL", funcs="PFX_poly_chknorm")], family="X")
    assert vc == "needs-analysis"


def test_tool_problem_when_only_error():
    vc, _ = classify_harness([_cell("ERROR")], family="X")
    assert vc == "tool-problem"


def test_verdict_override_wins():
    vc, _ = classify_harness([_cell("PASS")], family="X", verdict_override="ct-leak")
    assert vc == "ct-leak"


def test_note_override_appended():
    _vc, notes = classify_harness([_cell("PASS")], family="X", note_override="manual note here")
    assert "manual note here" in notes


def test_dudect_warning_surfaced_in_notes():
    _vc, notes = classify_harness([_cell("PASS")], family="X", dudect_status="WARNING")
    assert "WARNING" in notes


def test_clean_classes_subset_of_taxonomy():
    assert set(CLEAN_CLASSES) <= set(VERDICT_CLASSES)
    assert "robust" in CLEAN_CLASSES and "ct-clean-untriaged" not in CLEAN_CLASSES


def test_opt_of():
    assert opt_of("-O2 -g -fno-lto") == "-O2"
    assert opt_of("-g -DX") == "-O0"


def test_summarize_groups_and_orders_by_harness():
    cells = [
        {"target": "t", "harness": "a", **_cell("PASS")},
        {"target": "t", "harness": "b", **_cell("FAIL", funcs="PFX_x")},
        {"target": "t", "harness": "a", **_cell("FAIL")},  # 'a' flips
    ]
    rows = summarize(cells, family="X", triage={}, dud_by={}, dcfg={})
    by = {r["harness"]: r for r in rows}
    assert [r["harness"] for r in rows] == ["a", "b"]      # first-seen order
    assert by["a"]["verdict_class"] == "build-sensitive-ct"
    assert by["b"]["verdict_class"] == "needs-analysis"
    assert by["a"]["target"] == "t"
