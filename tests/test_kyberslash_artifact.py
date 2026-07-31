"""Drift guards for the ML-KEM-768 KyberSlash positive control.

The point of this artifact is narrow:
  * structural Memcheck/ctgrind-style checking remains clean;
  * asm-scan still surfaces the restored division candidates;
  * KyberSlash poly helpers and public Keccak rate divisions stay separated by
    corpus triage.
"""

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MLKEM = ROOT / "examples" / "pqc_mlkem768"
CORPUS = ROOT / "docs" / "corpus"
BUILD_COMBOS = {
    "gcc_debug",
    "gcc_opt1",
    "gcc_release",
    "gcc_opt3",
    "gcc_size",
    "clang_debug",
    "clang_opt1",
    "clang_release",
    "clang_opt3",
    "clang_size",
}
MODERN_SECRET_FUNCTIONS = {
    "pqclean_mlkem768_kyberslash1": {
        "PQCLEAN_MLKEM768_CLEAN_poly_tomsg",
    },
    "pqclean_mlkem768_kyberslash2": {
        "PQCLEAN_MLKEM768_CLEAN_poly_compress",
        "PQCLEAN_MLKEM768_CLEAN_polyvec_compress",
    },
    "pqclean_mlkem768_kyberslash": {
        "PQCLEAN_MLKEM768_CLEAN_poly_compress",
        "PQCLEAN_MLKEM768_CLEAN_poly_tomsg",
        "PQCLEAN_MLKEM768_CLEAN_polyvec_compress",
    },
}


def _csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def _cell_rows(target: str, harness: str) -> list[dict[str, str]]:
    return [
        row
        for row in _csv_rows(CORPUS / "corpus_cells.csv")
        if row["target"] == target and row["harness"] == harness
    ]


def _summary_row(target: str, harness: str) -> dict[str, str]:
    matches = [
        row
        for row in _csv_rows(CORPUS / "corpus_summary.csv")
        if row["target"] == target and row["harness"] == harness
    ]
    assert len(matches) == 1
    return matches[0]


def test_modern_kyberslash_matrices_are_clean_and_variant_separated():
    public_funcs = {"shake128", "shake256"}
    for target, expected_secret in MODERN_SECRET_FUNCTIONS.items():
        rows = _cell_rows(target, "kem_dec")
        assert len(rows) == 10
        assert {row["combo"] for row in rows} == BUILD_COMBOS
        assert {row["ct_status"] for row in rows} == {"PASS"}
        assert {row["ct_findings"] for row in rows} == {"0"}
        assert all(row["ct_finding_funcs"] == "" for row in rows)
        assert all(row["ct_error"] == "" for row in rows)
        assert {row["asm_status"] for row in rows} == {"PASS"}

        hits = {
            row["combo"]: set(filter(None, row["asm_div_funcs"].split(";")))
            for row in rows
            if row["asm_div_funcs"]
        }
        assert hits == {
            "gcc_size": expected_secret | public_funcs,
            "clang_debug": expected_secret | public_funcs,
        }

        summary = _summary_row(target, "kem_dec")
        assert summary["correctness"] == "pass"
        assert summary["structural"] == "no-finding"
        assert summary["asm_attribution"] == "secret-risk"
        assert summary["review_id"] == "rvw-kyberslash-ground-truth-v1"
        assert summary["overall"] == "risk-detected"


def test_historical_kyber_preserves_compiler_induced_structural_finding():
    target = "pqcrystals_kyber768_ref_a621b8d"
    rows = _cell_rows(target, "kem_dec")
    assert len(rows) == 10
    assert {row["combo"] for row in rows} == BUILD_COMBOS
    findings = {
        row["combo"]: (row["ct_status"], row["ct_finding_funcs"])
        for row in rows
        if row["ct_status"] != "PASS"
    }
    assert findings == {
        "clang_opt1": ("FAIL", "pqcrystals_kyber768_ref_poly_frommsg"),
        "clang_size": ("FAIL", "pqcrystals_kyber768_ref_poly_frommsg"),
    }
    assert all(row["asm_status"] == "PASS" for row in rows)

    candidate_cells = {
        row["combo"]: set(filter(None, row["asm_div_funcs"].split(";")))
        for row in rows
        if row["asm_div_funcs"]
    }
    expected_candidates = {
        "pqcrystals_kyber768_ref_gen_matrix",
        "pqcrystals_kyber768_ref_poly_compress",
        "pqcrystals_kyber768_ref_poly_tomsg",
        "pqcrystals_kyber768_ref_polyvec_compress",
        "pqcrystals_kyber_fips202_ref_shake128",
        "pqcrystals_kyber_fips202_ref_shake256",
    }
    assert candidate_cells == {
        "gcc_size": expected_candidates,
        "clang_debug": expected_candidates,
    }

    summary = _summary_row(target, "kem_dec")
    assert summary["correctness"] == "pass"
    assert summary["structural"] == "finding"
    assert summary["ct_flips"] == "yes"
    assert summary["ct_finding_funcs"] == "pqcrystals_kyber768_ref_poly_frommsg"
    assert summary["review_id"] == "rvw-kyberslash-ground-truth-v1"
    assert summary["overall"] == "risk-detected"


def test_kyberslash_varlat_report_keeps_secret_and_public_triage_separate():
    secret_funcs = {
        "PQCLEAN_MLKEM768_CLEAN_poly_compress",
        "PQCLEAN_MLKEM768_CLEAN_poly_tomsg",
        "PQCLEAN_MLKEM768_CLEAN_polyvec_compress",
    }
    public_funcs = {"shake128", "shake256"}

    stock_rows = _cell_rows("pqclean_mlkem768", "kem_dec")
    vulnerable_rows = _cell_rows("pqclean_mlkem768_kyberslash", "kem_dec")
    assert stock_rows and vulnerable_rows

    stock_hits = {
        row["combo"]: set(filter(None, row["asm_div_funcs"].split(";")))
        for row in stock_rows
        if row["asm_div_funcs"]
    }
    vulnerable_hits = {
        row["combo"]: set(filter(None, row["asm_div_funcs"].split(";")))
        for row in vulnerable_rows
        if row["asm_div_funcs"]
    }

    assert all(not (funcs & secret_funcs) for funcs in stock_hits.values())
    assert stock_hits == {
        "gcc_size": public_funcs,
        "clang_debug": public_funcs,
    }
    assert vulnerable_hits == {
        "gcc_size": secret_funcs | public_funcs,
        "clang_debug": secret_funcs | public_funcs,
    }

    stock_summary = _summary_row("pqclean_mlkem768", "kem_dec")
    vulnerable_summary = _summary_row("pqclean_mlkem768_kyberslash", "kem_dec")
    assert stock_summary["varlat_triage"] == "public"
    assert stock_summary["legacy_verdict_class"] == "robust"
    # The raw timing FAIL is explicitly confounded, so it cannot coexist with a
    # clean v2 headline even though the structural/asm attribution is public.
    assert stock_summary["timing_validity"] == "confounded"
    assert stock_summary["timing_signal"] == "signal"
    assert stock_summary["overall"] == "inconclusive"
    assert vulnerable_summary["varlat_triage"] == "secret-risk"
    assert vulnerable_summary["legacy_verdict_class"] == "varlat-secret-risk"
    assert vulnerable_summary["asm_attribution"] == "secret-risk"
    assert vulnerable_summary["overall"] == "risk-detected"


def test_kyberslash_source_restores_division_while_stock_source_uses_reciprocal_multiply():
    vulnerable = (MLKEM / "clean_kyberslash" / "poly.c").read_text()
    vulnerable_polyvec = (MLKEM / "clean_kyberslash" / "polyvec.c").read_text()
    fixed = (MLKEM / "clean" / "poly.c").read_text()
    fixed_polyvec = (MLKEM / "clean" / "polyvec.c").read_text()

    assert "CTKAT-KS2-POLY" in vulnerable
    assert "CTKAT-KS1" in vulnerable
    assert "CTKAT-KS2-POLYVEC" in vulnerable_polyvec

    assert "d0 *= 80635;" in fixed
    assert "d0 >>= 28;" in fixed
    assert "t *= 80635;" in fixed
    assert "t >>= 28;" in fixed
    assert "d0 *= 1290167;" in fixed_polyvec
