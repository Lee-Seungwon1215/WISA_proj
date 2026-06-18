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


def _csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def _cell_rows(target: str, harness: str) -> list[dict[str, str]]:
    return [
        row for row in _csv_rows(CORPUS / "corpus_cells.csv")
        if row["target"] == target and row["harness"] == harness
    ]


def _summary_row(target: str, harness: str) -> dict[str, str]:
    matches = [
        row for row in _csv_rows(CORPUS / "corpus_summary.csv")
        if row["target"] == target and row["harness"] == harness
    ]
    assert len(matches) == 1
    return matches[0]


def test_kyberslash_ct_matrix_stays_structurally_clean():
    rows = _cell_rows("pqclean_mlkem768_kyberslash", "kem_dec")
    assert rows
    assert {row["harness"] for row in rows} == {"kem_dec"}
    assert {row["combo"] for row in rows} == {
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
    assert {row["ct_status"] for row in rows} == {"PASS"}
    assert {row["ct_findings"] for row in rows} == {"0"}
    assert all(row["ct_finding_funcs"] == "" for row in rows)
    assert all(row["ct_error"] == "" for row in rows)


def test_kyberslash_varlat_report_keeps_secret_and_public_triage_separate():
    secret_funcs = {
        "PQCLEAN_MLKEM768_CLEAN_poly_compress",
        "PQCLEAN_MLKEM768_CLEAN_poly_tomsg",
    }
    public_funcs = {"shake128", "shake256"}

    stock_rows = _cell_rows("pqclean_mlkem768", "kem_dec")
    vulnerable_rows = _cell_rows("pqclean_mlkem768_kyberslash", "kem_dec")
    assert stock_rows and vulnerable_rows

    stock_hits = {
        row["combo"]: set(filter(None, row["asm_div_funcs"].split(";")))
        for row in stock_rows if row["asm_div_funcs"]
    }
    vulnerable_hits = {
        row["combo"]: set(filter(None, row["asm_div_funcs"].split(";")))
        for row in vulnerable_rows if row["asm_div_funcs"]
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
    assert stock_summary["verdict_class"] == "robust"
    assert vulnerable_summary["varlat_triage"] == "secret-risk"
    assert vulnerable_summary["verdict_class"] == "varlat-secret-risk"


def test_kyberslash_source_restores_division_while_stock_source_uses_reciprocal_multiply():
    vulnerable = (MLKEM / "clean_kyberslash" / "poly.c").read_text()
    fixed = (MLKEM / "clean" / "poly.c").read_text()

    assert "t[j] = ((((uint16_t)u << 4) + KYBER_Q/2)/KYBER_Q) & 15;" in vulnerable
    assert "t = (((t << 1) + KYBER_Q/2)/KYBER_Q) & 1;" in vulnerable
    assert "KyberSlash: secret-dependent /KYBER_Q" in vulnerable

    assert "d0 *= 80635;" in fixed
    assert "d0 >>= 28;" in fixed
    assert "t *= 80635;" in fixed
    assert "t >>= 28;" in fixed
