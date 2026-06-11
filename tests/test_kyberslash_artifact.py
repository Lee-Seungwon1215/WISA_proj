"""Drift guards for the ML-KEM-768 KyberSlash positive control.

The point of this artifact is narrow:
  * structural Memcheck/ctgrind-style checking remains clean;
  * asm-scan still surfaces the restored division candidates;
  * KyberSlash poly helpers and public Keccak rate divisions stay separated by
    manual triage.
"""

import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "examples" / "pqc_mlkem768_kyberslash"
REPORTS = TARGET / "reports"
MLKEM = ROOT / "examples" / "pqc_mlkem768"


def _csv_rows(name: str) -> list[dict[str, str]]:
    with (REPORTS / name).open(newline="") as fh:
        return list(csv.DictReader(fh))


def test_kyberslash_ct_matrix_stays_structurally_clean():
    rows = _csv_rows("ctkat_ct_matrix.csv")
    assert rows
    assert {row["project"] for row in rows} == {"pqclean_mlkem768_kyberslash"}
    assert {row["harness"] for row in rows} == {"kem_dec"}
    assert {row["combo"] for row in rows} == {
        "gcc_debug",
        "gcc_release",
        "gcc_size",
        "clang_debug",
        "clang_release",
        "clang_size",
    }
    assert {row["valgrind_status"] for row in rows} == {"PASS"}
    assert {row["findings"] for row in rows} == {"0"}
    assert all(row["finding_funcs"] == "" for row in rows)
    assert all(row["error"] == "" for row in rows)


def test_kyberslash_varlat_report_keeps_secret_and_public_triage_separate():
    rows = _csv_rows("ctkat_varlat_candidates.csv")
    assert rows

    kyberslash_rows = [
        row for row in rows if row["source_file"].endswith("clean_kyberslash/poly.c")
    ]
    assert {row["function"] for row in kyberslash_rows} == {
        "PQCLEAN_MLKEM768_CLEAN_poly_compress",
        "PQCLEAN_MLKEM768_CLEAN_poly_tomsg",
    }
    assert {row["triage_hint"] for row in kyberslash_rows} == {
        "kyberslash-poly-review-secret-risk"
    }
    assert {
        (row["compiler"], row["opt_levels"]) for row in kyberslash_rows
    } == {("gcc", "-Os"), ("clang", "-O0")}
    assert all(row["mnemonics"] in {"div", "idiv"} for row in kyberslash_rows)

    keccak_rows = [row for row in rows if row["source_file"].endswith("common/fips202.c")]
    assert {row["function"] for row in keccak_rows} == {"shake128", "shake256"}
    assert {row["triage_hint"] for row in keccak_rows} == {
        "keccak-rate-review-likely-public"
    }

    assert not any(
        row["triage_hint"] == "keccak-rate-review-likely-public"
        for row in kyberslash_rows
    )
    assert not any(
        row["triage_hint"] == "kyberslash-poly-review-secret-risk"
        for row in keccak_rows
    )


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
