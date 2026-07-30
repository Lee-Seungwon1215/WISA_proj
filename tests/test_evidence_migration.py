"""The frozen v1.2 corpus must reproduce its committed v2 snapshot exactly."""

import csv
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "migrate_evidence_v1_to_v2.py"
SPEC = importlib.util.spec_from_file_location("migrate_evidence_v1_to_v2", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MIGRATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MIGRATION)


def _read(path):
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_committed_v2_is_exact_deterministic_migration():
    cells_text, summary_text = MIGRATION.expected_outputs(
        cells_in=MIGRATION.DEFAULT_ARCHIVE / "corpus_cells.csv",
        summary_in=MIGRATION.DEFAULT_ARCHIVE / "corpus_summary.csv",
        manifest_path=MIGRATION.DEFAULT_MANIFEST,
    )
    assert cells_text == (MIGRATION.DEFAULT_MIGRATED / "corpus_cells.csv").read_text()
    assert summary_text == (MIGRATION.DEFAULT_MIGRATED / "corpus_summary.csv").read_text()


def test_mlkem_raw_fail_migrates_to_confounded_inconclusive():
    rows = _read(MIGRATION.DEFAULT_MIGRATED / "corpus_summary.csv")
    row = next(
        row for row in rows if row["target"] == "pqclean_mlkem768" and row["harness"] == "kem_dec"
    )
    assert row["timing_raw_status"] == "FAIL"
    assert row["timing_signal"] == "signal"
    assert row["timing_validity"] == "confounded"
    assert row["overall"] == "inconclusive"
    assert row["legacy_verdict_class"] == "robust"


def test_summary_only_axis_does_not_invent_structural_or_asm_evidence():
    rows = _read(MIGRATION.DEFAULT_MIGRATED / "corpus_summary.csv")
    row = next(
        row
        for row in rows
        if row["target"] == "pqclean_mlkem768" and row["harness"] == "kem_dec_ct"
    )
    assert row["structural"] == "not-run"
    assert row["asm"] == "not-run"
    assert row["asm_attribution"] == "not-applicable"
    assert "no matching cell artifact" in row["notes"]


def test_v1_review_basis_does_not_self_promote_without_manifest_override():
    v1 = _read(MIGRATION.DEFAULT_ARCHIVE / "corpus_summary.csv")
    source = next(row for row in v1 if row["target"] == "pqclean_mlkem512")
    manifest = {
        "schema_version": "2.0",
        "source_schema_version": "1.2",
        "default_correctness": "not-run",
        "default_timing_validity": "insufficient-power",
        "default_timing_backend": "experimental-first-order-v1",
        "rows": [],
    }
    row = MIGRATION.migrate_summary([source], manifest)[0]
    assert source["basis"] == "review"
    assert row["review"] == "pending"
    assert row["review_id"] == ""
    assert row["overall"] == "needs-review"
