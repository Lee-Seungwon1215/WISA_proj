import hashlib
from pathlib import Path

from scripts.check_kyberslash_ground_truth import (
    EXPECTED_TIMECOP_FUNCTIONS,
    VARIANT_ORDER,
    load_manifest,
    render_patch,
    validate_static,
    verify_functional_equivalence,
)

ROOT = Path(__file__).resolve().parent.parent


def test_kyberslash_ground_truth_static_contract_is_closed():
    manifest = load_manifest()
    assert validate_static(manifest) == []
    assert tuple(manifest["variants"]) == VARIANT_ORDER
    assert (
        manifest["timecop_backend"]["execution_status"]
        == "validated-in-arm64-container-and-amd64-emulation"
    )
    assert manifest["expected_evidence"]["physical_timing"]["all_variants"] == "not-run"
    historical_memcheck = manifest["expected_evidence"]["ordinary_memcheck"]["historical"]
    assert historical_memcheck["finding_cells"] == ["clang_opt1", "clang_size"]
    assert historical_memcheck["finding_function"] == "pqcrystals_kyber768_ref_poly_frommsg"
    timecop = manifest["expected_evidence"]["timecop"]
    assert timecop["kem_dec_secret_key_path"]["ks2"] == []
    assert set(timecop["site_operand_attribution"]["ks2"]) == {
        "PQCLEAN_MLKEM768_CLEAN_poly_compress",
        "PQCLEAN_MLKEM768_CLEAN_polyvec_compress",
    }
    for scope, expected_targets in EXPECTED_TIMECOP_FUNCTIONS.items():
        for target, expected_functions in expected_targets.items():
            assert set(timecop[scope][target]) == expected_functions


def test_kyberslash_unified_diffs_are_exact_and_hashed():
    manifest = load_manifest()
    for name in VARIANT_ORDER[1:]:
        variant = manifest["variants"][name]
        patch_path = ROOT / variant["patch"]
        assert patch_path.read_text(encoding="utf-8") == render_patch(name)
        assert hashlib.sha256(patch_path.read_bytes()).hexdigest() == variant["patch_sha256"]


def test_kyberslash_four_variants_have_byte_identical_full_kem_transcripts():
    manifest = load_manifest()
    transcript_sha256, transcript_bytes = verify_functional_equivalence(manifest)
    expected = manifest["functional_equivalence"]
    assert transcript_sha256 == expected["transcript_sha256"]
    assert transcript_bytes == expected["transcript_bytes"]
