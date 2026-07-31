from scripts.check_falcon_comparators import (
    SPLIT_HARNESSES,
    load_fp_audit,
    load_manifest,
    load_structural_snapshot,
    validate_fp_audit,
    validate_static,
    validate_structural_snapshot,
)


def test_falcon_comparator_static_contract_is_closed():
    manifest = load_manifest()
    assert validate_static(manifest) == []
    assert manifest["sources"]["pqclean"]["role"] == "reference"
    assert manifest["sources"]["c_fndsa"]["role"] == "constant-time-comparator"
    assert manifest["sources"]["c_fndsa"]["conformance"] == "none"
    assert manifest["evidence_policy"]["physical_timing"] == "not-run"
    assert manifest["evidence_policy"]["timing_blocker"] == "blocked-by-native-linux-host"


def test_falcon_structural_snapshot_matches_manifest_and_policy():
    manifest = load_manifest()
    snapshot = load_structural_snapshot()
    assert validate_structural_snapshot(manifest, snapshot) == []
    assert snapshot["environment"]["native_timing_evidence"] is False
    assert set(snapshot["full_sign_matrices"]) == {
        "pqclean_falcon512_reference",
        "pqclean_falcon1024_reference",
        "c_fndsa512_prospective",
        "c_fndsa1024_prospective",
    }


def test_falcon_fp_audit_keeps_build_facts_below_timing_verdict():
    manifest = load_manifest()
    audit = load_fp_audit()
    assert validate_fp_audit(manifest, audit) == []
    assert audit["host"]["qemu_emulation_detected"] is True
    assert audit["host"]["timing_evidence"] is False
    assert audit["classification"]["opcode_presence_is_leak_verdict"] is False


def test_falcon_split_harness_names_are_case_insensitive_filesystem_safe():
    assert len({name.casefold() for name in SPLIT_HARNESSES}) == len(SPLIT_HARNESSES)
