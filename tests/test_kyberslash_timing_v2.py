from pathlib import Path

import yaml

from ctkat.cli import _dudect_context
from ctkat.config import load_config
from ctkat.timing_harness_generator import render_timing_harness

ROOT = Path(__file__).resolve().parent.parent
BASE_CFLAGS = [
    "-std=c99",
    "-Os",
    "-g",
    "-fno-inline",
    "-fno-omit-frame-pointer",
    "-fno-lto",
]
FULL_CONFIGS = {
    "stock": ROOT / "examples/pqc_mlkem768/ctkat_timing_kyberslash_v2.yaml",
    "ks1": ROOT / "examples/pqc_mlkem768_kyberslash1/ctkat_timing_v2.yaml",
    "ks2": ROOT / "examples/pqc_mlkem768_kyberslash2/ctkat_timing_v2.yaml",
    "ks1_ks2": ROOT / "examples/pqc_mlkem768_kyberslash/ctkat_timing_v2.yaml",
}
CANARY_DIR = ROOT / "examples/kyberslash_operand_latency"


def test_full_kem_v2_holds_sk_fixed_and_uses_division_surviving_cell():
    selectors = {}
    for selector, path in FULL_CONFIGS.items():
        cfg = load_config(path)
        harness = cfg.dudect.harnesses[0]
        assert cfg.dudect.compiler.cflags == BASE_CFLAGS
        assert harness.name == "kem_dec_chosen_ct"
        assert harness.leak_target == "chosen_ct"
        assert harness.rejection_oracle_function == ("PQCLEAN_MLKEM768_CLEAN_kyber_shake256_rkprf")
        assert harness.rejection_seed_offset == "KYBER_SECRETKEYBYTES - KYBER_SYMBYTES"
        assert harness.binary_contract is not None
        selectors[selector] = harness.binary_contract.target
        assert not any(Path(source).name == "randombytes.c" for source in harness.sources)
    assert selectors == {key: key for key in FULL_CONFIGS}


def test_chosen_ct_template_freezes_corpus_and_records_strong_digests():
    cfg = load_config(FULL_CONFIGS["stock"])
    dudect = cfg.dudect
    harness = dudect.harnesses[0]
    source = render_timing_harness(
        "kem",
        _dudect_context(harness, dudect, dudect.seed, "monotonic"),
    )

    assert "ctkat_prng_init(CTKAT_SEED);" in source
    assert "ctkat_prng_init(options.seed);" in source
    assert "paired-invalid-public-chosen-ciphertexts" in source
    assert "rejection_witness=exact-rkprf-output" in source
    assert "fixed_sk_sha3_256" in source
    assert "class0_ct_sha3_256" in source
    assert "class1_ct_sha3_256" in source
    assert source.count("memcpy(CTKAT_SLOT(pool0_sk") == 1
    assert source.count("memcpy(CTKAT_SLOT(pool1_sk") == 1
    assert "crypto_kem_keypair(pk_tmp, sk_tmp)" not in source
    assert "chosen-ct rejection witness failed" in source
    assert "PQCLEAN_MLKEM768_CLEAN_kyber_shake256_rkprf(" in source


def test_direct_canary_pairs_have_identical_base_flags_and_frozen_axis():
    configs = sorted(CANARY_DIR.glob("ctkat_*.yaml"))
    assert len(configs) == 6
    selectors = set()
    for path in configs:
        cfg = load_config(path)
        harness = cfg.dudect.harnesses[0]
        assert cfg.dudect.compiler.cflags == BASE_CFLAGS
        assert harness.leak_target == "operand_bin"
        assert harness.binary_contract is not None
        selectors.add(harness.binary_contract.target)
        assert Path("operand_kem.c") in harness.sources
    assert selectors == {
        "ks1_vulnerable",
        "ks1_patched",
        "ks2_poly_vulnerable",
        "ks2_poly_patched",
        "ks2_polyvec_vulnerable",
        "ks2_polyvec_patched",
    }


def test_direct_canary_patched_arithmetic_matches_vulnerable_all_coefficients():
    for coefficient in range(3329):
        ks1_vulnerable = (((coefficient << 1) + 1664) // 3329) & 1
        ks1_patched = ((((coefficient << 1) + 1665) * 80635) & 0xFFFFFFFF) >> 28
        assert ks1_vulnerable == (ks1_patched & 1)

        ks2_poly_vulnerable = (((coefficient << 4) + 1664) // 3329) & 15
        ks2_poly_patched = ((((coefficient << 4) + 1665) * 80635) & 0xFFFFFFFF) >> 28
        assert ks2_poly_vulnerable == (ks2_poly_patched & 15)

        ks2_polyvec_vulnerable = (((coefficient << 10) + 1664) // 3329) & 0x3FF
        ks2_polyvec_patched = (((coefficient << 10) + 1665) * 1290167) >> 32
        assert ks2_polyvec_vulnerable == (ks2_polyvec_patched & 0x3FF)


def test_v2_manifest_replaces_confounded_sk_axis_with_explicit_layers():
    manifest = yaml.safe_load(
        (ROOT / "docs/measurement/kyberslash_native_v2.yaml").read_text(encoding="utf-8")
    )
    assert manifest["campaign_id"] == "kyberslash-native-v2"
    assert len(manifest["targets"]) == 10
    axes = {axis for target in manifest["targets"] for axis in target["axes"].values()}
    assert axes == {"chosen_ct", "operand_bin"}
    assert all("sk" not in target["axes"].values() for target in manifest["targets"])
