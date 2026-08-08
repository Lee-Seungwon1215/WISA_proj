from pathlib import Path

from ctkat.config import load_config
from scripts.check_paper_campaign import load_manifest, validate

ROOT = Path(__file__).parents[1]


def test_every_premeasurement_timing_config_loads_through_master_campaign():
    errors, report = validate(load_manifest())
    assert errors == []
    assert report["target_executions"] == 26
    assert report["timing_axes"] == 28


def test_timing_adapters_use_seeded_interpose_not_fixed_test_vectors():
    fndsa = (ROOT / "examples/fndsa_prospective/timing_adapter.c").read_text()
    mldsa = (ROOT / "examples/mldsa_native/timing_adapter.c").read_text()
    assert "randombytes(seed, sizeof seed)" in fndsa
    assert "ctkat_keygen_seed" not in fndsa
    assert "randombytes(seed, sizeof seed)" in mldsa
    assert "randombytes(rnd, sizeof rnd)" in mldsa


def test_historical_randombytes_abi_is_declared_exactly():
    cfg = load_config(ROOT / "examples/pqc_kyber768_historical/ctkat_timing.yaml")
    assert cfg.dudect is not None
    assert cfg.dudect.harnesses[0].randombytes_return == "void"
