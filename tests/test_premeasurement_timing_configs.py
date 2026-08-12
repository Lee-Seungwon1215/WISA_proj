import platform
import shutil
from pathlib import Path

import pytest
import yaml

from ctkat.cli import _dudect_context
from ctkat.config import load_config
from ctkat.dudect_runner import run_timing_harness
from ctkat.timing_harness_generator import generate_and_compile_timing
from scripts.check_paper_campaign import load_manifest, validate
from scripts.run_native_timing_campaign import load_campaign

ROOT = Path(__file__).parents[1]


def _resolved(base: Path, value: Path) -> Path:
    return value if value.is_absolute() else (base / value).resolve()


def _compile_mldsa_timing_profile(config_name: str, output_dir: Path):
    config_path = ROOT / "examples/mldsa_native" / config_name
    cfg = load_config(config_path)
    assert cfg.dudect is not None
    dudect = cfg.dudect
    if shutil.which(dudect.compiler.cc) is None:
        pytest.skip(f"{dudect.compiler.cc} is unavailable")
    harness = dudect.harnesses[0]
    context = _dudect_context(harness, dudect, 0xC0FFEE, "monotonic")
    context.update(measurements=2, warmup=1, pool_size=2)
    return (
        generate_and_compile_timing(
            name=harness.name,
            template=harness.template,
            context=context,
            output_dir=output_dir,
            sources=[_resolved(config_path.parent, source) for source in harness.sources],
            include_dirs=[
                _resolved(config_path.parent, include_dir) for include_dir in harness.include_dirs
            ],
            cflags=dudect.compiler.cflags,
            cc=dudect.compiler.cc,
            workdir=_resolved(config_path.parent, dudect.workdir),
            timeout=120,
        ),
        dudect,
        harness,
        config_path.parent,
    )


def test_every_premeasurement_timing_config_loads_through_master_campaign():
    errors, report = validate(load_manifest())
    assert errors == []
    assert report["target_executions"] == 26
    assert report["timing_axes"] == 28


def test_diverse_v2_changes_only_attribution_and_broken_compile_contracts():
    v1 = load_campaign(ROOT / "docs/measurement/diverse_native_v1.yaml")
    v2 = load_campaign(ROOT / "docs/measurement/diverse_native_v2.yaml")

    assert v1.host == v2.host
    assert v1.protocol == v2.protocol
    assert [target.id for target in v1.targets] == [target.id for target in v2.targets]
    for old, new in zip(v1.targets, v2.targets, strict=True):
        assert old.target_measurements == new.target_measurements
        assert old.control_measurements == new.control_measurements
        assert old.positive_control_effects == new.positive_control_effects
        assert old.timeout == new.timeout
        if old.id.startswith("mlkem_"):
            assert old.harnesses == ("kem_dec",)
            assert old.axes == (("kem_dec", "sk"),)
            assert new.harnesses == ("kem_dec_valid_tuple",)
            assert new.axes == (("kem_dec_valid_tuple", "valid_tuple"),)
            old_cfg = load_config(old.config)
            new_cfg = load_config(new.config)
            assert old_cfg.dudect is not None
            assert new_cfg.dudect is not None
            assert old_cfg.dudect.harnesses[0].leak_target == "sk"
            assert new_cfg.dudect.harnesses[0].leak_target == "valid_tuple"
        else:
            assert old.family == new.family
            assert old.config == new.config
            assert old.harnesses == new.harnesses
            assert old.axes == new.axes

    paper_v3 = yaml.safe_load((ROOT / "docs/measurement/paper_native_campaign_v3.yaml").read_text())
    paper_v4 = yaml.safe_load((ROOT / "docs/measurement/paper_native_campaign_v4.yaml").read_text())
    old_diverse = next(item for item in paper_v3["components"] if item["id"] == "diverse-lineages")
    new_diverse = next(item for item in paper_v4["components"] if item["id"] == "diverse-lineages")
    assert old_diverse["manifest"] == "docs/measurement/diverse_native_v1.yaml"
    assert new_diverse["manifest"] == "docs/measurement/diverse_native_v2.yaml"
    assert paper_v4["campaign_id"] == "ctkat-paper-native-v4"


def test_committed_corpus_v3_changes_only_the_mixed_mlkem_axis():
    v2 = load_campaign(ROOT / "docs/measurement/native_timing_v2_campaign.yaml")
    v3 = load_campaign(ROOT / "docs/measurement/native_timing_v3_campaign.yaml")

    assert v2.host == v3.host
    assert v2.protocol == v3.protocol
    assert [target.id for target in v2.targets] == [target.id for target in v3.targets]
    for old, new in zip(v2.targets, v3.targets, strict=True):
        assert old.family == new.family
        assert old.harnesses == new.harnesses
        assert old.target_measurements == new.target_measurements
        assert old.control_measurements == new.control_measurements
        assert old.positive_control_effects == new.positive_control_effects
        assert old.timeout == new.timeout
        if old.id == "pqclean_mlkem768":
            assert old.axes == (
                ("kem_dec", "sk"),
                ("kem_dec_ct", "ct"),
                ("kem_dec_fo", "fo"),
            )
            assert new.axes == (
                ("kem_dec", "valid_tuple"),
                ("kem_dec_ct", "ct"),
                ("kem_dec_fo", "fo"),
            )
            old_cfg = load_config(old.config)
            new_cfg = load_config(new.config)
            assert old_cfg.dudect is not None
            assert new_cfg.dudect is not None
            assert old_cfg.dudect.harnesses[0].leak_target == "sk"
            assert new_cfg.dudect.harnesses[0].leak_target == "valid_tuple"
        else:
            assert old.config == new.config
            assert old.axes == new.axes

    paper_v3 = yaml.safe_load((ROOT / "docs/measurement/paper_native_campaign_v3.yaml").read_text())
    paper_v4 = yaml.safe_load((ROOT / "docs/measurement/paper_native_campaign_v4.yaml").read_text())
    old_core = next(
        item for item in paper_v3["components"] if item["id"] == "committed-corpus-refresh"
    )
    new_core = next(
        item for item in paper_v4["components"] if item["id"] == "committed-corpus-refresh"
    )
    assert old_core["manifest"] == "docs/measurement/native_timing_v2_campaign.yaml"
    assert new_core["manifest"] == "docs/measurement/native_timing_v3_campaign.yaml"


def test_paper_v8_keeps_v7_measurement_scope_and_freezes_rng_contract_correction():
    paper_v7 = yaml.safe_load((ROOT / "docs/measurement/paper_native_campaign_v7.yaml").read_text())
    paper_v8 = load_manifest()
    assert paper_v8["campaign_id"] == "ctkat-paper-native-v8-single-host"
    assert paper_v8["execution_policy"]["minimum_physical_hosts"] == 1
    assert paper_v8["execution_policy"]["independent_human_review_required"] is False
    assert any("dual-read-masked-select-v4" in limit for limit in paper_v8["claim_limits"])
    assert any("randomness policy" in limit for limit in paper_v8["claim_limits"])
    assert any("failed v7 final attempt" in limit for limit in paper_v8["claim_limits"])
    old_components = {item["id"]: item for item in paper_v7["components"]}
    new_components = {item["id"]: item for item in paper_v8["components"]}
    assert set(old_components) == set(new_components)
    for component_id in old_components:
        assert old_components[component_id]["manifest"] == new_components[component_id]["manifest"]
        assert old_components[component_id]["purpose"] == new_components[component_id]["purpose"]
        assert "--final-gate single-host" in new_components[component_id]["command"]


def test_timing_adapters_use_seeded_interpose_not_fixed_test_vectors():
    fndsa = (ROOT / "examples/fndsa_prospective/timing_adapter.c").read_text()
    mldsa = (ROOT / "examples/mldsa_native/timing_adapter.c").read_text()
    assert "randombytes(seed, sizeof seed)" in fndsa
    assert "ctkat_keygen_seed" not in fndsa
    assert "randombytes(seed, sizeof seed)" in mldsa
    assert "randombytes(rnd, sizeof rnd)" in mldsa


def test_null_randombytes_header_does_not_infer_the_runtime_rng_contract():
    seeded_configs = [
        "examples/kyberslash_operand_latency/ctkat_ks1_vulnerable_v3.yaml",
        "examples/kyberslash_operand_latency/ctkat_ks1_patched_v3.yaml",
        "examples/kyberslash_operand_latency/ctkat_ks2_poly_vulnerable_v3.yaml",
        "examples/kyberslash_operand_latency/ctkat_ks2_poly_patched_v3.yaml",
        "examples/kyberslash_operand_latency/ctkat_ks2_polyvec_vulnerable_v3.yaml",
        "examples/kyberslash_operand_latency/ctkat_ks2_polyvec_patched_v3.yaml",
        "examples/c_fndsa512_prospective/ctkat_timing_native.yaml",
        "examples/c_fndsa512_prospective/ctkat_timing_fpr_emu.yaml",
        "examples/c_fndsa1024_prospective/ctkat_timing_native.yaml",
        "examples/c_fndsa1024_prospective/ctkat_timing_fpr_emu.yaml",
    ]
    for relative_path in seeded_configs:
        cfg = load_config(ROOT / relative_path)
        assert cfg.dudect is not None
        harness = cfg.dudect.harnesses[0]
        assert harness.randombytes_header is None
        assert harness.randomness_policy == "seeded-interpose"

    toy = load_config(ROOT / "examples/toy_kem_ct_leak/ctkat.yaml")
    assert toy.dudect is not None
    assert {
        (harness.randombytes_header, harness.randomness_policy)
        for harness in toy.dudect.harnesses
    } == {(None, "external-or-none")}


def test_historical_randombytes_abi_is_declared_exactly():
    cfg = load_config(ROOT / "examples/pqc_kyber768_historical/ctkat_timing.yaml")
    assert cfg.dudect is not None
    assert cfg.dudect.harnesses[0].randombytes_return == "void"


def test_mldsa_portable_timing_harness_compiles_and_passes_verify_gate(tmp_path):
    generated, _, harness, workdir = _compile_mldsa_timing_profile(
        "ctkat_timing_portable.yaml",
        tmp_path,
    )

    samples = run_timing_harness(
        generated.binary_path,
        workdir,
        timeout=120,
        seed_override=0xC0FFEE,
        mode="target",
        measurements_override=2,
        signature_length_contract=harness.signature_length_contract,
    )

    assert samples.raw_n_total == 2
    assert samples.signature_return_codes == [0, 0]
    assert set(samples.output_lengths) == {3309}
    assert samples.runtime_metadata["signature_correctness_gate"] == "passed"


def test_mldsa_x86_timing_config_pins_canonical_native_backend_headers():
    cfg = load_config(ROOT / "examples/mldsa_native/ctkat_timing_x86_64.yaml")
    assert cfg.dudect is not None
    flags = set(cfg.dudect.compiler.cflags)

    assert {
        "-DMLD_CONFIG_USE_NATIVE_BACKEND_ARITH",
        '-DMLD_CONFIG_ARITH_BACKEND_FILE="native/meta.h"',
        "-DMLD_CONFIG_USE_NATIVE_BACKEND_FIPS202",
        '-DMLD_CONFIG_FIPS202_BACKEND_FILE="fips202/native/auto.h"',
        "-DMLD_FORCE_X86_64",
        "-mavx2",
        "-mbmi2",
    } <= flags
    assert any(source.name == "mldsa_native_asm.S" for source in cfg.dudect.harnesses[0].sources)


@pytest.mark.skipif(
    platform.machine().lower() not in {"x86_64", "amd64"},
    reason="mldsa-native AVX2 assembly profile is x86_64-only",
)
def test_mldsa_x86_timing_harness_compiles_and_passes_verify_gate(tmp_path):
    generated, _, harness, workdir = _compile_mldsa_timing_profile(
        "ctkat_timing_x86_64.yaml",
        tmp_path,
    )

    samples = run_timing_harness(
        generated.binary_path,
        workdir,
        timeout=120,
        seed_override=0xC0FFEE,
        mode="target",
        measurements_override=2,
        signature_length_contract=harness.signature_length_contract,
    )

    assert samples.raw_n_total == 2
    assert samples.signature_return_codes == [0, 0]
    assert set(samples.output_lengths) == {3309}
    assert samples.runtime_metadata["signature_correctness_gate"] == "passed"
