from pathlib import Path

import yaml

from ctkat.cli import _dudect_context
from ctkat.config import load_config
from ctkat.timing_binary_contract import load_timing_binary_contract
from ctkat.timing_harness_generator import render_timing_harness
from scripts.run_native_timing_campaign import load_campaign, static_check

ROOT = Path(__file__).resolve().parent.parent
CANARY_DIR = ROOT / "examples/kyberslash_operand_latency"
V3_CONFIGS = sorted(CANARY_DIR.glob("ctkat_*_v3.yaml"))
SELECTORS = {
    "ks1_vulnerable",
    "ks1_patched",
    "ks2_poly_vulnerable",
    "ks2_poly_patched",
    "ks2_polyvec_vulnerable",
    "ks2_polyvec_patched",
}


def test_v3_six_canaries_opt_in_without_mutating_v2_configs():
    assert len(V3_CONFIGS) == 6
    selectors = set()
    for v3_path in V3_CONFIGS:
        v2_path = v3_path.with_name(v3_path.name.removesuffix("_v3.yaml") + ".yaml")
        v3 = load_config(v3_path)
        v2 = load_config(v2_path)
        assert v3.dudect is not None and v2.dudect is not None
        v3_harness = v3.dudect.harnesses[0]
        v2_harness = v2.dudect.harnesses[0]
        assert v3.project == v2.project
        assert v3.dudect.compiler == v2.dudect.compiler
        assert v3_harness.sources == v2_harness.sources
        assert v3_harness.include_dirs == v2_harness.include_dirs
        assert v2_harness.operand_setup_contract == "legacy-class-pools"
        assert v3_harness.operand_setup_contract == "same-address-branchless-v3"
        assert v3_harness.binary_contract is not None
        assert v3_harness.binary_contract.manifest == Path("binary_contracts_v3.yaml")
        selectors.add(v3_harness.binary_contract.target)
    assert selectors == SELECTORS


def test_v3_binary_contract_binds_wrapper_to_exact_site_and_division_pair():
    manifest = CANARY_DIR / "binary_contracts_v3.yaml"
    for selector in SELECTORS:
        root, rule = load_timing_binary_contract(manifest, selector)
        assert root["contract_id"] == "kyberslash-direct-operand-linked-binary-v3"
        symbols = rule["symbols"]
        assert symbols["CTKAT_KS_crypto_kem_dec"]["required_call_targets"] == [
            "ctkat_kyberslash_site_operation"
        ]
        expected_divisions = 1 if selector.endswith("vulnerable") else 0
        assert symbols["ctkat_kyberslash_site_operation"]["division_count"] == (expected_divisions)


def test_v3_render_freezes_valid_placebo_and_all_return_code_witnesses():
    cfg = load_config(V3_CONFIGS[0])
    assert cfg.dudect is not None
    harness = cfg.dudect.harnesses[0]
    source = render_timing_harness(
        harness.template,
        _dudect_context(harness, cfg.dudect, cfg.dudect.seed, "rdtsc"),
    )

    assert "setup_contract=same-address-branchless-v3" in source
    assert "class_address_policy=fixed-sk-and-shared-ct-work" in source
    assert "placebo_coefficient=1664" in source
    assert "coefficient_witness=all-bin-members" in source
    assert "int warmup_dec_rc" in source
    assert "measured_dec_contract_failures=%zu" in source


def test_v3_campaign_replaces_only_six_operand_configs_and_discloses_v2_confounds():
    v2 = load_campaign(ROOT / "docs/measurement/kyberslash_native_v2.yaml")
    v3 = load_campaign(ROOT / "docs/measurement/kyberslash_native_v3.yaml")
    assert static_check(v3) == []
    assert v3.campaign_id == "kyberslash-native-v3"
    assert v2.host == v3.host
    assert v2.protocol == v3.protocol
    assert [target.id for target in v2.targets] == [target.id for target in v3.targets]
    for old, new in zip(v2.targets, v3.targets, strict=True):
        assert old.harnesses == new.harnesses
        assert old.axes == new.axes
        assert old.target_measurements == new.target_measurements
        assert old.control_measurements == new.control_measurements
        assert old.positive_control_effects == new.positive_control_effects
        assert old.timeout == new.timeout
        if old.id.startswith("kyberslash_operand_"):
            assert new.config.stem.endswith("_v3")
        else:
            assert old.config == new.config

    raw = yaml.safe_load(
        (ROOT / "docs/measurement/kyberslash_native_v3.yaml").read_text(encoding="utf-8")
    )
    description = raw["description"]
    assert "invalid placebo" in description
    assert "class-specific source addresses" in description
    assert "no v2 trace may be reused" in description
