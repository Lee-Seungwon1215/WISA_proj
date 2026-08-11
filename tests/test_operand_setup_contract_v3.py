from pathlib import Path

import pytest
from pydantic import ValidationError

import ctkat.cli as cli_module
from ctkat.cli import _dudect_context
from ctkat.config import DudectConfig, DudectHarnessConfig
from ctkat.dudect_runner import TimingSamples
from ctkat.statistics import WelchResult
from ctkat.timing_harness_generator import render_timing_harness
from ctkat.timing_input_contract import (
    build_operand_v3_input_contract,
    validate_operand_v3_harness_report,
)

OPERAND_V3_METADATA = {
    "axis": "operand_bin",
    "key_policy": "fixed",
    "class_contract": "frozen-public-coefficient-bins",
    "class0_coefficients": "0-63",
    "class1_coefficients": "3265-3328",
    "setup_contract": "same-address-branchless-v3",
    "class_address_policy": "fixed-sk-and-shared-ct-work",
    "placebo_coefficient": "1664",
    "placebo_target_path": "valid-decapsulation",
    "setup_return_codes": "checked",
    "coefficient_witness": "all-bin-members",
    "measured_dec_contract_failures": "0",
}


def _operand_harness(**overrides) -> DudectHarnessConfig:
    values = {
        "name": "operand_bin",
        "template": "kem",
        "header": "api.h",
        "randombytes_header": None,
        "prefix": "TEST_",
        "leak_target": "operand_bin",
    }
    values.update(overrides)
    return DudectHarnessConfig(**values)


def _render_operand(harness: DudectHarnessConfig) -> str:
    dudect = DudectConfig(
        measurements=100,
        warmup=10,
        # Keep model construction host-portable; the resolved context below
        # deliberately renders the x86 campaign clock contract.
        clock="monotonic",
        harnesses=[harness],
    )
    return render_timing_harness(
        "kem",
        _dudect_context(harness, dudect, dudect.seed, "rdtsc"),
    )


def test_operand_setup_contract_defaults_to_legacy_and_is_kem_operand_only():
    assert _operand_harness().operand_setup_contract == "legacy-class-pools"
    assert (
        _operand_harness(operand_setup_contract="same-address-branchless-v3").operand_setup_contract
        == "same-address-branchless-v3"
    )

    with pytest.raises(ValidationError, match="only valid.*leak_target='operand_bin'"):
        DudectHarnessConfig(
            name="ct_axis",
            template="kem",
            header="api.h",
            leak_target="ct",
            operand_setup_contract="same-address-branchless-v3",
        )
    with pytest.raises(ValidationError, match="only valid.*leak_target='operand_bin'"):
        DudectHarnessConfig(
            name="sign",
            template="sign",
            header="api.h",
            operand_setup_contract="same-address-branchless-v3",
        )


def test_dudect_context_plumbs_exact_operand_setup_contract():
    harness = _operand_harness(operand_setup_contract="same-address-branchless-v3")
    dudect = DudectConfig(measurements=100, warmup=0, harnesses=[harness])

    context = _dudect_context(harness, dudect, dudect.seed, "monotonic")

    assert context["operand_setup_contract"] == "same-address-branchless-v3"


def test_operand_v3_render_uses_same_addresses_branchless_mask_and_mfence():
    source = _render_operand(_operand_harness(operand_setup_contract="same-address-branchless-v3"))
    main_source = source[source.index("int main(") :]
    measurement = main_source[main_source.index("for (size_t i = 0; i < options.measurements") :]

    assert "pool0_sk" not in main_source
    assert "pool1_sk" not in main_source
    assert "pool0_ct" not in main_source
    assert "pool1_ct" not in main_source
    assert "const uint8_t *src_sk" not in main_source
    assert "const uint8_t *src_ct" not in main_source
    assert "sk_work" not in main_source
    assert "uint16_t low_coefficient = (uint16_t)(p % 64U);" in measurement
    assert "uint16_t high_coefficient = (uint16_t)(3265U + (p % 64U));" in measurement
    assert "0U - (uint16_t)((unsigned int)data_class & 1U)" in measurement
    assert "low_coefficient ^ ((low_coefficient ^ high_coefficient) & class_mask)" in measurement
    assert "memcpy(ct_work, ct_fixed, CTKAT_CT_BYTES);" in measurement
    assert "ctkat_store_u16_le(ct_work, coefficient);" in measurement
    assert "ss_work, ct_work, sk_fixed" in measurement
    assert "data_class ?" not in measurement
    assert source.count("_mm_mfence();") == 1

    assert measurement.index("ctkat_store_u16_le(ct_work, coefficient);") < measurement.index(
        "if (options.mode == CTKAT_MODE_PLACEBO)"
    )
    assert measurement.index("ctkat_store_u16_le(ct_work, (uint16_t)1664U);") < (
        measurement.index("_mm_mfence();")
    )
    assert measurement.index("_mm_mfence();") < measurement.index("uint64_t t0 = ctkat_now(&aux0);")


def test_operand_v3_render_witnesses_setup_and_measured_dec_contract():
    source = _render_operand(_operand_harness(operand_setup_contract="same-address-branchless-v3"))

    assert "int setup_keypair_rc = TEST_crypto_kem_keypair" in source
    assert "int setup_enc_rc = TEST_crypto_kem_enc" in source
    assert "ctkat_store_u16_le(ct_fixed, (uint16_t)1664U);" in source
    assert "int fixed_placebo_dec_rc" in source
    assert "for (size_t p = 0; p < 64U; p++)" in source
    assert "int low_dec_rc = TEST_crypto_kem_dec" in source
    assert "int high_dec_rc = TEST_crypto_kem_dec" in source
    assert "if (low_dec_rc != 0 || high_dec_rc != 0)" in source
    assert "int warmup_dec_rc = TEST_crypto_kem_dec" in source
    assert "if (warmup_dec_rc != 0)" in source
    assert "if (dec_rc != 0) measured_dec_contract_failures++;" in source
    assert "if (measured_dec_contract_failures != 0)" in source

    for key, value in OPERAND_V3_METADATA.items():
        if key == "measured_dec_contract_failures":
            assert "measured_dec_contract_failures=%zu" in source
            assert "measured_dec_contract_failures," in source
        else:
            assert f"{key}={value}" in source


def test_operand_legacy_config_keeps_pool_contract_with_v7_masked_materialization():
    implicit = _render_operand(_operand_harness())
    explicit = _render_operand(_operand_harness(operand_setup_contract="legacy-class-pools"))

    assert implicit == explicit
    assert "ctkat_select_bytes(\n            sk_work" in implicit
    assert "ctkat_select_bytes(\n            ct_work" in implicit
    assert "class_setup_contract=dual-read-masked-select-v4" in implicit
    assert "data_class ? CTKAT_SLOT" not in implicit
    assert "pool0_ct" in implicit
    assert "class_contract=frozen-public-coefficient-bins" in implicit
    assert " setup_contract=same-address-branchless-v3" not in implicit
    assert "class_address_policy=" not in implicit
    assert "measured_dec_contract_failures=" not in implicit
    assert "_mm_mfence();" not in implicit


def _protocol_input_contract(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    backend: str = "official-dudect",
    corrupt_call: int | None = None,
) -> tuple[dict, int]:
    harness = _operand_harness(operand_setup_contract="same-address-branchless-v3")
    dudect = DudectConfig(
        backend=backend,
        measurements=100,
        warmup=0,
        batches=2,
        clock="monotonic",
        harnesses=[harness],
    )
    effective_seed = int(dudect.seed)
    calls = 0

    def fake_run(*args, **kwargs):
        nonlocal calls
        calls += 1
        metadata = {
            **OPERAND_V3_METADATA,
            "corpus_seed": str(effective_seed),
            "randomness": "seeded-interpose",
            "measurements": str(kwargs.get("measurements_override") or dudect.measurements),
        }
        if calls == corrupt_call:
            metadata["measured_dec_contract_failures"] = "1"
        cycles = [float(100 + (i % 3)) if i % 2 == 0 else float(110 + (i % 5)) for i in range(100)]
        return TimingSamples(
            classes=[i & 1 for i in range(100)],
            cycles=cycles,
            raw_n_total=100,
            protocol_version="timing-harness-v2",
            runtime_metadata=metadata,
        )

    monkeypatch.setattr(cli_module, "run_timing_harness", fake_run)
    monkeypatch.setattr(cli_module, "analyze_with_official_dudect", lambda *a, **k: object())
    monkeypatch.setattr(
        cli_module,
        "_official_to_welch",
        lambda result: WelchResult(
            n0=50,
            n1=50,
            mean0=101.0,
            mean1=112.0,
            var0=1.0,
            var1=1.0,
            t_score=-20.0,
            abs_t_score=20.0,
            status="FAIL",
            backend="official-dudect-dc269651",
            enough_measurements=True,
        ),
    )

    _, result, _ = cli_module._run_v2_harness_protocol(
        binary=tmp_path / "operand-bin",
        workdir=tmp_path,
        dud=dudect,
        harness=harness,
        effective_seed=effective_seed,
        official_adapter=(tmp_path / "adapter" if backend == "official-dudect" else None),
        crop=False,
        crop_warn_t=4.5,
        crop_fail_t=10.0,
        warn_t=4.5,
        fail_t=10.0,
    )
    return result.harness_protocol["input_contract"], calls


def test_operand_v3_cli_input_contract_validates_all_21_traces(monkeypatch, tmp_path):
    contract, calls = _protocol_input_contract(monkeypatch, tmp_path)

    assert calls == 21
    assert contract["traces_required"] == 21
    assert contract["traces_validated"] == 21
    assert contract["setup_contract"] == "same-address-branchless-v3"
    assert contract["class_address_policy"] == "fixed-sk-and-shared-ct-work"
    assert contract["measured_dec_contract_failures"] == 0
    assert contract["passed"] is True


def test_operand_v3_cli_input_contract_fails_closed(monkeypatch, tmp_path):
    corrupt, calls = _protocol_input_contract(monkeypatch, tmp_path, corrupt_call=7)
    assert calls == 21
    assert corrupt["measured_dec_contract_failures"] == 1
    assert corrupt["passed"] is False

    partial, calls = _protocol_input_contract(
        monkeypatch,
        tmp_path,
        backend="experimental-first-order",
    )
    assert calls == 18
    assert partial["traces_required"] == 21
    assert partial["traces_validated"] == 18
    assert partial["passed"] is False


def _independent_operand_report() -> dict:
    base_seed = 1234

    def metadata():
        return {**OPERAND_V3_METADATA, "corpus_seed": str(base_seed)}

    target_repeats = []
    aa_controls = []
    placebo_controls = []
    positive_controls = []
    all_metadata = []
    next_seed = base_seed
    for process_index in range(3):
        analysis_metadata = metadata()
        calibration_metadata = metadata()
        target_repeats.append(
            {
                "process_index": process_index,
                "analysis_seed": next_seed,
                "calibration_seed": next_seed + 1,
                "runtime_metadata": analysis_metadata,
                "calibration_runtime_metadata": calibration_metadata,
            }
        )
        next_seed += 2
        all_metadata.extend([analysis_metadata, calibration_metadata])
        aa_metadata = metadata()
        aa_controls.append(
            {
                "process_index": process_index,
                "seed": next_seed,
                "runtime_metadata": aa_metadata,
            }
        )
        next_seed += 1
        all_metadata.append(aa_metadata)
        placebo_metadata = metadata()
        placebo_controls.append(
            {
                "process_index": process_index,
                "seed": next_seed,
                "runtime_metadata": placebo_metadata,
            }
        )
        next_seed += 1
        all_metadata.append(placebo_metadata)
        for effect_ticks in (64, 512, 4096):
            positive_metadata = metadata()
            positive_controls.append(
                {
                    "process_index": process_index,
                    "seed": next_seed,
                    "effect_ticks": effect_ticks,
                    "runtime_metadata": positive_metadata,
                }
            )
            next_seed += 1
            all_metadata.append(positive_metadata)
    protocol = {
        "axis": "operand_bin",
        "process_repeats_observed": 3,
        "target_repeats": target_repeats,
        "aa_controls": aa_controls,
        "setup_placebo_controls": placebo_controls,
        "positive_controls": positive_controls,
        "input_contract": build_operand_v3_input_contract(
            all_metadata,
            base_seed=base_seed,
            traces_required=21,
            backend_is_official=True,
        ),
    }
    return {
        "analysis_seed": target_repeats[0]["analysis_seed"],
        "analysis_runtime_metadata": target_repeats[0]["runtime_metadata"],
        "harness_protocol": protocol,
    }


def test_operand_v3_independent_validator_reconstructs_all_21_trace_contracts():
    report = _independent_operand_report()

    assert (
        validate_operand_v3_harness_report(
            report,
            base_seed=1234,
            label="operand",
        )
        == []
    )


def test_operand_v3_independent_validator_rejects_self_consistent_backend_tampering():
    report = _independent_operand_report()
    protocol = report["harness_protocol"]
    protocol["setup_placebo_controls"][0]["runtime_metadata"]["placebo_coefficient"] = "45124"

    errors = validate_operand_v3_harness_report(
        report,
        base_seed=1234,
        label="operand",
    )

    assert any("placebo_coefficient" in error for error in errors)
    assert any("reconstructed contract" in error for error in errors)
