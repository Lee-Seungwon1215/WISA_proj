import json
import subprocess
from pathlib import Path

import pytest

from ctkat.timing_binary_contract import (
    TimingBinaryContractError,
    evaluate_disassembly,
    load_timing_binary_contract,
    split_disassembly_symbols,
    verify_timing_binary_contract,
)

ROOT = Path(__file__).resolve().parent.parent


def test_kyberslash_contracts_are_strict_and_selectable():
    manifest = ROOT / "examples/pqc_mlkem768/kyberslash_binary_contracts_v2.yaml"
    root, stock = load_timing_binary_contract(manifest, "stock")
    _, combined = load_timing_binary_contract(manifest, "ks1_ks2")

    assert root["kind"] == "ctkat-timing-binary-instruction-contract"
    assert stock["cflags"] == combined["cflags"]
    assert stock["comparison_group"] == combined["comparison_group"]
    assert {rule["division_count"] for rule in stock["symbols"].values()} == {0}
    assert {rule["division_count"] for rule in combined["symbols"].values()} == {1}


def test_falcon_contracts_freeze_actual_sampler_fp_profiles():
    manifest = ROOT / "examples/falcon_comparator_support/timing_binary_contracts_v1.yaml"
    root, pqclean = load_timing_binary_contract(manifest, "pqclean_falcon512_reference")
    _, native = load_timing_binary_contract(manifest, "c_fndsa512_native_fp")
    _, integer_fpr = load_timing_binary_contract(manifest, "c_fndsa512_fpr_emu")

    assert root["contract_id"] == "falcon-signing-linked-binary-v1"
    assert pqclean["symbols"]["PQCLEAN_FALCON512_CLEAN_sampler"]["floating_point"] == {
        "min_count": 0,
        "max_count": 0,
    }
    assert native["symbols"]["fndsa_sampler_next"]["required_tail_targets"] == ["sampler_next_sse2"]
    assert native["symbols"]["sampler_next_sse2"]["floating_point"]["min_count"] >= 1
    assert integer_fpr["symbols"]["sampler_next_sse2"] == {"present": False}


def test_disassembly_contract_counts_only_exact_symbol_local_divisions():
    disassembly = """
0000000000001000 <wanted>:
    1000:\tf7 f1\tdiv    %ecx
    1002:\tf2 0f 5e c1\tdivsd  %xmm1,%xmm0
    1006:\te8 00 00 00 00\tcall   2000 <other>
0000000000002000 <other>:
    2000:\tf7 f2\tdiv    %edx
"""
    observations, errors = evaluate_disassembly(
        disassembly,
        {
            "wanted": {
                "division_count": 1,
                "forbid_division_helpers": True,
            }
        },
    )
    assert errors == []
    assert observations["wanted"]["division_count"] == 1
    assert observations["wanted"]["floating_point_arithmetic_count"] == 1


def test_disassembly_contract_supports_falcon_fp_presence_and_absence_rules():
    disassembly = """
0000000000001000 <native_fp>:
    1000:\tf2 0f 59 c1\tmulsd  %xmm1,%xmm0
    1004:\tc5 f4 58 c2\tvaddps %ymm2,%ymm1,%ymm0
    1008:\td9 e8\tfld1
    100a:\tde c1\tfaddp  %st,%st(1)
0000000000002000 <integer_fpr>:
    2000:\t48 0f af c1\timul   %rcx,%rax
"""
    observations, errors = evaluate_disassembly(
        disassembly,
        {
            "native_fp": {
                "floating_point": {"min_count": 3, "max_count": 3},
            },
            "integer_fpr": {
                "floating_point": {"min_count": 0, "max_count": 0},
            },
        },
    )
    assert errors == []
    assert observations["native_fp"]["floating_point_arithmetic_count"] == 3
    assert observations["integer_fpr"]["floating_point_arithmetic_count"] == 0


def test_disassembly_contract_checks_exact_tail_target_and_expected_absence():
    disassembly = """
0000000000001000 <fndsa_sampler_next>:
    1000:\t66 48 0f 6e c6\tmovq   %rsi,%xmm0
    1005:\te9 f6 0f 00 00\tjmp    2000 <sampler_next_sse2>
0000000000002000 <sampler_next_sse2>:
    2000:\tf2 0f 59 c1\tmulsd  %xmm1,%xmm0
"""
    observations, errors = evaluate_disassembly(
        disassembly,
        {
            "fndsa_sampler_next": {
                "floating_point": {"min_count": 0, "max_count": 0},
                "required_tail_targets": ["sampler_next_sse2"],
            },
            "sampler_next_sse2": {
                "floating_point": {"min_count": 1, "max_count": 32},
            },
            "integer_only_backend": {"present": False},
        },
    )

    assert errors == []
    assert observations["fndsa_sampler_next"]["tail_targets"] == ["sampler_next_sse2"]
    assert observations["integer_only_backend"]["present"] is False
    assert observations["integer_only_backend"]["expected_present"] is False


def test_disassembly_contract_rejects_tail_target_drift_and_forbidden_symbol():
    disassembly = """
0000000000001000 <fndsa_sampler_next>:
    1000:\te9 fb 0f 00 00\tjmp    2000 <unexpected_backend>
0000000000002000 <sampler_next_sse2>:
    2000:\t90\tnop
"""
    observations, errors = evaluate_disassembly(
        disassembly,
        {
            "fndsa_sampler_next": {
                "required_tail_targets": ["sampler_next_sse2"],
            },
            "sampler_next_sse2": {"present": False},
        },
    )

    assert observations["sampler_next_sse2"]["present"] is True
    assert any("missing required_tail_targets" in error for error in errors)
    assert any("forbidden symbol present" in error for error in errors)


def test_disassembly_contract_fails_closed_on_missing_symbol_and_fp_drift():
    observations, errors = evaluate_disassembly(
        "0000000000001000 <native_fp>:\n    1000:\t90\tnop\n",
        {
            "native_fp": {
                "floating_point": {"min_count": 1, "max_count": 100},
            },
            "missing": {
                "division_count": 0,
                "forbid_division_helpers": True,
            },
        },
    )
    assert observations["missing"]["present"] is False
    assert any("floating-point arithmetic count=0" in error for error in errors)
    assert any("required symbol absent" in error for error in errors)


def test_contract_parser_rejects_inverted_fp_range(tmp_path):
    manifest = tmp_path / "bad.yaml"
    manifest.write_text(
        """
schema_version: "1.0"
kind: ctkat-timing-binary-instruction-contract
contract_id: bad
system: Linux
machines: [x86_64]
disassembler: objdump
file_format_pattern: elf64
targets:
  bad:
    compiler: gcc
    cflags: [-Os]
    symbols:
      f:
        floating_point: {min_count: 2, max_count: 1}
""",
        encoding="utf-8",
    )
    with pytest.raises(TimingBinaryContractError, match="min_count exceeds"):
        load_timing_binary_contract(manifest, "bad")


def test_contract_parser_rejects_instruction_rules_on_absent_symbol(tmp_path):
    manifest = tmp_path / "bad-absence.yaml"
    manifest.write_text(
        """
schema_version: "1.0"
kind: ctkat-timing-binary-instruction-contract
contract_id: bad
system: Linux
machines: [x86_64]
disassembler: objdump
file_format_pattern: elf64
targets:
  bad:
    compiler: gcc
    cflags: [-O2]
    symbols:
      forbidden:
        present: false
        floating_point: {min_count: 0, max_count: 0}
""",
        encoding="utf-8",
    )
    with pytest.raises(TimingBinaryContractError, match="present=false"):
        load_timing_binary_contract(manifest, "bad")


def test_split_disassembly_does_not_merge_neighboring_functions():
    blocks = split_disassembly_symbols(
        "0000000000001000 <a>:\n 1000:\t90\tnop\n0000000000002000 <b>:\n 2000:\tf7 f1\tdiv %ecx\n"
    )
    assert set(blocks) == {"a", "b"}
    assert "div" not in "\n".join(blocks["a"])
    assert "div" in "\n".join(blocks["b"])


def test_verifier_preserves_full_provenance_before_returning(monkeypatch, tmp_path):
    manifest = tmp_path / "contract.yaml"
    manifest.write_text(
        """
schema_version: "1.0"
kind: ctkat-timing-binary-instruction-contract
contract_id: unit
system: Linux
machines: [x86_64]
disassembler: objdump
file_format_pattern: elf64-x86-64
targets:
  vulnerable:
    compiler: gcc
    cflags: [-Os, -fno-lto]
    comparison_group: pair
    evidence_boundary: unit-only
    symbols:
      site: {division_count: 1, forbid_division_helpers: true}
""",
        encoding="utf-8",
    )
    binary = tmp_path / "timing"
    generated = tmp_path / "timing.c"
    linked = tmp_path / "site.c"
    fake_gcc = tmp_path / "gcc"
    fake_objdump = tmp_path / "objdump"
    for path, data in (
        (binary, b"ELF"),
        (generated, b"int main(void){return 0;}\n"),
        (linked, b"unsigned site(unsigned x){return x/3;}\n"),
        (fake_gcc, b"gcc"),
        (fake_objdump, b"objdump"),
    ):
        path.write_bytes(data)

    from ctkat import timing_binary_contract as contract_module

    monkeypatch.setattr(contract_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(contract_module.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(
        contract_module.shutil,
        "which",
        lambda command: str(fake_gcc if command == "gcc" else fake_objdump),
    )

    def fake_run(command, timeout=60):
        del timeout
        if command[-1] == "--version":
            version = (
                "gcc (GCC) 13.3.0\n"
                if command[0] == str(fake_gcc.resolve())
                else "GNU objdump 2.42\n"
            )
            return subprocess.CompletedProcess(command, 0, version, "")
        if "-f" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                "timing: file format elf64-x86-64\narchitecture: i386:x86-64\n",
                "",
            )
        return subprocess.CompletedProcess(
            command,
            0,
            "0000000000001000 <site>:\n 1000:\tf7 f1\tdiv %ecx\n",
            "",
        )

    monkeypatch.setattr(contract_module, "_run", fake_run)
    report = verify_timing_binary_contract(
        manifest_path=manifest,
        target="vulnerable",
        binary_path=binary,
        generated_source_path=generated,
        config_path=None,
        source_paths=[linked],
        compiler="gcc",
        cflags=["-Os", "-fno-lto"],
        compile_command="gcc -Os timing.c site.c -o timing",
        output_dir=tmp_path / "evidence",
    )
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert payload["binary"]["sha256"]
    assert payload["compiler"]["version"] == "gcc (GCC) 13.3.0"
    assert payload["compiler"]["executable"]["version_command"] == [
        str(fake_gcc.resolve()),
        "--version",
    ]
    assert payload["disassembly"]["full_sha256"]
    assert payload["disassembly"]["tool"]["version"] == "GNU objdump 2.42"
    assert payload["disassembly"]["tool"]["version_command"] == [
        str(fake_objdump.resolve()),
        "--version",
    ]
    assert (report.parent / payload["disassembly"]["full_artifact"]).is_file()
