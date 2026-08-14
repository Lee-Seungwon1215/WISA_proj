#!/usr/bin/env python3
"""Validate Falcon comparator provenance, profiles, taint boundaries, and KATs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctkat.config import HarnessConfig, load_config  # noqa: E402
from ctkat.timing_binary_contract import load_timing_binary_contract  # noqa: E402
from scripts.check_third_party import tree_sha256  # noqa: E402

MANIFEST_PATH = ROOT / "docs/ground_truth/falcon/manifest.yaml"
STRUCTURAL_PATH = ROOT / "docs/ground_truth/falcon/structural_evidence_x86_64.yaml"
FP_AUDIT_PATH = ROOT / "docs/ground_truth/falcon/fp_audit_x86_64.json"
UPSTREAM = ROOT / "examples/fndsa_prospective/upstream"
ADAPTER = ROOT / "examples/fndsa_prospective/adapter.c"
KAT = ROOT / "examples/fndsa_prospective/kat.c"
DETERMINISTIC_RANDOMBYTES = ROOT / "examples/falcon_comparator_support/deterministic_randombytes.c"
TIMING_CAMPAIGN_PATH = ROOT / "docs/measurement/falcon_native_v4.yaml"
TIMING_BINARY_CONTRACT_PATH = (
    ROOT / "examples/falcon_comparator_support/timing_binary_contracts_v1.yaml"
)

PQ_TIMING_CFLAGS = ["-std=c99", "-O2", "-g", "-fno-omit-frame-pointer", "-fno-lto"]
FNDSA_TIMING_COMMON_CFLAGS = [
    "-std=c99",
    "-O2",
    "-g",
    "-fno-omit-frame-pointer",
    "-fno-lto",
    "-D_GNU_SOURCE",
]
FALCON_TIMING_TARGETS = {
    "pqclean_falcon512_reference": {
        "config": "examples/pqc_falcon512/ctkat.yaml",
        "cflags": PQ_TIMING_CFLAGS,
        "degree": "512",
        "profile": "pqclean",
    },
    "pqclean_falcon1024_reference": {
        "config": "examples/pqc_falcon1024/ctkat_timing.yaml",
        "cflags": PQ_TIMING_CFLAGS,
        "degree": "1024",
        "profile": "pqclean",
    },
    "c_fndsa512_native_fp": {
        "config": "examples/c_fndsa512_prospective/ctkat_timing_native.yaml",
        "cflags": FNDSA_TIMING_COMMON_CFLAGS + ["-DCTKAT_FNDSA_LOGN=9", "-DFNDSA_AVX2=0"],
        "degree": "512",
        "profile": "native_fp",
    },
    "c_fndsa1024_native_fp": {
        "config": "examples/c_fndsa1024_prospective/ctkat_timing_native.yaml",
        "cflags": FNDSA_TIMING_COMMON_CFLAGS + ["-DCTKAT_FNDSA_LOGN=10", "-DFNDSA_AVX2=0"],
        "degree": "1024",
        "profile": "native_fp",
    },
    "c_fndsa512_fpr_emu": {
        "config": "examples/c_fndsa512_prospective/ctkat_timing_fpr_emu.yaml",
        "cflags": FNDSA_TIMING_COMMON_CFLAGS
        + [
            "-DCTKAT_FNDSA_LOGN=9",
            "-DFNDSA_AVX2=0",
            "-DFNDSA_SSE2=0",
            "-DFNDSA_NEON=0",
            "-DFNDSA_RV64D=0",
            "-DFNDSA_DIV_EMU=1",
            "-DFNDSA_SQRT_EMU=1",
        ],
        "degree": "512",
        "profile": "integer_fpr",
    },
    "c_fndsa1024_fpr_emu": {
        "config": "examples/c_fndsa1024_prospective/ctkat_timing_fpr_emu.yaml",
        "cflags": FNDSA_TIMING_COMMON_CFLAGS
        + [
            "-DCTKAT_FNDSA_LOGN=10",
            "-DFNDSA_AVX2=0",
            "-DFNDSA_SSE2=0",
            "-DFNDSA_NEON=0",
            "-DFNDSA_RV64D=0",
            "-DFNDSA_DIV_EMU=1",
            "-DFNDSA_SQRT_EMU=1",
        ],
        "degree": "1024",
        "profile": "integer_fpr",
    },
}

COMMON_SOURCES = (
    "codec.c",
    "mq.c",
    "sha3.c",
    "sysrng.c",
    "util.c",
    "kgen.c",
    "kgen_fxp.c",
    "kgen_gauss.c",
    "kgen_mp31.c",
    "kgen_ntru.c",
    "kgen_poly.c",
    "kgen_zint31.c",
    "sign.c",
    "sign_core.c",
    "sign_fpoly.c",
    "sign_fpr.c",
    "sign_sampler.c",
    "vrfy.c",
)
HARDWARE_MACROS = ("FNDSA_SSE2", "FNDSA_NEON", "FNDSA_RV64D")
EMU_FLAGS = (
    "-DFNDSA_AVX2=0",
    "-DFNDSA_SSE2=0",
    "-DFNDSA_NEON=0",
    "-DFNDSA_RV64D=0",
    "-DFNDSA_DIV_EMU=1",
    "-DFNDSA_SQRT_EMU=1",
)
SPLIT_HARNESSES = (
    "sign_little_f_only",
    "sign_little_g_only",
    "sign_big_f_only",
)
BOUNDARY_HARNESSES = {
    "decode_valid_encoded": {"fndsa_trim_i8_decode"},
    "sampler_native_fp": {"ber_exp", "sampler_next_sse2"},
    "sampler_fpr_emu": {"ber_exp", "fndsa_sampler_next"},
    "signature_encoding": {"fndsa_comp_encode"},
}


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Falcon manifest root must be a mapping")
    return data


def load_structural_snapshot(path: Path = STRUCTURAL_PATH) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Falcon structural snapshot root must be a mapping")
    return data


def load_fp_audit(path: Path = FP_AUDIT_PATH) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Falcon FP audit root must be an object")
    return data


def load_timing_campaign(path: Path = TIMING_CAMPAIGN_PATH) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Falcon timing campaign root must be a mapping")
    return data


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _repo_path(value: str) -> Path:
    path = (ROOT / value).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"path escapes repository: {value}") from exc
    return path


def _only_harness(config_path: Path, name: str) -> HarnessConfig:
    config = load_config(config_path)
    if config.ct is None:
        raise ValueError(f"{config_path}: missing ct section")
    matches = [harness for harness in config.ct.harnesses if harness.name == name]
    if len(matches) != 1:
        raise ValueError(f"{config_path}: expected exactly one {name!r} harness")
    return matches[0]


def _flags(harness: HarnessConfig) -> set[str]:
    return set(harness.cflags or [])


def _region_pairs(harness: HarnessConfig) -> list[tuple[str, str]]:
    return [(region.offset, region.length) for region in harness.secret_regions]


def _exact_fp_rule(rule: dict[str, Any], count: int) -> bool:
    return rule.get("floating_point") == {"min_count": count, "max_count": count}


def validate_timing_campaign(
    campaign: dict[str, Any] | None = None,
) -> list[str]:
    """Close the six-target native campaign over configs and linked contracts."""

    errors: list[str] = []
    campaign = load_timing_campaign() if campaign is None else campaign
    if campaign.get("schema_version") != "1.0":
        errors.append("Falcon timing campaign schema_version must be '1.0'")
    if campaign.get("campaign_id") != "falcon-native-v4":
        errors.append("Falcon timing campaign_id drifted")
    if campaign.get("coverage_mode") != "manifest-only":
        errors.append("Falcon timing campaign coverage_mode drifted")
    if campaign.get("protocol", {}).get("compiler") != "gcc":
        errors.append("Falcon timing campaign compiler must be gcc")

    records = campaign.get("targets")
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        return errors + ["Falcon timing campaign targets must be a mapping list"]
    ids = [str(item.get("id", "")) for item in records]
    if len(ids) != len(set(ids)):
        errors.append("Falcon timing campaign target ids are duplicated")
    if set(ids) != set(FALCON_TIMING_TARGETS):
        errors.append("Falcon timing campaign target set drifted")

    loaded_contract_root: dict[str, Any] | None = None
    for record in records:
        target = str(record.get("id", ""))
        expected = FALCON_TIMING_TARGETS.get(target)
        if expected is None:
            continue
        if record.get("config") != expected["config"]:
            errors.append(f"{target}: timing config path drifted")
            continue
        if record.get("harnesses") != ["sign"] or record.get("axes") != {"sign": "sk"}:
            errors.append(f"{target}: timing harness/axis drifted")

        config_path = _repo_path(expected["config"])
        config = load_config(config_path)
        if config.project.name != target:
            errors.append(f"{target}: timing config project name drifted")
        if config.dudect is None:
            errors.append(f"{target}: dudect config missing")
            continue
        if config.dudect.compiler.cc != "gcc":
            errors.append(f"{target}: timing compiler must be gcc")
        expected_cflags = expected["cflags"]
        if config.dudect.compiler.cflags != expected_cflags:
            errors.append(f"{target}: exact timing cflags drifted")
        if len(config.dudect.harnesses) != 1 or config.dudect.harnesses[0].name != "sign":
            errors.append(f"{target}: expected exactly one sign timing harness")
            continue
        harness = config.dudect.harnesses[0]
        contract_ref = harness.binary_contract
        if contract_ref is None:
            errors.append(f"{target}: linked-binary contract missing")
            continue
        resolved_manifest = (config_path.parent / contract_ref.manifest).resolve()
        if resolved_manifest != TIMING_BINARY_CONTRACT_PATH.resolve():
            errors.append(f"{target}: linked-binary contract manifest drifted")
            continue
        if contract_ref.target != target:
            errors.append(f"{target}: linked-binary contract target drifted")
            continue

        contract_root, rule = load_timing_binary_contract(resolved_manifest, target)
        loaded_contract_root = contract_root
        if rule["compiler"] != "gcc" or rule["cflags"] != expected_cflags:
            errors.append(f"{target}: contract toolchain tuple differs from config")
        expected_group = f"falcon-{expected['degree']}-full-sign-gcc-O2"
        if rule.get("comparison_group") != expected_group:
            errors.append(f"{target}: contract comparison group drifted")

        symbols = rule["symbols"]
        profile = expected["profile"]
        if profile == "pqclean":
            sampler = f"PQCLEAN_FALCON{expected['degree']}_CLEAN_sampler"
            if set(symbols) != {sampler} or not _exact_fp_rule(symbols.get(sampler, {}), 0):
                errors.append(f"{target}: PQClean software-FPR sampler contract drifted")
        elif profile == "native_fp":
            if set(symbols) != {"fndsa_sampler_next", "sampler_next_sse2"}:
                errors.append(f"{target}: native sampler symbol set drifted")
            entry = symbols.get("fndsa_sampler_next", {})
            implementation = symbols.get("sampler_next_sse2", {})
            if not _exact_fp_rule(entry, 0) or entry.get("required_tail_targets") != [
                "sampler_next_sse2"
            ]:
                errors.append(f"{target}: native sampler entry/tail contract drifted")
            fp_range = implementation.get("floating_point", {})
            if fp_range.get("min_count", 0) < 1 or not isinstance(fp_range.get("max_count"), int):
                errors.append(f"{target}: native sampler implementation FP contract drifted")
        else:
            if set(symbols) != {"fndsa_sampler_next", "sampler_next_sse2"}:
                errors.append(f"{target}: integer-FPR sampler symbol set drifted")
            if not _exact_fp_rule(symbols.get("fndsa_sampler_next", {}), 0):
                errors.append(f"{target}: integer-FPR sampler FP contract drifted")
            if symbols.get("sampler_next_sse2") != {"present": False}:
                errors.append(f"{target}: integer-FPR SSE2 absence contract drifted")

    if loaded_contract_root is not None and set(loaded_contract_root["targets"]) != set(
        FALCON_TIMING_TARGETS
    ):
        errors.append("Falcon timing binary-contract target set drifted")
    return errors


def validate_static(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if manifest.get("status") != "build-and-structural-comparator":
        errors.append("status must remain build-and-structural-comparator")

    sources = manifest.get("sources", {})
    if set(sources) != {"pqclean", "c_fndsa"}:
        errors.append("sources must define exactly pqclean and c_fndsa")
        return errors

    for source_name, source in sources.items():
        revision = str(source.get("revision", ""))
        if len(revision) != 40 or any(ch not in "0123456789abcdef" for ch in revision):
            errors.append(f"{source_name}: revision must be a full lowercase commit hash")

    pqclean = sources["pqclean"]
    if pqclean.get("role") != "reference":
        errors.append("PQClean role must be reference")
    if pqclean.get("standard_identity") != "Falcon":
        errors.append("PQClean standard identity must be Falcon")
    if pqclean.get("constant_time_implementation_claim") is not False:
        errors.append("PQClean reference must not carry a constant-time claim")

    expected_reference_regions = {
        "512": [("1", "384"), ("385", "384"), ("769", "512")],
        "1024": [("1", "640"), ("641", "640"), ("1281", "1024")],
    }
    for degree, record in pqclean.get("degrees", {}).items():
        import_path = _repo_path(record["import_path"])
        actual_tree = tree_sha256(import_path)
        if actual_tree != record["tree_sha256"]:
            errors.append(
                f"PQClean Falcon-{degree}: tree hash drift "
                f"(expected {record['tree_sha256']}, got {actual_tree})"
            )
        config_path = _repo_path(record["config"])
        config = load_config(config_path)
        if config.project.name != record["target"]:
            errors.append(
                f"PQClean Falcon-{degree}: config project {config.project.name!r} "
                f"does not match target {record['target']!r}"
            )
        sign = _only_harness(config_path, "sign")
        expected_full = f"PQCLEAN_FALCON{degree}_CLEAN_CRYPTO_SECRETKEYBYTES - 1"
        if _region_pairs(sign) != [("1", expected_full)]:
            errors.append(f"PQClean Falcon-{degree}: full encoded-key taint drift")
        if not any(path.name == DETERMINISTIC_RANDOMBYTES.name for path in sign.sources):
            errors.append(f"PQClean Falcon-{degree}: deterministic randombytes interposer missing")

        split = load_config(_repo_path(record["split_config"]))
        if split.ct is None:
            errors.append(f"PQClean Falcon-{degree}: split config lacks ct section")
        else:
            actual_regions: list[tuple[str, str]] = []
            for name in SPLIT_HARNESSES:
                matches = [item for item in split.ct.harnesses if item.name == name]
                if len(matches) != 1 or len(matches[0].secret_regions) != 1:
                    errors.append(f"PQClean Falcon-{degree}: split harness {name} is not singular")
                    continue
                if not any(
                    path.name == DETERMINISTIC_RANDOMBYTES.name for path in matches[0].sources
                ):
                    errors.append(
                        f"PQClean Falcon-{degree}/{name}: deterministic "
                        "randombytes interposer missing"
                    )
                region = matches[0].secret_regions[0]
                actual_regions.append((region.offset, region.length))
            if actual_regions != expected_reference_regions[degree]:
                errors.append(
                    f"PQClean Falcon-{degree}: split regions {actual_regions!r} "
                    f"do not match {expected_reference_regions[degree]!r}"
                )

    c_fndsa = sources["c_fndsa"]
    if c_fndsa.get("role") != "constant-time-comparator":
        errors.append("c-fn-dsa role must be constant-time-comparator")
    if c_fndsa.get("standard_identity") != "prospective-fn-dsa":
        errors.append("c-fn-dsa must remain labeled prospective-fn-dsa")
    if c_fndsa.get("conformance") != "none":
        errors.append("c-fn-dsa conformance must remain none")
    c_fndsa_path = _repo_path(c_fndsa["import_path"])
    actual_tree = tree_sha256(c_fndsa_path)
    if actual_tree != c_fndsa["tree_sha256"]:
        errors.append(
            f"c-fn-dsa tree hash drift (expected {c_fndsa['tree_sha256']}, got {actual_tree})"
        )

    profile_records = c_fndsa.get("profiles", {})
    if set(profile_records) != {"native_fp", "integer_fpr"}:
        errors.append("c-fn-dsa profiles must be native_fp and integer_fpr")
        return errors

    for degree, record in c_fndsa.get("degrees", {}).items():
        config_path = _repo_path(record["config"])
        config = load_config(config_path)
        if config.project.name != record["target"]:
            errors.append(
                f"c-fn-dsa-{degree}: config project {config.project.name!r} "
                f"does not match target {record['target']!r}"
            )
        expected_logn_flag = f"-DCTKAT_FNDSA_LOGN={record['logn']}"
        expected_secret_length = "CTKAT_FNDSA_CRYPTO_SECRETKEYBYTES - 65"
        for profile_name, profile in profile_records.items():
            harness = _only_harness(config_path, profile["harness"])
            actual_flags = _flags(harness)
            required = set(profile["required_flags"])
            if not required.issubset(actual_flags):
                errors.append(
                    f"c-fn-dsa-{degree}/{profile_name}: missing flags "
                    f"{sorted(required - actual_flags)}"
                )
            if expected_logn_flag not in actual_flags:
                errors.append(f"c-fn-dsa-{degree}/{profile_name}: missing {expected_logn_flag}")
            for forbidden in profile.get("forbidden_forced_flags", []):
                if forbidden in actual_flags:
                    errors.append(f"c-fn-dsa-{degree}/{profile_name}: forbidden flag {forbidden}")
            if _region_pairs(harness) != [("1", expected_secret_length)]:
                errors.append(f"c-fn-dsa-{degree}/{profile_name}: encoded-key taint boundary drift")
            source_names = {path.name for path in harness.sources}
            missing_sources = set(COMMON_SOURCES) - source_names
            if missing_sources:
                errors.append(
                    f"c-fn-dsa-{degree}/{profile_name}: missing sources {sorted(missing_sources)}"
                )
            if "adapter.c" not in source_names:
                errors.append(f"c-fn-dsa-{degree}/{profile_name}: adapter.c missing")

        split_path = _repo_path(record["split_config"])
        split = load_config(split_path)
        if split.ct is None:
            errors.append(f"c-fn-dsa-{degree}: split config lacks ct section")
        else:
            actual_regions = []
            for name in SPLIT_HARNESSES:
                matches = [item for item in split.ct.harnesses if item.name == name]
                if len(matches) != 1 or len(matches[0].secret_regions) != 1:
                    errors.append(f"c-fn-dsa-{degree}: split harness {name} is not singular")
                    continue
                harness = matches[0]
                region = harness.secret_regions[0]
                actual_regions.append((region.offset, region.length))
                split_flags = set(harness.cflags if harness.cflags is not None else split.ct.cflags)
                missing_emu = set(EMU_FLAGS) - split_flags
                if missing_emu:
                    errors.append(
                        f"c-fn-dsa-{degree}/{name}: split profile missing flags "
                        f"{sorted(missing_emu)}"
                    )
            if actual_regions != expected_reference_regions[degree]:
                errors.append(
                    f"c-fn-dsa-{degree}: split regions {actual_regions!r} "
                    f"do not match {expected_reference_regions[degree]!r}"
                )

        boundary_path = _repo_path(record["boundary_config"])
        boundary = load_config(boundary_path)
        if boundary.ct is None:
            errors.append(f"c-fn-dsa-{degree}: boundary config lacks ct section")
        else:
            actual_names = {item.name for item in boundary.ct.harnesses}
            if actual_names != set(BOUNDARY_HARNESSES):
                errors.append(
                    f"c-fn-dsa-{degree}: boundary harnesses {sorted(actual_names)!r} "
                    f"do not match {sorted(BOUNDARY_HARNESSES)!r}"
                )
            for harness in boundary.ct.harnesses:
                flags = _flags(harness)
                if harness.name == "sampler_native_fp":
                    if any(flag in flags for flag in EMU_FLAGS[1:]):
                        errors.append(f"c-fn-dsa-{degree}: native boundary forced emulation")
                elif harness.name in BOUNDARY_HARNESSES:
                    missing_emu = set(EMU_FLAGS) - flags
                    if missing_emu:
                        errors.append(
                            f"c-fn-dsa-{degree}/{harness.name}: boundary profile "
                            f"missing flags {sorted(missing_emu)}"
                        )

    source_needles = {
        "README.md": (
            "no FN-DSA draft has been",
            "best guess",
            "The API works only with keys in their encoded formats.",
        ),
        "inner.h": (
            "#define FNDSA_SSE2",
            "#define FNDSA_NEON",
            "#define FNDSA_RV64D",
            "#define FNDSA_DIV_EMU",
            "#define FNDSA_SQRT_EMU",
        ),
        "sign_fpr.c": ("fpr_div", "fpr_sqrt"),
        "sign_core.c": (
            "#if !(FNDSA_SSE2 || FNDSA_NEON || FNDSA_RV64D)",
            "for (uint8_t counter = 0; counter < 27; counter ++)",
        ),
        "sign_inner.h": ("Infinites, NaNs and", "denormals are not used"),
    }
    for name, needles in source_needles.items():
        text = (UPSTREAM / name).read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                errors.append(f"c-fn-dsa {name}: expected source marker missing: {needle!r}")

    adapter_text = ADAPTER.read_text(encoding="utf-8")
    for needle in ("fndsa_keygen_seeded(", "fndsa_sign_seeded(", "fndsa_verify("):
        if needle not in adapter_text:
            errors.append(f"adapter: missing deterministic/API marker {needle!r}")

    randombytes_text = DETERMINISTIC_RANDOMBYTES.read_text(encoding="utf-8")
    for needle in (
        "PQCLEAN_randombytes(",
        "NOT a cryptographic RNG",
        "ctkat_falcon_prng",
    ):
        if needle not in randombytes_text:
            errors.append(f"PQClean deterministic randombytes: expected marker missing {needle!r}")

    versioned_evidence = manifest.get("versioned_evidence", {})
    if versioned_evidence.get("structural_snapshot") != str(STRUCTURAL_PATH.relative_to(ROOT)):
        errors.append("structural snapshot path drifted")
    if versioned_evidence.get("floating_point_audit") != str(FP_AUDIT_PATH.relative_to(ROOT)):
        errors.append("floating-point audit path drifted")

    policy = manifest.get("evidence_policy", {})
    if policy.get("physical_timing") != "not-run":
        errors.append("physical timing must remain not-run until a native campaign is reviewed")
    if policy.get("timing_blocker") != "blocked-by-native-linux-host":
        errors.append("native timing blocker drifted")
    errors.extend(validate_timing_campaign())
    return errors


def _target_records(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for source_name in ("pqclean", "c_fndsa"):
        for record in manifest["sources"][source_name]["degrees"].values():
            records[record["target"]] = record
    return records


def validate_structural_snapshot(manifest: dict[str, Any], snapshot: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if snapshot.get("schema_version") != 1:
        errors.append("structural snapshot schema_version must be 1")
    if snapshot.get("kind") != "ctkat-falcon-structural-snapshot":
        errors.append("structural snapshot kind drifted")

    environment = snapshot.get("environment", {})
    if environment.get("system") != "Linux" or environment.get("machine") != "x86_64":
        errors.append("structural snapshot must remain Linux/x86_64")
    if environment.get("execution") != "docker-desktop-qemu":
        errors.append("structural snapshot execution mode drifted")
    if environment.get("native_timing_evidence") is not False:
        errors.append("QEMU structural snapshot cannot be timing evidence")
    if environment.get("tools") != {
        "gcc": "13.3.0",
        "clang": "18.1.3",
        "valgrind": "3.22.0",
        "binutils": "2.42",
    }:
        errors.append("structural snapshot toolchain tuple drifted")

    source = snapshot.get("source", {})
    if source.get("pqclean_revision") != manifest["sources"]["pqclean"]["revision"]:
        errors.append("structural snapshot PQClean revision drifted")
    if source.get("c_fndsa_revision") != manifest["sources"]["c_fndsa"]["revision"]:
        errors.append("structural snapshot c-fn-dsa revision drifted")

    target_records = _target_records(manifest)
    matrices = snapshot.get("full_sign_matrices", {})
    if set(matrices) != set(target_records):
        errors.append("structural snapshot matrix target set drifted")
    expected_cells = {
        "pqclean_falcon512_reference": {
            "gcc_debug",
            "gcc_opt1",
            "gcc_release",
            "gcc_opt3",
            "clang_debug",
            "clang_opt1",
            "clang_release",
            "clang_opt3",
        }
    }
    default_cells = {"gcc_debug", "gcc_release", "clang_debug", "clang_release"}
    for target, record in matrices.items():
        if target not in target_records:
            continue
        if record.get("config") != target_records[target]["config"]:
            errors.append(f"{target}: structural matrix config path drifted")
        harnesses = record.get("harnesses", {})
        expected_harnesses = (
            {"sign"} if target.startswith("pqclean_") else {"sign_native_fp", "sign_fpr_emu"}
        )
        if set(harnesses) != expected_harnesses:
            errors.append(f"{target}: structural matrix harness set drifted")
        for harness_name, harness in harnesses.items():
            cells = harness.get("cells", {})
            target_cells = expected_cells.get(target, default_cells)
            if set(cells) != target_cells:
                errors.append(f"{target}/{harness_name}: matrix cell set drifted")
            for combo, cell in cells.items():
                if cell.get("status") != "FAIL":
                    errors.append(f"{target}/{harness_name}/{combo}: expected FAIL")
                if not isinstance(cell.get("findings"), int) or cell["findings"] <= 0:
                    errors.append(f"{target}/{harness_name}/{combo}: invalid finding count")
            functions = set(harness.get("function_union", []))
            if target.startswith("pqclean_"):
                required = {"BerExp", "do_sign_dyn", "fpr_floor"}
            else:
                required = {
                    "ber_exp",
                    "fndsa_comp_encode",
                    "fndsa_sign_core",
                    "fndsa_trim_i8_decode",
                    "sign_step1",
                }
                required.add(
                    "sampler_next_sse2"
                    if harness_name == "sign_native_fp"
                    else "fndsa_sampler_next"
                )
            if not required.issubset(functions):
                errors.append(
                    f"{target}/{harness_name}: structural function union "
                    f"missing {sorted(required - functions)}"
                )
        replay = record.get("deterministic_replay")
        if target.startswith("pqclean_"):
            if not isinstance(replay, dict):
                errors.append(f"{target}: deterministic matrix replay missing")
            elif replay.get("runs") != 2 or replay.get("byte_identical") is not True:
                errors.append(f"{target}: deterministic matrix replay drifted")

    boundary_records = snapshot.get("c_fndsa_boundary_probes", {})
    expected_c_fndsa = {
        record["target"] for record in manifest["sources"]["c_fndsa"]["degrees"].values()
    }
    if set(boundary_records) != expected_c_fndsa:
        errors.append("c-fn-dsa boundary target set drifted")
    for target, record in boundary_records.items():
        harnesses = record.get("harnesses", {})
        if set(harnesses) != set(BOUNDARY_HARNESSES):
            errors.append(f"{target}: boundary snapshot harness set drifted")
            continue
        for name, expected_functions in BOUNDARY_HARNESSES.items():
            actual = set(harnesses[name].get("functions", []))
            if actual != expected_functions:
                errors.append(f"{target}/{name}: boundary function set drifted")
            if harnesses[name].get("findings") != len(expected_functions):
                if name != "signature_encoding":
                    errors.append(f"{target}/{name}: boundary finding count drifted")
            if name == "signature_encoding" and harnesses[name].get("findings") != 3:
                errors.append(f"{target}/{name}: boundary finding count drifted")

    split_records = snapshot.get("encoded_origin_split", {})
    if set(split_records) != set(target_records):
        errors.append("encoded-origin split target set drifted")
    for target, record in split_records.items():
        harnesses = record.get("harnesses", {})
        if set(harnesses) != set(SPLIT_HARNESSES):
            errors.append(f"{target}: encoded-origin harness set drifted")
            continue
        for name, harness in harnesses.items():
            if not isinstance(harness.get("findings"), int) or harness["findings"] <= 0:
                errors.append(f"{target}/{name}: split finding count is invalid")
            functions = set(harness.get("functions", []))
            if target.startswith("pqclean_"):
                required = {"BerExp", "do_sign_dyn", "fpr_floor"}
            else:
                required = {
                    "ber_exp",
                    "fndsa_comp_encode",
                    "fndsa_sampler_next",
                    "fndsa_sign_core",
                    "fndsa_trim_i8_decode",
                }
            if not required.issubset(functions):
                errors.append(
                    f"{target}/{name}: split function set missing {sorted(required - functions)}"
                )

    core = snapshot.get("pqclean512_core_split", {}).get("harnesses", {})
    if set(core) != {"sign_core_dyn", "sign_core_tree"}:
        errors.append("PQClean Falcon-512 core split drifted")
    else:
        for name, expected_parent in (
            ("sign_core_dyn", "do_sign_dyn"),
            ("sign_core_tree", "do_sign_tree"),
        ):
            functions = set(core[name].get("functions", []))
            if not {"BerExp", "fpr_floor", expected_parent}.issubset(functions):
                errors.append(f"PQClean Falcon-512/{name}: core functions drifted")

    scans = snapshot.get("integer_division_scan", {})
    if set(scans) != set(target_records):
        errors.append("integer-division scan target set drifted")
    for target, record in scans.items():
        rows = record.get("candidate_rows")
        functions = set(record.get("functions", []))
        if target.startswith("c_fndsa"):
            if rows != 0 or functions:
                errors.append(f"{target}: expected no integer-division candidates")
        elif rows not in {3, 6} or functions != {
            "shake128",
            "shake256",
            "solve_NTRU_intermediate",
        }:
            errors.append(f"{target}: PQClean integer-division snapshot drifted")
    return errors


def validate_fp_audit(manifest: dict[str, Any], audit: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if audit.get("schema_version") != 1:
        errors.append("FP audit schema_version must be 1")
    if audit.get("kind") != "ctkat-falcon-floating-point-build-audit":
        errors.append("FP audit kind drifted")

    host = audit.get("host", {})
    if host.get("system") != "Linux" or host.get("machine") != "x86_64":
        errors.append("FP audit must remain Linux/x86_64")
    if host.get("qemu_emulation_detected") is not True:
        errors.append("FP audit must disclose QEMU emulation")
    if host.get("timing_evidence") is not False:
        errors.append("FP opcode audit cannot be timing evidence")

    c_fndsa = manifest["sources"]["c_fndsa"]
    source = audit.get("source", {})
    for field in ("revision", "tree_sha256", "standard_identity", "conformance"):
        if source.get(field) != c_fndsa.get(field):
            errors.append(f"FP audit source field drifted: {field}")

    classification = audit.get("classification", {})
    if classification.get("opcode_presence_is_leak_verdict") is not False:
        errors.append("FP opcode presence must not be a leak verdict")
    if classification.get("fenv_screen_proves_global_nonexceptional_range") is not False:
        errors.append("FP exception screen must not claim a global proof")

    targets = {int(degree): record for degree, record in c_fndsa["degrees"].items()}
    expected_pairs = {
        (degree, profile) for degree in targets for profile in ("native_fp", "integer_fpr")
    }
    profiles = audit.get("profiles")
    if not isinstance(profiles, list):
        return errors + ["FP audit profiles must be a list"]
    actual_pairs = {
        (record.get("degree"), record.get("profile"))
        for record in profiles
        if isinstance(record, dict)
    }
    if actual_pairs != expected_pairs:
        errors.append("FP audit degree/profile set drifted")
    for record in profiles:
        if not isinstance(record, dict):
            errors.append("FP audit profile entry must be an object")
            continue
        degree = record.get("degree")
        profile = record.get("profile")
        if degree not in targets or profile not in {"native_fp", "integer_fpr"}:
            continue
        target = targets[degree]
        expected_kat = manifest["deterministic_kat"]["degrees"][str(degree)]
        if record.get("target") != target["target"]:
            errors.append(f"FP audit {degree}/{profile}: target drifted")
        if record.get("transcript_sha256") != expected_kat["transcript_sha256"]:
            errors.append(f"FP audit {degree}/{profile}: transcript drifted")
        if record.get("round_trip") != "pass":
            errors.append(f"FP audit {degree}/{profile}: round trip did not pass")
        if record.get("external_math_symbols") != []:
            errors.append(f"FP audit {degree}/{profile}: external math call present")

        macros = record.get("resolved_macros", {})
        fp_scope = (
            record.get("instructions", {})
            .get("floating_point", {})
            .get("signing_scope_classes", {})
        )
        integer_division = (
            record.get("instructions", {}).get("integer_division", {}).get("signing_scope", {})
        )
        if integer_division:
            errors.append(f"FP audit {degree}/{profile}: integer division present")
        if profile == "native_fp":
            if macros.get("FNDSA_SSE2") != "1":
                errors.append(f"FP audit {degree}/native_fp: SSE2 not active")
            if any(macros.get(name) != "0" for name in ("FNDSA_NEON", "FNDSA_RV64D")):
                errors.append(f"FP audit {degree}/native_fp: non-x86 backend active")
            for instruction_class in ("arithmetic", "division", "sqrt"):
                if fp_scope.get(instruction_class, 0) <= 0:
                    errors.append(f"FP audit {degree}/native_fp: no {instruction_class} opcodes")
            if record.get("fenv_exception_screen") != "pass":
                errors.append(f"FP audit {degree}/native_fp: fenv screen failed")
        else:
            if any(macros.get(name) != "0" for name in HARDWARE_MACROS):
                errors.append(f"FP audit {degree}/integer_fpr: hardware FP active")
            if macros.get("FNDSA_DIV_EMU") != "1" or macros.get("FNDSA_SQRT_EMU") != "1":
                errors.append(f"FP audit {degree}/integer_fpr: emulation inactive")
            if set(fp_scope) - {"move_or_sign"}:
                errors.append(f"FP audit {degree}/integer_fpr: arithmetic FP opcode present")
            if record.get("fenv_exception_screen") != "not-applicable-integer-fpr":
                errors.append(f"FP audit {degree}/integer_fpr: fenv label drifted")
    return errors


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise ValueError(f"local evidence report missing: {path.relative_to(ROOT)}")
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _validate_finding_report(
    errors: list[str],
    label: str,
    path: Path,
    expected_harnesses: dict[str, Any],
) -> None:
    rows = _read_csv(path)
    actual_names = {row["harness"] for row in rows}
    if actual_names != set(expected_harnesses):
        errors.append(f"{label}: report harness set drifted")
        return
    for name, expected in expected_harnesses.items():
        selected = [row for row in rows if row["harness"] == name]
        functions = {row["function"] for row in selected}
        if len(selected) != expected["findings"]:
            errors.append(f"{label}/{name}: {len(selected)} findings != {expected['findings']}")
        if functions != set(expected["functions"]):
            errors.append(f"{label}/{name}: finding function set drifted")


def validate_local_reports(manifest: dict[str, Any], snapshot: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for target, record in snapshot["full_sign_matrices"].items():
        report = _repo_path(record["report"])
        rows = _read_csv(report)
        harnesses = record["harnesses"]
        actual_keys = {(row["harness"], row["combo"]) for row in rows}
        expected_keys = {
            (harness, combo)
            for harness, harness_record in harnesses.items()
            for combo in harness_record["cells"]
        }
        if actual_keys != expected_keys:
            errors.append(f"{target}: local matrix cell set drifted")
            continue
        config_path = _repo_path(record["config"])
        for harness_name, harness_record in harnesses.items():
            expected_flags = {
                flag
                for flag in _flags(_only_harness(config_path, harness_name))
                if flag.startswith("-D")
            }
            selected = [row for row in rows if row["harness"] == harness_name]
            function_union: set[str] = set()
            for row in selected:
                cell = harness_record["cells"][row["combo"]]
                if row["project"] != target:
                    errors.append(f"{target}/{harness_name}: matrix project drifted")
                if row["valgrind_status"] != cell["status"]:
                    errors.append(f"{target}/{harness_name}/{row['combo']}: status drifted")
                if int(row["findings"]) != cell["findings"]:
                    errors.append(f"{target}/{harness_name}/{row['combo']}: count drifted")
                if row["error"]:
                    errors.append(f"{target}/{harness_name}/{row['combo']}: matrix error present")
                function_union.update(filter(None, row["finding_funcs"].split(";")))
                actual_flags = set(shlex.split(row["cflags"]))
                if not expected_flags.issubset(actual_flags):
                    errors.append(
                        f"{target}/{harness_name}/{row['combo']}: effective flags "
                        f"missing {sorted(expected_flags - actual_flags)}"
                    )
            if function_union != set(harness_record["function_union"]):
                errors.append(f"{target}/{harness_name}: matrix function union drifted")

        replay = record.get("deterministic_replay")
        if replay:
            if _sha256(report) != replay["csv_sha256"]:
                errors.append(f"{target}: deterministic matrix CSV hash drifted")
            json_report = report.with_suffix(".json")
            if _sha256(json_report) != replay["json_sha256"]:
                errors.append(f"{target}: deterministic matrix JSON hash drifted")

    for target, record in snapshot["c_fndsa_boundary_probes"].items():
        _validate_finding_report(
            errors,
            f"{target}/boundaries",
            _repo_path(record["report"]),
            record["harnesses"],
        )
    for target, record in snapshot["encoded_origin_split"].items():
        _validate_finding_report(
            errors,
            f"{target}/encoded-origin",
            _repo_path(record["report"]),
            record["harnesses"],
        )
    core = snapshot["pqclean512_core_split"]
    _validate_finding_report(
        errors,
        "pqclean_falcon512_reference/core",
        _repo_path(core["report"]),
        core["harnesses"],
    )
    for target, record in snapshot["integer_division_scan"].items():
        rows = _read_csv(_repo_path(record["report"]))
        if len(rows) != record["candidate_rows"]:
            errors.append(f"{target}: asm candidate row count drifted")
        if {row["function"] for row in rows} != set(record["functions"]):
            errors.append(f"{target}: asm candidate function set drifted")
    return errors


def profile_flags(logn: int, profile: str) -> list[str]:
    common = ["-D_GNU_SOURCE", f"-DCTKAT_FNDSA_LOGN={logn}", "-DFNDSA_AVX2=0"]
    if profile == "native_fp":
        return common + ["-DCTKAT_FNDSA_FENV_CHECK=1"]
    if profile == "integer_fpr":
        return [
            "-D_GNU_SOURCE",
            f"-DCTKAT_FNDSA_LOGN={logn}",
            *EMU_FLAGS,
            "-DCTKAT_FNDSA_FENV_CHECK=0",
        ]
    raise ValueError(f"unknown profile: {profile}")


def macro_dump(cc: str, flags: list[str]) -> dict[str, str]:
    command = [
        cc,
        "-std=c99",
        *flags,
        "-I",
        str(UPSTREAM),
        "-dM",
        "-E",
        "-include",
        "inner.h",
        "-x",
        "c",
        "-",
    ]
    result = subprocess.run(
        command,
        cwd=ROOT,
        input=b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=120,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"macro preprocessing failed: {detail}")
    macros: dict[str, str] = {}
    for line in result.stdout.decode("utf-8").splitlines():
        parts = line.split(maxsplit=2)
        if len(parts) == 3 and parts[0] == "#define":
            macros[parts[1]] = parts[2]
    return macros


def validate_active_profile(profile: str, macros: dict[str, str]) -> None:
    if macros.get("FNDSA_AVX2") != "0":
        raise RuntimeError(f"{profile}: FNDSA_AVX2 did not resolve to 0")
    active = [name for name in HARDWARE_MACROS if macros.get(name) == "1"]
    if profile == "native_fp":
        if len(active) != 1:
            raise RuntimeError(
                "native_fp requires exactly one SSE2/NEON/RV64D backend; "
                f"active={active}, values="
                f"{[(name, macros.get(name)) for name in HARDWARE_MACROS]}"
            )
    elif active:
        raise RuntimeError(f"integer_fpr unexpectedly enabled hardware backends: {active}")


def run_kats(manifest: dict[str, Any], cc: str) -> dict[str, dict[str, str]]:
    compiler_version = subprocess.run(
        [cc, "--version"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
        timeout=30,
        text=True,
    ).stdout.splitlines()[0]
    outcomes: dict[str, dict[str, str]] = {}
    degrees = manifest["sources"]["c_fndsa"]["degrees"]
    kat_records = manifest["deterministic_kat"]["degrees"]
    with tempfile.TemporaryDirectory(prefix="ctkat-falcon-kat-") as tmp:
        temp = Path(tmp)
        for degree in ("512", "1024"):
            logn = int(degrees[degree]["logn"])
            target_dir = _repo_path(degrees[degree]["config"]).parent
            transcripts: dict[str, bytes] = {}
            for profile in ("native_fp", "integer_fpr"):
                flags = profile_flags(logn, profile)
                macros = macro_dump(cc, flags)
                validate_active_profile(profile, macros)
                binary = temp / f"kat_{degree}_{profile}"
                command = [
                    cc,
                    "-std=c99",
                    "-O2",
                    "-fno-strict-aliasing",
                    *flags,
                    "-I",
                    str(target_dir),
                    "-I",
                    str(UPSTREAM),
                    str(ADAPTER),
                    str(KAT),
                    *(str(UPSTREAM / name) for name in COMMON_SOURCES),
                    "-lm",
                    "-o",
                    str(binary),
                ]
                compiled = subprocess.run(
                    command,
                    cwd=ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=900,
                    text=True,
                )
                if compiled.returncode != 0:
                    raise RuntimeError(
                        f"Falcon-{degree}/{profile} compile failed:\n{compiled.stderr}"
                    )
                executed = subprocess.run(
                    [str(binary)],
                    cwd=ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=300,
                )
                if executed.returncode != 0:
                    detail = executed.stderr.decode("utf-8", errors="replace")
                    raise RuntimeError(
                        f"Falcon-{degree}/{profile} KAT failed with "
                        f"exit {executed.returncode}: {detail}"
                    )
                transcripts[profile] = executed.stdout
                expected = kat_records[degree]
                digest = hashlib.sha256(executed.stdout).hexdigest()
                if len(executed.stdout) != expected["transcript_bytes"]:
                    raise RuntimeError(
                        f"Falcon-{degree}/{profile} transcript size "
                        f"{len(executed.stdout)} != {expected['transcript_bytes']}"
                    )
                if digest != expected["transcript_sha256"]:
                    raise RuntimeError(
                        f"Falcon-{degree}/{profile} transcript hash "
                        f"{digest} != {expected['transcript_sha256']}"
                    )
            if transcripts["native_fp"] != transcripts["integer_fpr"]:
                raise RuntimeError(f"Falcon-{degree}: native and emulated KATs differ")
            outcomes[degree] = {
                "transcript_sha256": hashlib.sha256(transcripts["native_fp"]).hexdigest(),
                "compiler": compiler_version,
            }
    return outcomes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument(
        "--static-only",
        action="store_true",
        help="validate manifests/configs/source markers without compiling KATs",
    )
    parser.add_argument(
        "--verify-local-reports",
        action="store_true",
        help="also compare ignored, locally generated reports with the snapshot",
    )
    args = parser.parse_args()
    try:
        manifest = load_manifest()
        errors = validate_static(manifest)
        snapshot = load_structural_snapshot()
        errors.extend(validate_structural_snapshot(manifest, snapshot))
        errors.extend(validate_fp_audit(manifest, load_fp_audit()))
        if args.verify_local_reports:
            errors.extend(validate_local_reports(manifest, snapshot))
        if errors:
            for error in errors:
                print(f"[falcon] ERROR: {error}", file=sys.stderr)
            return 1
        if args.static_only:
            detail = " + local reports" if args.verify_local_reports else ""
            print(f"[falcon] OK: provenance, profiles, boundaries, evidence, and policies{detail}")
            return 0
        outcomes = run_kats(manifest, args.cc)
    except (KeyError, OSError, RuntimeError, ValueError, yaml.YAMLError) as exc:
        print(f"[falcon] ERROR: {exc}", file=sys.stderr)
        return 1

    details = ", ".join(
        f"{degree}={record['transcript_sha256'][:12]}" for degree, record in outcomes.items()
    )
    print(
        f"[falcon] OK: exact provenance + native/integer-FPR byte-identical round trips ({details})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
