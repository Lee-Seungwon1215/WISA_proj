#!/usr/bin/env python3
"""Verify the frozen KyberSlash variants, provenance, diffs, and KEM equivalence."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctkat.config import HarnessConfig, load_config  # noqa: E402
from scripts.check_third_party import tree_sha256  # noqa: E402

MANIFEST_PATH = ROOT / "docs/ground_truth/kyberslash/ground_truth.yaml"
VARIANT_ORDER = ("stock", "ks1", "ks2", "ks1_ks2")
EXPECTED_SITE_SETS = {
    "stock": set(),
    "ks1": {"ks1_poly_tomsg"},
    "ks2": {"ks2_poly_compress", "ks2_polyvec_compress"},
    "ks1_ks2": {
        "ks1_poly_tomsg",
        "ks2_poly_compress",
        "ks2_polyvec_compress",
    },
}
EXPECTED_TIMECOP_FUNCTIONS = {
    "kem_dec_secret_key_path": {
        "stock": set(),
        "ks1": {"PQCLEAN_MLKEM768_CLEAN_poly_tomsg"},
        "ks2": set(),
        "ks1_ks2": {"PQCLEAN_MLKEM768_CLEAN_poly_tomsg"},
        "historical": {"pqcrystals_kyber768_ref_poly_tomsg"},
    },
    "site_operand_attribution": {
        "stock": set(),
        "ks1": {"PQCLEAN_MLKEM768_CLEAN_poly_tomsg"},
        "ks2": {
            "PQCLEAN_MLKEM768_CLEAN_poly_compress",
            "PQCLEAN_MLKEM768_CLEAN_polyvec_compress",
        },
        "ks1_ks2": {
            "PQCLEAN_MLKEM768_CLEAN_poly_tomsg",
            "PQCLEAN_MLKEM768_CLEAN_poly_compress",
            "PQCLEAN_MLKEM768_CLEAN_polyvec_compress",
        },
        "historical": {
            "pqcrystals_kyber768_ref_poly_tomsg",
            "pqcrystals_kyber768_ref_poly_compress",
            "pqcrystals_kyber768_ref_polyvec_compress",
        },
    },
}
PATCH_PAIRS = {
    "ks1": (("poly.c", "clean_kyberslash1/poly.c"),),
    "ks2": (
        ("poly.c", "clean_kyberslash2/poly.c"),
        ("polyvec.c", "clean_kyberslash2/polyvec.c"),
    ),
    "ks1_ks2": (
        ("poly.c", "clean_kyberslash/poly.c"),
        ("polyvec.c", "clean_kyberslash/polyvec.c"),
    ),
}

KAT_SOURCE = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "api.h"

static uint64_t ctkat_prng = UINT64_C(0x4b59424552534c41);

int PQCLEAN_randombytes(uint8_t *out, size_t outlen) {
    for (size_t i = 0; i < outlen; i++) {
        ctkat_prng ^= ctkat_prng << 13;
        ctkat_prng ^= ctkat_prng >> 7;
        ctkat_prng ^= ctkat_prng << 17;
        out[i] = (uint8_t)(ctkat_prng >> 56);
    }
    return 0;
}

static int emit(const uint8_t *buf, size_t len) {
    return fwrite(buf, 1, len, stdout) == len ? 0 : 20;
}

int main(void) {
    uint8_t pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ct[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss_enc[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    uint8_t ss_dec[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    uint8_t ss_invalid[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];

    for (size_t round = 0; round < 8; round++) {
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk) != 0) return 10;
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss_enc, pk) != 0) return 11;
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss_dec, ct, sk) != 0) return 12;
        if (memcmp(ss_enc, ss_dec, sizeof(ss_enc)) != 0) return 13;

        if (emit(pk, sizeof(pk)) || emit(sk, sizeof(sk)) ||
                emit(ct, sizeof(ct)) || emit(ss_enc, sizeof(ss_enc))) return 20;

        ct[round % sizeof(ct)] ^= (uint8_t)(1u << (round & 7u));
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss_invalid, ct, sk) != 0) return 14;
        if (memcmp(ss_enc, ss_invalid, sizeof(ss_enc)) == 0) return 15;
        if (emit(ss_invalid, sizeof(ss_invalid))) return 20;
    }
    return 0;
}
"""

HISTORICAL_SMOKE_SOURCE = r"""
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "ctkat_api.h"

static uint64_t ctkat_prng = UINT64_C(0x4b59424552534c41);

void randombytes(uint8_t *out, size_t outlen) {
    for (size_t i = 0; i < outlen; i++) {
        ctkat_prng ^= ctkat_prng << 13;
        ctkat_prng ^= ctkat_prng >> 7;
        ctkat_prng ^= ctkat_prng << 17;
        out[i] = (uint8_t)(ctkat_prng >> 56);
    }
}

int main(void) {
    uint8_t pk[pqcrystals_kyber768_ref_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[pqcrystals_kyber768_ref_CRYPTO_SECRETKEYBYTES];
    uint8_t ct[pqcrystals_kyber768_ref_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss_enc[pqcrystals_kyber768_ref_CRYPTO_BYTES];
    uint8_t ss_dec[pqcrystals_kyber768_ref_CRYPTO_BYTES];

    if (pqcrystals_kyber768_ref_crypto_kem_keypair(pk, sk) != 0) return 10;
    if (pqcrystals_kyber768_ref_crypto_kem_enc(ct, ss_enc, pk) != 0) return 11;
    if (pqcrystals_kyber768_ref_crypto_kem_dec(ss_dec, ct, sk) != 0) return 12;
    return memcmp(ss_enc, ss_dec, sizeof(ss_enc)) == 0 ? 0 : 13;
}
"""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("ground-truth manifest root must be a mapping")
    return data


def _resolve_repo_path(value: str) -> Path:
    path = (ROOT / value).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"path escapes repository: {value}") from exc
    return path


def render_patch(variant: str) -> str:
    chunks: list[str] = []
    for baseline_name, overlay_relative in PATCH_PAIRS[variant]:
        baseline = ROOT / "examples/pqc_mlkem768/clean" / baseline_name
        overlay = ROOT / "examples/pqc_mlkem768" / overlay_relative
        chunks.extend(
            difflib.unified_diff(
                baseline.read_text(encoding="utf-8").splitlines(keepends=True),
                overlay.read_text(encoding="utf-8").splitlines(keepends=True),
                fromfile=f"a/clean/{baseline_name}",
                tofile=f"b/{overlay_relative}",
            )
        )
    return "".join(chunks)


def _kem_harness(config_path: Path) -> HarnessConfig:
    config = load_config(config_path)
    if config.ct is None:
        raise ValueError(f"{config_path}: missing ct section")
    matches = [harness for harness in config.ct.harnesses if harness.name == "kem_dec"]
    if len(matches) != 1:
        raise ValueError(f"{config_path}: expected exactly one kem_dec harness")
    return matches[0]


def _validate_file_hash(
    errors: list[str],
    label: str,
    path: Path,
    expected: object,
) -> None:
    if not path.is_file():
        errors.append(f"{label}: missing {path.relative_to(ROOT)}")
        return
    actual = _sha256(path)
    if actual != expected:
        errors.append(f"{label}: SHA-256 expected {expected}, got {actual}")


def validate_static(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema_version") != 1:
        errors.append("schema_version must be 1")

    variants = manifest.get("variants")
    if not isinstance(variants, dict) or tuple(variants) != VARIANT_ORDER:
        errors.append(f"variants must appear exactly in order {VARIANT_ORDER}")
        return errors
    if set(manifest.get("sites", {})) != set(EXPECTED_SITE_SETS["ks1_ks2"]):
        errors.append("sites must define exactly the three frozen KyberSlash sites")

    baseline = manifest["baseline"]
    baseline_dir = ROOT / "examples/pqc_mlkem768/clean"
    if tree_sha256(baseline_dir) != baseline["tree_sha256"]:
        errors.append("PQClean baseline tree hash drift")
    for label, record in baseline["files"].items():
        _validate_file_hash(
            errors,
            f"baseline {label}",
            _resolve_repo_path(record["path"]),
            record["sha256"],
        )

    history = manifest["history"]
    history_dir = _resolve_repo_path(history["import_path"])
    if tree_sha256(history_dir) != history["tree_sha256"]:
        errors.append("historical pq-crystals/kyber tree hash drift")
    for name, record in history["files"].items():
        _validate_file_hash(
            errors,
            f"historical {name}",
            history_dir / name,
            record["sha256"],
        )
    history_poly = (history_dir / "poly.c").read_text(encoding="utf-8")
    history_polyvec = (history_dir / "polyvec.c").read_text(encoding="utf-8")
    historical_needles = (
        ("historical KS1", "(((t << 1) + KYBER_Q/2)/KYBER_Q) & 1", history_poly),
        (
            "historical KS2 poly",
            "((((uint16_t)u << 4) + KYBER_Q/2)/KYBER_Q) & 15",
            history_poly,
        ),
        (
            "historical KS2 polyvec",
            "((((uint32_t)t[k] << 10) + KYBER_Q/2)/ KYBER_Q) & 0x3ff",
            history_polyvec,
        ),
    )
    for label, needle, source in historical_needles:
        if needle not in source:
            errors.append(f"{label}: vulnerable expression missing")

    backend = manifest["timecop_backend"]
    _validate_file_hash(
        errors,
        "TIMECOP patch",
        _resolve_repo_path(backend["patch_path"]),
        backend["patch_sha256"],
    )
    timecop = manifest.get("expected_evidence", {}).get("timecop", {})
    if set(timecop) != set(EXPECTED_TIMECOP_FUNCTIONS):
        errors.append(
            "timecop evidence must define exactly kem_dec_secret_key_path and "
            "site_operand_attribution"
        )
    else:
        for scope, expected_targets in EXPECTED_TIMECOP_FUNCTIONS.items():
            scope_record = timecop[scope]
            actual_targets = {
                name: set(values)
                for name, values in scope_record.items()
                if name != "interpretation" and isinstance(values, list)
            }
            if actual_targets != expected_targets:
                errors.append(
                    f"timecop {scope}: function expectations drifted: "
                    f"actual={actual_targets}, wanted={expected_targets}"
                )
            if not isinstance(scope_record.get("interpretation"), str):
                errors.append(f"timecop {scope}: interpretation must be text")

    all_markers = {site["marker"] for site in manifest["sites"].values()}
    for variant_name in VARIANT_ORDER:
        variant = variants[variant_name]
        expected_sites = set(variant.get("expected_sites", []))
        if expected_sites != EXPECTED_SITE_SETS[variant_name]:
            errors.append(
                f"{variant_name}: expected_sites={sorted(expected_sites)}, "
                f"wanted {sorted(EXPECTED_SITE_SETS[variant_name])}"
            )
        config_path = _resolve_repo_path(variant["config"])
        try:
            config = load_config(config_path)
            harness = _kem_harness(config_path)
        except (OSError, ValueError) as exc:
            errors.append(f"{variant_name}: invalid config: {exc}")
            continue
        if config.project.name != variant["target"]:
            errors.append(
                f"{variant_name}: project.name={config.project.name!r}, "
                f"wanted {variant['target']!r}"
            )
        configured_sources = {(config_path.parent / source).resolve() for source in harness.sources}
        source_files = {_resolve_repo_path(path) for path in variant["source_files"]}
        if not source_files.issubset(configured_sources):
            missing = sorted(
                str(path.relative_to(ROOT)) for path in source_files - configured_sources
            )
            errors.append(f"{variant_name}: config omits frozen sources {missing}")

        source_text = "\n".join(source.read_text(encoding="utf-8") for source in source_files)
        expected_markers = {manifest["sites"][site_name]["marker"] for site_name in expected_sites}
        for marker in all_markers:
            count = source_text.count(f"/* {marker} */")
            wanted = 1 if marker in expected_markers else 0
            if count != wanted:
                errors.append(f"{variant_name}: marker {marker} count={count}, wanted {wanted}")

        patch_value = variant.get("patch")
        if variant_name == "stock":
            if patch_value is not None:
                errors.append("stock: patch must be null")
            continue
        patch_path = _resolve_repo_path(patch_value)
        _validate_file_hash(
            errors,
            f"{variant_name} patch",
            patch_path,
            variant.get("patch_sha256"),
        )
        if patch_path.is_file():
            expected_patch = render_patch(variant_name)
            if patch_path.read_text(encoding="utf-8") != expected_patch:
                errors.append(f"{variant_name}: committed unified diff is stale")

    return errors


def _compiler() -> str:
    requested = os.environ.get("CC", "cc")
    compiler = shutil.which(requested)
    if compiler is None:
        raise RuntimeError(f"C compiler not found: {requested}")
    return compiler


def _compile(
    *,
    compiler: str,
    source_path: Path,
    output_path: Path,
    include_dirs: list[Path],
    sources: list[Path],
    cflags: list[str],
) -> None:
    command = [
        compiler,
        "-std=c99",
        "-O2",
        *cflags,
        *(flag for directory in include_dirs for flag in ("-I", str(directory))),
        str(source_path),
        *(str(source) for source in sources),
        "-o",
        str(output_path),
    ]
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=180)
    if result.returncode != 0:
        raise RuntimeError(
            f"compile failed ({output_path.name}, rc={result.returncode}):\n"
            f"{result.stdout}{result.stderr}"
        )


def _variant_transcript(
    compiler: str,
    variant: dict[str, Any],
    temp_dir: Path,
) -> bytes:
    config_path = _resolve_repo_path(variant["config"])
    harness = _kem_harness(config_path)
    include_dirs = [(config_path.parent / path).resolve() for path in harness.include_dirs]
    sources = [
        (config_path.parent / path).resolve()
        for path in harness.sources
        if Path(path).name != "randombytes.c"
    ]
    source_path = temp_dir / f"{variant['target']}_kat.c"
    binary_path = temp_dir / f"{variant['target']}_kat"
    source_path.write_text(KAT_SOURCE, encoding="utf-8")
    _compile(
        compiler=compiler,
        source_path=source_path,
        output_path=binary_path,
        include_dirs=include_dirs,
        sources=sources,
        cflags=["-DPQCLEAN_NO_GLIBC_RANDOMBYTES"],
    )
    result = subprocess.run(
        [str(binary_path)],
        cwd=ROOT,
        capture_output=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{variant['target']}: KAT binary rc={result.returncode}, "
            f"stderr={result.stderr.decode('utf-8', errors='replace')}"
        )
    return result.stdout


def _historical_smoke(compiler: str, temp_dir: Path) -> None:
    config_path = ROOT / "examples/pqc_kyber768_historical/ctkat.yaml"
    harness = _kem_harness(config_path)
    include_dirs = [(config_path.parent / path).resolve() for path in harness.include_dirs]
    sources = [
        (config_path.parent / path).resolve()
        for path in harness.sources
        if Path(path).name != "randombytes.c"
    ]
    source_path = temp_dir / "historical_smoke.c"
    binary_path = temp_dir / "historical_smoke"
    source_path.write_text(HISTORICAL_SMOKE_SOURCE, encoding="utf-8")
    _compile(
        compiler=compiler,
        source_path=source_path,
        output_path=binary_path,
        include_dirs=include_dirs,
        sources=sources,
        cflags=["-DKYBER_K=3"],
    )
    result = subprocess.run([str(binary_path)], cwd=ROOT, capture_output=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(
            f"historical smoke rc={result.returncode}: "
            f"{result.stderr.decode('utf-8', errors='replace')}"
        )


def verify_functional_equivalence(
    manifest: dict[str, Any],
) -> tuple[str, int]:
    compiler = _compiler()
    with tempfile.TemporaryDirectory(prefix="ctkat-kyberslash-") as raw_temp:
        temp_dir = Path(raw_temp)
        transcripts = {
            name: _variant_transcript(compiler, manifest["variants"][name], temp_dir)
            for name in VARIANT_ORDER
        }
        _historical_smoke(compiler, temp_dir)
    stock = transcripts["stock"]
    for name, transcript in transcripts.items():
        if transcript != stock:
            raise RuntimeError(
                f"{name}: KEM transcript differs from stock "
                f"(stock={hashlib.sha256(stock).hexdigest()}, "
                f"variant={hashlib.sha256(transcript).hexdigest()})"
            )
    return hashlib.sha256(stock).hexdigest(), len(stock)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--emit-kat-sha",
        action="store_true",
        help="print the measured deterministic transcript identity",
    )
    parser.add_argument(
        "--static-only",
        action="store_true",
        help="skip C compilation (provenance/diff checks only)",
    )
    args = parser.parse_args()

    try:
        manifest = load_manifest()
        errors = validate_static(manifest)
        if errors:
            for error in errors:
                print(f"[kyberslash] ERROR: {error}", file=sys.stderr)
            return 1
        if args.static_only:
            print("[kyberslash] OK: provenance, variants, markers, and diffs")
            return 0

        transcript_sha, transcript_bytes = verify_functional_equivalence(manifest)
        expected = manifest["functional_equivalence"]
        if args.emit_kat_sha:
            print(f"transcript_sha256={transcript_sha}")
            print(f"transcript_bytes={transcript_bytes}")
        if transcript_sha != expected["transcript_sha256"]:
            print(
                "[kyberslash] ERROR: KEM transcript SHA-256 drift: "
                f"expected={expected['transcript_sha256']} actual={transcript_sha}",
                file=sys.stderr,
            )
            return 1
        if transcript_bytes != expected["transcript_bytes"]:
            print(
                "[kyberslash] ERROR: KEM transcript length drift: "
                f"expected={expected['transcript_bytes']} actual={transcript_bytes}",
                file=sys.stderr,
            )
            return 1
    except (KeyError, OSError, RuntimeError, ValueError, yaml.YAMLError) as exc:
        print(f"[kyberslash] ERROR: {exc}", file=sys.stderr)
        return 1

    print(
        "[kyberslash] OK: 4 byte-identical ML-KEM transcripts; "
        "historical smoke; provenance/diff ground truth"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
