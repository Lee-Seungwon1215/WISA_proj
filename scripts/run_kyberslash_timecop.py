#!/usr/bin/env python3
"""Run pinned KyberSlash TIMECOP operand attribution for all frozen variants."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctkat.cli import _template_context  # noqa: E402
from ctkat.config import load_config  # noqa: E402
from ctkat.harness_generator import render_harness  # noqa: E402
from ctkat.valgrind_parser import (  # noqa: E402
    Finding,
    FindingType,
    parse_valgrind_log_with_stats,
)
from scripts.check_kyberslash_ground_truth import (  # noqa: E402
    MANIFEST_PATH,
    VARIANT_ORDER,
    load_manifest,
    validate_static,
)

DEFAULT_OUTPUT_ROOT = ROOT / "measurement_runs/kyberslash_timecop"
TIMECOP_FINDING = FindingType.SECRET_DEPENDENT_VARIABLE_LATENCY
CANARY_SOURCE = r"""
#include <stdint.h>
#include <stdio.h>
#include <valgrind/memcheck.h>

int main(void) {
    volatile uint32_t numerator = UINT32_C(0x6f12a35b);
    volatile uint32_t divisor = UINT32_C(3329);
    VALGRIND_ENABLE_TIMECOP_MODE;
    VALGRIND_MAKE_MEM_UNDEFINED((void *)&numerator, sizeof(numerator));
    volatile uint32_t quotient = numerator / divisor;
    VALGRIND_MAKE_MEM_DEFINED((void *)&numerator, sizeof(numerator));
    VALGRIND_MAKE_MEM_DEFINED((void *)&quotient, sizeof(quotient));
    printf("CTKAT-TIMECOP-CANARY:%u\n", (unsigned)quotient);
    return 0;
}
"""
SITE_OPERAND_SOURCE = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <valgrind/memcheck.h>
#include "params.h"
#include "poly.h"
#include "polyvec.h"

#ifdef CTKAT_HISTORICAL
#define CTKAT_POLY_COMPRESS poly_compress
#define CTKAT_POLY_TOMSG poly_tomsg
#define CTKAT_POLYVEC_COMPRESS polyvec_compress
#else
#define CTKAT_POLY_COMPRESS PQCLEAN_MLKEM768_CLEAN_poly_compress
#define CTKAT_POLY_TOMSG PQCLEAN_MLKEM768_CLEAN_poly_tomsg
#define CTKAT_POLYVEC_COMPRESS PQCLEAN_MLKEM768_CLEAN_polyvec_compress
#endif

static uint32_t checksum(const uint8_t *data, size_t length) {
    uint32_t value = UINT32_C(2166136261);
    for (size_t i = 0; i < length; i++) {
        value = (value ^ data[i]) * UINT32_C(16777619);
    }
    return value;
}

int main(void) {
    poly p;
    polyvec pv;
    uint8_t message[KYBER_INDCPA_MSGBYTES];
    uint8_t compressed_poly[KYBER_POLYCOMPRESSEDBYTES];
    uint8_t compressed_polyvec[KYBER_POLYVECCOMPRESSEDBYTES];

    for (size_t i = 0; i < KYBER_N; i++) {
        p.coeffs[i] = (int16_t)((i * 17u + 23u) % KYBER_Q);
    }
    for (size_t i = 0; i < KYBER_K; i++) {
        for (size_t j = 0; j < KYBER_N; j++) {
            pv.vec[i].coeffs[j] =
                (int16_t)((i * 911u + j * 29u + 31u) % KYBER_Q);
        }
    }

    /*
     * This is deliberately a site-level operand canary, not a claim that
     * Memcheck's undefinedness survives the complete KEM dataflow. The
     * companion kem_dec scope tests that separate end-to-end question.
     */
    VALGRIND_ENABLE_TIMECOP_MODE;
    VALGRIND_MAKE_MEM_UNDEFINED((void *)&p, sizeof(p));
    VALGRIND_MAKE_MEM_UNDEFINED((void *)&pv, sizeof(pv));
    CTKAT_POLY_TOMSG(message, &p);
    CTKAT_POLY_COMPRESS(compressed_poly, &p);
    CTKAT_POLYVEC_COMPRESS(compressed_polyvec, &pv);
    VALGRIND_MAKE_MEM_DEFINED((void *)&p, sizeof(p));
    VALGRIND_MAKE_MEM_DEFINED((void *)&pv, sizeof(pv));
    VALGRIND_MAKE_MEM_DEFINED((void *)message, sizeof(message));
    VALGRIND_MAKE_MEM_DEFINED((void *)compressed_poly, sizeof(compressed_poly));
    VALGRIND_MAKE_MEM_DEFINED(
        (void *)compressed_polyvec, sizeof(compressed_polyvec)
    );

    printf(
        "CTKAT-TIMECOP-SITES:%08x\n",
        (unsigned)(
            checksum(message, sizeof(message))
            ^ checksum(compressed_poly, sizeof(compressed_poly))
            ^ checksum(compressed_polyvec, sizeof(compressed_polyvec))
        )
    );
    return 0;
}
"""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run_text(
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def _serialize_finding(finding: Finding) -> dict[str, Any]:
    def frame_value(frame: Any) -> dict[str, Any]:
        return {
            "address": frame.address,
            "function": frame.function,
            "file": frame.file,
            "line": frame.line,
        }

    return {
        "type": finding.type.value,
        "severity": finding.severity.value,
        "message": finding.message,
        "frames": [frame_value(frame) for frame in finding.frames],
        "origin_frames": [frame_value(frame) for frame in finding.origin_frames],
    }


def _find_backend(valgrind_arg: str, prefix_arg: Path | None) -> tuple[Path, Path]:
    executable_value = (
        shutil.which(valgrind_arg) if not Path(valgrind_arg).is_absolute() else valgrind_arg
    )
    if not executable_value:
        raise RuntimeError(f"Valgrind executable not found: {valgrind_arg}")
    executable = Path(executable_value).resolve()
    candidates: list[Path] = []
    if prefix_arg is not None:
        candidates.append(prefix_arg.resolve() / "include")
    env_prefix = os.environ.get("CTKAT_TIMECOP_PREFIX")
    if env_prefix:
        candidates.append(Path(env_prefix).resolve() / "include")
    candidates.extend(
        [
            executable.parent.parent / "include",
            Path("/usr/local/include"),
            Path("/usr/include"),
        ]
    )
    for include_dir in candidates:
        header = include_dir / "valgrind/memcheck.h"
        if header.is_file() and "VALGRIND_ENABLE_TIMECOP_MODE" in header.read_text(
            encoding="utf-8", errors="replace"
        ):
            return executable, include_dir
    raise RuntimeError("patched memcheck.h not found; pass --prefix or set CTKAT_TIMECOP_PREFIX")


def _compile(
    *,
    compiler: str,
    source: Path,
    binary: Path,
    includes: list[Path],
    sources: list[Path],
    defines: list[str],
) -> dict[str, Any]:
    command = [
        compiler,
        "-std=c99",
        "-Os",
        "-g",
        "-fno-inline",
        "-fno-omit-frame-pointer",
        "-fno-lto",
        *(flag for directory in includes for flag in ("-I", str(directory))),
        *defines,
        str(source),
        *(str(item) for item in sources),
        "-o",
        str(binary),
    ]
    result = _run_text(command, cwd=ROOT, timeout=600)
    if result.returncode != 0:
        raise RuntimeError(
            f"compile failed ({binary.name}, rc={result.returncode}):\n"
            f"{result.stdout}{result.stderr}"
        )
    return {
        "argv": command,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "binary_sha256": _sha256(binary),
    }


def _run_under_timecop(
    *,
    valgrind: Path,
    binary: Path,
    log_path: Path,
) -> dict[str, Any]:
    command = [
        str(valgrind),
        "--tool=memcheck",
        "--track-origins=yes",
        "--leak-check=no",
        "--error-exitcode=99",
        f"--log-file={log_path}",
        str(binary),
    ]
    result = _run_text(command, cwd=ROOT, timeout=600)
    if not log_path.is_file():
        raise RuntimeError(f"{binary.name}: Valgrind did not create {log_path}")
    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    findings, dropped = parse_valgrind_log_with_stats(log_text)
    varlat = [finding for finding in findings if finding.type == TIMECOP_FINDING]
    return {
        "argv": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "log": str(log_path.relative_to(log_path.parent.parent)),
        "log_sha256": _sha256(log_path),
        "dropped_valgrind_messages": dropped,
        "findings": [_serialize_finding(finding) for finding in findings],
        "variable_latency_functions": sorted(
            {
                finding.primary_frame.function
                for finding in varlat
                if finding.primary_frame is not None
            }
        ),
    }


def _expected_timecop_functions(
    manifest: dict[str, Any],
    scope: str,
    name: str,
) -> list[str]:
    values = manifest["expected_evidence"]["timecop"][scope][name]
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError(f"timecop expectation for {scope}/{name} must be a list of functions")
    return sorted(values)


def _variant_config(manifest: dict[str, Any], name: str) -> Path:
    if name == "historical":
        return ROOT / "examples/pqc_kyber768_historical/ctkat.yaml"
    return ROOT / manifest["variants"][name]["config"]


def _evaluate_execution(
    *,
    manifest: dict[str, Any],
    scope: str,
    name: str,
    execution: dict[str, Any],
) -> bool:
    expected = _expected_timecop_functions(manifest, scope, name)
    actual = execution["variable_latency_functions"]
    execution["expected_variable_latency_functions"] = expected
    execution["function_set_match"] = actual == expected
    execution["exit_status_match"] = execution["returncode"] == (99 if expected else 0)
    return execution["function_set_match"] and execution["exit_status_match"]


def _run_variant(
    *,
    manifest: dict[str, Any],
    name: str,
    compiler: str,
    valgrind: Path,
    patched_include: Path,
    output_dir: Path,
) -> dict[str, Any]:
    config_path = _variant_config(manifest, name)
    config = load_config(config_path)
    if config.ct is None:
        raise RuntimeError(f"{config_path}: missing ct section")
    harnesses = [harness for harness in config.ct.harnesses if harness.name == "kem_dec"]
    if len(harnesses) != 1:
        raise RuntimeError(f"{config_path}: expected exactly one kem_dec harness")
    harness = harnesses[0]
    kem_source_path = output_dir / f"harness_{name}_kem_dec.c"
    kem_binary_path = output_dir / f"harness_{name}_kem_dec"
    kem_source_path.write_text(
        render_harness(
            "kem",
            _template_context(harness, config.ct.seed, timecop_mode=True),
        ),
        encoding="utf-8",
    )
    includes = [patched_include]
    includes.extend((config_path.parent / path).resolve() for path in harness.include_dirs)
    sources = [(config_path.parent / path).resolve() for path in harness.sources]
    defines = [flag for flag in config.ct.cflags if flag.startswith("-D")]
    kem_compile = _compile(
        compiler=compiler,
        source=kem_source_path,
        binary=kem_binary_path,
        includes=includes,
        sources=sources,
        defines=defines,
    )
    kem_execution = _run_under_timecop(
        valgrind=valgrind,
        binary=kem_binary_path,
        log_path=output_dir / f"{name}_kem_dec.valgrind.log",
    )
    kem_passed = _evaluate_execution(
        manifest=manifest,
        scope="kem_dec_secret_key_path",
        name=name,
        execution=kem_execution,
    )

    site_source_path = output_dir / f"harness_{name}_site_operands.c"
    site_binary_path = output_dir / f"harness_{name}_site_operands"
    site_source_path.write_text(SITE_OPERAND_SOURCE, encoding="utf-8")
    site_defines = [*defines]
    if name == "historical":
        site_defines.append("-DCTKAT_HISTORICAL")
    site_compile = _compile(
        compiler=compiler,
        source=site_source_path,
        binary=site_binary_path,
        includes=includes,
        sources=sources,
        defines=site_defines,
    )
    site_execution = _run_under_timecop(
        valgrind=valgrind,
        binary=site_binary_path,
        log_path=output_dir / f"{name}_site_operands.valgrind.log",
    )
    site_passed = _evaluate_execution(
        manifest=manifest,
        scope="site_operand_attribution",
        name=name,
        execution=site_execution,
    )
    return {
        "config": str(config_path.relative_to(ROOT)),
        "config_sha256": _sha256(config_path),
        "scopes": {
            "kem_dec_secret_key_path": {
                "source": str(kem_source_path.relative_to(output_dir.parent)),
                "source_sha256": _sha256(kem_source_path),
                "compile": kem_compile,
                "execution": kem_execution,
                "passed": kem_passed,
            },
            "site_operand_attribution": {
                "source": str(site_source_path.relative_to(output_dir.parent)),
                "source_sha256": _sha256(site_source_path),
                "compile": site_compile,
                "execution": site_execution,
                "passed": site_passed,
            },
        },
        "passed": kem_passed and site_passed,
    }


def run_campaign(
    *,
    valgrind_arg: str,
    prefix: Path | None,
    output_dir: Path,
) -> tuple[dict[str, Any], int]:
    manifest = load_manifest()
    static_errors = validate_static(manifest)
    if static_errors:
        raise RuntimeError("static ground truth failed: " + "; ".join(static_errors))
    valgrind, patched_include = _find_backend(valgrind_arg, prefix)
    version_result = _run_text([str(valgrind), "--version"], cwd=ROOT, timeout=30)
    version = version_result.stdout.strip()
    expected_version = f"valgrind-{manifest['timecop_backend']['target_valgrind_version']}"
    if version_result.returncode != 0 or version != expected_version:
        raise RuntimeError(f"backend version={version!r}, wanted {expected_version!r}")

    compiler = shutil.which(os.environ.get("CC", "gcc"))
    if compiler is None:
        raise RuntimeError(f"C compiler not found: {os.environ.get('CC', 'gcc')}")
    compiler_version = _run_text([compiler, "--version"], cwd=ROOT, timeout=30)
    output_dir.mkdir(parents=True, exist_ok=False)

    canary_source = output_dir / "timecop_canary.c"
    canary_binary = output_dir / "timecop_canary"
    canary_source.write_text(CANARY_SOURCE, encoding="utf-8")
    canary_compile = _compile(
        compiler=compiler,
        source=canary_source,
        binary=canary_binary,
        includes=[patched_include],
        sources=[],
        defines=[],
    )
    canary_execution = _run_under_timecop(
        valgrind=valgrind,
        binary=canary_binary,
        log_path=output_dir / "canary.valgrind.log",
    )
    canary_passed = (
        canary_execution["returncode"] == 99
        and len(canary_execution["variable_latency_functions"]) >= 1
        and "CTKAT-TIMECOP-CANARY:" in canary_execution["stdout"]
    )

    targets: dict[str, Any] = {}
    errors: list[str] = []
    for name in (*VARIANT_ORDER, "historical"):
        try:
            targets[name] = _run_variant(
                manifest=manifest,
                name=name,
                compiler=compiler,
                valgrind=valgrind,
                patched_include=patched_include,
                output_dir=output_dir,
            )
            if not targets[name]["passed"]:
                errors.append(f"{name}: finding/exit expectation mismatch")
        except (OSError, RuntimeError, ValueError) as exc:
            targets[name] = {"passed": False, "error": str(exc)}
            errors.append(f"{name}: {exc}")

    promotion_ready = canary_passed and not errors
    record = {
        "schema_version": 2,
        "kind": "ctkat-kyberslash-timecop-attribution",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "manifest": str(MANIFEST_PATH.relative_to(ROOT)),
        "manifest_sha256": _sha256(MANIFEST_PATH),
        "backend": {
            "executable": str(valgrind),
            "executable_sha256": _sha256(valgrind),
            "version": version,
            "patched_include": str(patched_include),
            "patch_sha256": manifest["timecop_backend"]["patch_sha256"],
            "target_tarball_sha256": manifest["timecop_backend"]["target_tarball_sha256"],
        },
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": sys.version,
            "compiler": compiler,
            "compiler_version": compiler_version.stdout.splitlines()[0],
            "timing_evidence": False,
        },
        "canary": {
            "compile": canary_compile,
            "execution": canary_execution,
            "passed": canary_passed,
        },
        "targets": targets,
        "errors": errors,
        "promotion_ready": promotion_ready,
        "evidence_boundary": {
            "kem_dec_secret_key_path": (
                "undefinedness seeded at secret-key regions; KS2 absence is a "
                "dynamic-taint propagation limitation, not evidence of safety"
            ),
            "site_operand_attribution": (
                "undefinedness seeded directly at polynomial operands; proves "
                "variable-latency instruction attribution, not end-to-end leakage"
            ),
            "timing": "this artifact is not physical timing evidence",
        },
    }
    report_path = output_dir / "timecop_report.json"
    report_path.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return record, 0 if promotion_ready else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--valgrind", default="valgrind", help="patched Valgrind executable")
    parser.add_argument(
        "--prefix",
        type=Path,
        help="patched Valgrind install prefix (used to locate include/valgrind)",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=DEFAULT_OUTPUT_ROOT,
        help="parent directory for an immutable timestamped run",
    )
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = args.output_root.resolve() / stamp
    try:
        record, returncode = run_campaign(
            valgrind_arg=args.valgrind,
            prefix=args.prefix,
            output_dir=output_dir,
        )
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        print(f"[kyberslash-timecop] ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"[kyberslash-timecop] report: {output_dir / 'timecop_report.json'}")
    print(f"[kyberslash-timecop] promotion_ready={record['promotion_ready']}")
    if record["errors"]:
        for error in record["errors"]:
            print(f"[kyberslash-timecop] ERROR: {error}", file=sys.stderr)
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
