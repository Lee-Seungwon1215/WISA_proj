#!/usr/bin/env python3
"""Compile and inventory Falcon comparator floating-point instruction profiles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctkat.qemu_detect import detect_qemu_emulation  # noqa: E402
from scripts.check_falcon_comparators import (  # noqa: E402
    ADAPTER,
    COMMON_SOURCES,
    KAT,
    UPSTREAM,
    load_manifest,
    macro_dump,
    profile_flags,
    validate_active_profile,
)

FUNCTION_RE = re.compile(r"^\s*[0-9a-fA-F]+\s+<([^>]+)>:$")
INSTRUCTION_RE = re.compile(r"^\s*[0-9a-fA-F]+:\s+([A-Za-z][A-Za-z0-9_.]*)")

X86_FP_RE = re.compile(
    r"^v?(?:"
    r"(?:add|sub|mul|div|max|min|sqrt|round|cmp|comi|ucomi)(?:sd|pd|ss|ps|ph)"
    r"|cvt[a-z0-9]*(?:sd|pd|ss|ps|ph|si|dq)"
    r"|mov(?:sd|pd|ss|ps|ddup|hlps|lhps)"
    r")$"
)
X87_FP_RE = re.compile(r"^f(?:add|sub|subr|mul|div|divr|sqrt|rndint|com|comp|ucom|ucomp|ld|stp?)")
ARM_FP_RE = re.compile(
    r"^(?:fadd|fsub|fmul|fdiv|fsqrt|fmadd|fmsub|fnmadd|fnmsub|"
    r"fcmp|fcmpe|fcvt[a-z0-9]*|frint[a-z0-9]*|fmov|fabs|fneg|fmax|fmin)$"
)
RISCV_FP_RE = re.compile(
    r"^f(?:add|sub|mul|div|sqrt|min|max|madd|msub|nmadd|nmsub|"
    r"cvt|class|sgnj|mv)\.(?:d|s|w|wu|l|lu)$"
)
INTEGER_DIV_RE = re.compile(r"^(?:idiv|div|sdiv|udiv)(?:[bwlq])?$")
SIGN_SCOPE_RE = re.compile(
    r"(?:fndsa_(?:sign|fpr|fpoly|sampler|ber|ffsamp|comp_encode|gaussian)"
    r"|ber_exp|ffsamp|sampler|mtwop63|CTKAT_FNDSA_crypto_sign_signature)"
)
MATH_SYMBOL_RE = re.compile(
    r"(?:^|_)(?:sqrt|sqrtf|floor|floorf|ceil|ceilf|round|roundf|"
    r"nearbyint|rint|rintf|exp|expf|pow|powf|log|logf)(?:$|@)"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tool_version(command: str) -> str:
    result = subprocess.run(
        [command, "--version"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
        timeout=30,
        text=True,
    )
    return result.stdout.splitlines()[0]


def _is_fp_instruction(mnemonic: str) -> bool:
    value = mnemonic.lower()
    return bool(
        X86_FP_RE.fullmatch(value)
        or X87_FP_RE.match(value)
        or ARM_FP_RE.fullmatch(value)
        or RISCV_FP_RE.fullmatch(value)
    )


def _fp_class(mnemonic: str) -> str:
    value = mnemonic.lower()
    if "sqrt" in value:
        return "sqrt"
    if "div" in value:
        return "division"
    if any(part in value for part in ("round", "rndint", "cvt", "rint")):
        return "rounding_or_conversion"
    if any(part in value for part in ("cmp", "comi", "ucom", "class")):
        return "comparison"
    if any(part in value for part in ("mov", "sgnj", "fabs", "fneg")):
        return "move_or_sign"
    return "arithmetic"


def _disassemble(objdump: str, binary: Path) -> tuple[str, str]:
    command = [objdump, "-d", "--no-show-raw-insn", str(binary)]
    result = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=300,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"objdump failed: {result.stderr.strip()}")
    return result.stdout, " ".join(command[:-1] + ["<binary>"])


def _instruction_inventory(disassembly: str) -> dict[str, Any]:
    current = "<unknown>"
    fp_by_function: dict[str, Counter[str]] = defaultdict(Counter)
    int_div_by_function: dict[str, Counter[str]] = defaultdict(Counter)
    for line in disassembly.splitlines():
        function_match = FUNCTION_RE.match(line)
        if function_match:
            current = function_match.group(1)
            continue
        instruction_match = INSTRUCTION_RE.match(line)
        if not instruction_match:
            continue
        mnemonic = instruction_match.group(1).lower()
        if _is_fp_instruction(mnemonic):
            fp_by_function[current][mnemonic] += 1
        if INTEGER_DIV_RE.fullmatch(mnemonic):
            int_div_by_function[current][mnemonic] += 1

    def serialize(
        records: dict[str, Counter[str]],
        *,
        scope_only: bool = False,
    ) -> dict[str, dict[str, int]]:
        return {
            function: dict(sorted(counts.items()))
            for function, counts in sorted(records.items())
            if counts and (not scope_only or SIGN_SCOPE_RE.search(function))
        }

    all_fp = Counter[str]()
    sign_fp = Counter[str]()
    classes = Counter[str]()
    sign_classes = Counter[str]()
    for function, counts in fp_by_function.items():
        all_fp.update(counts)
        for mnemonic, count in counts.items():
            classes[_fp_class(mnemonic)] += count
        if SIGN_SCOPE_RE.search(function):
            sign_fp.update(counts)
            for mnemonic, count in counts.items():
                sign_classes[_fp_class(mnemonic)] += count

    all_int_div = Counter[str]()
    sign_int_div = Counter[str]()
    for function, counts in int_div_by_function.items():
        all_int_div.update(counts)
        if SIGN_SCOPE_RE.search(function):
            sign_int_div.update(counts)

    return {
        "floating_point": {
            "all_binary": dict(sorted(all_fp.items())),
            "all_binary_classes": dict(sorted(classes.items())),
            "signing_scope": dict(sorted(sign_fp.items())),
            "signing_scope_classes": dict(sorted(sign_classes.items())),
            "functions": serialize(fp_by_function),
            "signing_functions": serialize(fp_by_function, scope_only=True),
        },
        "integer_division": {
            "all_binary": dict(sorted(all_int_div.items())),
            "signing_scope": dict(sorted(sign_int_div.items())),
            "functions": serialize(int_div_by_function),
            "signing_functions": serialize(int_div_by_function, scope_only=True),
        },
    }


def _undefined_symbols(nm: str, binary: Path) -> tuple[list[str], list[str]]:
    result = subprocess.run(
        [nm, "-u", str(binary)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"nm failed: {result.stderr.strip()}")
    symbols: list[str] = []
    for line in result.stdout.splitlines():
        value = line.strip().split()[-1] if line.strip() else ""
        if value:
            symbols.append(value)
    symbols = sorted(set(symbols))
    return symbols, [symbol for symbol in symbols if MATH_SYMBOL_RE.search(symbol)]


def _display_command(command: list[str], binary: Path) -> list[str]:
    displayed: list[str] = []
    for value in command:
        if value == str(binary):
            displayed.append("<temporary-binary>")
        elif value.startswith(str(ROOT)):
            displayed.append("." + value[len(str(ROOT)) :])
        else:
            displayed.append(value)
    return displayed


def build_audit(
    *,
    cc: str,
    objdump: str,
    nm: str,
) -> dict[str, Any]:
    manifest = load_manifest()
    c_fndsa = manifest["sources"]["c_fndsa"]
    kat_records = manifest["deterministic_kat"]["degrees"]
    profiles: list[dict[str, Any]] = []
    relevant_macros = (
        "FNDSA_AVX2",
        "FNDSA_SSE2",
        "FNDSA_NEON",
        "FNDSA_RV64D",
        "FNDSA_DIV_EMU",
        "FNDSA_SQRT_EMU",
        "FNDSA_64",
    )
    with tempfile.TemporaryDirectory(prefix="ctkat-falcon-fp-") as tmp:
        temp = Path(tmp)
        for degree in ("512", "1024"):
            degree_record = c_fndsa["degrees"][degree]
            logn = int(degree_record["logn"])
            target_dir = (ROOT / degree_record["config"]).resolve().parent
            for profile_name in ("native_fp", "integer_fpr"):
                flags = profile_flags(logn, profile_name)
                macros = macro_dump(cc, flags)
                validate_active_profile(profile_name, macros)
                binary = temp / f"falcon_{degree}_{profile_name}"
                command = [
                    cc,
                    "-std=c99",
                    "-O2",
                    "-g",
                    "-fno-inline",
                    "-fno-omit-frame-pointer",
                    "-fno-strict-aliasing",
                    "-fno-lto",
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
                        f"Falcon-{degree}/{profile_name} compile failed:\n{compiled.stderr}"
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
                    raise RuntimeError(
                        f"Falcon-{degree}/{profile_name} KAT/fenv screen failed "
                        f"with exit {executed.returncode}"
                    )
                transcript_hash = hashlib.sha256(executed.stdout).hexdigest()
                if transcript_hash != kat_records[degree]["transcript_sha256"]:
                    raise RuntimeError(
                        f"Falcon-{degree}/{profile_name} transcript drift: {transcript_hash}"
                    )
                disassembly, disassembly_command = _disassemble(objdump, binary)
                undefined, math_symbols = _undefined_symbols(nm, binary)
                profiles.append(
                    {
                        "degree": int(degree),
                        "target": degree_record["target"],
                        "profile": profile_name,
                        "build_flags": flags,
                        "resolved_macros": {
                            name: macros.get(name, "<undefined>") for name in relevant_macros
                        },
                        "compile_command": _display_command(command, binary),
                        "binary_sha256": _sha256(binary),
                        "transcript_sha256": transcript_hash,
                        "round_trip": "pass",
                        "fenv_exception_screen": (
                            "pass" if profile_name == "native_fp" else "not-applicable-integer-fpr"
                        ),
                        "disassembly_command": disassembly_command,
                        "instructions": _instruction_inventory(disassembly),
                        "undefined_symbols": undefined,
                        "external_math_symbols": math_symbols,
                    }
                )

    return {
        "schema_version": 1,
        "kind": "ctkat-falcon-floating-point-build-audit",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": {
            "upstream": c_fndsa["upstream"],
            "revision": c_fndsa["revision"],
            "tree_sha256": c_fndsa["tree_sha256"],
            "standard_identity": c_fndsa["standard_identity"],
            "conformance": c_fndsa["conformance"],
        },
        "host": {
            "system": platform.system(),
            "machine": platform.machine(),
            "release": platform.release(),
            "qemu_emulation_detected": detect_qemu_emulation(),
            "timing_evidence": False,
        },
        "tools": {
            "compiler": _tool_version(cc),
            "objdump": _tool_version(objdump),
            "nm": _tool_version(nm),
        },
        "classification": {
            "signing_scope_pattern": SIGN_SCOPE_RE.pattern,
            "opcode_presence_is_leak_verdict": False,
            "fenv_screen_scope": "one deterministic seeded signing transcript",
            "fenv_screen_proves_global_nonexceptional_range": False,
        },
        "profiles": profiles,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--nm", default="nm")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "docs/ground_truth/falcon/fp_audit.json",
    )
    args = parser.parse_args()
    try:
        report = build_audit(cc=args.cc, objdump=args.objdump, nm=args.nm)
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
        print(f"[falcon-fp] ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"[falcon-fp] wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
