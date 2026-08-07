#!/usr/bin/env python3
"""Freeze and verify deterministic functional API round trips for corpus targets."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctkat.config import HarnessConfig, load_config  # noqa: E402
from ctkat.evidence import (  # noqa: E402
    AsmAttribution,
    AsmEvidence,
    Correctness,
    EvidenceV2,
    ReviewStatus,
    Structural,
    TimingSignal,
    TimingValidity,
)
from scripts.build_corpus_table import SUMMARY_FIELDS  # noqa: E402

MANIFEST = ROOT / "docs/corpus/correctness_v1.yaml"
SUMMARY = ROOT / "docs/corpus/corpus_summary.csv"
REQUIRED_TARGET_KEYS = {"id", "config", "source_harness", "template", "summary_harnesses"}
SNAPSHOT_TARGET_KEYS = {
    "target",
    "template",
    "summary_harnesses",
    "config",
    "config_sha256",
    "input_set_sha256",
    "transcript_sha256",
    "transcript_bytes",
    "status",
}
SNAPSHOT_KEYS = {
    "schema_version",
    "kind",
    "snapshot_id",
    "method",
    "randomness",
    "compiler",
    "compiler_version",
    "system",
    "machine",
    "targets",
}

RNG_SOURCE = r"""
#include <stddef.h>
#include <stdint.h>
static uint64_t ctkat_correctness_prng = UINT64_C(0x43544b4154434f52);
int PQCLEAN_randombytes(uint8_t *out, size_t length) {
    for (size_t i = 0; i < length; i++) {
        uint64_t x = ctkat_correctness_prng;
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        ctkat_correctness_prng = x;
        out[i] = (uint8_t)(x >> 56);
    }
    return 0;
}
"""


def _repo_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty repository path")
    path = (ROOT / value).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"{label} escapes repository") from exc
    return path


def load_manifest(path: Path = MANIFEST) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("correctness manifest root must be a mapping")
    return data


def validate_manifest(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if data.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if data.get("status") != "deterministic-api-roundtrip-frozen":
        errors.append("status drift")
    compiler = data.get("compiler")
    if not isinstance(compiler, dict) or compiler.get("cc") != "gcc":
        errors.append("compiler.cc must be gcc")
    required_flags = {"-O2", "-fno-omit-frame-pointer", "-fno-lto"}
    if not isinstance(compiler, dict) or not required_flags <= set(compiler.get("cflags", [])):
        errors.append("compiler flags drift")
    targets = data.get("targets")
    if not isinstance(targets, list) or not targets:
        return [*errors, "targets must be a non-empty list"]
    seen_targets: set[str] = set()
    seen_pairs: set[tuple[str, str]] = set()
    for index, target in enumerate(targets):
        if not isinstance(target, dict) or set(target) != REQUIRED_TARGET_KEYS:
            errors.append(f"targets[{index}] field drift")
            continue
        target_id = target["id"]
        if not isinstance(target_id, str) or target_id in seen_targets:
            errors.append(f"targets[{index}] id is missing or duplicate")
        seen_targets.add(str(target_id))
        if target["template"] not in {"kem", "sign"}:
            errors.append(f"targets[{index}] template must be kem or sign")
        if not isinstance(target["summary_harnesses"], list) or not target["summary_harnesses"]:
            errors.append(f"targets[{index}] summary_harnesses must be non-empty")
        else:
            for harness in target["summary_harnesses"]:
                pair = (str(target_id), str(harness))
                if pair in seen_pairs:
                    errors.append(f"duplicate summary pair: {pair}")
                seen_pairs.add(pair)
        try:
            config_path = _repo_path(target["config"], f"targets[{index}].config")
            cfg = load_config(config_path)
            if cfg.project.name != target_id:
                errors.append(f"targets[{index}] config project name drift")
            if cfg.ct is None:
                errors.append(f"targets[{index}] config has no ct harnesses")
            else:
                matching = [h for h in cfg.ct.harnesses if h.name == target["source_harness"]]
                if len(matching) != 1 or matching[0].template != target["template"]:
                    errors.append(f"targets[{index}] source harness/template drift")
        except (OSError, ValueError) as exc:
            errors.append(f"targets[{index}] config invalid: {exc}")
    try:
        snapshot = _repo_path(data.get("snapshot"), "snapshot")
        if not snapshot.is_file():
            errors.append("snapshot is missing")
    except ValueError as exc:
        errors.append(str(exc))
    return errors


def _harness_source(harness: HarnessConfig) -> str:
    includes = [f'#include "{harness.header}"']
    includes.extend(f'#include "{header}"' for header in harness.extra_headers)
    prefix = harness.prefix
    if harness.template == "kem":
        body = f"""
    uint8_t pk[{prefix}CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[{prefix}CRYPTO_SECRETKEYBYTES];
    uint8_t ct[{prefix}CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss1[{prefix}CRYPTO_BYTES], ss2[{prefix}CRYPTO_BYTES];
    if ({prefix}crypto_kem_keypair(pk, sk) != 0 ||
        {prefix}crypto_kem_enc(ct, ss1, pk) != 0 ||
        {prefix}crypto_kem_dec(ss2, ct, sk) != 0 ||
        memcmp(ss1, ss2, sizeof ss1) != 0) return 10;
    if (fwrite(pk, 1, sizeof pk, stdout) != sizeof pk ||
        fwrite(sk, 1, sizeof sk, stdout) != sizeof sk ||
        fwrite(ct, 1, sizeof ct, stdout) != sizeof ct ||
        fwrite(ss1, 1, sizeof ss1, stdout) != sizeof ss1) return 11;
"""
    else:
        body = f"""
    static const uint8_t message[] = "ctkat/corpus-correctness/v1";
    uint8_t pk[{prefix}CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[{prefix}CRYPTO_SECRETKEYBYTES];
    uint8_t sig[{prefix}CRYPTO_BYTES];
    size_t siglen = 0;
    if ({prefix}crypto_sign_keypair(pk, sk) != 0 ||
        {prefix}crypto_sign_signature(sig, &siglen, message, sizeof message - 1, sk) != 0 ||
        siglen > sizeof sig ||
        {prefix}crypto_sign_verify(sig, siglen, message, sizeof message - 1, pk) != 0) return 20;
    if (fwrite(pk, 1, sizeof pk, stdout) != sizeof pk ||
        fwrite(sk, 1, sizeof sk, stdout) != sizeof sk ||
        fwrite(&siglen, 1, sizeof siglen, stdout) != sizeof siglen ||
        fwrite(sig, 1, siglen, stdout) != siglen) return 21;
"""
    return (
        "#include <stddef.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n"
        + "\n".join(includes)
        + "\nint main(void) {\n"
        + body
        + "    return 0;\n}\n"
    )


def _compiler_version(cc: str) -> str:
    result = subprocess.run([cc, "--version"], check=True, text=True, stdout=subprocess.PIPE)
    return result.stdout.splitlines()[0]


def _input_set_sha256(
    config_path: Path,
    sources: list[Path],
    include_dirs: list[Path],
    harness_source: str,
) -> str:
    """Hash every repository input that can affect the functional round trip."""
    inputs = {config_path.resolve(), *(source.resolve() for source in sources)}
    for include_dir in include_dirs:
        inputs.update(
            path.resolve()
            for path in include_dir.rglob("*")
            if path.is_file() and path.suffix.lower() in {".h", ".inc"}
        )
    digest = hashlib.sha256()
    generated = {
        "generated/roundtrip.c": harness_source.encode(),
        "generated/deterministic_randombytes.c": RNG_SOURCE.encode(),
    }
    for label, payload in sorted(generated.items()):
        digest.update(label.encode())
        digest.update(b"\0")
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    for path in sorted(inputs):
        try:
            label = path.relative_to(ROOT).as_posix()
        except ValueError as exc:
            raise ValueError(f"correctness input escapes repository: {path}") from exc
        payload = path.read_bytes()
        digest.update(label.encode())
        digest.update(b"\0")
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def run_targets(data: dict[str, Any]) -> dict[str, Any]:
    static_errors = validate_manifest(data)
    # A missing snapshot is allowed only while bootstrapping --write-snapshot.
    static_errors = [error for error in static_errors if error != "snapshot is missing"]
    if static_errors:
        raise ValueError("; ".join(static_errors))
    compiler = data["compiler"]
    cc = str(compiler["cc"])
    records: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="ctkat-correctness-") as raw_temp:
        temp = Path(raw_temp)
        rng = temp / "deterministic_randombytes.c"
        rng.write_text(RNG_SOURCE, encoding="utf-8")
        for index, target in enumerate(data["targets"]):
            config_path = _repo_path(target["config"], "target.config")
            cfg = load_config(config_path)
            assert cfg.ct is not None
            harness = next(h for h in cfg.ct.harnesses if h.name == target["source_harness"])
            harness_source = _harness_source(harness)
            source = temp / f"roundtrip_{index}.c"
            source.write_text(harness_source, encoding="utf-8")
            binary = temp / f"roundtrip_{index}"
            sources = [(config_path.parent / value).resolve() for value in harness.sources]
            sources = [
                value
                for value in sources
                if value.name != "randombytes.c" and "deterministic_randombytes" not in value.name
            ]
            include_dirs = [
                (config_path.parent / value).resolve() for value in harness.include_dirs
            ]
            inherited = [
                flag
                for flag in [*(cfg.ct.cflags or []), *(harness.cflags or [])]
                if flag.startswith("-D") or flag.startswith("-std=")
            ]
            flags = list(dict.fromkeys([*compiler["cflags"], *inherited]))
            command = [
                cc,
                *flags,
                *(f"-I{value}" for value in include_dirs),
                str(source),
                *(str(value) for value in sources),
                str(rng),
                "-o",
                str(binary),
            ]
            compiled = subprocess.run(
                command,
                cwd=config_path.parent,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=900,
            )
            if compiled.returncode != 0:
                raise RuntimeError(
                    f"{target['id']}: compile failed\n{compiled.stdout}\n{compiled.stderr}"
                )
            executed = subprocess.run(
                [str(binary)],
                cwd=config_path.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=900,
            )
            if executed.returncode != 0:
                raise RuntimeError(
                    f"{target['id']}: round trip failed rc={executed.returncode}: "
                    + executed.stderr.decode(errors="replace")
                )
            records.append(
                {
                    "target": target["id"],
                    "template": target["template"],
                    "summary_harnesses": target["summary_harnesses"],
                    "config": target["config"],
                    "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
                    "input_set_sha256": _input_set_sha256(
                        config_path, sources, include_dirs, harness_source
                    ),
                    "transcript_sha256": hashlib.sha256(executed.stdout).hexdigest(),
                    "transcript_bytes": len(executed.stdout),
                    "status": "pass",
                }
            )
            print(f"[correctness] PASS: {target['id']}", flush=True)
    return {
        "schema_version": 1,
        "kind": "ctkat-corpus-correctness-snapshot",
        "snapshot_id": data["snapshot_id"],
        "method": "deterministic-keygen-enc-dec-or-sign-verify-api-roundtrip",
        "randomness": data["randomness"],
        "compiler": cc,
        "compiler_version": _compiler_version(cc),
        "system": platform.system(),
        "machine": platform.machine(),
        "targets": records,
    }


def load_snapshot(data: dict[str, Any]) -> dict[str, Any]:
    path = _repo_path(data["snapshot"], "snapshot")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("correctness snapshot root must be an object")
    return raw


def validate_snapshot(data: dict[str, Any], snapshot: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if set(snapshot) != SNAPSHOT_KEYS:
        errors.append("snapshot top-level field drift")
    if (
        snapshot.get("schema_version") != 1
        or snapshot.get("kind") != "ctkat-corpus-correctness-snapshot"
    ):
        errors.append("snapshot schema/kind drift")
    if snapshot.get("snapshot_id") != data.get("snapshot_id"):
        errors.append("snapshot id drift")
    if snapshot.get("method") != "deterministic-keygen-enc-dec-or-sign-verify-api-roundtrip":
        errors.append("snapshot method drift")
    if snapshot.get("randomness") != data.get("randomness"):
        errors.append("snapshot randomness drift")
    if snapshot.get("compiler") != data.get("compiler", {}).get("cc"):
        errors.append("snapshot compiler drift")
    for field in ("compiler_version", "system", "machine"):
        if not isinstance(snapshot.get(field), str) or not snapshot[field].strip():
            errors.append(f"snapshot {field} must be non-empty")
    expected = data.get("targets", [])
    actual = snapshot.get("targets")
    if not isinstance(actual, list) or len(actual) != len(expected):
        return [*errors, "snapshot target count drift"]
    for index, (target, record) in enumerate(zip(expected, actual, strict=True)):
        if not isinstance(record, dict):
            errors.append(f"snapshot target[{index}] must be an object")
            continue
        if set(record) != SNAPSHOT_TARGET_KEYS:
            errors.append(f"snapshot target[{index}] field drift")
        if record.get("target") != target["id"] or record.get("status") != "pass":
            errors.append(f"snapshot target[{index}] identity/status drift")
        if record.get("template") != target["template"] or record.get("config") != target["config"]:
            errors.append(f"snapshot target[{index}] method/config drift")
        if record.get("summary_harnesses") != target["summary_harnesses"]:
            errors.append(f"snapshot target[{index}] summary scope drift")
        for field in ("config_sha256", "input_set_sha256", "transcript_sha256"):
            if not isinstance(record.get(field), str) or not re.fullmatch(
                r"[0-9a-f]{64}", record[field]
            ):
                errors.append(f"snapshot target[{index}] invalid {field}")
        config_path = _repo_path(target["config"], "target.config")
        if record.get("config_sha256") != hashlib.sha256(config_path.read_bytes()).hexdigest():
            errors.append(f"snapshot target[{index}] config hash drift")
        cfg = load_config(config_path)
        assert cfg.ct is not None
        harness = next(h for h in cfg.ct.harnesses if h.name == target["source_harness"])
        sources = [(config_path.parent / value).resolve() for value in harness.sources]
        sources = [
            value
            for value in sources
            if value.name != "randombytes.c" and "deterministic_randombytes" not in value.name
        ]
        include_dirs = [(config_path.parent / value).resolve() for value in harness.include_dirs]
        observed_input_hash = _input_set_sha256(
            config_path, sources, include_dirs, _harness_source(harness)
        )
        if record.get("input_set_sha256") != observed_input_hash:
            errors.append(f"snapshot target[{index}] input set hash drift")
        if not isinstance(record.get("transcript_bytes"), int) or record["transcript_bytes"] <= 0:
            errors.append(f"snapshot target[{index}] invalid transcript length")
    return errors


def _fold_row(row: dict[str, str]) -> str:
    evidence = EvidenceV2(
        correctness=Correctness.PASS,
        structural=Structural(row["structural"]),
        asm=AsmEvidence(row["asm"]),
        asm_attribution=AsmAttribution(row["asm_attribution"]),
        timing_validity=TimingValidity(row["timing_validity"]),
        timing_signal=TimingSignal(row["timing_signal"]),
        review=ReviewStatus(row["review"]),
        review_id=row["review_id"],
        legacy_verdict_class=row["legacy_verdict_class"],
    )
    assert evidence.overall is not None
    return evidence.overall.value


def apply_corpus(data: dict[str, Any], snapshot: dict[str, Any]) -> int:
    errors = validate_snapshot(data, snapshot)
    if errors:
        raise ValueError("; ".join(errors))
    approved = {
        (record["target"], harness)
        for record in snapshot["targets"]
        for harness in record["summary_harnesses"]
    }
    with SUMMARY.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != SUMMARY_FIELDS:
            raise ValueError("corpus summary header drift")
        rows = list(reader)
    present = {(row["target"], row["harness"]) for row in rows}
    if not approved <= present:
        raise ValueError(
            f"correctness snapshot has unknown corpus pairs: {sorted(approved - present)}"
        )
    changed = 0
    note = f"correctness={data['snapshot_id']} deterministic API round-trip PASS"
    for row in rows:
        if (row["target"], row["harness"]) not in approved:
            continue
        if row["correctness"] != "pass":
            changed += 1
        row["correctness"] = "pass"
        row["overall"] = _fold_row(row)
        notes = [item for item in (row["notes"], note) if item]
        row["notes"] = "; ".join(dict.fromkeys(notes))
    temporary = SUMMARY.with_name(f".{SUMMARY.name}.tmp")
    with temporary.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SUMMARY_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(SUMMARY)
    return changed


def check_corpus_mapping(data: dict[str, Any], snapshot: dict[str, Any]) -> list[str]:
    approved = {
        (record["target"], harness)
        for record in snapshot.get("targets", [])
        for harness in record.get("summary_harnesses", [])
    }
    with SUMMARY.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    mapped = {(row["target"], row["harness"]) for row in rows if row["correctness"] == "pass"}
    missing = approved - mapped
    return [f"snapshot PASS not applied to corpus: {pair}" for pair in sorted(missing)]


def main() -> int:
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--write-snapshot", action="store_true")
    action.add_argument("--verify-snapshot", action="store_true")
    action.add_argument("--apply-corpus", action="store_true")
    args = parser.parse_args()
    try:
        data = load_manifest()
        if args.write_snapshot:
            snapshot = run_targets(data)
            path = _repo_path(data["snapshot"], "snapshot")
            path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"[correctness] wrote {path.relative_to(ROOT)}")
            return 0
        errors = validate_manifest(data)
        snapshot = load_snapshot(data)
        errors.extend(validate_snapshot(data, snapshot))
        if args.apply_corpus and not errors:
            changed = apply_corpus(data, snapshot)
            print(f"[correctness] applied PASS to {changed} corpus rows")
            return 0
        if args.verify_snapshot and not errors:
            observed = run_targets(data)
            expected_hashes = {
                row["target"]: (
                    row["input_set_sha256"],
                    row["transcript_sha256"],
                    row["transcript_bytes"],
                )
                for row in snapshot["targets"]
            }
            observed_hashes = {
                row["target"]: (
                    row["input_set_sha256"],
                    row["transcript_sha256"],
                    row["transcript_bytes"],
                )
                for row in observed["targets"]
            }
            if observed_hashes != expected_hashes:
                errors.append(
                    f"transcript hash drift: expected={expected_hashes}, observed={observed_hashes}"
                )
        if args.check:
            errors.extend(check_corpus_mapping(data, snapshot))
        if errors:
            for error in errors:
                print(f"[correctness] ERROR: {error}", file=sys.stderr)
            return 2
        print(f"[correctness] OK: {len(snapshot['targets'])} deterministic API round trips")
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, yaml.YAMLError) as exc:
        print(f"[correctness] ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
