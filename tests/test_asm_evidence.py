"""Fail-closed contracts for source-granular ML-KEM assembly evidence."""

from __future__ import annotations

import copy
import csv
import hashlib
import json
import subprocess
from pathlib import Path

import pytest
import yaml

from ctkat.asm_evidence import (
    AsmEvidenceError,
    build_bundle,
    campaign_scope,
    load_campaign,
    load_target_index,
    validate_bundle,
    validate_campaign,
)

COMMIT = "a" * 40
ROOT = Path(__file__).resolve().parent.parent
DISASSEMBLY = """\
mini/common/fips202.c:1
0000000000000000 <shake128>:
   4:\t48 f7 f1             \tdivq   %rcx
mini/common/fips202.c:2
0000000000000010 <shake256>:
  14:\t48 f7 f2             \tdivq   %rdx
"""
NM = """\
0000000000000000 T shake128
0000000000000010 T shake256
"""


def _identity(command: str) -> dict:
    payload = {
        "command": command,
        "available": True,
        "resolved_path": f"/evidence-tools/{command}",
        "version": f"{command} fixture 1.0",
        "binary_sha256": hashlib.sha256(command.encode()).hexdigest(),
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    payload["identity_sha256"] = hashlib.sha256(encoded).hexdigest()
    return payload


def _write_fixture_repo(root: Path) -> Path:
    project = root / "mini"
    source = project / "common/fips202.c"
    source.parent.mkdir(parents=True)
    source.write_text("void shake128(void) {}\nvoid shake256(void) {}\n", encoding="utf-8")
    (project / "ctkat.yaml").write_text(
        """
project: {name: mini, language: c, root: .}
build: {command: "true", workdir: .}
ct:
  workdir: .
  generated_dir: ./_generated
  harnesses:
    - name: kem_dec
      template: kem
      header: api.h
      prefix: MINI_
      include_dirs: [common]
      sources: [common/fips202.c]
report: {output_dir: ./reports}
""".lstrip(),
        encoding="utf-8",
    )

    corpus = root / "corpus.csv"
    with corpus.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["family", "target", "harness", "asm_attribution"]
        )
        writer.writeheader()
        writer.writerow(
            {
                "family": "ML-KEM",
                "target": "mini",
                "harness": "kem_dec",
                "asm_attribution": "public",
            }
        )
    (root / "review.yaml").write_text(
        yaml.safe_dump({"scope": [{"target": "mini", "harness": "kem_dec"}]}),
        encoding="utf-8",
    )
    schema_bytes = (ROOT / "docs/measurement/asm_evidence_bundle_v1.schema.json").read_bytes()
    (root / "schema.json").write_bytes(schema_bytes)
    campaign = {
        "schema_version": "1.0",
        "kind": "ctkat-asm-evidence-campaign",
        "campaign_id": "mini-asm-v1",
        "status": "premeasurement-frozen",
        "source_revision_policy": "exact-clean-git-head",
        "host": {"system": "Linux", "architecture": "x86_64"},
        "tools": {
            "objdump": "objdump",
            "nm": "nm",
            "full_disassembly_argv": ["-dSl"],
        },
        "compilers": ["gcc", "clang"],
        "optimization_levels": ["-O0", "-O1", "-O2", "-O3", "-Os"],
        "corpus": {
            "path": "corpus.csv",
            "family": "ML-KEM",
            "attribution": "public",
            "review": "review.yaml",
        },
        "attribution_policy": {
            "allowed_source_suffixes": ["common/fips202.c"],
            "allowed_functions": ["shake128", "shake256"],
            "required_functions_per_harness": ["shake128", "shake256"],
        },
        "targets": [
            {
                "id": "mini",
                "config": "mini/ctkat.yaml",
                "harnesses": ["kem_dec"],
            }
        ],
        "artifact": {
            "schema": "schema.json",
            "schema_sha256": hashlib.sha256(schema_bytes).hexdigest(),
            "manifest_name": "asm_evidence_bundle.json",
            "raw_directory": "raw/sha256",
            "raw_content_addressed": True,
            "commit_raw_to_git": False,
        },
    }
    campaign_path = root / "campaign.yaml"
    campaign_path.write_text(yaml.safe_dump(campaign, sort_keys=False), encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=asm-evidence-test",
            "-c",
            "user.email=asm-evidence@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        cwd=root,
        check=True,
    )
    return campaign_path


def _fake_runner(argv, *, cwd=None, timeout=None):
    del cwd, timeout
    command = Path(argv[0]).name
    if command in {"gcc", "clang"}:
        Path(argv[-1]).write_bytes(b"fixture-object")
        dependency_path = Path(argv[argv.index("-MF") + 1])
        source_path = argv[argv.index("-c") + 1]
        dependency_path.write_text(f"{argv[-1]}: {source_path}\n", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, "", "")
    if command == "objdump":
        return subprocess.CompletedProcess(argv, 0, DISASSEMBLY, "")
    if command == "nm":
        return subprocess.CompletedProcess(argv, 0, NM, "")
    raise AssertionError(f"unexpected command: {argv}")


@pytest.fixture
def evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    campaign_path = _write_fixture_repo(tmp_path)
    monkeypatch.setattr("ctkat.asm_evidence.platform.system", lambda: "Linux")
    monkeypatch.setattr("ctkat.asm_evidence.platform.machine", lambda: "x86_64")
    identities = {command: _identity(command) for command in ("gcc", "clang", "objdump", "nm")}
    manifest, bundle_path, indexes = build_bundle(
        campaign_path,
        tmp_path / "external",
        repo_root=tmp_path,
        git_state_override=(COMMIT, True),
        tool_identities_override=identities,
        runner=_fake_runner,
    )
    return {
        "root": tmp_path,
        "campaign": campaign_path,
        "manifest": manifest,
        "bundle": bundle_path,
        "index": indexes[0],
        "identities": identities,
    }


def _validate(item: dict, **kwargs) -> list[str]:
    runner = kwargs.pop("runner", _fake_runner)
    return validate_bundle(
        item["bundle"],
        item["campaign"],
        repo_root=item["root"],
        current_git_state_override=(COMMIT, True),
        tool_identities_override=item["identities"],
        runner=runner,
        **kwargs,
    )


def _replace_manifest(item: dict, manifest: dict) -> None:
    item["bundle"].write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def test_builder_records_every_source_compiler_opt_and_full_operands(evidence):
    manifest = evidence["manifest"]
    assert manifest["coverage"] == {
        "status": "pass",
        "expected_cells": 10,
        "passed_cells": 10,
        "failed_cells": 0,
    }
    assert manifest["paper_eligible"] is True
    assert not _validate(evidence)
    assert all(cell["objdump_argv"][1:-1] == ["-dSl"] for cell in manifest["cells"])
    assert {
        candidate["operand_text"] for cell in manifest["cells"] for candidate in cell["candidates"]
    } == {
        "%rcx",
        "%rdx",
    }
    assert manifest["raw_bundle"]["artifact_count"] == 5
    assert len(manifest["raw_bundle"]["sha256"]) == 64


def test_target_index_can_resolve_parent_bundle_and_is_verified(evidence):
    loaded = load_target_index(
        evidence["index"],
        expected_target="mini",
        campaign_path=evidence["campaign"],
        repo_root=evidence["root"],
        tool_identities_override=evidence["identities"],
        runner=_fake_runner,
    )
    assert len(loaded["cells"]) == 10
    assert loaded["bundle_path"] == evidence["bundle"]


def test_deleted_raw_disassembly_is_rejected(evidence):
    raw = next((evidence["bundle"].parent / "raw/sha256").glob("*.objdump.txt"))
    raw.unlink()
    errors = _validate(evidence)
    assert any("raw disassembly unavailable" in error for error in errors)
    assert any("raw directory is incomplete" in error for error in errors)


def test_modified_raw_disassembly_is_rejected(evidence):
    raw = next((evidence["bundle"].parent / "raw/sha256").glob("*.objdump.txt"))
    raw.write_text(DISASSEMBLY + "tamper\n", encoding="utf-8")
    errors = _validate(evidence)
    assert any("raw disassembly hash mismatch" in error for error in errors)
    assert any("raw disassembly size mismatch" in error for error in errors)


@pytest.mark.parametrize(
    ("field", "bad_value", "expected_error"),
    [
        ("source_sha256", "0" * 64, "source_sha256 drift"),
        ("config_sha256", "1" * 64, "config_sha256 drift"),
        ("object_sha256", "2" * 64, "preserved object hash drift"),
    ],
)
def test_source_config_and_object_hash_tamper_is_rejected(
    evidence, field, bad_value, expected_error
):
    manifest = copy.deepcopy(evidence["manifest"])
    manifest["cells"][0][field] = bad_value
    _replace_manifest(evidence, manifest)
    assert any(expected_error in error for error in _validate(evidence))


def test_tool_identity_and_all_recorded_argv_are_checked(evidence):
    mutations = [
        (
            lambda manifest: manifest["toolchain"]["compilers"]["gcc"].__setitem__(
                "binary_sha256", "0" * 64
            ),
            "compiler gcc identity hash drift",
        ),
        (
            lambda manifest: manifest["cells"][0]["compile_argv"].__setitem__(1, "-O9"),
            "compile argv drift",
        ),
        (
            lambda manifest: manifest["cells"][0]["compile_argv"].__setitem__(
                -1, "/attacker/output.o"
            ),
            "compile argv drift",
        ),
        (
            lambda manifest: manifest["cells"][0]["objdump_argv"].__setitem__(1, "-d"),
            "objdump argv drift",
        ),
        (
            lambda manifest: manifest["cells"][0]["nm_argv"].__setitem__(1, "-u"),
            "nm argv drift",
        ),
    ]
    for mutate, expected in mutations:
        manifest = copy.deepcopy(evidence["manifest"])
        mutate(manifest)
        _replace_manifest(evidence, manifest)
        assert any(expected in error for error in _validate(evidence))


def test_compile_transcript_hashes_are_bound_to_preserved_artifacts(evidence):
    manifest = copy.deepcopy(evidence["manifest"])
    manifest["cells"][0]["compile"]["stdout_sha256"] = "b" * 64
    manifest["cells"][0]["compile"]["stderr_sha256"] = "c" * 64
    _replace_manifest(evidence, manifest)
    errors = _validate(evidence)
    assert any("compile stdout hash/artifact drift" in error for error in errors)
    assert any("compile stderr hash/artifact drift" in error for error in errors)


def test_dependency_manifest_is_tracked_hashed_and_rebuilt(evidence):
    manifest = copy.deepcopy(evidence["manifest"])
    dependency = manifest["cells"][0]["dependencies"][0]
    dependency["sha256"] = "d" * 64
    _replace_manifest(evidence, manifest)
    errors = _validate(evidence)
    assert any("dependency content drift" in error for error in errors)


def test_runtime_json_schema_rejects_unknown_fields(evidence):
    manifest = copy.deepcopy(evidence["manifest"])
    manifest["attacker_extension"] = {"ignored_before": True}
    manifest["cells"][0]["compile"]["attacker_extension"] = True
    _replace_manifest(evidence, manifest)
    errors = _validate(evidence)
    assert any("bundle schema violation" in error for error in errors)


@pytest.mark.parametrize("entry_kind", ["directory", "broken-symlink"])
def test_raw_tree_rejects_every_non_regular_entry(evidence, entry_kind):
    raw_dir = evidence["bundle"].parent / "raw/sha256"
    entry = raw_dir / f"unindexed-{entry_kind}"
    if entry_kind == "directory":
        entry.mkdir()
    else:
        entry.symlink_to("missing-target")
    errors = _validate(evidence)
    assert any("raw directory contains non-regular entries" in error for error in errors)


def test_output_root_and_parent_symlinks_are_rejected(tmp_path, monkeypatch):
    campaign_path = _write_fixture_repo(tmp_path)
    monkeypatch.setattr("ctkat.asm_evidence.platform.system", lambda: "Linux")
    monkeypatch.setattr("ctkat.asm_evidence.platform.machine", lambda: "x86_64")
    identities = {command: _identity(command) for command in ("gcc", "clang", "objdump", "nm")}
    actual = tmp_path / "actual-output"
    actual.mkdir()
    linked_root = tmp_path / "linked-output"
    linked_root.symlink_to(actual, target_is_directory=True)
    with pytest.raises(AsmEvidenceError, match="output root contains a symlink"):
        build_bundle(
            campaign_path,
            linked_root,
            repo_root=tmp_path,
            git_state_override=(COMMIT, True),
            tool_identities_override=identities,
            runner=_fake_runner,
        )

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(AsmEvidenceError, match="output root contains a symlink"):
        build_bundle(
            campaign_path,
            linked_parent / "bundle",
            repo_root=tmp_path,
            git_state_override=(COMMIT, True),
            tool_identities_override=identities,
            runner=_fake_runner,
        )


def test_tracked_symlink_to_ignored_source_is_rejected(tmp_path):
    campaign_path = _write_fixture_repo(tmp_path)
    source = tmp_path / "mini/common/fips202.c"
    ignored = tmp_path / "mini/.ignored/payload.c"
    ignored.parent.mkdir()
    ignored.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    source.unlink()
    source.symlink_to("../.ignored/payload.c")
    (tmp_path / ".gitignore").write_text("mini/.ignored/\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=asm-evidence-test",
            "-c",
            "user.email=asm-evidence@example.invalid",
            "commit",
            "-qm",
            "tracked symlink fixture",
        ],
        cwd=tmp_path,
        check=True,
    )
    campaign = load_campaign(campaign_path)
    errors = validate_campaign(
        campaign,
        campaign_path=campaign_path,
        repo_root=tmp_path,
    )
    assert any("sources[0] contains a symlink" in error for error in errors)


def test_campaign_binds_exact_runtime_schema_hash(tmp_path):
    campaign_path = _write_fixture_repo(tmp_path)
    campaign = load_campaign(campaign_path)
    campaign["artifact"]["schema_sha256"] = "0" * 64
    errors = validate_campaign(
        campaign,
        campaign_path=campaign_path,
        repo_root=tmp_path,
    )
    assert "artifact schema hash drift" in errors


@pytest.mark.parametrize(
    ("relative_path", "expected_error"),
    [
        ("campaign.yaml", "campaign manifest contains a symlink"),
        ("corpus.csv", "corpus.path contains a symlink"),
        ("review.yaml", "corpus.review contains a symlink"),
        ("schema.json", "artifact.schema contains a symlink"),
    ],
)
def test_campaign_support_inputs_reject_tracked_symlinks(tmp_path, relative_path, expected_error):
    campaign_path = _write_fixture_repo(tmp_path)
    original = tmp_path / relative_path
    ignored = tmp_path / ".ignored" / relative_path
    ignored.parent.mkdir(parents=True, exist_ok=True)
    original.replace(ignored)
    original.symlink_to(ignored.relative_to(original.parent))
    (tmp_path / ".gitignore").write_text(".ignored/\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=asm-evidence-test",
            "-c",
            "user.email=asm-evidence@example.invalid",
            "commit",
            "-qm",
            f"tracked {relative_path} symlink fixture",
        ],
        cwd=tmp_path,
        check=True,
    )
    campaign = load_campaign(campaign_path)
    errors = validate_campaign(
        campaign,
        campaign_path=campaign_path,
        repo_root=tmp_path,
    )
    assert any(expected_error in error for error in errors)


def test_candidate_operand_and_aggregate_raw_hash_tamper_is_rejected(evidence):
    manifest = copy.deepcopy(evidence["manifest"])
    manifest["cells"][0]["candidates"][0]["operand_text"] = "%attacker"
    manifest["raw_bundle"]["sha256"] = "0" * 64
    _replace_manifest(evidence, manifest)
    errors = _validate(evidence)
    assert any("raw candidate/operand transcript drift" in error for error in errors)
    assert "aggregate raw bundle hash mismatch" in errors


def test_independent_source_rebuild_must_match_preserved_object_semantics(evidence):
    def divergent_rebuild_runner(argv, *, cwd=None, timeout=None):
        del timeout
        command = Path(argv[0]).name
        if command in {"gcc", "clang"}:
            Path(argv[-1]).write_bytes(b"independently-rebuilt-object")
            dependency_path = Path(argv[argv.index("-MF") + 1])
            source_path = argv[argv.index("-c") + 1]
            dependency_path.write_text(f"{argv[-1]}: {source_path}\n", encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0, "", "")
        object_path = Path(argv[-1])
        if not object_path.is_absolute() and cwd is not None:
            object_path = Path(cwd) / object_path
        rebuilt = object_path.read_bytes() == b"independently-rebuilt-object"
        if command == "objdump":
            output = DISASSEMBLY + (
                "0000000000000020 <drift>:\n  20:\t90\tnop\n" if rebuilt else ""
            )
            return subprocess.CompletedProcess(argv, 0, output, "")
        if command == "nm":
            output = NM + ("0000000000000020 T drift\n" if rebuilt else "")
            return subprocess.CompletedProcess(argv, 0, output, "")
        raise AssertionError(f"unexpected command: {argv}")

    errors = _validate(evidence, runner=divergent_rebuild_runner)
    assert any("independent source rebuild disassembly differs" in error for error in errors)
    assert any("independent source rebuild nm symbols differ" in error for error in errors)


def test_partial_optimization_failure_can_never_keep_coverage_pass(evidence):
    manifest = copy.deepcopy(evidence["manifest"])
    victim = next(cell for cell in manifest["cells"] if cell["opt"] == "-O2")
    victim["compile"] = {"status": "error", "diagnostic": "fixture failure"}
    victim["disassembly"] = {"status": "not-run"}
    victim["status"] = "compile-error"
    _replace_manifest(evidence, manifest)
    errors = _validate(evidence)
    assert any("incomplete cell compile-error" in error for error in errors)
    assert any("coverage summary drift" in error for error in errors)
    assert any("complete coverage required" in error for error in errors)


def test_missing_cell_counts_as_failed_not_as_smaller_campaign(evidence):
    manifest = copy.deepcopy(evidence["manifest"])
    manifest["cells"].pop()
    _replace_manifest(evidence, manifest)
    errors = _validate(evidence)
    assert any("missing source/compiler/opt cells" in error for error in errors)
    assert any("'failed_cells': 1" in error for error in errors)


def test_exact_clean_commit_is_enforced(evidence):
    mismatch = validate_bundle(
        evidence["bundle"],
        evidence["campaign"],
        repo_root=evidence["root"],
        current_git_state_override=("b" * 40, True),
    )
    assert any("!= current HEAD" in error for error in mismatch)
    dirty = validate_bundle(
        evidence["bundle"],
        evidence["campaign"],
        repo_root=evidence["root"],
        current_git_state_override=(COMMIT, False),
    )
    assert "current repository is dirty" in dirty


def test_every_public_attributed_corpus_row_must_be_in_frozen_scope(tmp_path):
    campaign_path = _write_fixture_repo(tmp_path)
    with (tmp_path / "corpus.csv").open("a", encoding="utf-8") as handle:
        handle.write("ML-KEM,forgotten,kem_dec,public\n")
    campaign = yaml.safe_load(campaign_path.read_text(encoding="utf-8"))
    errors = validate_campaign(campaign, campaign_path=campaign_path, repo_root=tmp_path)
    assert any("public-attributed corpus scope mismatch" in error for error in errors)


def test_committed_mlkem_campaign_covers_all_six_public_rows():
    campaign_path = ROOT / "docs/measurement/mlkem_asm_evidence_v1.yaml"
    schema_path = ROOT / "docs/measurement/asm_evidence_bundle_v1.schema.json"
    tracked = subprocess.run(
        [
            "git",
            "ls-files",
            "--error-unmatch",
            "--",
            str(campaign_path.relative_to(ROOT)),
            str(schema_path.relative_to(ROOT)),
        ],
        cwd=ROOT,
        capture_output=True,
    )
    if tracked.returncode != 0:
        pytest.skip("new campaign/schema must be committed before static validation")
    campaign = load_campaign(campaign_path)
    assert not validate_campaign(campaign, campaign_path=campaign_path, repo_root=ROOT)
    assert {(row["target"], row["harness"]) for row in campaign_scope(campaign)} == {
        (target, harness)
        for target in (
            "pqclean_mlkem512",
            "pqclean_mlkem768",
            "pqclean_mlkem1024",
        )
        for harness in ("kem_dec", "kem_dec_fo")
    }
