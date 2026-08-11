import json
import shutil
from pathlib import Path

import pytest

from ctkat import cli
from ctkat.dudect_runner import TimingSamples
from ctkat.timing_build_provenance import (
    TimingBuildProvenanceError,
    assert_timing_build_provenance_unchanged,
    assert_timing_build_seal_unchanged,
    capture_timing_build_provenance,
    sha256_file,
    write_timing_build_provenance,
)


def _capture(tmp_path: Path) -> tuple[dict, Path, str, dict[str, Path]]:
    compiler = shutil.which("cc") or shutil.which("gcc")
    assert compiler is not None
    include_dir = tmp_path / "include"
    include_dir.mkdir()
    config = tmp_path / "ctkat.yaml"
    source = tmp_path / "implementation.c"
    generated = tmp_path / "timing_h.c"
    binary = tmp_path / "timing_h"
    config.write_text("project: {name: seal-test}\n", encoding="utf-8")
    source.write_text("int implementation(void) { return 7; }\n", encoding="utf-8")
    generated.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    binary.write_bytes(b"compiled timing harness\n")
    payload = capture_timing_build_provenance(
        compiler=compiler,
        cflags=["-O2", "-fno-lto"],
        include_dirs=[include_dir],
        linked_sources=[source],
        generated_source=generated,
        binary=binary,
        config_path=config,
        compile_command=f"{compiler} -O2 timing_h.c implementation.c -o timing_h.tmp",
    )
    seal = tmp_path / "reports" / "timing_h.build-seal.json"
    seal_hash = write_timing_build_provenance(seal, payload)
    paths = {
        "config": config,
        "source": source,
        "generated": generated,
        "binary": binary,
        "include": include_dir,
    }
    return payload, seal, seal_hash, paths


def test_build_provenance_captures_exact_replayable_inputs(tmp_path):
    payload, seal, seal_hash, paths = _capture(tmp_path)

    assert payload["schema_version"] == "1.0"
    assert payload["kind"] == "ctkat-timing-build-provenance"
    assert payload["captured_before_measurement"] is True
    assert payload["config"]["sha256"] == sha256_file(paths["config"])
    assert payload["generated_source"]["sha256"] == sha256_file(paths["generated"])
    assert payload["binary"]["sha256"] == sha256_file(paths["binary"])
    assert payload["linked_sources"][0]["sha256"] == sha256_file(paths["source"])
    assert payload["reproduction_argv"][-2:] == ["-o", str(paths["binary"].resolve())]
    assert json.loads(seal.read_text(encoding="utf-8")) == payload
    assert seal_hash == sha256_file(seal)
    assert_timing_build_seal_unchanged(payload, seal, seal_hash)


@pytest.mark.parametrize("target", ["config", "source", "generated", "binary"])
def test_build_provenance_rejects_any_sealed_input_mutation(tmp_path, target):
    payload, _, _, paths = _capture(tmp_path)
    path = paths[target]
    if target == "binary":
        path.write_bytes(path.read_bytes() + b"tampered")
    else:
        path.write_text(path.read_text(encoding="utf-8") + "/* tampered */\n", encoding="utf-8")

    with pytest.raises(TimingBuildProvenanceError, match="changed after sealing"):
        assert_timing_build_provenance_unchanged(payload)


def test_build_provenance_rejects_published_seal_mutation(tmp_path):
    payload, seal, seal_hash, _ = _capture(tmp_path)
    seal.write_text(seal.read_text(encoding="utf-8") + " ", encoding="utf-8")

    with pytest.raises(TimingBuildProvenanceError, match="seal changed"):
        assert_timing_build_seal_unchanged(payload, seal, seal_hash)


def test_measured_subprocess_wrapper_rejects_mid_run_binary_replacement(tmp_path, monkeypatch):
    payload, seal, seal_hash, paths = _capture(tmp_path)

    def replace_binary_during_run(*_args, **_kwargs):
        paths["binary"].write_bytes(b"replacement timing binary\n")
        return TimingSamples()

    monkeypatch.setattr(cli, "run_timing_harness", replace_binary_during_run)

    with pytest.raises(TimingBuildProvenanceError, match="changed after sealing"):
        cli._run_timing_harness_with_build_seal(
            paths["binary"],
            tmp_path,
            build_provenance=payload,
            build_provenance_path=seal,
            build_provenance_sha256=seal_hash,
        )


def test_build_provenance_rejects_symlink_inputs(tmp_path):
    payload, _, _, paths = _capture(tmp_path)
    compiler = payload["compiler"]["requested_command"]
    linked_symlink = tmp_path / "linked-symlink.c"
    linked_symlink.symlink_to(paths["source"])
    include_symlink = tmp_path / "include-symlink"
    include_symlink.symlink_to(paths["include"], target_is_directory=True)

    common = {
        "compiler": compiler,
        "cflags": [],
        "generated_source": paths["generated"],
        "binary": paths["binary"],
        "config_path": paths["config"],
        "compile_command": "cc timing_h.c -o timing_h.tmp",
    }
    with pytest.raises(TimingBuildProvenanceError, match="non-symlink"):
        capture_timing_build_provenance(
            **common,
            include_dirs=[paths["include"]],
            linked_sources=[linked_symlink],
        )
    with pytest.raises(TimingBuildProvenanceError, match="non-symlink"):
        capture_timing_build_provenance(
            **common,
            include_dirs=[include_symlink],
            linked_sources=[paths["source"]],
        )


def test_build_provenance_rejects_duplicate_inputs_and_schema_drift(tmp_path):
    payload, _, _, paths = _capture(tmp_path)
    compiler = payload["compiler"]["requested_command"]
    common = {
        "compiler": compiler,
        "cflags": [],
        "generated_source": paths["generated"],
        "binary": paths["binary"],
        "config_path": paths["config"],
        "compile_command": "cc timing_h.c -o timing_h.tmp",
    }
    with pytest.raises(TimingBuildProvenanceError, match="include directory.*duplicates"):
        capture_timing_build_provenance(
            **common,
            include_dirs=[paths["include"], paths["include"]],
            linked_sources=[paths["source"]],
        )
    with pytest.raises(TimingBuildProvenanceError, match="linked source.*duplicates"):
        capture_timing_build_provenance(
            **common,
            include_dirs=[paths["include"]],
            linked_sources=[paths["source"], paths["source"]],
        )

    payload["unexpected"] = True
    with pytest.raises(TimingBuildProvenanceError, match="field set drifted"):
        assert_timing_build_provenance_unchanged(payload)
