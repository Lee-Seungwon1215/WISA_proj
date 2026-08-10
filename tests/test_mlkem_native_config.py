import platform
import shutil
import subprocess
from pathlib import Path

import pytest

from ctkat.cli import _dudect_context
from ctkat.config import load_config
from ctkat.dudect_runner import run_timing_harness
from ctkat.timing_harness_generator import generate_and_compile_timing

ROOT = Path(__file__).resolve().parents[1]
MLKEM_DIR = ROOT / "examples/mlkem_native"
X86_CONFIG = MLKEM_DIR / "ctkat_timing_x86_64.yaml"
PORTABLE_CONFIG = MLKEM_DIR / "ctkat_timing_portable.yaml"
X86_V2_CONFIG = MLKEM_DIR / "ctkat_timing_x86_64_v2.yaml"
PORTABLE_V2_CONFIG = MLKEM_DIR / "ctkat_timing_portable_v2.yaml"

ARITH_BACKEND_FLAG = '-DMLK_CONFIG_ARITH_BACKEND_FILE="native/meta.h"'
FIPS202_BACKEND_FLAG = '-DMLK_CONFIG_FIPS202_BACKEND_FILE="fips202/native/auto.h"'


def test_mlkem_x86_config_pins_canonical_native_backend_headers():
    x86 = load_config(X86_CONFIG)
    portable = load_config(PORTABLE_CONFIG)
    assert x86.dudect is not None
    assert portable.dudect is not None

    flags = x86.dudect.compiler.cflags
    assert ARITH_BACKEND_FLAG in flags
    assert FIPS202_BACKEND_FLAG in flags

    harness = x86.dudect.harnesses[0]
    assert harness.include_dirs == [Path("upstream/mlkem")]
    assert harness.sources == [
        Path("upstream/mlkem/mlkem_native.c"),
        Path("upstream/mlkem/mlkem_native_asm.S"),
    ]

    include_root = MLKEM_DIR / harness.include_dirs[0]
    assert (include_root / "src/native/meta.h").is_file()
    assert (include_root / "src/fips202/native/auto.h").is_file()

    portable_flags = portable.dudect.compiler.cflags
    assert ARITH_BACKEND_FLAG not in portable_flags
    assert FIPS202_BACKEND_FLAG not in portable_flags
    assert portable.dudect.harnesses[0].sources == [Path("upstream/mlkem/mlkem_native.c")]


def test_mlkem_v2_configs_use_explicit_valid_tuple_axis():
    portable = load_config(PORTABLE_V2_CONFIG)
    x86 = load_config(X86_V2_CONFIG)

    for cfg in (portable, x86):
        assert cfg.dudect is not None
        assert len(cfg.dudect.harnesses) == 1
        harness = cfg.dudect.harnesses[0]
        assert harness.name == "kem_dec_valid_tuple"
        assert harness.leak_target == "valid_tuple"

    assert x86.dudect is not None
    assert ARITH_BACKEND_FLAG in x86.dudect.compiler.cflags
    assert FIPS202_BACKEND_FLAG in x86.dudect.compiler.cflags
    assert portable.dudect is not None
    assert ARITH_BACKEND_FLAG not in portable.dudect.compiler.cflags
    assert FIPS202_BACKEND_FLAG not in portable.dudect.compiler.cflags


def test_mlkem_v2_portable_harness_emits_mixed_attribution_contract(tmp_path):
    cfg = load_config(PORTABLE_V2_CONFIG)
    assert cfg.dudect is not None
    dudect = cfg.dudect
    if shutil.which(dudect.compiler.cc) is None:
        pytest.skip(f"compiler {dudect.compiler.cc!r} is unavailable")
    harness = dudect.harnesses[0]
    context = _dudect_context(harness, dudect, 0xC0FFEE, "monotonic")
    context.update(measurements=2, warmup=1, pool_size=2)
    generated = generate_and_compile_timing(
        name=harness.name,
        template=harness.template,
        context=context,
        output_dir=tmp_path,
        sources=[(MLKEM_DIR / source).resolve() for source in harness.sources],
        include_dirs=[(MLKEM_DIR / path).resolve() for path in harness.include_dirs],
        cflags=dudect.compiler.cflags,
        cc=dudect.compiler.cc,
        workdir=MLKEM_DIR,
        timeout=120,
    )

    samples = run_timing_harness(
        generated.binary_path,
        MLKEM_DIR,
        timeout=120,
        seed_override=0xC0FFEE,
        mode="target",
        measurements_override=2,
    )

    assert samples.raw_n_total == 2
    expected_metadata = {
        "axis": "valid_tuple",
        "key_policy": "class0-fixed-class1-fresh",
        "class_contract": "fixed-valid-tuple-vs-fresh-valid-tuples",
        "secret_key_varies_between_classes": "true",
        "public_ciphertext_varies_between_classes": "true",
        "embedded_public_key_material_varies_between_classes": "true",
        "secret_attribution_permitted": "false",
        "setup_return_codes": "checked",
        "valid_tuple_round_trip_witness": "all-pool-members",
        "corpus_seed": str(0xC0FFEE),
    }
    assert {
        key: samples.runtime_metadata.get(key) for key in expected_metadata
    } == expected_metadata


@pytest.mark.skipif(
    platform.machine().lower() not in {"x86_64", "amd64"},
    reason="mlkem-native AVX2 assembly profile is x86_64-only",
)
def test_mlkem_v2_x86_generated_harness_full_links_and_round_trips(tmp_path):
    cfg = load_config(X86_V2_CONFIG)
    assert cfg.dudect is not None
    dudect = cfg.dudect
    if shutil.which(dudect.compiler.cc) is None:
        pytest.skip(f"compiler {dudect.compiler.cc!r} is unavailable")

    harness = dudect.harnesses[0]
    sources = [(MLKEM_DIR / source).resolve() for source in harness.sources]
    include_dirs = [(MLKEM_DIR / path).resolve() for path in harness.include_dirs]
    pinned_files = [MLKEM_DIR / "FETCH_INFO.md", *sources]
    missing = [str(path) for path in pinned_files if not path.is_file()]
    if missing:
        pytest.skip(f"pinned mlkem-native checkout is unavailable: {', '.join(missing)}")
    assert "Revision: `398050c877ff4353c96305c6434b63528accfc37`" in (
        MLKEM_DIR / "FETCH_INFO.md"
    ).read_text(encoding="utf-8")

    context = _dudect_context(harness, dudect, 0xC0FFEE, "rdtsc")
    context.update(measurements=2, warmup=1, pool_size=2)
    generated = generate_and_compile_timing(
        name=harness.name,
        template=harness.template,
        context=context,
        output_dir=tmp_path,
        sources=sources,
        include_dirs=include_dirs,
        cflags=dudect.compiler.cflags,
        cc=dudect.compiler.cc,
        workdir=MLKEM_DIR,
        timeout=120,
    )

    assert ARITH_BACKEND_FLAG in generated.compile_command
    assert FIPS202_BACKEND_FLAG in generated.compile_command
    assert all(str(source) in generated.compile_command for source in sources)
    assert str(MLKEM_DIR / "upstream/mlkem/mlkem_native.c") in generated.compile_command
    assert str(MLKEM_DIR / "upstream/mlkem/mlkem_native_asm.S") in generated.compile_command

    # run_timing_harness raises on a nonzero process return code, so reaching
    # these assertions also records an rc=0 full-link execution witness.
    samples = run_timing_harness(
        generated.binary_path,
        MLKEM_DIR,
        timeout=120,
        seed_override=0xC0FFEE,
        mode="target",
        measurements_override=2,
    )

    assert samples.raw_n_total == 2
    assert samples.runtime_metadata["measurements"] == "2"
    assert samples.runtime_metadata["setup_return_codes"] == "checked"
    assert samples.runtime_metadata["valid_tuple_round_trip_witness"] == "all-pool-members"


@pytest.mark.parametrize("config_path", [X86_CONFIG, X86_V2_CONFIG])
def test_mlkem_x86_config_compiles_public_then_internal_headers(config_path):
    """Match the generated timing harness's failure-prone include order."""
    cfg = load_config(config_path)
    assert cfg.dudect is not None
    compiler = shutil.which(cfg.dudect.compiler.cc)
    if compiler is None:
        pytest.skip(f"compiler {cfg.dudect.compiler.cc!r} is unavailable")

    target_flags: list[str] = []
    machine = platform.machine().lower()
    if platform.system() == "Darwin" and machine in {"arm64", "aarch64"}:
        target_flags = ["-arch", "x86_64"]
    elif machine not in {"x86_64", "amd64"}:
        pytest.skip("an x86_64 compiler target is unavailable")

    harness = cfg.dudect.harnesses[0]
    include_flags = [f"-I{MLKEM_DIR / path}" for path in harness.include_dirs]
    probe = '#include "mlkem_native.h"\n#include "src/randombytes.h"\n'
    result = subprocess.run(
        [
            compiler,
            *target_flags,
            *cfg.dudect.compiler.cflags,
            *include_flags,
            "-x",
            "c",
            "-fsyntax-only",
            "-",
        ],
        input=probe,
        cwd=MLKEM_DIR,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
