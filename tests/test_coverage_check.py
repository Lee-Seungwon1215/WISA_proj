"""Bundle F (F6): unit tests for the secret_regions coverage probe.

We can't depend on PQClean macros being available in the test environment,
so the tests fabricate a tiny header with a literal CRYPTO_SECRETKEYBYTES
macro and a couple of dummy size macros. The compile path here is
end-to-end real (gcc on the test host), not mocked — F6 is precisely
"the framework's integer math doesn't match the compiler's integer math"
detection, so mocking gcc would defeat the test.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from ctkat.coverage_check import (
    CoverageResult,
    _render_sentinel_c,
    check_secret_region_coverage,
)


# Skip the compile-path tests entirely on hosts without gcc — F6 itself
# would just emit a yellow note there.
_HAS_CC = shutil.which("gcc") is not None
needs_cc = pytest.mark.skipif(not _HAS_CC, reason="gcc not available")


def _write_fake_header(dir_path: Path, total: int, parts: dict) -> None:
    body = [f"#define TEST_CRYPTO_SECRETKEYBYTES {total}"]
    for name, value in parts.items():
        body.append(f"#define {name} {value}")
    (dir_path / "fake_api.h").write_text("\n".join(body) + "\n")


def test_render_sentinel_c_handles_empty_extras():
    code = _render_sentinel_c(
        header="api.h", extra_headers=[], prefix="FOO_",
        secret_region_lengths=["32", "8"],
    )
    assert '#include "api.h"' in code
    assert "(32) + (8)" in code
    assert "FOO_CRYPTO_SECRETKEYBYTES" in code


def test_no_secret_regions_returns_none(tmp_path):
    # Full-sk taint policy → nothing to verify, return None immediately
    # (and don't bother compiling).
    result = check_secret_region_coverage(
        harness_name="h", header="fake_api.h", extra_headers=[],
        prefix="TEST_", secret_region_lengths=[],
        include_dirs=[tmp_path], workdir=tmp_path,
    )
    assert result is None


@needs_cc
def test_coverage_above_threshold_passes_silently(tmp_path, capsys):
    _write_fake_header(tmp_path, total=100, parts={"SEC_A": 80, "SEC_B": 20})
    result = check_secret_region_coverage(
        harness_name="kem_full", header="fake_api.h", extra_headers=[],
        prefix="TEST_", secret_region_lengths=["SEC_A", "SEC_B"],
        include_dirs=[tmp_path], workdir=tmp_path,
    )
    assert isinstance(result, CoverageResult)
    assert result.covered == 100
    assert result.total == 100
    assert result.ratio == 1.0
    out = capsys.readouterr().out
    # Dim-style info line, not a WARNING.
    assert "WARNING" not in out
    assert "100/100" in out


@needs_cc
def test_coverage_below_threshold_warns(tmp_path, capsys):
    # 32 bytes claimed out of 2400 = 1.3% coverage — the canonical
    # "user typed `length: 32` instead of the real macro" mistake.
    _write_fake_header(tmp_path, total=2400, parts={"WRONG_LEN": 32})
    result = check_secret_region_coverage(
        harness_name="kem_typo", header="fake_api.h", extra_headers=[],
        prefix="TEST_", secret_region_lengths=["WRONG_LEN"],
        include_dirs=[tmp_path], workdir=tmp_path,
    )
    assert result is not None
    assert result.covered == 32
    assert result.total == 2400
    assert result.ratio < 0.5
    out = capsys.readouterr().out
    assert "WARNING" in out
    assert "kem_typo" in out
    assert "32/2400" in out


@needs_cc
def test_compile_failure_returns_none_with_note(tmp_path, capsys):
    # Reference an undefined macro — gcc errors, we must emit a yellow
    # note and return None (never block).
    result = check_secret_region_coverage(
        harness_name="missing_header", header="does_not_exist.h",
        extra_headers=[], prefix="TEST_", secret_region_lengths=["32"],
        include_dirs=[tmp_path], workdir=tmp_path,
    )
    assert result is None
    out = capsys.readouterr().out
    assert "F6 coverage check skipped" in out


@needs_cc
def test_total_zero_returns_result_but_skips_comparison(tmp_path, capsys):
    # Defensive: if CRYPTO_SECRETKEYBYTES somehow expands to 0 we
    # shouldn't divide. The probe still runs and returns a result with
    # ratio=0.0, but no WARNING line (we can't say "below threshold"
    # when the threshold itself is undefined).
    _write_fake_header(tmp_path, total=0, parts={"SEC_A": 0})
    result = check_secret_region_coverage(
        harness_name="zero_total", header="fake_api.h", extra_headers=[],
        prefix="TEST_", secret_region_lengths=["SEC_A"],
        include_dirs=[tmp_path], workdir=tmp_path,
    )
    assert result is not None
    assert result.total == 0
    out = capsys.readouterr().out
    assert "WARNING" not in out
    assert "total=0" in out


# --- Bundle P (T17): user cflags propagation to probe ----------------


def test_filter_probe_cflags_keeps_define_and_include_only():
    """T17 regression: ct cflags like `-O2 -g -fno-lto -DCONFIG_X=1
    -isystem /usr/include/foo` had only `-I` paths reach the probe.
    The filter must keep `-D`/`-U`/`-isystem`/`-iquote`/`-I` (everything
    that influences which headers / macros the preprocessor sees) and
    drop the rest (`-O*`, `-g`, `-fno-lto`, etc.) since the probe is
    intentionally `-O0` and incompatible with some flags."""
    from ctkat.coverage_check import _filter_probe_cflags
    cflags = [
        "-O2", "-g", "-fno-omit-frame-pointer", "-fno-lto",
        "-DCONFIG_X=1", "-D", "CONFIG_Y=2", "-UFOO",
        "-isystem", "/usr/include/foo",
        "-Ipath/inline", "-I", "path/separated",
        "-Wall", "-Werror",
    ]
    kept = _filter_probe_cflags(cflags)
    assert "-DCONFIG_X=1" in kept
    assert "-D" in kept and "CONFIG_Y=2" in kept
    assert "-UFOO" in kept
    assert "-isystem" in kept and "/usr/include/foo" in kept
    assert "-Ipath/inline" in kept
    assert "-I" in kept and "path/separated" in kept
    # Noise must be dropped.
    for noise in ("-O2", "-g", "-fno-lto", "-fno-omit-frame-pointer",
                  "-Wall", "-Werror"):
        assert noise not in kept, f"{noise} leaked through filter"
