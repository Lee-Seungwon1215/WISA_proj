"""Generator for dudect-style timing harnesses.

Distinct from `harness_generator.py` (the Valgrind-side generator) because
the templates and code-generation concerns are different:
  - timing harness needs a clock backend (rdtsc / monotonic)
  - it bakes in measurement count, warmup count, and PRNG seed
  - it doesn't link against valgrind/memcheck.h
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from ._proc import run_text
from .harness_generator import (
    CompilerNotFoundError,
    HarnessGenerationError,
    TEMPLATE_DIR,
    _atomic_write_text,
    _temp_output_path,
)


TIMING_TEMPLATE_FILES = {
    "generic": "timing_generic.c.j2",
    "kem": "timing_kem.c.j2",
}


@dataclass
class GeneratedTimingHarness:
    source_path: Path
    binary_path: Path
    compile_command: str


def _make_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_timing_harness(template: str, context: Dict[str, Any]) -> str:
    if template not in TIMING_TEMPLATE_FILES:
        raise HarnessGenerationError(
            f"unknown timing template {template!r}; expected one of "
            f"{sorted(TIMING_TEMPLATE_FILES)}"
        )
    env = _make_env()
    return env.get_template(TIMING_TEMPLATE_FILES[template]).render(**context)


def _compile(
    cc: str,
    source_path: Path,
    binary_path: Path,
    sources: List[Path],
    include_dirs: List[Path],
    cflags: List[str],
    workdir: Path,
    *,
    timeout: float,
) -> str:
    import subprocess as _sp
    binary_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_binary = _temp_output_path(binary_path)
    cmd: List[str] = [cc]
    cmd.extend(cflags)
    cmd.extend(f"-I{d}" for d in include_dirs)
    cmd.append(str(source_path))
    cmd.extend(str(s) for s in sources)
    cmd.extend(["-o", str(tmp_binary)])

    cmd_str = " ".join(cmd)
    try:
        proc = run_text(cmd, cwd=workdir, timeout=timeout)
    except _sp.TimeoutExpired:
        try:
            tmp_binary.unlink()
        except FileNotFoundError:
            pass
        raise HarnessGenerationError(
            f"timing harness compile exceeded timeout={timeout}s ({cmd_str}). "
            "Bump cfg.dudect.compile_timeout or diagnose the hang."
        )
    except FileNotFoundError as e:
        try:
            tmp_binary.unlink()
        except FileNotFoundError:
            pass
        # Bundle Q (FN-1): dudect compiler (`cfg.dudect.compiler.cc`) missing /
        # not executable. CompilerNotFoundError so `_do_dudect` exits 2
        # (toolchain error), consistent with the ct path and the preflights.
        raise CompilerNotFoundError(
            f"compiler {cc!r} not found / not executable — install it (e.g. add "
            f"to the Docker image) or set cfg.dudect.compiler.cc. ({e})"
        )
    if proc.returncode != 0:
        try:
            tmp_binary.unlink()
        except FileNotFoundError:
            pass
        raise HarnessGenerationError(
            f"failed to compile timing harness ({cmd_str}):\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    try:
        import os
        os.replace(tmp_binary, binary_path)
    except OSError as e:
        try:
            tmp_binary.unlink()
        except FileNotFoundError:
            pass
        raise HarnessGenerationError(
            f"failed to publish compiled timing harness {binary_path}: {e}"
        ) from e
    return cmd_str


def generate_and_compile_timing(
    name: str,
    template: str,
    context: Dict[str, Any],
    output_dir: Path,
    sources: List[Path],
    include_dirs: List[Path],
    cflags: List[str],
    cc: str,
    workdir: Path,
    *,
    timeout: float,
) -> GeneratedTimingHarness:
    output_dir.mkdir(parents=True, exist_ok=True)
    source_path = output_dir / f"timing_{name}.c"
    binary_path = output_dir / f"timing_{name}"

    code = render_timing_harness(template, context)
    _atomic_write_text(source_path, code)
    compile_source_path = _temp_output_path(source_path, suffix=".c")
    compile_source_path.write_text(code, encoding="utf-8")

    try:
        cmd_str = _compile(
            cc=cc,
            source_path=compile_source_path,
            binary_path=binary_path,
            sources=sources,
            include_dirs=include_dirs,
            cflags=cflags,
            workdir=workdir,
            timeout=timeout,
        )
    finally:
        try:
            compile_source_path.unlink()
        except FileNotFoundError:
            pass
    return GeneratedTimingHarness(
        source_path=source_path,
        binary_path=binary_path,
        compile_command=cmd_str,
    )
