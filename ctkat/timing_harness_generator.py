"""Generator for dudect-style timing harnesses.

Distinct from `harness_generator.py` (the Valgrind-side generator) because
the templates and code-generation concerns are different:
  - timing harness needs a clock backend (rdtsc / monotonic)
  - it bakes in measurement count, warmup count, and PRNG seed
  - it doesn't link against valgrind/memcheck.h
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .harness_generator import HarnessGenerationError, TEMPLATE_DIR


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
) -> str:
    binary_path.parent.mkdir(parents=True, exist_ok=True)
    cmd: List[str] = [cc]
    cmd.extend(cflags)
    cmd.extend(f"-I{d}" for d in include_dirs)
    cmd.append(str(source_path))
    cmd.extend(str(s) for s in sources)
    cmd.extend(["-o", str(binary_path)])

    proc = subprocess.run(
        cmd, cwd=str(workdir), capture_output=True, text=True,
    )
    cmd_str = " ".join(cmd)
    if proc.returncode != 0:
        raise HarnessGenerationError(
            f"failed to compile timing harness ({cmd_str}):\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
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
) -> GeneratedTimingHarness:
    output_dir.mkdir(parents=True, exist_ok=True)
    source_path = output_dir / f"timing_{name}.c"
    binary_path = output_dir / f"timing_{name}"

    code = render_timing_harness(template, context)
    source_path.write_text(code)

    cmd_str = _compile(
        cc=cc,
        source_path=source_path,
        binary_path=binary_path,
        sources=sources,
        include_dirs=include_dirs,
        cflags=cflags,
        workdir=workdir,
    )
    return GeneratedTimingHarness(
        source_path=source_path,
        binary_path=binary_path,
        compile_command=cmd_str,
    )
