import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader, StrictUndefined


TEMPLATE_DIR = Path(__file__).parent / "templates"

# Map of yaml `template` value -> template file under TEMPLATE_DIR.
TEMPLATE_FILES = {
    "generic": "harness_generic.c.j2",
    "kem": "harness_kem.c.j2",
    "sign": "harness_sign.c.j2",
}


class HarnessGenerationError(RuntimeError):
    pass


@dataclass
class GeneratedHarness:
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


def render_harness(template: str, context: Dict[str, Any]) -> str:
    """Render a harness template to C source code."""
    if template not in TEMPLATE_FILES:
        raise HarnessGenerationError(
            f"unknown template {template!r}; expected one of {sorted(TEMPLATE_FILES)}"
        )
    env = _make_env()
    return env.get_template(TEMPLATE_FILES[template]).render(**context)


def compile_harness(
    source_path: Path,
    binary_path: Path,
    sources: List[Path],
    include_dirs: List[Path],
    cflags: List[str],
    workdir: Path,
) -> str:
    """Compile a generated harness with gcc. Returns the command string used."""
    binary_path.parent.mkdir(parents=True, exist_ok=True)
    cmd: List[str] = ["gcc"]
    cmd.extend(cflags)
    cmd.extend(f"-I{d}" for d in include_dirs)
    cmd.append(str(source_path))
    cmd.extend(str(s) for s in sources)
    cmd.extend(["-o", str(binary_path)])

    proc = subprocess.run(
        cmd,
        cwd=str(workdir),
        capture_output=True,
        text=True,
    )
    cmd_str = " ".join(cmd)
    if proc.returncode != 0:
        raise HarnessGenerationError(
            f"failed to compile harness ({cmd_str}):\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return cmd_str


def generate_and_compile(
    name: str,
    template: str,
    context: Dict[str, Any],
    output_dir: Path,
    sources: List[Path],
    include_dirs: List[Path],
    cflags: List[str],
    workdir: Path,
) -> GeneratedHarness:
    output_dir.mkdir(parents=True, exist_ok=True)
    source_path = output_dir / f"harness_{name}.c"
    binary_path = output_dir / f"harness_{name}"

    code = render_harness(template, context)
    source_path.write_text(code)

    cmd_str = compile_harness(
        source_path=source_path,
        binary_path=binary_path,
        sources=sources,
        include_dirs=include_dirs,
        cflags=cflags,
        workdir=workdir,
    )
    return GeneratedHarness(
        source_path=source_path,
        binary_path=binary_path,
        compile_command=cmd_str,
    )
