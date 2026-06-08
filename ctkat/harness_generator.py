import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from ._proc import run_text


def _atomic_write_text(path: Path, content: str) -> None:
    """Bundle P (T19): write `path` atomically. The tempfile + rename
    pattern means concurrent `ctkat` runs sharing the same `_generated/`
    directory can't see a half-written `harness_*.c` — either the old
    contents or the complete new contents, never a mix. Important for
    CI matrix builds that fan out the same yaml across OS / seed.

    `os.replace` is atomic on POSIX (rename(2)) and on Windows (the
    underlying ReplaceFile API). `tempfile` lives in the same directory
    so the rename is within one filesystem (otherwise rename can fall
    back to a non-atomic copy)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp_name, path)
    except BaseException:
        # Best-effort cleanup if rename never happened — don't shadow the
        # original exception.
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


TEMPLATE_DIR = Path(__file__).parent / "templates"

# Map of yaml `template` value -> template file under TEMPLATE_DIR.
TEMPLATE_FILES = {
    "generic": "harness_generic.c.j2",
    "kem": "harness_kem.c.j2",
    "sign": "harness_sign.c.j2",
}


class HarnessGenerationError(RuntimeError):
    pass


class CompilerNotFoundError(HarnessGenerationError):
    """The compiler itself is missing / not executable (FN-1 via run_text's
    ToolNotFoundError), as opposed to a genuine non-zero compile of valid
    inputs. Subclasses HarnessGenerationError so existing
    `except HarnessGenerationError` handlers still catch it, but the cli can
    catch it FIRST and exit 2 (toolchain error) — consistent with the
    objdump/valgrind/ct-matrix preflights — instead of exit 1 (a real
    compile failure). FN-5(exit-code)."""
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
    *,
    timeout: float,
    cc: str = "gcc",
) -> str:
    """Compile a generated harness with `cc` (default gcc). Returns the command
    string used.

    Bundle N (T12): `timeout` is keyword-only and required so a pathological
    compile (cyclic include, runaway optimizer) can't hang CI silently.
    Raises HarnessGenerationError on either non-zero rc or timeout.

    Phase C: `cc` is parameterized so the ct-matrix can recompile the *same*
    harness under several compilers (gcc/clang); the single-build ct stage keeps
    the gcc default so existing behavior is unchanged.
    """
    import subprocess as _sp  # local import to keep TimeoutExpired narrow
    binary_path.parent.mkdir(parents=True, exist_ok=True)
    cmd: List[str] = [cc]
    cmd.extend(cflags)
    cmd.extend(f"-I{d}" for d in include_dirs)
    cmd.append(str(source_path))
    cmd.extend(str(s) for s in sources)
    cmd.extend(["-o", str(binary_path)])

    cmd_str = " ".join(cmd)
    try:
        proc = run_text(cmd, cwd=workdir, timeout=timeout)
    except _sp.TimeoutExpired:
        raise HarnessGenerationError(
            f"harness compile exceeded timeout={timeout}s ({cmd_str}). "
            "Bump cfg.ct.compile_timeout or diagnose the hang."
        )
    except FileNotFoundError as e:
        # Bundle Q (FN-1): the compiler (`cc`, default gcc) is missing / not
        # executable (run_text raised ToolNotFoundError, a FileNotFoundError
        # subclass). Raise CompilerNotFoundError so the cli reports it cleanly
        # AND exits 2 (toolchain error), not a raw traceback or exit 1.
        raise CompilerNotFoundError(
            f"compiler {cc!r} not found / not executable — install it (e.g. add "
            f"to the Docker image) or set the harness `cc`. ({e})"
        )
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
    *,
    timeout: float,
    cc: str = "gcc",
) -> GeneratedHarness:
    output_dir.mkdir(parents=True, exist_ok=True)
    source_path = output_dir / f"harness_{name}.c"
    binary_path = output_dir / f"harness_{name}"

    code = render_harness(template, context)
    _atomic_write_text(source_path, code)

    cmd_str = compile_harness(
        source_path=source_path,
        binary_path=binary_path,
        sources=sources,
        include_dirs=include_dirs,
        cflags=cflags,
        workdir=workdir,
        timeout=timeout,
        cc=cc,
    )
    return GeneratedHarness(
        source_path=source_path,
        binary_path=binary_path,
        compile_command=cmd_str,
    )
