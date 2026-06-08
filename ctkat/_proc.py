"""Bundle N (T12 + T18): single source of truth for `subprocess.run`.

Every external invocation in this codebase needs:
  - a `timeout` to prevent CI hangs on infinite-loop / runaway commands
  - `encoding="utf-8", errors="replace"` so misbehaving binaries that dump
    garbage bytes on stdout/stderr can't escape as a raw `UnicodeDecodeError`
    traceback (T6's "ERROR status, no Python traceback" promise was leaking
    at 7 call sites before this helper).

`timeout` is *required* — no default. Forgetting to pass it is exactly the
T12 mistake we're trying to make impossible, so the type checker / runtime
should reject the call instead of silently using `None` (no limit).

Bundle Q (FN-1): the policy this helper centralizes used to cover timeout and
decoding but NOT the single most common real-world failure — the program in
`argv[0]` can't be run. A bare `subprocess.run` raises an `OSError` (most often
`FileNotFoundError` "not installed / not on PATH", but also `PermissionError`
for a non-executable file or noexec mount, `NotADirectoryError`/`IsADirectoryError`
for a bad path component, or `ETXTBSY` for a binary still being written) from
deep inside `_execute_child`. That escaped every runner that only caught
`TimeoutExpired` (valgrind/gcc/objdump/the harness binary) as a raw Python
traceback — the exact opposite of the ERROR/INCONCLUSIVE contract those runners
advertise. We translate the WHOLE family here, once, into a `ToolNotFoundError`
so "can't run the tool" is handled by the same single source of truth as
timeout/encoding. It subclasses `FileNotFoundError` so every site that already
caught `FileNotFoundError` (asm_scan `nm`, coverage_check probe, and the FN-1
runner catches) handles the non-exec case too with no per-caller edit.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional, Sequence, Union


class ToolNotFoundError(FileNotFoundError):
    """`argv[0]` could not be executed — it isn't installed / on PATH, isn't
    executable, sits behind a bad path component, or is text-file-busy.

    Subclasses `FileNotFoundError` deliberately: existing `except
    FileNotFoundError` call sites keep catching it, while callers that want to
    distinguish a missing/unrunnable *tool* from a missing *data file* can catch
    this narrower type. `.tool` carries the offending program name; the message
    appends the original OSError so the real cause (missing vs not-executable vs
    bad cwd) is never misreported.
    """

    def __init__(self, tool: str, original: OSError) -> None:
        self.tool = tool
        super().__init__(
            f"could not execute {tool!r}: {original} — is it installed, on "
            f"PATH, and executable?"
        )


def run_text(
    argv: Union[str, Sequence[str]],
    *,
    timeout: float,
    cwd: Optional[Path] = None,
    shell: bool = False,
    check: bool = False,
    capture_output: bool = True,
) -> subprocess.CompletedProcess:
    """Invoke a subprocess with the policy enforced.

    Raises `subprocess.TimeoutExpired` if the child exceeds `timeout` —
    callers wrap this into their own ERROR/INCONCLUSIVE status. Does NOT
    raise on non-zero exit codes unless `check=True`.

    Raises `ToolNotFoundError` (a `FileNotFoundError` subclass) when the
    program in `argv[0]` can't be found/executed, so callers get a typed,
    user-readable failure instead of a raw `_execute_child` traceback. With
    `shell=True` a missing command surfaces as rc=127 from the shell, not as
    this exception (the shell itself exists); the only OSError a `shell=True`
    call raises this way is a missing/!dir `cwd`, which is also translated here.
    """
    try:
        return subprocess.run(
            argv,
            cwd=str(cwd) if cwd is not None else None,
            shell=shell,
            capture_output=capture_output,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=check,
        )
    except OSError as e:
        # Every OSError out of a subprocess start means "couldn't run argv[0]":
        # FileNotFoundError (missing / not on PATH / missing cwd), PermissionError
        # (not executable / noexec mount), NotADirectoryError / IsADirectoryError
        # (bad path component), ETXTBSY (binary still being written). Translate
        # the whole family into ToolNotFoundError so the single source of truth
        # covers them all — callers that catch FileNotFoundError get the non-exec
        # case for free (ToolNotFoundError subclasses it). The message appends the
        # original error so a missing-cwd is never mislabeled as a missing-tool.
        # `subprocess.TimeoutExpired` is NOT an OSError, so it still propagates to
        # the caller's own timeout handling untouched.
        if isinstance(e, ToolNotFoundError):
            raise
        prog = argv if isinstance(argv, str) else (argv[0] if argv else "")
        raise ToolNotFoundError(str(prog), e) from e
