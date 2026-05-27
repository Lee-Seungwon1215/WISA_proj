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
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional, Sequence, Union


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
    """
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
