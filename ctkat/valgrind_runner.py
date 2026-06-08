"""Bundle N (T12 + T18): subprocess goes through `_proc.run_text`.
A hung valgrind run (rare, but possible on some interception edge cases)
is now bounded by `cfg.ct.valgrind_timeout`; the caller catches
TimeoutExpired and lands the harness as status=ERROR → INCONCLUSIVE.
"""

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ._proc import run_text


@dataclass
class ValgrindResult:
    returncode: int
    log_path: Path
    stdout: str
    stderr: str
    timed_out: bool = False


def run_valgrind(
    binary: Path,
    log_path: Path,
    valgrind_flags: List[str],
    workdir: Path,
    *,
    timeout: float,
) -> ValgrindResult:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "valgrind",
        *valgrind_flags,
        f"--log-file={log_path}",
        str(binary.resolve()),
    ]
    try:
        proc = run_text(cmd, cwd=workdir, timeout=timeout)
    except subprocess.TimeoutExpired:
        # Caller routes timed_out=True into status=ERROR. Picked a recognizable
        # rc to keep the path through `_do_ct`'s "rc not in (0, 99)" check.
        return ValgrindResult(
            returncode=124,
            log_path=log_path,
            stdout="",
            stderr=f"[ctkat] valgrind exceeded timeout={timeout}s",
            timed_out=True,
        )
    except FileNotFoundError as e:
        # Bundle Q (FN-1): valgrind is missing / not executable (run_text raised
        # ToolNotFoundError). This is the single most common failure on a fresh
        # (esp. non-Linux) machine and used to escape as a raw traceback. Return
        # a recognizable rc (127) so `classify_valgrind_run` maps it to ERROR ->
        # INCONCLUSIVE, fail-closed, no traceback. (ct-matrix / asm-scan already
        # shutil.which()-preflight this; the ct/run path now fails just as
        # cleanly.) The message carries the original error to stay accurate.
        return ValgrindResult(
            returncode=127,
            log_path=log_path,
            stdout="",
            stderr=(
                "[ctkat] valgrind could not be run — it needs a Linux/Docker "
                f"environment; install it and retry. ({e})"
            ),
        )
    return ValgrindResult(
        returncode=proc.returncode,
        log_path=log_path,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )
