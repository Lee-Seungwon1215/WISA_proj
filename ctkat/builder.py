"""Build / KAT step runners.

Bundle N (T12 + T18): every subprocess call routes through `_proc.run_text`,
which enforces a timeout, utf-8 decoding, and `errors='replace'`. The
`timeout` argument is keyword-only and required — callers must pass the
yaml-configurable value (`cfg.build.timeout` / `cfg.kat.timeout`) so a
hung script can't stall CI silently.
"""

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ._proc import run_text


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def _timeout_result(cmd_desc: str, timeout: float) -> RunResult:
    """Synthesize a non-zero RunResult that the caller can treat as a
    build/KAT failure when the subprocess exceeded its `timeout`.
    Keeping the diagnostic in stderr means the existing fail-message
    plumbing (red banner + dump) still shows the user what happened."""
    return RunResult(
        returncode=124,  # GNU `timeout(1)` convention
        stdout="",
        stderr=(
            f"[ctkat] subprocess exceeded timeout={timeout}s: {cmd_desc}\n"
            "Bump cfg.build.timeout / cfg.kat.timeout if the wall-clock "
            "limit was just too tight; otherwise diagnose the hang."
        ),
    )


def run_shell(command: str, workdir: Path, *, timeout: float) -> RunResult:
    """Run a user-provided shell command and capture its output."""
    try:
        proc = run_text(command, shell=True, cwd=workdir, timeout=timeout)
    except subprocess.TimeoutExpired:
        return _timeout_result(command, timeout)
    return RunResult(
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def run_argv(argv: List[str], workdir: Path, *, timeout: float) -> RunResult:
    """Bundle H2 (T4): structured alternative to `run_shell`. No shell
    interpolation — pass the program + args as a list and subprocess
    invokes execve directly. Use this whenever the user supplied an
    `argv:` yaml field instead of `command:`, so a yaml from an untrusted
    source can't smuggle shell metacharacters (`; rm -rf /`, backticks,
    pipes) past the framework.
    """
    try:
        proc = run_text(argv, cwd=workdir, timeout=timeout)
    except subprocess.TimeoutExpired:
        return _timeout_result(" ".join(argv), timeout)
    return RunResult(
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def run_step(
    *,
    command: Optional[str],
    argv: Optional[List[str]],
    workdir: Path,
    timeout: float,
) -> RunResult:
    """Dispatch: argv (shell=False) takes precedence over command
    (shell=True) when both happen to be set. Caller (config validator)
    should enforce "exactly one"; this helper just picks the safer
    branch if both leak through."""
    if argv is not None:
        return run_argv(argv, workdir, timeout=timeout)
    if command is None:
        raise ValueError("run_step: neither command nor argv supplied")
    return run_shell(command, workdir, timeout=timeout)
