import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run_shell(command: str, workdir: Path) -> RunResult:
    """Run a user-provided shell command and capture its output."""
    proc = subprocess.run(
        command,
        shell=True,
        cwd=str(workdir),
        capture_output=True,
        text=True,
    )
    return RunResult(
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def run_argv(argv: List[str], workdir: Path) -> RunResult:
    """Bundle H2 (T4): structured alternative to `run_shell`. No shell
    interpolation — pass the program + args as a list and subprocess
    invokes execve directly. Use this whenever the user supplied an
    `argv:` yaml field instead of `command:`, so a yaml from an untrusted
    source can't smuggle shell metacharacters (`; rm -rf /`, backticks,
    pipes) past the framework.
    """
    proc = subprocess.run(
        argv,
        cwd=str(workdir),
        capture_output=True,
        text=True,
    )
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
) -> RunResult:
    """Dispatch: argv (shell=False) takes precedence over command
    (shell=True) when both happen to be set. Caller (config validator)
    should enforce "exactly one"; this helper just picks the safer
    branch if both leak through."""
    if argv is not None:
        return run_argv(argv, workdir)
    if command is None:
        raise ValueError("run_step: neither command nor argv supplied")
    return run_shell(command, workdir)
