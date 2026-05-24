import subprocess
from dataclasses import dataclass
from pathlib import Path


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
