import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class ValgrindResult:
    returncode: int
    log_path: Path
    stdout: str
    stderr: str


def run_valgrind(
    binary: Path,
    log_path: Path,
    valgrind_flags: List[str],
    workdir: Path,
) -> ValgrindResult:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "valgrind",
        *valgrind_flags,
        f"--log-file={log_path}",
        str(binary.resolve()),
    ]
    proc = subprocess.run(
        cmd,
        cwd=str(workdir),
        capture_output=True,
        text=True,
    )
    return ValgrindResult(
        returncode=proc.returncode,
        log_path=log_path,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )
