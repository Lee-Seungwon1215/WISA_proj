"""Phase C: the single Valgrind run-and-classify step shared by the `ct` stage
(`cli._do_ct`) and the `ct-matrix` sweep (`ct_matrix.py`).

Extracted so the PASS / FAIL / ERROR mapping lives in ONE place. If the matrix
copy-pasted `_do_ct`'s inline classification, a future fix to one and not the
other is exactly the divergence CLAUDE.md §3/§5 warns about (the matrix would
quietly disagree with the run verdict on the same binary).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .valgrind_parser import Finding, parse_valgrind_log_with_stats
from .valgrind_runner import ValgrindResult


@dataclass
class CtRunOutcome:
    """The classified result of one Valgrind run."""

    status: str                                   # "PASS" | "FAIL" | "ERROR"
    findings: List[Finding] = field(default_factory=list)
    dropped: int = 0                              # parser-ignored lines (caller may warn if high)
    error: str = ""                               # human-readable reason when status == "ERROR"


def classify_valgrind_run(
    result: ValgrindResult,
    log_path: Path,
    *,
    lookup_patterns: Optional[List[str]] = None,
) -> CtRunOutcome:
    """Map one Valgrind run to PASS / FAIL / ERROR (Bundle E-2 F2 semantics):

    - ERROR — `returncode` not in {0, 99} (harness crash, Valgrind itself
      failed, or a timeout surfaced as rc=124), or the log file is missing. An
      incomplete analysis must NOT be read as "zero findings → PASS".
    - FAIL  — log parsed and at least one Finding.
    - PASS  — log parsed clean.

    The manual-binary sentinel check (F5) is deliberately NOT here: it is
    specific to manual harnesses and orthogonal to Valgrind's own outcome, so it
    stays in the caller (`_do_ct`). The ct-matrix only drives template harnesses,
    which never need it.
    """
    if result.returncode not in (0, 99):
        reason = f"valgrind exited with code {result.returncode}"
        if getattr(result, "timed_out", False):
            reason += " (timeout)"
        return CtRunOutcome("ERROR", error=reason)
    if not log_path.exists():
        return CtRunOutcome("ERROR", error="valgrind produced no log file")
    text = log_path.read_text(encoding="utf-8", errors="replace")
    findings, dropped = parse_valgrind_log_with_stats(text, lookup_patterns=lookup_patterns)
    status = "FAIL" if findings else "PASS"
    return CtRunOutcome(status, findings=findings, dropped=dropped)
