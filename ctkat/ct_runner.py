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

MAX_VALGRIND_LOG_BYTES = 128 * 1024 * 1024


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
    """Map one Valgrind run to PASS / FAIL / ERROR (Bundle E-2 F2 + Q FN-3):

    - ERROR — (a) `returncode` not in {0, 99} (harness crash, Valgrind itself
      failed, or a timeout surfaced as rc=124); (b) the log file is missing; or
      (c) rc=99 (`--error-exitcode`: Valgrind detected >=1 error) but the parser
      matched ZERO known finding categories — a whitelist gap (new or
      locale-translated Memcheck message). An incomplete OR unverifiable
      analysis must NOT be read as "zero findings → PASS".
    - FAIL  — log parsed and at least one Finding.
    - PASS  — log parsed clean AND rc != 99 (rc=0 means Valgrind itself found
      nothing, so zero findings there is genuinely clean).

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
    log_size = log_path.stat().st_size
    if log_size > MAX_VALGRIND_LOG_BYTES:
        return CtRunOutcome(
            "ERROR",
            error=(
                f"valgrind log {log_path} is {log_size} bytes, exceeding "
                f"the {MAX_VALGRIND_LOG_BYTES}-byte parser limit — analysis "
                "incomplete; reduce the harness output or raise the limit in code."
            ),
        )
    text = log_path.read_text(encoding="utf-8", errors="replace")
    findings, dropped = parse_valgrind_log_with_stats(text, lookup_patterns=lookup_patterns)
    # Bundle Q (FN-3): rc=99 is `--error-exitcode=99` — Valgrind's ground-truth
    # signal "I detected >= 1 error". If we parsed ZERO findings from a log that
    # Valgrind says contains an error, our text whitelist (_FINDING_CLASSIFIERS)
    # missed it: a new/locale-translated Memcheck message, or an error category
    # we don't model. Reporting PASS here would be a fail-open — exactly the
    # false-green this tool exists to prevent. Classify it as ERROR so the
    # verdict matrix routes it to INCONCLUSIVE ("couldn't verify"), never CLEAN.
    # (rc=0 means Valgrind found nothing, so 0 findings there is genuinely PASS;
    # only the rc=99-with-0-findings combination is the whitelist-gap tell.)
    if result.returncode == 99 and not findings:
        return CtRunOutcome(
            "ERROR",
            findings=[],
            dropped=dropped,
            error=(
                "valgrind exited 99 (--error-exitcode: it detected >=1 error) "
                f"but the parser matched 0 known finding categories ({dropped} "
                "unrecognized lines) — likely a whitelist gap (new or "
                "locale-translated valgrind message). Refusing to report PASS."
            ),
        )
    status = "FAIL" if findings else "PASS"
    return CtRunOutcome(status, findings=findings, dropped=dropped)
