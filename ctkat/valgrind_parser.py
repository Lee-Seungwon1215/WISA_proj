import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple


class FindingType(str, Enum):
    SECRET_DEPENDENT_BRANCH = "SECRET_DEPENDENT_BRANCH"
    SECRET_DEPENDENT_VALUE_USE = "SECRET_DEPENDENT_VALUE_USE"
    SECRET_DEPENDENT_MEMORY_ACCESS = "SECRET_DEPENDENT_MEMORY_ACCESS"
    MEMORY_ERROR = "MEMORY_ERROR"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class StackFrame:
    address: str
    function: str
    file: Optional[str] = None
    line: Optional[int] = None


@dataclass
class Finding:
    type: FindingType
    severity: Severity
    message: str
    frames: List[StackFrame] = field(default_factory=list)
    origin_frames: List[StackFrame] = field(default_factory=list)

    @property
    def primary_frame(self) -> Optional[StackFrame]:
        return self.frames[0] if self.frames else None

    @property
    def origin_frame(self) -> Optional[StackFrame]:
        return self.origin_frames[0] if self.origin_frames else None


_HEADER_RE = re.compile(r"^==(?P<pid>\d+)==\s?(?P<content>.*)$")
_FRAME_RE = re.compile(
    r"^==(?P<pid>\d+)==\s+(?:at|by)\s+"
    r"(?P<addr>0x[0-9A-Fa-f]+):\s+"
    r"(?P<fn>.+?)(?:\s+\((?P<loc>.+)\))?\s*$"
)
_FILE_LINE_RE = re.compile(r"^(.+):(\d+)$")
# Bundle P (T16): binary-only frame locations look like `in /lib/libc.so.6`
# (no source mapping — common when leaks surface inside shared libs without
# `-g`). `_FILE_LINE_RE` doesn't match these and used to leak through as
# file="in /lib/...", line=None. Now we recognize them explicitly: file
# is the binary path, line stays None, and downstream code can render
# "(/lib/libc.so.6:?)" instead of the ambiguous "(in /lib/...)".
_BINARY_LOCATION_RE = re.compile(r"^in\s+(.+)$")


# Whitelist of message prefixes that start a real finding. Anything else
# (banner lines like "Memcheck, a memory error detector", "ERROR SUMMARY",
# "HEAP SUMMARY", "Command:", etc.) is treated as non-finding noise.
_FINDING_CLASSIFIERS: tuple[tuple[str, FindingType, Severity], ...] = (
    ("Conditional jump or move", FindingType.SECRET_DEPENDENT_BRANCH, Severity.HIGH),
    ("Use of uninitialised value", FindingType.SECRET_DEPENDENT_VALUE_USE, Severity.MEDIUM),
    ("Syscall param", FindingType.SECRET_DEPENDENT_VALUE_USE, Severity.MEDIUM),
    ("Invalid read", FindingType.MEMORY_ERROR, Severity.HIGH),
    ("Invalid write", FindingType.MEMORY_ERROR, Severity.HIGH),
    ("Invalid free", FindingType.MEMORY_ERROR, Severity.HIGH),
    ("Mismatched free", FindingType.MEMORY_ERROR, Severity.HIGH),
    ("Source and destination overlap", FindingType.MEMORY_ERROR, Severity.HIGH),
)


def _classify(message: str) -> Optional[Finding]:
    for prefix, ftype, severity in _FINDING_CLASSIFIERS:
        if message.startswith(prefix):
            return Finding(type=ftype, severity=severity, message=message)
    return None


# Heuristics for promoting a `SECRET_DEPENDENT_VALUE_USE` finding to
# `SECRET_DEPENDENT_MEMORY_ACCESS` once the stack trace is known. We use
# this because Memcheck's textual output doesn't natively distinguish
# "secret value used in an address calculation" from "secret value used in
# arithmetic" — both surface as "Use of uninitialised value of size N".
#
# Signals (any one is enough):
#   - top frame's function is a known memory routine (memcpy, etc.)
#   - any frame function or file name contains a lookup-table pattern
#     (sbox, ttable, lookup, table)
# Only memory-touching primitives belong here. Comparison routines
# (memcmp/strcmp/strncmp) walk inputs sequentially with an index that's a
# loop counter, not a secret-derived offset, so a tainted-value finding in
# their stack is a VALUE_USE (e.g. byte values being compared), not a
# memory-address leak. Including them here would over-promote findings to
# HIGH/MEMORY_ACCESS and inflate severity.
_MEMORY_FUNCTION_NAMES = frozenset({
    "memcpy", "__memcpy", "mempcpy", "memmove", "memset", "bcopy",
    "strcpy", "strncpy", "stpcpy",
})
_LOOKUP_PATTERNS = ("sbox", "ttable", "tbox", "lookup", "_table")


def _is_memory_access(
    frames: List[StackFrame],
    lookup_patterns: Sequence[str] = _LOOKUP_PATTERNS,
    memory_function_names: FrozenSet[str] = _MEMORY_FUNCTION_NAMES,
) -> bool:
    """Bundle I (T2): both heuristic vocabularies are now overridable.
    `_LOOKUP_PATTERNS` defaults stay (sbox/ttable/...) but users with
    domain-specific names (e.g. `verify_table_size` getting false-
    positive promoted) can pass a tighter list via yaml
    `ct.lookup_function_patterns`."""
    if not frames:
        return False
    top_fn = frames[0].function.lower()
    if top_fn in memory_function_names:
        return True
    for fr in frames:
        fn = fr.function.lower()
        if any(pat in fn for pat in lookup_patterns):
            return True
        if fr.file and any(pat in fr.file.lower() for pat in lookup_patterns):
            return True
    return False


def _finalize(
    f: Finding,
    lookup_patterns: Sequence[str] = _LOOKUP_PATTERNS,
    memory_function_names: FrozenSet[str] = _MEMORY_FUNCTION_NAMES,
) -> Finding:
    """Optionally promote VALUE_USE to MEMORY_ACCESS based on stack context."""
    if (
        f.type == FindingType.SECRET_DEPENDENT_VALUE_USE
        and _is_memory_access(f.frames, lookup_patterns, memory_function_names)
    ):
        f.type = FindingType.SECRET_DEPENDENT_MEMORY_ACCESS
        f.severity = Severity.HIGH
    return f


def _parse_frame_location(location: str) -> tuple[Optional[str], Optional[int]]:
    m = _FILE_LINE_RE.match(location)
    if m:
        try:
            return m.group(1).strip(), int(m.group(2))
        except ValueError:
            return location, None
    # T16: binary-only location, e.g. "in /lib/x86_64-linux-gnu/libc.so.6".
    # Strip the "in " prefix so the rendered output is the raw binary path
    # (`/lib/libc.so.6:?` after the cli's `file:line` formatter).
    bm = _BINARY_LOCATION_RE.match(location)
    if bm:
        return bm.group(1).strip(), None
    return location, None


def _make_frame(address: str, function: str, location: Optional[str]) -> StackFrame:
    file_, line = _parse_frame_location(location) if location is not None else (None, None)
    return StackFrame(address=address, function=function, file=file_, line=line)


def parse_valgrind_log(
    text: str,
    lookup_patterns: Optional[Sequence[str]] = None,
) -> List[Finding]:
    """Parse a Valgrind Memcheck log into a list of Finding objects.

    Bundle I (T2): `lookup_patterns` lets the caller (cli, yaml) override
    the built-in heuristic substring list (`sbox/ttable/tbox/lookup/_table`)
    when domain function names cause false-positive promotion to
    `SECRET_DEPENDENT_MEMORY_ACCESS`. `None` keeps backward-compat defaults.

    State machine over `==PID==` lines:
      - A non-empty content line that is NOT a frame line starts a new finding
        (or switches to origin mode if it says "Uninitialised value was created").
      - Frame lines append to current finding's frames or origin_frames.
      - An empty content line (`==PID== `) closes the current finding.
    """
    findings, _stats = parse_valgrind_log_with_stats(text, lookup_patterns)
    return findings


def parse_valgrind_log_with_stats(
    text: str,
    lookup_patterns: Optional[Sequence[str]] = None,
) -> Tuple[List[Finding], int]:
    """Bundle I (T3): like `parse_valgrind_log`, but also returns the
    number of valgrind lines our `_classify` whitelist didn't recognize.

    Includes banner/footer (`Memcheck, a memory error detector`,
    `ERROR SUMMARY`, `Command:`, etc.) so the count is a *raw signal*:
    when this number suddenly jumps after a Valgrind version upgrade or
    locale change, the parser may have stopped recognizing real findings.

    Returns `(findings, dropped_messages)`.
    """
    lp = tuple(lookup_patterns) if lookup_patterns is not None else _LOOKUP_PATTERNS
    findings: List[Finding] = []
    current_by_pid: Dict[str, Finding] = {}
    in_origin_by_pid: Dict[str, bool] = {}
    dropped = 0

    for raw in text.splitlines():
        header = _HEADER_RE.match(raw)
        if not header:
            continue
        pid = header.group("pid")
        content = header.group("content").rstrip()

        # finding boundary
        if content == "":
            current = current_by_pid.pop(pid, None)
            if current is not None:
                findings.append(_finalize(current, lp))
                in_origin_by_pid.pop(pid, None)
            continue

        # frame line?
        fm = _FRAME_RE.match(raw)
        if fm:
            current = current_by_pid.get(pid)
            if current is None:
                continue
            frame = _make_frame(
                fm.group("addr"),
                fm.group("fn").strip(),
                fm.group("loc").strip() if fm.group("loc") is not None else None,
            )
            if in_origin_by_pid.get(pid, False):
                current.origin_frames.append(frame)
            else:
                current.frames.append(frame)
            continue

        # origin marker switches to origin-frame collection within current finding
        if "Uninitialised value was created" in content:
            if pid in current_by_pid:
                in_origin_by_pid[pid] = True
            continue

        # otherwise this is a new finding header — close previous if any
        new_finding = _classify(content.lstrip())
        if new_finding is None:
            # banner/footer/unrecognized line. Bundle I (T3) counts these
            # so a Valgrind format drift becomes a visible signal.
            dropped += 1
            continue
        current = current_by_pid.get(pid)
        if current is not None:
            # Apply post-classification heuristics (e.g. VALUE_USE→MEMORY_ACCESS
            # promotion) even when the previous finding closes without an
            # explicit blank separator. Without _finalize here, two findings
            # printed back-to-back would silently skip promotion on the first.
            findings.append(_finalize(current, lp))
        current_by_pid[pid] = new_finding
        in_origin_by_pid[pid] = False

    for current in current_by_pid.values():
        findings.append(_finalize(current, lp))

    return findings, dropped
