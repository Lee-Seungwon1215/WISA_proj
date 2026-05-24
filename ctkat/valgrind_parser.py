import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


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


_HEADER_RE = re.compile(r"^==\d+==\s?(.*)$")
_FRAME_RE = re.compile(
    r"^==\d+==\s+(?:at|by)\s+(0x[0-9A-Fa-f]+):\s+(.+?)\s+\((.+)\)\s*$"
)
_FILE_LINE_RE = re.compile(r"^(.+):(\d+)$")


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


def _is_memory_access(frames: List[StackFrame]) -> bool:
    if not frames:
        return False
    top_fn = frames[0].function.lower()
    if top_fn in _MEMORY_FUNCTION_NAMES:
        return True
    for fr in frames:
        fn = fr.function.lower()
        if any(pat in fn for pat in _LOOKUP_PATTERNS):
            return True
        if fr.file and any(pat in fr.file.lower() for pat in _LOOKUP_PATTERNS):
            return True
    return False


def _finalize(f: Finding) -> Finding:
    """Optionally promote VALUE_USE to MEMORY_ACCESS based on stack context."""
    if f.type == FindingType.SECRET_DEPENDENT_VALUE_USE and _is_memory_access(f.frames):
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
    return location, None


def _make_frame(address: str, function: str, location: str) -> StackFrame:
    file_, line = _parse_frame_location(location)
    return StackFrame(address=address, function=function, file=file_, line=line)


def parse_valgrind_log(text: str) -> List[Finding]:
    """Parse a Valgrind Memcheck log into a list of Finding objects.

    State machine over `==PID==` lines:
      - A non-empty content line that is NOT a frame line starts a new finding
        (or switches to origin mode if it says "Uninitialised value was created").
      - Frame lines append to current finding's frames or origin_frames.
      - An empty content line (`==PID== `) closes the current finding.
    """
    findings: List[Finding] = []
    current: Optional[Finding] = None
    in_origin = False

    for raw in text.splitlines():
        header = _HEADER_RE.match(raw)
        if not header:
            continue
        content = header.group(1).rstrip()

        # finding boundary
        if content == "":
            if current is not None:
                findings.append(_finalize(current))
                current = None
                in_origin = False
            continue

        # frame line?
        fm = _FRAME_RE.match(raw)
        if fm:
            if current is None:
                continue
            frame = _make_frame(fm.group(1), fm.group(2).strip(), fm.group(3).strip())
            if in_origin:
                current.origin_frames.append(frame)
            else:
                current.frames.append(frame)
            continue

        # origin marker switches to origin-frame collection within current finding
        if "Uninitialised value was created" in content:
            in_origin = True
            continue

        # otherwise this is a new finding header — close previous if any
        new_finding = _classify(content.lstrip())
        if new_finding is None:
            # banner/footer/unrecognized line; if we had an open finding,
            # leave it open until we hit the closing empty line.
            continue
        if current is not None:
            # Apply post-classification heuristics (e.g. VALUE_USE→MEMORY_ACCESS
            # promotion) even when the previous finding closes without an
            # explicit blank separator. Without _finalize here, two findings
            # printed back-to-back would silently skip promotion on the first.
            findings.append(_finalize(current))
        current = new_finding
        in_origin = False

    if current is not None:
        findings.append(_finalize(current))

    return findings
