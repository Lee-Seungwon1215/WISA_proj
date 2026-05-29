"""Lightweight regex-based C header parser.

Designed for PQClean-style and similar simple cryptographic API headers:
no typedefs of function pointers, no preprocessor magic that affects
visible declarations. We don't run a real preprocessor — we strip
comments and directive lines, drop `extern "C"` braces, and flatten
multi-line declarations onto a single line before matching.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple


@dataclass
class ParamInfo:
    name: str
    type: str
    is_pointer: bool = False
    is_const: bool = False
    array_suffix: Optional[str] = None


@dataclass
class FunctionSig:
    return_type: str
    name: str
    params: List[ParamInfo] = field(default_factory=list)
    source_file: Optional[str] = None
    source_line: Optional[int] = None

    def render(self) -> str:
        params = ", ".join(f"{p.type} {p.name}".strip() for p in self.params) or "void"
        return f"{self.return_type} {self.name}({params})"


_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"//[^\n]*")
# T31: the old `\(\([^)]*\)\)` stopped at the first inner `)`, so attributes
# with nested parens — `__attribute__((nonnull(1)))`,
# `__attribute__((format(printf, 1, 2)))` — were only partially stripped.
# The leftover `)` then broke `_DECL_RE`, making the whole function silently
# vanish from `infer` (and uncounted by the T11/T13 skip total). Allow one
# level of nested parens, same as `_DECL_LOOSE_RE`.
_ATTRIBUTE = re.compile(r"__attribute__\s*\(\((?:[^()]|\([^()]*\))*\)\)")
_EXTERN_C = re.compile(r'extern\s+"C"\s*\{?|^\s*\}\s*(?:/\*.*?\*/)?\s*$', re.MULTILINE)

# A function declaration. We require the params to be enclosed in a single
# pair of parens with no nested parens (good enough for PQClean-style APIs).
# The semicolon must terminate the declaration; definitions (with `{`) are
# skipped on purpose.
_DECL_RE = re.compile(
    r"""
    (?P<ret>(?:[A-Za-z_][\w\s\*]*?))   # return type (may include pointer)
    \s+
    (?P<name>[A-Za-z_]\w*)             # function name
    \s*
    \(
    (?P<params>[^()]*)                 # params (no nested parens)
    \)
    \s*;                               # declaration terminator
    """,
    re.VERBOSE,
)

# Bundle H2 (T11): loose-match counterpart that accepts nested parens
# inside the param list, so we can count function declarations whose
# params our strict regex would silently skip (function pointers like
# `int register_cb(int (*cb)(int))`, variadic, etc.). We don't try to
# *parse* these — just to flag their existence so the user knows the
# infer output is incomplete.
_DECL_LOOSE_RE = re.compile(
    r"""
    (?P<ret>(?:[A-Za-z_][\w\s\*]*?))
    \s+
    (?P<name>[A-Za-z_]\w*)
    \s*
    \(
    (?P<params>(?:[^()]|\([^()]*\))*)  # one level of nested parens allowed
    \)
    \s*;
    """,
    re.VERBOSE,
)

# A "line directive" left over from preprocessing — we don't run cpp so this
# is unlikely to appear, but strip just in case.
_DIRECTIVE_LINE = re.compile(r"^\s*#.*$", re.MULTILINE)


def _blank_keep_newlines(m: "re.Match[str]") -> str:
    """Replace a stripped region with a single space plus exactly as many
    newlines as it contained (T36). `_line_of` derives a declaration's
    reported source line from its byte offset in the *stripped* text, so any
    removal that drops newlines shifts every later decl's line number up.
    Collapsing a multi-line `/* ... */` to one space used to do exactly that.
    Preserving the newline count keeps stripped-text line numbers aligned
    with the original file; the leading space keeps token boundaries intact
    (so `int/* */foo` doesn't fuse into `intfoo`)."""
    return " " + "\n" * m.group(0).count("\n")


def _strip_preprocessing(text: str) -> str:
    """Remove comments and preprocessor directives from header text.

    Removals that can span multiple lines (block comments, attributes, the
    `extern "C"` wrapper) are blanked with newline-preserving replacements so
    reported source-line numbers stay accurate (T36). Single-line removals
    (line comments, `#` directives) can't drop a newline, so a plain blank is
    fine — directive lines keep their trailing newline because `.` doesn't
    match it under the default flags.
    """
    text = _BLOCK_COMMENT.sub(_blank_keep_newlines, text)
    text = _LINE_COMMENT.sub(" ", text)
    text = _DIRECTIVE_LINE.sub("", text)
    text = _ATTRIBUTE.sub(_blank_keep_newlines, text)
    text = _EXTERN_C.sub(_blank_keep_newlines, text)
    return text


def _line_of(offset: int, source: str) -> int:
    """1-based line number of `offset` within `source`."""
    return source.count("\n", 0, offset) + 1


def _parse_param(text: str, index: int = 0) -> Optional[ParamInfo]:
    text = text.strip()
    if not text or text.lower() == "void":
        return None

    # Strip trailing array suffix like "[16]" or "[]" — keep it as metadata.
    array_suffix: Optional[str] = None
    m = re.search(r"\s*(\[[^\]]*\])\s*$", text)
    if m:
        array_suffix = m.group(1)
        text = text[: m.start()].rstrip()

    # Tokenize, keeping clusters of asterisks as single tokens.
    tokens = re.findall(r"\*+|[A-Za-z_]\w*", text)
    if not tokens:
        return None

    last = tokens[-1]
    if re.fullmatch(r"\*+", last):
        # Trailing token is all asterisks — an ANONYMOUS pointer parameter
        # (`uint8_t *`, `uint8_t **`). T32: the old `== "*"` check only caught
        # single-pointer; `**` slipped through as a bogus identifier name with
        # is_pointer=False, so secret_infer mis-classified a double-pointer
        # buffer as a scalar (no taint). Synthesize a name and keep every
        # token as the type. Index-based (not hash()) for cross-process
        # determinism (PYTHONHASHSEED).
        name = f"_arg{index}"
        type_tokens = tokens
    elif len(tokens) == 1:
        # A single identifier is an unnamed parameter whose token is the TYPE,
        # not a name (`int f(size_t)`, `int f(int)`). T32: previously this set
        # name=<type>, type="" — a buffer/scalar with no usable type. Treat
        # the lone token as the type and synthesize the name.
        name = f"_arg{index}"
        type_tokens = tokens
    else:
        name = last
        type_tokens = tokens[:-1]

    type_str = " ".join(type_tokens).strip()
    type_str = re.sub(r"\s*\*\s*", " *", type_str).strip()  # tidy "uint8_t *"
    is_pointer = "*" in type_str or array_suffix is not None
    is_const = "const" in type_tokens

    return ParamInfo(
        name=name,
        type=type_str,
        is_pointer=is_pointer,
        is_const=is_const,
        array_suffix=array_suffix,
    )


def _split_params(text: str) -> List[str]:
    """Split a parameter list on commas (no nested parens expected)."""
    return [p for p in (s.strip() for s in text.split(",")) if p]


_KEYWORDS = {"if", "while", "for", "switch", "return", "sizeof"}


def parse_functions(text: str, source_file: Optional[str] = None) -> List[FunctionSig]:
    """Extract function declarations from C header text."""
    return _parse_functions_impl(text, source_file)[0]


def parse_functions_with_stats(
    text: str, source_file: Optional[str] = None
) -> tuple[List[FunctionSig], int]:
    """Bundle H2 (T11): like `parse_functions`, but also returns the
    number of function declarations the strict regex skipped (function
    pointers, variadic, nested-paren signatures). Callers can surface
    this so the user knows the parsed list is incomplete.

    Returns `(sigs, skipped_count)`.
    """
    return _parse_functions_impl(text, source_file)


def _parse_functions_impl(
    text: str, source_file: Optional[str]
) -> tuple[List[FunctionSig], int]:
    stripped = _strip_preprocessing(text)
    sigs: List[FunctionSig] = []
    strict_starts: set[int] = set()
    for m in _DECL_RE.finditer(stripped):
        ret = re.sub(r"\s+", " ", m.group("ret")).strip()
        name = m.group("name").strip()
        if not ret:
            continue
        if name in _KEYWORDS:
            continue
        params_raw = m.group("params")
        params = [
            p for p in (
                _parse_param(s, i) for i, s in enumerate(_split_params(params_raw))
            )
            if p
        ]
        strict_starts.add(m.start())
        sigs.append(FunctionSig(
            return_type=ret,
            name=name,
            params=params,
            source_file=source_file,
            source_line=_line_of(m.start(), stripped),
        ))

    # T11: count loose-only matches (anything that looks like a function
    # decl with nested parens but didn't survive the strict regex). Don't
    # double-count strict-matches; don't count keyword false positives.
    skipped = 0
    for m in _DECL_LOOSE_RE.finditer(stripped):
        if m.start() in strict_starts:
            continue
        if m.group("name") in _KEYWORDS:
            continue
        if not m.group("ret").strip():
            continue
        skipped += 1
    return sigs, skipped


def parse_header_file(path: Path) -> List[FunctionSig]:
    # T21: header files are usually ASCII but third-party headers can
    # carry non-utf-8 bytes in comments / author names. Replace keeps the
    # parser from raising on encoding errors.
    return parse_functions(
        path.read_text(encoding="utf-8", errors="replace"),
        source_file=str(path),
    )


def parse_header_file_with_stats(path: Path) -> tuple[List[FunctionSig], int]:
    """Bundle P (T13): file-level wrapper around `parse_functions_with_stats`.
    Returns `(sigs, skipped_count)` so cli `infer` can surface declarations
    the strict regex couldn't parse (function pointers, variadic, nested-
    paren signatures) instead of dropping them silently."""
    return parse_functions_with_stats(
        path.read_text(encoding="utf-8", errors="replace"),
        source_file=str(path),
    )


def discover_headers(root: Path) -> List[Path]:
    """Find .h files under `root` (recursive)."""
    return sorted(p for p in root.rglob("*.h") if p.is_file())
