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
_ATTRIBUTE = re.compile(r"__attribute__\s*\(\([^)]*\)\)")
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

# A "line directive" left over from preprocessing — we don't run cpp so this
# is unlikely to appear, but strip just in case.
_DIRECTIVE_LINE = re.compile(r"^\s*#.*$", re.MULTILINE)


def _strip_preprocessing(text: str) -> str:
    """Remove comments and preprocessor directives from header text."""
    text = _BLOCK_COMMENT.sub(" ", text)
    text = _LINE_COMMENT.sub(" ", text)
    text = _DIRECTIVE_LINE.sub("", text)
    text = _ATTRIBUTE.sub("", text)
    text = _EXTERN_C.sub("", text)
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

    name = tokens[-1]
    if name == "*":
        # No identifier given (e.g. `int foo(uint8_t *);`). Synthesize a
        # name from the positional index — using hash() here would be
        # non-deterministic across Python processes (PYTHONHASHSEED), making
        # successive parses of the same header disagree.
        name = f"_arg{index}"
        type_tokens = tokens
    else:
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


def parse_functions(text: str, source_file: Optional[str] = None) -> List[FunctionSig]:
    """Extract function declarations from C header text."""
    stripped = _strip_preprocessing(text)
    # Flatten whitespace inside declarations but preserve newlines for line numbers.
    sigs: List[FunctionSig] = []
    for m in _DECL_RE.finditer(stripped):
        ret = re.sub(r"\s+", " ", m.group("ret")).strip()
        name = m.group("name").strip()
        if not ret:
            continue
        # Filter out things that look like control statements / definitions.
        if name in {"if", "while", "for", "switch", "return", "sizeof"}:
            continue
        params_raw = m.group("params")
        params = [
            p for p in (
                _parse_param(s, i) for i, s in enumerate(_split_params(params_raw))
            )
            if p
        ]
        sig = FunctionSig(
            return_type=ret,
            name=name,
            params=params,
            source_file=source_file,
            source_line=_line_of(m.start(), stripped),
        )
        sigs.append(sig)
    return sigs


def parse_header_file(path: Path) -> List[FunctionSig]:
    return parse_functions(path.read_text(), source_file=str(path))


def discover_headers(root: Path) -> List[Path]:
    """Find .h files under `root` (recursive)."""
    return sorted(p for p in root.rglob("*.h") if p.is_file())
