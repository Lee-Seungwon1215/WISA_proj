import platform
import re
from pathlib import Path
from typing import List, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .qemu_detect import detect_qemu_emulation


# Bundle O (T20, T7 follow-up): yaml fields that flow into generated C
# source or Jinja contexts. Validators run at config-load time so a
# malicious / typo'd value surfaces as a clear ValidationError instead of
# either (a) a confusing compile error 200 lines later or (b) — worse —
# a successfully-compiled probe / harness that imports the wrong file.
#
# `_HEADER_PATTERN` allows: alphanumerics, `_`, `.`, `/`, `-`, `+`. Covers
# every real header name we've seen (`api.h`, `subdir/foo.h`,
# `libc++/v1/x.hpp`, `gmp-6.h`) while excluding the quote/backslash/newline
# characters that would let a yaml value break out of `#include "..."`.
_HEADER_PATTERN = re.compile(r"^[A-Za-z0-9_./+-]+$")
# C identifier — function names, prefixes.
_C_IDENT_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# C type expression — allows pointers, `const`, `unsigned`, multi-token
# types, scoped names (`std::byte`). Deliberately loose: the user's
# generated C will compile-fail noisily if the type is nonsense, but a
# value with quotes / semicolons / braces is rejected up front.
_C_TYPE_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_:* ]*$")
# C expression — array sizes (BufferSpec.size), secret-region offset/length,
# and function-call args. Legitimately contains identifiers/macros
# (`KYBER_SECRETKEYBYTES`), integer literals, whitespace, arithmetic, parens
# (`sizeof(secret)`), and address-of/subscript/member (`&buf` `a[0]` `s.x`).
# Deliberately EXCLUDES:
#   - `/`  — no real size/offset/arg needs division, and banning it makes the
#            C comment tokens `/*`, `*/`, `//` unrepresentable (T35).
#   - `,`  — the C comma operator silently collapses a parenthesized value:
#            `length: '32, 0'` renders `(32, 0)` which evaluates to 0, marking
#            ZERO secret bytes undefined → a false-negative CLEAN verdict on
#            leaky code (R-6 re-audit finding). A single offset/length/size/arg
#            never legitimately needs a comma (the args LIST is joined with
#            commas at a higher level, not inside one entry).
# Quotes, semicolons, braces and backslashes are absent from the charset, so a
# yaml value can't smuggle a statement into generated C (T23). `+` quantifier
# => empty string is rejected.
_C_EXPR_PATTERN = re.compile(r"[A-Za-z0-9_ +\-*()&\[\].]+")
# A function-call head: an identifier immediately followed by `(`. Only
# `sizeof` may appear here — anything else (`abort()`, `system(0)`, `fork()`)
# would CALL that function when the harness runs, because the value lands in a
# VLA array-size or a function argument that C evaluates at runtime (R-6).
_C_CALL_HEAD = re.compile(r"([A-Za-z_]\w*)\s*\(")
# A `(` immediately after `)` or `]` = call through a pointer/array result
# (`(&abort)()`, `(abort)()`, `fns[0]()`) — dodges the identifier-head check.
_C_CALL_THRU = re.compile(r"[)\]]\s*\(")


def _check_c_expr(where: str, label: str, value: str) -> None:
    """Validate a yaml value emitted verbatim into generated C as an
    expression. Raises ValueError on injection-prone input so it surfaces at
    config load, not as a compile error 200 lines deep (or — worse — a
    successfully-compiled / silently-mistainting harness).

    Three checks: (1) charset (no comma/quote/semicolon/brace/slash);
    (2) balanced `()` and `[]` so the value can't close the surrounding macro
    or array early; (3) the only call syntax allowed is `sizeof(...)`."""
    if not _C_EXPR_PATTERN.fullmatch(value):
        raise ValueError(
            f"{where}: {label}={value!r} must be a simple C expression — "
            "identifiers / macros, integer literals, whitespace and "
            "`+ - * ( ) & [ ] .` only. Commas, quotes, semicolons, braces, "
            "backslashes, `/` and comment tokens are rejected to prevent "
            f"C-source injection / value-collapse (matches {_C_EXPR_PATTERN.pattern!r})."
        )
    depth_p = depth_b = 0
    for ch in value:
        if ch == "(":
            depth_p += 1
        elif ch == ")":
            depth_p -= 1
        elif ch == "[":
            depth_b += 1
        elif ch == "]":
            depth_b -= 1
        if depth_p < 0 or depth_b < 0:
            raise ValueError(
                f"{where}: {label}={value!r} has unbalanced parentheses or "
                "brackets — a stray `)`/`]` could close the surrounding macro "
                "or array early."
            )
    if depth_p != 0 or depth_b != 0:
        raise ValueError(
            f"{where}: {label}={value!r} has unbalanced parentheses or brackets."
        )
    for m in _C_CALL_HEAD.finditer(value):
        if m.group(1) != "sizeof":
            raise ValueError(
                f"{where}: {label}={value!r}: function-call syntax "
                f"`{m.group(1)}(...)` is not allowed (only `sizeof(...)`). It "
                "would call that function when the generated harness runs."
            )
    # A `(` right after `)` or `]` is a call through a pointer/array result
    # — e.g. `(&abort)()`, `(abort)()`, `fns[0]()` — which dodges the
    # identifier-head check above and still calls a function at runtime (R-6).
    if _C_CALL_THRU.search(value):
        raise ValueError(
            f"{where}: {label}={value!r}: a `(` following `)` or `]` is a "
            "call through a pointer/array result and is not allowed — it "
            "would invoke a function when the generated harness runs."
        )


def _check_c_comment(where: str, value: str) -> None:
    """A SecretRegion.comment is emitted inside `/* ... */` in the harness.
    Reject the comment tokens and newlines so a yaml comment can't break out
    of the C comment and inject code (T35)."""
    if "*/" in value or "/*" in value or "\n" in value or "\r" in value:
        raise ValueError(
            f"{where}: comment={value!r} may not contain `*/`, `/*`, or "
            "newlines — it is emitted inside a C `/* ... */` comment and "
            "those would let it break out (T35)."
        )


def _check_header(where: str, label: str, value: str) -> None:
    """Validate a header path emitted into `#include \"{value}\"`. Beyond the
    charset (quotes/backslash/newline already excluded), reject absolute paths
    and `..` traversal segments so the include is provably project-contained —
    a yaml `header: ../../etc/x` must not pull a file from outside the tree."""
    if not _HEADER_PATTERN.fullmatch(value):
        raise ValueError(
            f"{where}: {label}={value!r} contains characters that would "
            "break the generated `#include` directive "
            f"(allowed: {_HEADER_PATTERN.pattern!r})"
        )
    if value.startswith("/") or ".." in value.split("/"):
        raise ValueError(
            f"{where}: {label}={value!r} must be a project-relative path "
            "without `..` segments — absolute paths and parent-directory "
            "traversal are rejected (header is emitted into an #include)."
        )


def _check_unique_names(where: str, names: List[str]) -> None:
    """T37: harness names key the generated-binary map (cli `generated[name]`)
    and the `{generated_dir}/harness_<name>.c` path. Two harnesses sharing a
    name in the SAME list silently overwrite each other's source/binary and
    one disappears from the report with no error. Reject duplicates at load.
    (ct and dudect lists are checked independently — a ct harness and a dudect
    harness deliberately share a name to pair in the verdict matrix.)"""
    seen: set[str] = set()
    dups: List[str] = []
    for n in names:
        if n in seen and n not in dups:
            dups.append(n)
        seen.add(n)
    if dups:
        raise ValueError(
            f"{where}: duplicate harness name(s) {dups} — names must be unique "
            "within a list (they key the generated-binary map and the "
            "harness_<name>.c path; a collision silently overwrites one "
            "harness with another)."
        )


def _check_yaml_identifiers(
    where: str,
    *,
    prefix: Optional[str] = None,
    header: Optional[str] = None,
    extra_headers: Optional[List[str]] = None,
    function: Optional[str] = None,
    return_type: Optional[str] = None,
) -> None:
    """Apply Bundle O regex checks to the subset of fields present on the
    caller. Empty `prefix` is allowed (default). Other Optional fields are
    skipped when None."""
    # T34: `.fullmatch()` not `.match()`. The patterns are `^...$`-anchored,
    # but Python's `$` also matches just before a trailing `\n`, so `.match()`
    # would accept e.g. `function: "f\n"` and inject a newline into the
    # generated identifier. `fullmatch` requires the whole string to match.
    if prefix is not None and prefix != "" and not _C_IDENT_PATTERN.fullmatch(prefix):
        raise ValueError(
            f"{where}: prefix={prefix!r} must be empty or a valid C "
            "identifier (matches "
            f"{_C_IDENT_PATTERN.pattern!r})"
        )
    if header is not None:
        _check_header(where, "header", header)
    if extra_headers is not None:
        for h in extra_headers:
            _check_header(where, "extra_headers entry", h)
    if function is not None and not _C_IDENT_PATTERN.fullmatch(function):
        raise ValueError(
            f"{where}: function={function!r} must be a valid C identifier "
            f"(matches {_C_IDENT_PATTERN.pattern!r})"
        )
    if return_type is not None and not _C_TYPE_PATTERN.fullmatch(return_type):
        raise ValueError(
            f"{where}: return_type={return_type!r} must look like a C "
            f"type expression (matches {_C_TYPE_PATTERN.pattern!r})"
        )


# CPU architectures that support the x86 `rdtsc`/`rdtscp` instructions used
# by the dudect timing harness. Compared case-insensitively against
# platform.machine() because Windows reports "AMD64" while Linux/macOS Intel
# report "x86_64".
_X86_ARCHES = frozenset({"x86_64", "amd64"})


def _is_x86_native() -> bool:
    """True iff the host is x86_64-family AND not running under QEMU.

    QEMU x86 emulation (e.g. Docker on Apple Silicon) reports x86_64 from
    platform.machine() but its rdtsc is unreliable for timing — treat that
    as non-native so callers fall back to the monotonic clock.
    """
    if platform.machine().lower() not in _X86_ARCHES:
        return False
    if detect_qemu_emulation():
        return False
    return True


def resolve_clock(clock: str) -> str:
    """Resolve a yaml `clock:` value to a concrete backend.

    - "auto"     → "rdtsc" on native x86_64, else "monotonic".
    - "rdtsc"    → "rdtsc"  (validator already rejected this on non-x86).
    - "monotonic"→ "monotonic".

    Public (not _-prefixed) because cli.py imports it and tests mock it.
    """
    if clock != "auto":
        return clock
    return "rdtsc" if _is_x86_native() else "monotonic"


class ProjectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    language: str = "c"
    root: Path = Path(".")


class BuildConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # `command` (shell=True) is the legacy/convenient path. `argv`
    # (shell=False, Bundle H2 T4) is the structured alternative for
    # users who don't want yaml to be implicitly shell-executable.
    # Exactly one must be set.
    command: Optional[str] = None
    argv: Optional[List[str]] = None
    workdir: Path = Path(".")
    # Paths the build is expected to produce (Bundle E-1, F10). Each path
    # is resolved relative to `workdir` (or absolute). After the step
    # finishes with rc=0 we verify every entry exists; missing → build FAIL.
    # Empty list (default) preserves prior exit-code-only behavior with a
    # one-time per-run warning that the artifact check was skipped.
    expected_artifacts: List[Path] = Field(default_factory=list)
    # Bundle N (T12): kill the build subprocess after `timeout` seconds.
    # Prevents a hung build script (`sleep infinity`, infinite Make recursion)
    # from stalling CI silently. Configurable per-yaml; default 600s.
    timeout: int = Field(default=600, ge=1)

    @model_validator(mode="after")
    def _check_mode(self) -> "BuildConfig":
        if (self.command is None) == (self.argv is None):
            raise ValueError(
                "build: exactly one of `command` (shell=True, legacy) or "
                "`argv` (shell=False, T4 safer alternative) must be set"
            )
        # T39: `argv: []` passes the exactly-one check (it's not None) but
        # `run_argv([])` → subprocess.run([]) raises a raw IndexError. The
        # first element is the program to exec, so an empty list is never
        # valid — reject it at load with a clear message.
        if self.argv is not None and len(self.argv) == 0:
            raise ValueError(
                "build: argv must be a non-empty list — its first element is "
                "the program to execute (T39)."
            )
        return self


class KatConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Bundle H2 (T4): same command/argv split as BuildConfig. argv path
    # bypasses the shell entirely so an untrusted yaml can't smuggle
    # `; rm -rf /` past the framework.
    command: Optional[str] = None
    argv: Optional[List[str]] = None
    workdir: Path = Path(".")
    # Minimum number of KAT vectors the user expects to have executed
    # (Bundle E-1, F1). cli._do_kat greps the command's stdout with
    # `expected_pattern` and compares the captured count against
    # `expected_min`. Unset → KAT validates by exit code only (legacy
    # behavior) and emits a one-time per-run warning. Set to 0 to
    # opt out of the warning while keeping exit-code-only semantics.
    expected_min: Optional[int] = None
    # Regex (single capturing group with the count). cli._do_kat applies
    # this with `re.MULTILINE`, so `^...$` anchors line boundaries inside
    # the runner's stdout. Default matches PQClean / NIST KAT runner
    # output like "PASSED: 100 tests" appearing as a standalone summary
    # line — anchored, so substring matches inside error messages don't
    # falsely satisfy `expected_min` (F18).
    expected_pattern: str = r"^PASSED:?\s*(\d+)(?:\s|$)"
    # Bundle N (T12): kill the KAT subprocess after `timeout` seconds.
    timeout: int = Field(default=600, ge=1)

    @model_validator(mode="after")
    def _check_mode(self) -> "KatConfig":
        if (self.command is None) == (self.argv is None):
            raise ValueError(
                "kat: exactly one of `command` (shell=True, legacy) or "
                "`argv` (shell=False, T4 safer alternative) must be set"
            )
        # T39: empty argv would crash subprocess with a raw IndexError.
        if self.argv is not None and len(self.argv) == 0:
            raise ValueError(
                "kat: argv must be a non-empty list — its first element is "
                "the program to execute (T39)."
            )
        return self


class BufferSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    size: str
    role: Literal["secret", "public", "output"]

    @model_validator(mode="after")
    def _check_c_safety(self) -> "BufferSpec":
        # T23: `name` is emitted as a C variable name and `size` as an array
        # dimension (harness_generic.c.j2 / timing_generic.c.j2). Both were
        # previously unvalidated — a yaml `name: 'x[1]; system("id"); char y'`
        # injected arbitrary C into the compiled-and-executed harness.
        if not _C_IDENT_PATTERN.fullmatch(self.name):
            raise ValueError(
                f"buffer name={self.name!r} must be a valid C identifier "
                f"(matches {_C_IDENT_PATTERN.pattern!r}) — it is emitted as a "
                "C variable name in the generated harness (T23)."
            )
        _check_c_expr(f"buffer {self.name!r}", "size", self.size)
        return self


class SecretRegion(BaseModel):
    """A byte range inside a larger buffer that is the actual secret.

    Used by the `kem` and `sign` templates when the scheme's `sk` blob
    embeds public material (e.g. ML-KEM's `sk = [s || ek || H(ek) || z]`).
    Offsets and lengths are emitted into C as-is, so they can be either
    integer literals ("1152") or C expressions ("KYBER_INDCPA_SECRETKEYBYTES").
    """

    model_config = ConfigDict(extra="forbid")

    offset: str
    length: str
    comment: Optional[str] = None

    @model_validator(mode="after")
    def _check_c_safety(self) -> "SecretRegion":
        # T23/T35: offset/length are emitted as C expressions inside
        # VALGRIND_MAKE_MEM_*(sk + (offset), (length)) and the F6 coverage
        # probe; comment is emitted inside `/* ... */`. All three were
        # unvalidated — `length: '32);} system("id"); ('` or
        # `comment: '*/ system("id"); /*'` injected executable C.
        _check_c_expr("secret_region", "offset", self.offset)
        _check_c_expr("secret_region", "length", self.length)
        if self.comment is not None:
            _check_c_comment("secret_region", self.comment)
        return self


class HarnessConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Bundle H2 (T7): `name` becomes part of a filesystem path
    # (`{generated_dir}/harness_{name}.c` in harness_generator.py:93).
    # A path-traversal value like `../../etc/passwd` would otherwise
    # escape the generated dir. Restrict to filename-safe characters so
    # the path interpolation is provably contained.
    name: str = Field(pattern=r"^[A-Za-z0-9_-]+$")

    # --- Manual mode (Phase 1) ---
    binary: Optional[Path] = None

    # --- Auto-generated mode (Phase 2) ---
    template: Optional[Literal["generic", "kem", "sign"]] = None

    # Shared by all auto templates:
    # Bundle O (T20, T7 follow-up): header / extra_headers go into
    # generated C via `#include "{value}"`. Quote/newline characters would
    # let an untrusted yaml break out of the include directive (CVE-style
    # C-source injection). Restrict to filename-safe characters that cover
    # real-world header names (`api.h`, `pqclean/include/foo.h`,
    # `libc++/v1/x.hpp`).
    extra_headers: List[str] = Field(
        default_factory=list,
    )
    include_dirs: List[Path] = Field(default_factory=list)
    sources: List[Path] = Field(default_factory=list)
    cflags: Optional[List[str]] = None  # None => inherit from CtConfig.cflags

    # generic-only:
    function: Optional[str] = None
    args: List[str] = Field(default_factory=list)
    return_type: Optional[str] = None
    buffers: List[BufferSpec] = Field(default_factory=list)

    # kem/sign-only:
    header: Optional[str] = None
    # Symbol prefix prepended to crypto_kem_*/crypto_sign_* identifiers and
    # to CRYPTO_* macros. Empty string by default; set to e.g.
    # "PQCLEAN_MLKEM768_CLEAN_" for PQClean-style namespaced builds.
    # T20/T7: must be empty or a valid C identifier — anything that isn't
    # a legal identifier prefix would either break the generated code
    # noisily (best case) or smuggle non-identifier tokens into the macro
    # / function-name interpolations (worst case).
    prefix: str = ""
    # If set, only these byte ranges of `sk` are tainted (instead of the
    # whole buffer). Lets us avoid false positives from public material
    # embedded inside `sk` (e.g. ML-KEM stores `pk` inside `sk`).
    secret_regions: List[SecretRegion] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_mode(self) -> "HarnessConfig":
        if self.binary is None and self.template is None:
            raise ValueError(
                f"harness {self.name!r}: must set either 'binary' (manual) "
                "or 'template' (auto)"
            )
        if self.binary is not None and self.template is not None:
            raise ValueError(
                f"harness {self.name!r}: 'binary' and 'template' are mutually exclusive"
            )
        if self.template == "generic" and not self.function:
            raise ValueError(
                f"harness {self.name!r}: template=generic requires 'function'"
            )
        if self.template in ("kem", "sign") and not self.header:
            raise ValueError(
                f"harness {self.name!r}: template={self.template} requires 'header'"
            )
        # Bundle O (T20, T7 follow-up): enforce the regex policy that was
        # left as Bundle H2 follow-up after the `name` field landed.
        _check_yaml_identifiers(
            f"ct harness {self.name!r}",
            prefix=self.prefix,
            header=self.header,
            extra_headers=self.extra_headers,
            function=self.function,
            return_type=self.return_type,
        )
        # T23: args are emitted verbatim into `{{ function }}({{ args }})`.
        for i, a in enumerate(self.args):
            _check_c_expr(f"ct harness {self.name!r}", f"args[{i}]", a)
        return self


def _default_valgrind_flags() -> List[str]:
    # `--error-exitcode=99` makes Valgrind exit with 99 instead of the
    # harness's own status when it detects an error. We don't actually
    # branch on this exit code (we parse the log directly), but it's a
    # de-facto standard convention from the doc/PQClean world and keeps the
    # exit code distinguishable from a normal harness failure (0/1) or a
    # shell signal (128+sig).
    return [
        "--tool=memcheck",
        "--track-origins=yes",
        "--error-exitcode=99",
    ]


def _default_cflags() -> List[str]:
    return ["-O0", "-g", "-fno-inline", "-fno-omit-frame-pointer"]


class CtConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workdir: Path = Path(".")
    harnesses: List[HarnessConfig]
    valgrind_flags: List[str] = Field(default_factory=_default_valgrind_flags)
    cflags: List[str] = Field(default_factory=_default_cflags)
    generated_dir: Path = Path("./_generated")
    # Seed baked into auto-generated harnesses' PRNG so that the same yaml
    # produces the same input sequence across runs — a CT verdict flipping
    # between days should mean code changed, not "today's random inputs
    # happened to hit a different branch". See harness_generic.c.j2.
    # Use the same default sentinel as the dudect side (0xC0FFEE).
    # F16: `seed=0` is rejected at config load because the generated C swaps
    # it to 0xC0FFEE (xorshift64 gets stuck on state=0) — accepting it here
    # would mean Python logs `0x0` while C runs with `0xC0FFEE`. The swap is
    # semantically necessary; we just refuse to let the two layers disagree.
    seed: int = Field(default=0xC0FFEE, gt=0)
    # Bundle E-2 (F5): manual-binary harnesses produce zero findings if the
    # binary never actually invokes the target function with tainted input
    # — `binary: /bin/true` would happily report a PASS. When True, _do_ct
    # checks the binary's stdout for `sentinel_pattern` and downgrades the
    # harness to status=ERROR if absent. Default False keeps legacy yaml
    # working (with a per-run note); flip to True once your harnesses emit
    # the sentinel.
    require_sentinel: bool = False
    # Regex matched against the manual binary's stdout. One capturing
    # group, expected to hold the harness name so a single binary can
    # legitimately wrap multiple harnesses if needed. Default matches
    # `puts("CTKAT-HARNESS-RAN: <name>")`-style lines.
    sentinel_pattern: str = r"CTKAT-HARNESS-RAN:\s*(\S+)"
    # Bundle I (T2): substring patterns the parser uses to promote
    # `SECRET_DEPENDENT_VALUE_USE` to `SECRET_DEPENDENT_MEMORY_ACCESS`
    # when they appear in a stack frame's function name. Set to override
    # the built-in `sbox/ttable/tbox/lookup/_table` list when domain
    # function names cause false positives (e.g. `verify_table_size`).
    # Set to `[]` to disable the substring-based promotion entirely.
    lookup_function_patterns: Optional[List[str]] = None
    # Bundle N (T12): timeouts (seconds) for the two subprocess steps
    # cli._do_ct fires per harness — `gcc` (compile_timeout) and `valgrind`
    # (valgrind_timeout). A hung compile or runaway valgrind no longer
    # stalls CI; instead the per-harness path lands as status=ERROR →
    # verdict INCONCLUSIVE.
    compile_timeout: int = Field(default=600, ge=1)
    valgrind_timeout: int = Field(default=600, ge=1)

    @model_validator(mode="after")
    def _check_unique_harness_names(self) -> "CtConfig":
        _check_unique_names("ct.harnesses", [h.name for h in self.harnesses])
        return self


class ReportConfig(BaseModel):
    # `populate_by_name=True` lets us keep the friendly YAML keys (`csv`, `json`)
    # while avoiding pydantic v2's complaint about field names shadowing BaseModel
    # attributes (notably `.json`).
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    output_dir: Path = Path("./reports")
    csv_file: str = Field(default="ctkat_report.csv", alias="csv")
    json_file: str = Field(default="ctkat_report.json", alias="json")

    @model_validator(mode="after")
    def _check_report_filenames(self) -> "ReportConfig":
        # R-6 re-audit: csv_file/json_file are joined onto output_dir and
        # written. Unvalidated, `csv: '../../tmp/pwned.csv'` or `/tmp/x.csv`
        # escapes the output dir → arbitrary file write. They are meant to be
        # plain filenames; reject path separators, parent traversal, and
        # absolute paths. (output_dir is the configurable directory; these are
        # just the file names within it.)
        for label, name in (("csv", self.csv_file), ("json", self.json_file)):
            if (
                "/" in name
                or "\\" in name
                or ".." in name
                or Path(name).is_absolute()
                or name in ("", ".")
            ):
                raise ValueError(
                    f"report.{label}={name!r} must be a plain filename "
                    "(no '/', '\\', '..', or absolute path) — it is written "
                    "inside report.output_dir."
                )
        return self


def _default_dudect_cflags() -> List[str]:
    # `-fno-lto` keeps the compiler from peeking past the timed function's
    # external linkage boundary. With LTO the optimizer can see the callee's
    # body, decide an unused return value (or even the whole call) is
    # pure/dead, and elide it — which silently zeros out the measurement.
    return ["-O2", "-g", "-fno-omit-frame-pointer", "-fno-lto"]


class DudectCompilerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cc: str = "gcc"
    cflags: List[str] = Field(default_factory=_default_dudect_cflags)


class DudectHarnessConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # T7: filename-safe pattern, see HarnessConfig.name.
    name: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    template: Literal["generic", "kem"] = "generic"
    extra_headers: List[str] = Field(default_factory=list)
    include_dirs: List[Path] = Field(default_factory=list)
    sources: List[Path] = Field(default_factory=list)

    # generic-only
    function: Optional[str] = None
    return_type: Optional[str] = None
    args: List[str] = Field(default_factory=list)
    buffers: List[BufferSpec] = Field(default_factory=list)

    # kem-only
    header: Optional[str] = None
    prefix: str = ""
    # Which axis of the KEM API is varied between class 0 and class 1.
    #   "sk" — class 0 fixed sk vs class 1 fresh sk (default; detects sk leaks)
    #   "ct" — class 0 fixed ct vs class 1 fresh ct (sk held constant;
    #          detects ct-content leaks, e.g. branches/lookups indexed by ct)
    #   "fo" — class 0 valid ct (via enc) vs class 1 random/invalid ct
    #          (sk held constant; detects timing leaks in FO fallback /
    #           implicit rejection path — Bundle K, U2 #1)
    # Pick one per harness; define multiple harnesses for multiple modes.
    # Only meaningful for template=kem; rejected at load time if combined
    # with template=generic.
    leak_target: Literal["sk", "ct", "fo"] = "sk"

    @model_validator(mode="after")
    def _check_mode(self) -> "DudectHarnessConfig":
        # Mirror the validation HarnessConfig already does, so that yaml
        # mistakes surface at config-load time rather than as a confusing
        # Jinja2 KeyError deep inside the generator.
        if self.template == "generic" and not self.function:
            raise ValueError(
                f"dudect harness {self.name!r}: template=generic requires "
                "'function'"
            )
        if self.template == "kem" and not self.header:
            raise ValueError(
                f"dudect harness {self.name!r}: template=kem requires 'header'"
            )
        if self.template != "kem" and self.leak_target != "sk":
            # leak_target is a KEM-specific axis; on the generic template
            # there's no canonical "sk vs ct" split, so silently accepting
            # ct here would be a noisy no-op.
            raise ValueError(
                f"dudect harness {self.name!r}: leak_target={self.leak_target!r} "
                "only valid for template=kem"
            )
        _check_yaml_identifiers(
            f"dudect harness {self.name!r}",
            prefix=self.prefix,
            header=self.header,
            extra_headers=self.extra_headers,
            function=self.function,
            return_type=self.return_type,
        )
        # T23: args are emitted verbatim into `{{ function }}({{ args }})`.
        for i, a in enumerate(self.args):
            _check_c_expr(f"dudect harness {self.name!r}", f"args[{i}]", a)
        return self


class DudectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    # Bundle H2 (T8): defensive upper bounds. A typo (extra zero,
    # copy-paste mistake) on `measurements` previously allocated
    # ~800 MB in the C harness's static BSS arrays and produced an
    # opaque "Killed" / segfault diagnostic. 10M is a defensible
    # ceiling (~80 MB BSS for cycles_buf + classes_buf). Lower
    # `measurements` than this is fine; we just refuse the absurdly
    # large case at config load.
    measurements: int = Field(default=100_000, ge=100, le=10_000_000)
    warmup: int = Field(default=1_000, ge=0, le=10_000_000)
    batches: int = Field(default=10, ge=1, le=1_000)
    # "auto" (default) picks rdtsc on native x86_64 and monotonic elsewhere
    # (incl. ARM, QEMU). Explicit "rdtsc" is hard-validated against the host
    # arch so the failure surfaces at config load instead of as a cryptic
    # `<x86intrin.h>` compile error.
    clock: Literal["rdtsc", "monotonic", "auto"] = "auto"
    # Default seed is the hex-readable constant 0xC0FFEE — picked to be
    # memorable and obviously-not-real-entropy, so it's clear at a glance
    # that two runs sharing this seed are deliberately reproducing the
    # same input sequence (rather than independent measurements).
    # `None` (yaml null) means "pick a random 63-bit seed at run time and
    # log it" — use that when you want independent samples for stability
    # checks across runs.
    # F16: `seed=0` is rejected because the timing harness C swaps it to
    # 0xC0FFEE (xorshift64 stuck-at-zero), which would make Python log `0x0`
    # while the running binary uses 0xC0FFEE — a silent reproducibility lie.
    # Optional[int] keeps `None` (random-pick) working.
    seed: Optional[int] = Field(default=0xC0FFEE, gt=0)
    threshold_warning: float = 4.5
    threshold_fail: float = 10.0
    compiler: DudectCompilerConfig = Field(default_factory=DudectCompilerConfig)
    workdir: Path = Path(".")
    generated_dir: Path = Path("./_generated_dudect")
    harnesses: List[DudectHarnessConfig] = Field(default_factory=list)
    # Per-harness wall-clock ceiling for the timing binary (Bundle E-1, T6).
    # Reaching this raises a TimeoutExpired which `_do_dudect` catches and
    # turns into status=ERROR / verdict=INCONCLUSIVE rather than letting a
    # raw Python traceback escape. Bump for slow targets (e.g. QEMU + many
    # measurements); shrink in CI to surface infinite-loop bugs faster.
    timeout: int = Field(default=600, ge=1)
    # Bundle N (T12): timeout for the timing-harness *compile* step (gcc).
    # T6 only covered the runtime; the compile path could still hang on a
    # cyclic include or pathological optimization. Separate knob so users
    # can keep the compile tight while the runtime is long.
    compile_timeout: int = Field(default=600, ge=1)
    # Bundle G (R2): the multi-cutoff cropping protocol takes max |t| over
    # 5 correlated tests, which inflates the per-test Type-I rate. When
    # True, scale `threshold_warning` and `threshold_fail` by
    # sqrt(len(CROP_PERCENTILES)) (≈2.24) — a conservative Bonferroni-like
    # adjustment that keeps the family-wise error rate ≈ what a single
    # Welch test would have. Default False because most users tune
    # thresholds against the literature's "4.5 / 10.0 single-test" advice
    # and would be confused by a stricter scale.
    bonferroni_correct: bool = False

    @model_validator(mode="after")
    def _check_clock_arch(self) -> "DudectConfig":
        # Explicit clock=rdtsc on a non-x86 host would compile-fail with a
        # confusing `<x86intrin.h>` not-found error. Reject it at load time
        # with a message that points at the cause. `auto` and `monotonic`
        # are always portable so they bypass this check.
        if self.clock == "rdtsc" and platform.machine().lower() not in _X86_ARCHES:
            raise ValueError(
                f"dudect.clock='rdtsc' requires an x86_64 host (current: "
                f"{platform.machine()}). Use 'auto' (default) or 'monotonic'."
            )
        # T37: reject duplicate harness names within the dudect list.
        _check_unique_names("dudect.harnesses", [h.name for h in self.harnesses])
        return self


class CtkatConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project: ProjectConfig
    build: BuildConfig
    kat: Optional[KatConfig] = None
    # Both `ct` and `dudect` are optional so a user can run a yaml with
    # only one stage configured (e.g. dudect-only timing run).
    ct: Optional[CtConfig] = None
    dudect: Optional[DudectConfig] = None
    report: ReportConfig = Field(default_factory=ReportConfig)
    # Bundle I (F9 #3): top-level convenience. When set, both stages
    # (ct + dudect.compiler) adopt this flag list, overriding their
    # per-stage defaults. Users wanting "verify what I'll ship" can set
    # `shared_cflags: [-O2, -g]` and accept the Valgrind debug-info loss
    # as the cost of consistency. Per-stage explicit `cflags` still take
    # precedence to allow targeted overrides.
    shared_cflags: Optional[List[str]] = None

    @model_validator(mode="after")
    def _apply_shared_cflags(self) -> "CtkatConfig":
        if self.shared_cflags is None:
            return self
        # F15: detect "user did not explicitly set cflags" by checking
        # pydantic v2's `model_fields_set` (the set of field names actually
        # present in the input). The earlier `== _default_cflags()` check
        # was a value comparison — a user who happened to specify the same
        # list as the default would get their explicit choice silently
        # overridden. `model_fields_set` is input-based, so explicit-but-
        # equal-to-default keeps the user's intent.
        if self.ct is not None and "cflags" not in self.ct.model_fields_set:
            self.ct.cflags = list(self.shared_cflags)
        if (
            self.dudect is not None
            and "cflags" not in self.dudect.compiler.model_fields_set
        ):
            self.dudect.compiler.cflags = list(self.shared_cflags)
        return self


def load_config(path: Path) -> CtkatConfig:
    # T24: explicit utf-8 so a yaml authored on one OS (or carrying non-ASCII
    # comments) loads identically regardless of the host locale's default
    # encoding (Windows cp1252 vs POSIX utf-8).
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict):
        raise ValueError(f"Config root must be a mapping, got {type(raw).__name__}")
    return CtkatConfig.model_validate(raw)
