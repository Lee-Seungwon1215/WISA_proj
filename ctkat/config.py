import platform
from pathlib import Path
from typing import List, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .qemu_detect import detect_qemu_emulation


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

    command: str
    workdir: Path = Path(".")
    # Paths the build is expected to produce (Bundle E-1, F10). Each path
    # is resolved relative to `workdir` (or absolute). After `command`
    # finishes with rc=0 we verify every entry exists; missing → build FAIL.
    # Empty list (default) preserves prior exit-code-only behavior with a
    # one-time per-run warning that the artifact check was skipped.
    expected_artifacts: List[Path] = Field(default_factory=list)


class KatConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: str
    workdir: Path = Path(".")
    # Minimum number of KAT vectors the user expects to have executed
    # (Bundle E-1, F1). cli._do_kat greps the command's stdout with
    # `expected_pattern` and compares the captured count against
    # `expected_min`. Unset → KAT validates by exit code only (legacy
    # behavior) and emits a one-time per-run warning. Set to 0 to
    # opt out of the warning while keeping exit-code-only semantics.
    expected_min: Optional[int] = None
    # Regex (single capturing group with the count). Default matches
    # PQClean / NIST KAT runner output like "PASSED: 100 tests".
    expected_pattern: str = r"PASSED:?\s*(\d+)"


class BufferSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    size: str
    role: Literal["secret", "public", "output"]


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


class HarnessConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str

    # --- Manual mode (Phase 1) ---
    binary: Optional[Path] = None

    # --- Auto-generated mode (Phase 2) ---
    template: Optional[Literal["generic", "kem", "sign"]] = None

    # Shared by all auto templates:
    extra_headers: List[str] = Field(default_factory=list)
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
    seed: int = 0xC0FFEE
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


class ReportConfig(BaseModel):
    # `populate_by_name=True` lets us keep the friendly YAML keys (`csv`, `json`)
    # while avoiding pydantic v2's complaint about field names shadowing BaseModel
    # attributes (notably `.json`).
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    output_dir: Path = Path("./reports")
    csv_file: str = Field(default="ctkat_report.csv", alias="csv")
    json_file: str = Field(default="ctkat_report.json", alias="json")


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

    name: str
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
    # `ct` mode trades sk-leak coverage for ct-leak coverage — define two
    # harnesses if you want both. Only meaningful for template=kem; rejected
    # at load time if combined with template=generic.
    leak_target: Literal["sk", "ct"] = "sk"

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
        return self


class DudectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    measurements: int = 100_000
    warmup: int = 1_000
    batches: int = 10
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
    seed: Optional[int] = 0xC0FFEE
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
    timeout: int = 600

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


def load_config(path: Path) -> CtkatConfig:
    with open(path) as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict):
        raise ValueError(f"Config root must be a mapping, got {type(raw).__name__}")
    return CtkatConfig.model_validate(raw)
