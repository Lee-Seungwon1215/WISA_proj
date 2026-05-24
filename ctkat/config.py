from pathlib import Path
from typing import List, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class ProjectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    language: str = "c"
    root: Path = Path(".")


class BuildConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: str
    workdir: Path = Path(".")


class KatConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: str
    workdir: Path = Path(".")


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


class ReportConfig(BaseModel):
    # `populate_by_name=True` lets us keep the friendly YAML keys (`csv`, `json`)
    # while avoiding pydantic v2's complaint about field names shadowing BaseModel
    # attributes (notably `.json`).
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    output_dir: Path = Path("./reports")
    csv_file: str = Field(default="ctkat_report.csv", alias="csv")
    json_file: str = Field(default="ctkat_report.json", alias="json")


def _default_dudect_cflags() -> List[str]:
    return ["-O2", "-g", "-fno-omit-frame-pointer"]


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
        return self


class DudectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    measurements: int = 100_000
    warmup: int = 1_000
    batches: int = 10
    clock: Literal["rdtsc", "monotonic"] = "monotonic"
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
