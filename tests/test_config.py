from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from ctkat.config import (
    BufferSpec,
    CtkatConfig,
    HarnessConfig,
    SecretRegion,
    load_config,
)


MINIMAL_YAML = """
project:
  name: demo
build:
  command: "true"
ct:
  harnesses:
    - name: h1
      binary: ./bin/h1
"""


def test_minimal_config_validates(tmp_path: Path):
    p = tmp_path / "ctkat.yaml"
    p.write_text(MINIMAL_YAML)
    cfg = load_config(p)
    assert isinstance(cfg, CtkatConfig)
    assert cfg.project.name == "demo"
    assert cfg.kat is None
    assert cfg.ct.harnesses[0].name == "h1"
    # default valgrind flags present
    assert any(flag.startswith("--tool=") for flag in cfg.ct.valgrind_flags)


def test_unknown_field_rejected(tmp_path: Path):
    p = tmp_path / "ctkat.yaml"
    raw = yaml.safe_load(MINIMAL_YAML)
    raw["project"]["bogus"] = 1
    p.write_text(yaml.safe_dump(raw))
    with pytest.raises(ValidationError):
        load_config(p)


def test_missing_required_section_rejected(tmp_path: Path):
    # `project` is required; omitting it must fail validation.
    p = tmp_path / "ctkat.yaml"
    p.write_text("build:\n  command: 'true'\n")
    with pytest.raises(ValidationError):
        load_config(p)


def test_ct_and_dudect_both_optional(tmp_path: Path):
    # A config with only project+build is valid as of Phase 4 — both `ct`
    # and `dudect` sections are optional now.
    p = tmp_path / "ctkat.yaml"
    p.write_text("project:\n  name: demo\nbuild:\n  command: 'true'\n")
    cfg = load_config(p)
    assert cfg.ct is None
    assert cfg.dudect is None


# --- HarnessConfig mutex / required-field validation ------------------------


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "ctkat.yaml"
    p.write_text(body)
    return p


_HARNESS_BOTH_MODES = """
project: {name: demo}
build: {command: "true"}
ct:
  harnesses:
    - name: h1
      binary: ./bin/h1
      template: generic
      function: foo
"""

_HARNESS_NEITHER_MODE = """
project: {name: demo}
build: {command: "true"}
ct:
  harnesses:
    - name: h1
"""

_HARNESS_GENERIC_WITHOUT_FUNCTION = """
project: {name: demo}
build: {command: "true"}
ct:
  harnesses:
    - name: h1
      template: generic
"""

_HARNESS_KEM_WITHOUT_HEADER = """
project: {name: demo}
build: {command: "true"}
ct:
  harnesses:
    - name: h1
      template: kem
"""


def test_harness_binary_and_template_mutually_exclusive(tmp_path: Path):
    with pytest.raises(ValidationError, match="mutually exclusive"):
        load_config(_write(tmp_path, _HARNESS_BOTH_MODES))


def test_harness_requires_binary_or_template(tmp_path: Path):
    with pytest.raises(ValidationError, match="binary.*template"):
        load_config(_write(tmp_path, _HARNESS_NEITHER_MODE))


def test_harness_generic_requires_function(tmp_path: Path):
    with pytest.raises(ValidationError, match="requires 'function'"):
        load_config(_write(tmp_path, _HARNESS_GENERIC_WITHOUT_FUNCTION))


def test_harness_kem_requires_header(tmp_path: Path):
    with pytest.raises(ValidationError, match="requires 'header'"):
        load_config(_write(tmp_path, _HARNESS_KEM_WITHOUT_HEADER))


# --- DudectHarnessConfig validator ------------------------------------------


_DUDECT_KEM_WITHOUT_HEADER = """
project: {name: demo}
build: {command: "true"}
dudect:
  harnesses:
    - name: h1
      template: kem
"""

_DUDECT_GENERIC_WITHOUT_FUNCTION = """
project: {name: demo}
build: {command: "true"}
dudect:
  harnesses:
    - name: h1
      template: generic
"""


def test_dudect_kem_requires_header(tmp_path: Path):
    # Regression: previously the dudect validator was missing, so this
    # passed pydantic and exploded later inside the Jinja2 generator.
    with pytest.raises(ValidationError, match="requires 'header'"):
        load_config(_write(tmp_path, _DUDECT_KEM_WITHOUT_HEADER))


def test_dudect_generic_requires_function(tmp_path: Path):
    with pytest.raises(ValidationError, match="requires 'function'"):
        load_config(_write(tmp_path, _DUDECT_GENERIC_WITHOUT_FUNCTION))


def test_dudect_default_cflags_disable_lto():
    # `-fno-lto` is load-bearing: with LTO the optimizer can see across the
    # timed function's external linkage and elide it once it concludes the
    # return value is unused. Keep the flag in the default set so users who
    # don't override `dudect.compiler.cflags` are protected by default.
    from ctkat.config import DudectCompilerConfig
    flags = DudectCompilerConfig().cflags
    assert "-fno-lto" in flags


# --- Bundle C: clock=auto + ARM guard ----------------------------------------


def test_dudect_clock_default_is_auto():
    from ctkat.config import DudectConfig
    cfg = DudectConfig(harnesses=[])
    assert cfg.clock == "auto"


def test_resolve_clock_passes_through_explicit_values():
    from ctkat.config import resolve_clock
    assert resolve_clock("rdtsc") == "rdtsc"
    assert resolve_clock("monotonic") == "monotonic"


def test_resolve_clock_auto_picks_rdtsc_on_native_x86(monkeypatch):
    import ctkat.config as cfg_mod
    monkeypatch.setattr(cfg_mod.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(cfg_mod, "detect_qemu_emulation", lambda: False)
    assert cfg_mod.resolve_clock("auto") == "rdtsc"


def test_resolve_clock_auto_picks_monotonic_under_qemu(monkeypatch):
    # QEMU x86 (Docker on Apple Silicon) reports x86_64 but rdtsc is
    # unreliable — auto must downgrade to monotonic.
    import ctkat.config as cfg_mod
    monkeypatch.setattr(cfg_mod.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(cfg_mod, "detect_qemu_emulation", lambda: True)
    assert cfg_mod.resolve_clock("auto") == "monotonic"


def test_resolve_clock_auto_picks_monotonic_on_arm(monkeypatch):
    import ctkat.config as cfg_mod
    monkeypatch.setattr(cfg_mod.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(cfg_mod, "detect_qemu_emulation", lambda: False)
    assert cfg_mod.resolve_clock("auto") == "monotonic"


def test_resolve_clock_auto_handles_windows_amd64_casing(monkeypatch):
    # Regression guard: Windows reports "AMD64" (uppercase). Naive == check
    # against "amd64" would miss it and fall through to monotonic.
    import ctkat.config as cfg_mod
    monkeypatch.setattr(cfg_mod.platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(cfg_mod, "detect_qemu_emulation", lambda: False)
    assert cfg_mod.resolve_clock("auto") == "rdtsc"


def test_explicit_rdtsc_on_arm_raises(monkeypatch, tmp_path: Path):
    import ctkat.config as cfg_mod
    monkeypatch.setattr(cfg_mod.platform, "machine", lambda: "arm64")
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "dudect:\n"
        "  clock: rdtsc\n"
        "  harnesses: []\n"
    )
    with pytest.raises(ValidationError, match="rdtsc.*requires.*x86_64"):
        load_config(_write(tmp_path, body))


def test_explicit_monotonic_on_arm_is_fine(monkeypatch, tmp_path: Path):
    import ctkat.config as cfg_mod
    monkeypatch.setattr(cfg_mod.platform, "machine", lambda: "arm64")
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "dudect:\n"
        "  clock: monotonic\n"
        "  harnesses: []\n"
    )
    cfg = load_config(_write(tmp_path, body))
    assert cfg.dudect.clock == "monotonic"


def test_auto_clock_on_arm_loads_cleanly(monkeypatch, tmp_path: Path):
    # The yaml stays "auto"; resolution happens lazily at runtime.
    import ctkat.config as cfg_mod
    monkeypatch.setattr(cfg_mod.platform, "machine", lambda: "arm64")
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "dudect:\n"
        "  clock: auto\n"
        "  harnesses: []\n"
    )
    cfg = load_config(_write(tmp_path, body))
    assert cfg.dudect.clock == "auto"


# --- Bundle D: leak_target field ---------------------------------------------


def test_dudect_harness_leak_target_default_is_sk():
    from ctkat.config import DudectHarnessConfig
    h = DudectHarnessConfig(name="h", template="kem", header="api.h")
    assert h.leak_target == "sk"


def test_dudect_kem_can_set_leak_target_ct():
    from ctkat.config import DudectHarnessConfig
    h = DudectHarnessConfig(
        name="h", template="kem", header="api.h", leak_target="ct",
    )
    assert h.leak_target == "ct"


def test_dudect_generic_with_ct_leak_target_raises(tmp_path: Path):
    # leak_target is KEM-specific. On the generic template there's no
    # canonical sk-vs-ct split, so accepting `ct` would be a silent no-op.
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "dudect:\n"
        "  harnesses:\n"
        "    - name: h\n"
        "      template: generic\n"
        "      function: foo\n"
        "      leak_target: ct\n"
    )
    with pytest.raises(ValidationError, match="leak_target.*only valid for template=kem"):
        load_config(_write(tmp_path, body))


def test_dudect_kem_leak_target_fo_accepted(tmp_path: Path):
    # Bundle K (U2 #1): "fo" is a valid value for template=kem.
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "dudect:\n"
        "  harnesses:\n"
        "    - name: h\n"
        "      template: kem\n"
        "      header: api.h\n"
        "      leak_target: fo\n"
    )
    cfg = load_config(_write(tmp_path, body))
    assert cfg.dudect.harnesses[0].leak_target == "fo"


def test_dudect_leak_target_fo_rejected_on_generic(tmp_path: Path):
    # Same rule as ct: only valid for kem template.
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "dudect:\n"
        "  harnesses:\n"
        "    - name: h\n"
        "      template: generic\n"
        "      function: foo\n"
        "      leak_target: fo\n"
    )
    with pytest.raises(ValidationError, match="leak_target.*only valid for template=kem"):
        load_config(_write(tmp_path, body))


# --- Bundle H2: T4 argv / T7 name pattern / T8 bounds --------------------


def test_build_argv_alternative_to_command(tmp_path: Path):
    # T4: argv path replaces command. Both unset = error; both set = error.
    body = (
        "project: {name: demo}\n"
        "build:\n"
        "  argv: [make, -j4]\n"
        "ct:\n"
        "  harnesses:\n"
        "    - {name: h, binary: ./x}\n"
    )
    cfg = load_config(_write(tmp_path, body))
    assert cfg.build.argv == ["make", "-j4"]
    assert cfg.build.command is None


def test_build_neither_command_nor_argv_raises(tmp_path: Path):
    body = (
        "project: {name: demo}\n"
        "build: {}\n"
        "ct:\n"
        "  harnesses:\n"
        "    - {name: h, binary: ./x}\n"
    )
    with pytest.raises(ValidationError, match="exactly one of"):
        load_config(_write(tmp_path, body))


def test_build_both_command_and_argv_raises(tmp_path: Path):
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true', argv: ['true']}\n"
        "ct:\n"
        "  harnesses:\n"
        "    - {name: h, binary: ./x}\n"
    )
    with pytest.raises(ValidationError, match="exactly one of"):
        load_config(_write(tmp_path, body))


def test_kat_argv_alternative_to_command(tmp_path: Path):
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "kat: {argv: [./run_kat]}\n"
    )
    cfg = load_config(_write(tmp_path, body))
    assert cfg.kat.argv == ["./run_kat"]


def test_harness_name_pattern_rejects_path_traversal(tmp_path: Path):
    # T7: name lands in `{generated_dir}/harness_{name}.c` — must be
    # filename-safe.
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "ct:\n"
        "  harnesses:\n"
        "    - {name: '../../etc/passwd', binary: ./x}\n"
    )
    with pytest.raises(ValidationError, match=r"name"):
        load_config(_write(tmp_path, body))


def test_harness_name_pattern_rejects_shell_metas(tmp_path: Path):
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "ct:\n"
        "  harnesses:\n"
        "    - {name: 'h;rm -rf /', binary: ./x}\n"
    )
    with pytest.raises(ValidationError, match=r"name"):
        load_config(_write(tmp_path, body))


# --- Bundle O (T20, T7 follow-up): yaml identifier validators -----------


def test_harness_header_with_quote_rejected(tmp_path: Path):
    """T20: header lands inside `#include "{value}"` in generated C.
    A quote character would let the yaml break out of the include directive
    and inject arbitrary additional `#include` lines into the harness /
    coverage probe."""
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "ct:\n"
        "  harnesses:\n"
        '    - {name: h, template: kem, header: \'foo.h"\\n#include "/etc/passwd\'}\n'
    )
    with pytest.raises(ValidationError, match=r"header"):
        load_config(_write(tmp_path, body))


def test_harness_extra_headers_with_newline_rejected(tmp_path: Path):
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "ct:\n"
        "  harnesses:\n"
        '    - {name: h, template: kem, header: api.h, extra_headers: ["a.h\\nMALICIOUS"]}\n'
    )
    with pytest.raises(ValidationError, match=r"extra_headers"):
        load_config(_write(tmp_path, body))


def test_harness_prefix_must_be_valid_c_identifier(tmp_path: Path):
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "ct:\n"
        "  harnesses:\n"
        '    - {name: h, template: kem, header: api.h, prefix: "1bad_start"}\n'
    )
    with pytest.raises(ValidationError, match=r"prefix"):
        load_config(_write(tmp_path, body))


def test_harness_prefix_empty_is_allowed(tmp_path: Path):
    # Default value path: empty prefix must keep working (toy_password etc.).
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "ct:\n"
        "  harnesses:\n"
        '    - {name: h, template: kem, header: api.h}\n'
    )
    cfg = load_config(_write(tmp_path, body))
    assert cfg.ct.harnesses[0].prefix == ""


def test_harness_pqclean_prefix_passes(tmp_path: Path):
    # Real-world prefix used by examples/pqc_mlkem768.
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "ct:\n"
        "  harnesses:\n"
        '    - {name: h, template: kem, header: api.h, prefix: "PQCLEAN_MLKEM768_CLEAN_"}\n'
    )
    cfg = load_config(_write(tmp_path, body))
    assert cfg.ct.harnesses[0].prefix == "PQCLEAN_MLKEM768_CLEAN_"


def test_harness_function_must_be_c_identifier(tmp_path: Path):
    # T7 follow-up: function name flows into Jinja contexts as a C symbol.
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "ct:\n"
        "  harnesses:\n"
        '    - {name: h, template: generic, function: "system(\\"rm -rf /\\")"}\n'
    )
    with pytest.raises(ValidationError, match=r"function"):
        load_config(_write(tmp_path, body))


def test_dudect_harness_header_with_quote_rejected(tmp_path: Path):
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "dudect:\n"
        "  harnesses:\n"
        '    - {name: h, template: kem, header: \'evil.h"\'}\n'
    )
    with pytest.raises(ValidationError, match=r"header"):
        load_config(_write(tmp_path, body))


def test_harness_subdir_header_allowed(tmp_path: Path):
    # Power users put headers in subdirs; pattern must accept `/`.
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "ct:\n"
        "  harnesses:\n"
        '    - {name: h, template: kem, header: "pqclean/include/api.h"}\n'
    )
    cfg = load_config(_write(tmp_path, body))
    assert cfg.ct.harnesses[0].header == "pqclean/include/api.h"


def test_dudect_measurements_upper_bound_rejected(tmp_path: Path):
    # T8: typo'd 100,000,000 → silently allocated 800MB BSS pre-H2.
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "dudect:\n"
        "  measurements: 100000000\n"
        "  harnesses:\n"
        "    - {name: h, template: generic, function: foo}\n"
    )
    with pytest.raises(ValidationError, match=r"measurements"):
        load_config(_write(tmp_path, body))


def test_dudect_warmup_too_large_rejected(tmp_path: Path):
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "dudect:\n"
        "  warmup: 100000000\n"
        "  harnesses:\n"
        "    - {name: h, template: generic, function: foo}\n"
    )
    with pytest.raises(ValidationError, match=r"warmup"):
        load_config(_write(tmp_path, body))


def test_dudect_batches_zero_rejected(tmp_path: Path):
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "dudect:\n"
        "  batches: 0\n"
        "  harnesses:\n"
        "    - {name: h, template: generic, function: foo}\n"
    )
    with pytest.raises(ValidationError, match=r"batches"):
        load_config(_write(tmp_path, body))


# --- Bundle I (F9 #3): shared_cflags propagation -------------------------


def test_shared_cflags_propagates_to_both_stages(tmp_path: Path):
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "shared_cflags: ['-O2', '-g', '-fno-inline']\n"
        "ct:\n"
        "  harnesses:\n"
        "    - {name: h, binary: ./x}\n"
        "dudect:\n"
        "  harnesses:\n"
        "    - {name: h, template: generic, function: foo}\n"
    )
    cfg = load_config(_write(tmp_path, body))
    assert cfg.ct.cflags == ["-O2", "-g", "-fno-inline"]
    assert cfg.dudect.compiler.cflags == ["-O2", "-g", "-fno-inline"]


def test_shared_cflags_yields_to_explicit_ct_cflags(tmp_path: Path):
    # Explicit per-stage cflags must win over shared (so power users can
    # share *most* flags but tweak one stage).
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "shared_cflags: ['-O2', '-g']\n"
        "ct:\n"
        "  cflags: ['-O0', '-g']\n"
        "  harnesses:\n"
        "    - {name: h, binary: ./x}\n"
    )
    cfg = load_config(_write(tmp_path, body))
    assert cfg.ct.cflags == ["-O0", "-g"]


def test_shared_cflags_unset_leaves_defaults(tmp_path: Path):
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "ct:\n"
        "  harnesses:\n"
        "    - {name: h, binary: ./x}\n"
    )
    cfg = load_config(_write(tmp_path, body))
    # Default ct cflags should still be the original -O0 list (Bundle E-3
    # banner notices the asymmetry).
    assert "-O0" in cfg.ct.cflags


def test_example_yamls_have_fno_lto_when_overriding_dudect_cflags(tmp_path: Path):
    """T14 regression: example yamls that override dudect.compiler.cflags
    must keep `-fno-lto` — otherwise LTO can elide the very function being
    measured. README §"dudect 측정 강화" warns about this; the default
    factory includes the flag, but explicit yaml overrides drop it unless
    the author remembers to re-add it.
    """
    import yaml as _yaml
    examples_dir = Path(__file__).parent.parent / "examples"
    offenders: list[str] = []
    for yaml_path in examples_dir.glob("*/ctkat*.yaml"):
        body = _yaml.safe_load(yaml_path.read_text())
        if not body:
            continue
        dud = body.get("dudect")
        if not isinstance(dud, dict):
            continue
        compiler = dud.get("compiler")
        if not isinstance(compiler, dict):
            continue
        cflags = compiler.get("cflags")
        if cflags is None:
            continue  # using default factory, which already includes -fno-lto
        if "-fno-lto" not in cflags:
            offenders.append(str(yaml_path.relative_to(examples_dir.parent)))
    assert not offenders, (
        f"Example yamls override dudect cflags but drop `-fno-lto`: {offenders}. "
        "Add the flag explicitly — its absence silently lets LTO elide the "
        "measured function (see T14)."
    )


def test_mlkem_dudect_harnesses_omit_randombytes_for_reproducibility():
    """T38 regression: the ML-KEM example advertises reproducible dudect
    timings (README §"재현성 (seed)") via the weak `randombytes` override
    (R1 Option B). That only works if the dudect harnesses do NOT also link
    PQClean's strong `common/randombytes.c`, which would shadow the override
    with OS entropy. The ct/Valgrind harness, by contrast, MUST keep it (no
    override in that template). Lints the actual example so the advertised
    reproducibility can't silently drift away again."""
    import yaml as _yaml
    cfg = _yaml.safe_load(
        (Path(__file__).parent.parent
         / "examples" / "pqc_mlkem768" / "ctkat.yaml").read_text()
    )
    for h in cfg["dudect"]["harnesses"]:
        srcs = h.get("sources", [])
        assert not any("randombytes.c" in s for s in srcs), (
            f"dudect harness {h['name']!r} links common/randombytes.c — it "
            "shadows the weak override and breaks reproducibility (T38)."
        )
    # The ct harness keeps it (Valgrind harness has no override and needs the
    # strong symbol to link) — guard against an over-eager removal.
    ct_srcs = [s for h in cfg["ct"]["harnesses"] for s in h.get("sources", [])]
    assert any("randombytes.c" in s for s in ct_srcs), (
        "ct harness should still link common/randombytes.c (no weak override "
        "in the Valgrind template)."
    )


def test_dudect_seed_zero_rejected(tmp_path: Path):
    # F16: yaml `dudect.seed: 0` was silently swapped to 0xC0FFEE inside the
    # generated C harness while Python logged `0x0` — two layers in
    # disagreement. Validator must refuse the input outright.
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "dudect:\n"
        "  seed: 0\n"
        "  harnesses:\n"
        "    - {name: h, template: generic, function: foo}\n"
    )
    import pytest as _pytest
    with _pytest.raises(Exception):
        load_config(_write(tmp_path, body))


def test_dudect_seed_null_still_allowed(tmp_path: Path):
    # `null` (Python None) means "pick a random seed at run time and log it"
    # — that path must remain working after F16 (the gt=0 bound applies only
    # to non-None values).
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "dudect:\n"
        "  seed: null\n"
        "  harnesses:\n"
        "    - {name: h, template: generic, function: foo}\n"
    )
    cfg = load_config(_write(tmp_path, body))
    assert cfg.dudect.seed is None


def test_ct_seed_zero_rejected(tmp_path: Path):
    # Same family as the dudect side — harness_generic.c.j2 also has the
    # `CTKAT_SEED ? CTKAT_SEED : 0xC0FFEE` swap.
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "ct:\n"
        "  seed: 0\n"
        "  harnesses:\n"
        "    - {name: h, binary: ./x}\n"
    )
    import pytest as _pytest
    with _pytest.raises(Exception):
        load_config(_write(tmp_path, body))


def test_shared_cflags_yields_when_user_explicit_matches_default(tmp_path: Path):
    # F15 regression: a user who explicitly sets `ct.cflags` to a list that
    # happens to equal the default factory output must NOT be silently
    # overridden by `shared_cflags`. The earlier `==` check did exactly that;
    # the model_fields_set check fixes it.
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "shared_cflags: ['-O3']\n"
        "ct:\n"
        "  cflags: ['-O0', '-g', '-fno-inline', '-fno-omit-frame-pointer']\n"
        "  harnesses:\n"
        "    - {name: h, binary: ./x}\n"
    )
    cfg = load_config(_write(tmp_path, body))
    # User's explicit list (even though == default) must win over shared.
    assert cfg.ct.cflags == ["-O0", "-g", "-fno-inline", "-fno-omit-frame-pointer"]


# --- Bundle I (T2): lookup_function_patterns yaml field ------------------


def test_lookup_function_patterns_defaults_to_none(tmp_path: Path):
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "ct:\n"
        "  harnesses:\n"
        "    - {name: h, binary: ./x}\n"
    )
    cfg = load_config(_write(tmp_path, body))
    assert cfg.ct.lookup_function_patterns is None


def test_lookup_function_patterns_user_override(tmp_path: Path):
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "ct:\n"
        "  lookup_function_patterns: ['my_table']\n"
        "  harnesses:\n"
        "    - {name: h, binary: ./x}\n"
    )
    cfg = load_config(_write(tmp_path, body))
    assert cfg.ct.lookup_function_patterns == ["my_table"]


# --- R-2 (T23/T35/T34/F22): yaml -> C source injection lockdown -------------
#
# Bundle O (T20) validated prefix/header/extra_headers/function/return_type
# but left BufferSpec.name/size, HarnessConfig.args, and SecretRegion.
# offset/length/comment emitted into generated C unvalidated. Each of these
# could smuggle arbitrary C (incl. `system(...)`) into a harness that CT-KAT
# compiles and executes. R-2 closes them at config-load time.


def test_buffer_name_injection_rejected():
    """T23: buffer name is emitted as a C variable name. A non-identifier
    must be rejected, not compiled into the harness."""
    with pytest.raises(ValidationError, match=r"buffer name"):
        BufferSpec.model_validate(
            {"name": 'x[1]; system("id"); char y', "size": "8", "role": "secret"}
        )


def test_buffer_size_injection_rejected():
    """T23: buffer size is emitted as a C array dimension."""
    with pytest.raises(ValidationError, match=r"size"):
        BufferSpec.model_validate(
            {"name": "x", "size": '8]; system("id"); char z[1', "role": "secret"}
        )


def test_buffer_legitimate_values_pass():
    """Regression guard: real configs use plain idents + integer / sizeof
    sizes — these must NOT be rejected by the injection validator."""
    for size in ("16", "sizeof(secret)", "CRYPTO_BYTES"):
        BufferSpec.model_validate({"name": "secret", "size": size, "role": "secret"})


def test_harness_args_injection_rejected():
    """T23: args are emitted into `function(args...)`."""
    with pytest.raises(ValidationError, match=r"args"):
        HarnessConfig.model_validate(
            {
                "name": "h",
                "template": "generic",
                "function": "f",
                "args": ['a);} system("id"); ((void)(0'],
            }
        )


def test_harness_args_legitimate_values_pass():
    HarnessConfig.model_validate(
        {
            "name": "h",
            "template": "generic",
            "function": "f",
            "args": ["secret", "out", "sizeof(secret)"],
        }
    )


def test_secret_region_length_injection_rejected():
    """T23: secret_region length is emitted inside VALGRIND_MAKE_MEM_*(...)."""
    with pytest.raises(ValidationError, match=r"length"):
        SecretRegion.model_validate(
            {"offset": "0", "length": '32);} system("id"); int z=(0'}
        )


def test_secret_region_comment_injection_rejected():
    """T35: comment is emitted inside `/* ... */`; a `*/` would break out."""
    with pytest.raises(ValidationError, match=r"comment"):
        SecretRegion.model_validate(
            {"offset": "0", "length": "32", "comment": '*/ system("id"); /*'}
        )


def test_secret_region_legitimate_values_pass():
    """Regression guard: pqc_mlkem768 uses macro arithmetic offsets/lengths."""
    SecretRegion.model_validate(
        {
            "offset": "KYBER_SECRETKEYBYTES - KYBER_SYMBYTES",
            "length": "KYBER_INDCPA_SECRETKEYBYTES",
            "comment": "indcpa secret key bytes",
        }
    )


def test_header_path_traversal_rejected():
    """The header validator advertises 'provably contained' but used to allow
    `..` traversal and absolute paths through the charset (`.`/`/` allowed)."""
    for bad in ("../../../etc/passwd", "/etc/hosts", "a/../../b.h"):
        with pytest.raises(ValidationError, match=r"header|traversal|relative"):
            HarnessConfig.model_validate(
                {"name": "h", "template": "kem", "header": bad}
            )


def test_header_legitimate_relative_paths_pass():
    for good in ("api.h", "pqclean/include/foo.h", "gmp-6.h"):
        HarnessConfig.model_validate(
            {"name": "h", "template": "kem", "header": good}
        )


def test_validator_fullmatch_rejects_trailing_newline():
    """T34: validators used `.match()`, whose `$` also matches before a
    trailing `\\n`, so `function: "f\\n"` smuggled a newline into the C
    identifier. `.fullmatch()` rejects it."""
    with pytest.raises(ValidationError, match=r"function"):
        HarnessConfig.model_validate(
            {"name": "h", "template": "generic", "function": "f\n"}
        )


# --- R-4 (T37/T39): config robustness regressions ---------------------------


def test_duplicate_ct_harness_names_rejected(tmp_path: Path):
    """T37: two ct harnesses with the same name key the same generated-binary
    slot and harness_<name>.c path — one silently overwrites the other."""
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "ct:\n"
        "  harnesses:\n"
        "    - {name: dup, binary: ./a}\n"
        "    - {name: dup, binary: ./b}\n"
    )
    with pytest.raises(ValidationError, match=r"duplicate harness name"):
        load_config(_write(tmp_path, body))


def test_duplicate_dudect_harness_names_rejected(tmp_path: Path):
    """T37: same collision in the dudect list."""
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "dudect:\n"
        "  harnesses:\n"
        "    - {name: dup, template: generic, function: f}\n"
        "    - {name: dup, template: generic, function: g}\n"
    )
    with pytest.raises(ValidationError, match=r"duplicate harness name"):
        load_config(_write(tmp_path, body))


def test_same_name_across_ct_and_dudect_is_allowed(tmp_path: Path):
    """T37: a ct harness and a dudect harness deliberately share a name to
    pair in the combined verdict matrix (examples/pqc_mlkem768 does this).
    Uniqueness is per-list, so this must NOT be rejected."""
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "ct:\n"
        "  harnesses:\n"
        "    - {name: kem_dec, binary: ./a}\n"
        "dudect:\n"
        "  harnesses:\n"
        "    - {name: kem_dec, template: generic, function: f}\n"
    )
    cfg = load_config(_write(tmp_path, body))
    assert cfg.ct.harnesses[0].name == "kem_dec"
    assert cfg.dudect.harnesses[0].name == "kem_dec"


def test_build_empty_argv_rejected(tmp_path: Path):
    """T39: `argv: []` passes the exactly-one check but crashes subprocess
    with a raw IndexError (no program to exec)."""
    body = "project: {name: demo}\nbuild: {argv: []}\n"
    with pytest.raises(ValidationError, match=r"argv must be a non-empty"):
        load_config(_write(tmp_path, body))


def test_kat_empty_argv_rejected(tmp_path: Path):
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "kat: {argv: []}\n"
    )
    with pytest.raises(ValidationError, match=r"argv must be a non-empty"):
        load_config(_write(tmp_path, body))
