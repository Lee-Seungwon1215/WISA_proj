# Corpus result schema — LOCKED v1.2

> Status: **LOCKED** (review-corrected). This is the frozen Phase D result
> schema — adding a target must not reformat it. Columns are frozen; a breaking
> change requires a v2 bump + migration note. **v1.1**: additively added the
> `accepted-variable-time` verdict_class (prompted by real ML-DSA data). **v1.2**:
> additively added `basis` to distinguish classifier output, reviewed
> attribution, and default-deny stop rows.

## Framing (corrected)

The earlier "well-written CT code = build-robust / naive code = flips" binary is
**too clean and gets falsified by our own data**: PQClean ML-KEM is `ct`/Valgrind
PASS across builds, yet `asm-scan` DOES flag division candidates in it —
`common/fips202.c` `shake128`/`shake256` (gcc `-Os`, clang `-O0`). Those are
*public* Keccak-rate divisions, not secret-derived, but asm-scan can't tell; a
human must triage.

So Phase D is **not** a PASS/FAIL leaderboard. It is:

> Collect, per build configuration, the signals from three DIFFERENT threat
> models — `ct`/Valgrind (secret → branch/address), `dudect` (timing
> distribution), `asm-scan` (candidate variable-latency instruction) — and
> organize them into a table a human can triage for *secret-derived* risk.

`asm-scan` is intentionally taint-free: it reports candidate variable-latency
instructions and provenance, while `varlat_triage` records the human/source
review that separates public operands (for example Keccak rates) from
secret-derived risk (for example KyberSlash poly helpers). A future operand-taint
pass could reduce that manual review burden, but the locked v1.1 schema keeps
the candidate collection and the attribution judgment separate.

The honest contrast is then: ct-matrix shows *whether the structural verdict is
build-stable*; asm-scan shows *which builds keep a variable-latency instruction
alive* (which Valgrind is blind to); and the value is the **combined,
build-indexed, triaged table**, not any single tool's PASS.

## Why two tables

Granularity differs: `ct-matrix`+`asm-scan` are per build *cell*
`(target,harness,cc,opt/combo)`; `dudect` is per *target/harness* (one timing
run); the triage/flip judgment is per *(family,target,harness)*. So: a raw
**cells** table (mergeable backing data) + a **summary** table (one row per
target — the report's evidence table).

## Directory layout

```
examples/corpus/<family>/<target>/     # a normal ctkat project (ct + dudect + matrix)
    ctkat.yaml
    src/ include/ ...
    FETCH_INFO.md     # provenance: upstream repo + commit, or "synthetic"
```
Reuse existing `examples/pqc_mlkem768*`.

## Table 1 — `corpus_cells.csv` (raw, one row per build cell)

```
family,target,harness,combo,cc,cc_version,opt,cflags,arch,ctkat_commit,
ct_status,ct_findings,ct_error,asm_div_count,asm_div_funcs,asm_error
```

| column | source | notes |
|---|---|---|
| `family` / `target` / `harness` | manual / yaml | ML-KEM / pqclean_mlkem768 / kem_dec |
| `combo` | matrix | named combo, e.g. `gcc_release` (keeps `release`/`hardened`/`native`/`nolto` distinct — **don't collapse to bare `-O`**) |
| `cc` / `cc_version` | env | `gcc` / `gcc (Ubuntu 13.3.0)` — **version is mandatory; build-sensitivity is compiler-version-specific** |
| `opt` / `cflags` | matrix | the `-O` and the full flag list (provenance) |
| `arch` / `ctkat_commit` | env | reproducibility (x86_64 / `d7d5460`); `os_image` recorded once per run (below) |
| `ct_status` | ct-matrix | PASS / FAIL / ERROR / NA |
| `ct_findings` | ct-matrix | int |
| `ct_error` | ct-matrix | ct/Valgrind error reason (empty if none) — **separate from asm** |
| `asm_div_count` | asm-scan | # variable-latency candidates at this cc×opt |
| `asm_div_funcs` | asm-scan | `;`-joined functions (or empty) |
| `asm_error` | asm-scan | asm-scan compile/objdump error — **a cell can be ct PASS but asm compile-fail, or vice versa** |

`os_image` (e.g. `ubuntu:24.04`) + run date are recorded once per merge run in a
header comment or `corpus_run.txt`, not per row.

This is `ctkat_ct_matrix.csv` ⨝ `ctkat_varlat_candidates.csv` on
`(target,harness,cc,opt)` + labels + env meta. A merge script builds it from the
existing per-project artifacts — **no in-tool schema change needed**.

## Table 2 — `corpus_summary.csv` (judgment, one row per target/harness)

```
family,target,harness,ct_flips,ct_status_set,
varlat_candidates,varlat_triage,
dudect_status,dudect_abs_t,dudect_measurements,dudect_leak_target,dudect_seed,dudect_threshold,
verdict_class,basis,notes
```

| column | meaning |
|---|---|
| `ct_flips` | yes/no — does `ct_status` DIFFER across cells? |
| `ct_status_set` | e.g. `{PASS}` / `{PASS,FAIL}` |
| `varlat_candidates` | builds keeping a div, e.g. `gcc:-Os;clang:-O0`, or `none` |
| `varlat_triage` | **manual**: `none` / `public` (operand is public, e.g. Keccak rate) / `secret-risk` (secret-derived, KyberSlash class) / `untriaged` |
| `dudect_*` | one timing run — status, max abs-t, **+ measurements, leak_target(sk/ct/fo), seed, threshold** (all needed to reproduce/compare a timing claim) |
| `verdict_class` | see taxonomy |
| `basis` | `auto` = classifier output without manual attribution; `review` = reviewer/triage input affected the final row; `stop` = unresolved/incomplete default-deny state |
| `notes` | free text + optional *real-code-issue / tool-problem / env-noise* tag |

### `verdict_class` taxonomy (triage-aware)

> This taxonomy lives in the package (`ctkat/verdict_class.py`) and is computed by
> BOTH this corpus builder and the
> `ctkat screen` command (which emits `reports/screen_summary.{csv,json,md}`), so
> the tool's per-project output and the curated corpus can't drift. This script
> still owns the corpus-only curation metadata (family/target/cc_version/arch/commit)
> and the idempotent `merge_write`.

Decoupled: ct-clean ≠ no-candidates. A row's class comes from BOTH ct status and
the **triaged** varlat result:

- `robust` — ct PASS across all builds AND `varlat_triage ∈ {none, public}`.
  *(ML-KEM lands here: ct PASS, fips202 divs triaged `public`.)*
- `ct-clean-untriaged` — ct PASS across builds but `varlat_triage = untriaged`
  (candidates exist, secret-derivation not yet checked). The HONEST default for a
  freshly-added target before manual triage.
- `ct-clean-asm-incomplete` — ct PASS across builds but the asm-scan **errored**
  for at least one build (a source never compiled, a missing/non-exec compiler,
  or a disasm failure — see the cell's `asm_error`). We never disassembled that
  build, so a `0`-division count is a blind spot, not evidence of safety — the
  row is deliberately NOT `robust`. The `notes` column names the affected
  compiler(s) and the underlying error. (N2: prevents an incomplete asm-scan
  from reading as the strongest clean verdict.)
- `varlat-secret-risk` — `varlat_triage = secret-risk` (KyberSlash class). **Note:
  ct/Valgrind may still be PASS — that's the structural-check blind spot.**
- `build-sensitive-ct` — `ct_status` flips across builds (the structural verdict
  itself depends on the build).
A ct FAIL is triaged on its leak-site functions (`ct_finding_funcs`, surfaced per
cell since **v1.1**) against `docs/accepted_variable_time.md`:

- `accepted-variable-time` — ct FAIL judged as an analyzed-safe scheme behavior,
  not a key-recovery leak. The normal auto path requires ALL leak-site functions
  to be in the accepted registry for the family (e.g. Dilithium signing's
  `poly_chknorm`/`make_hint`/`poly_challenge`/`pack_sig` per FIPS 204). A manual
  override is allowed only for reviewed attribution artifacts such as optimized
  parent frames; the note must explain the source/line basis, and the coarse
  parent function should NOT be added to the registry.
- `needs-analysis` — ct FAIL with at least one leak-site function NOT in the
  registry. **Default-deny**: an unrecognized secret branch is never auto-accepted
  — it stays here until a reviewer either adds a cited registry entry or confirms
  a leak.
- `ct-leak` — a CONFIRMED leak (a real secret branch / memory access). Reached
  only via a manual `--verdict <h>=ct-leak` (the auto path stops at
  `needs-analysis`, never declaring a confirmed leak on its own).
- `tool-problem` / `env-noise` — false positive/negative, or QEMU/timing artifact.

**Do not** read "has div candidate" as "KyberSlash-grade risk" — nor "ct FAIL" as
"broken". Both need triage: `untriaged → public|secret-risk` for asm-scan, and
`accepted-variable-time` (cited) vs `needs-analysis` (default) vs `ct-leak`
(confirmed) for a ct FAIL.

## Schema decisions

1. Keep BOTH `combo` and raw `opt`/`cflags` in cells (don't collapse).
2. `cc_version` + `arch` + `ctkat_commit` mandatory in cells.
3. dudect is recorded **per target/harness, once**, at the ct stage's deploy-like
   `-O2` (not per opt) — keeps the matrix tractable; the timing dimension is about
   the deployed build.
4. Merge script lives at `scripts/build_corpus_table.py` and reads each project's
   `reports/` (`ctkat_ct_matrix.csv`, `ctkat_varlat_candidates.csv`,
   `dudect_summary.csv`) — the in-tool artifact schemas stay frozen; only this
   script knows the corpus layout.
