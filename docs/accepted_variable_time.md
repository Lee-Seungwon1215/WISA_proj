# Accepted variable-time registry

A `ct` FAIL means a secret-derived value reached a branch/address — but **not
every such finding is a leak**. This registry records the functions where a
secret-dependent branch is an *analyzed-safe part of the scheme's design*, with a
per-function citation. `scripts/build_corpus_table.py` reads the table below for
the **automatic** ct-FAIL classification path:

- **ALL** of a harness's leak-site functions are registered (for its family)
  → `accepted-variable-time`.
- **ANY** leak-site function is NOT registered → `needs-analysis`.

A reviewer may still use a manual `verdict` override for a documented
attribution artifact (for example, an optimized parent frame that should not be
registered wholesale). In evidence v2, the override only supplies the
`legacy_verdict_class`; it must also carry `review: reviewed` plus a stable
`review_id`. A note explaining the source/line basis is useful but cannot clear
the result by itself.

**Guardrails** (the whole point — "accepted" is not a free pass):

1. **Citation required** — no cited basis, no entry. Default-deny: an
   unrecognized secret branch is NEVER auto-accepted.
2. **timing-only** — every entry's scope is the *timing* channel. These say
   nothing about power / EM / fault side-channels (which can still exploit the
   same intermediates).
3. The tool's signal is **correct** — a real secret-dependent branch exists.
   "accepted" is a triage *decision* with a reason, not a claim the branch is
   absent.

## Registry

Match is by function-name **suffix**, so `PQCLEAN_MLDSA65_CLEAN_poly_chknorm`
matches the `poly_chknorm` entry.

| family | function | reason | basis | scope |
|---|---|---|---|---|

There are currently **no active automatic entries**. A CT finding therefore
remains `needs-analysis` unless an exact, independently reviewed artifact makes
a narrower decision. This is intentionally conservative.

### Withdrawn ML-DSA entries

The earlier registry entries for `poly_chknorm`, `poly_challenge`, `make_hint`,
and `pack_sig` were withdrawn before the paper-grade campaign. Rejected signing
iterations use long-term-key-derived values (`s1`, `s2`, and `t0`), and the
candidate `c`, `h`, and `w1` from a rejected iteration never enter the final
public signature. A value becoming public only after a later successful
iteration does not retroactively declassify the rejected iteration or its
rejection count.

An exact final-success serialization path may still admit a scoped public-output
argument, but that must be demonstrated at the precise data-flow boundary and
build. It is not safe to register an entire function suffix automatically.

> Adding an entry is a deliberate, reviewed act: it moves a finding from "flag"
> to legacy "accepted", so a final v2 corpus row must still link a scoped review
> artifact. When unsure, leave it out → `review=pending` and
> `overall=needs-review`.

## Limitation: inlining blurs finding attribution (build-dependent)

Finding attribution is **per build**. At `-O0 -fno-inline` Valgrind names the
real leak-site function (e.g. `poly_chknorm`); optimized cells
(`-O1`/`-O2`/`-O3`/`-Os`) can merge inner functions into the caller, so the SAME
accepted branch is attributed to a parent frame (e.g.
`crypto_sign_signature_ctx`). Because the corpus takes the
UNION of leak-site functions across the build matrix, an optimized-build parent
frame can obscure which exact inner dependency was observed. This is another
reason to keep the harness at `needs-analysis`, not a reason to broaden an
acceptance rule.

Do **NOT** "fix" this by registering the inlined parent (`crypto_sign_signature_ctx`):
a top-level frame is a catch-all that would accept anything inlined into it,
defeating default-deny. The correct resolution is to inspect the
**precise-attribution debug build** (`-O0 -fno-inline`) and triage every exact
data-flow path on its own merits. `pack_sig` and `crypto_sign_signature_ctx`
remain deliberately unregistered.

ML-DSA debug/no-inline builds localize the relevant rejection and serialization
functions. Optimized builds also add `crypto_sign_signature_ctx` as a coarse
parent frame. All of these findings remain `needs-analysis`; neither a parent
frame nor a rejection helper is eligible for registry-wide acceptance.

## Explicit non-entry: Falcon/FN-DSA sampler findings

Do **not** add Falcon's `sampler`, `BerExp`, `fpr_floor`, signing acceptance
loop, or wrapper parent frames to this registry as a shortcut.

The current `examples/pqc_falcon512` probes intentionally leave Falcon at
`needs-analysis`. Split-taint runs show that encoded long-term key material
(`f`, `g`, and `F`) reaches the Gaussian sampler / Bernoulli-exp / floating-point
rounding finding family. That differs in implementation detail from ML-DSA and
the SPHINCS+ harness-local public-output hypothesis, but none is automatically
accepted. A Falcon acceptance would
need a source-level isochrony argument for the exact implementation and build;
it is not a per-function registry entry.
