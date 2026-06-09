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
registered wholesale). That override must carry a note explaining the source/line
basis.

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
| ML-DSA | poly_chknorm | rejection-sampling norm check (Fiat-Shamir-with-aborts); the rejection *count* depends on the fresh per-signature nonce y — not the long-term key | FIPS 204 / Dilithium security analysis | timing-only |
| ML-DSA | poly_challenge | challenge c = SampleInBall(H(mu ‖ w1)); w1 (HighBits of A·y) is a PUBLIC signature component — tainted via the deterministic nonce derived from K but carries nothing beyond the published signature | FIPS 204 (w1 / c are public) | timing-only |
| ML-DSA | make_hint | produces the hint h — a PUBLIC signature component; the branch/timing reflect only the published hint structure | FIPS 204 (hint is public) | timing-only |
| ML-DSA | pack_sig | bit-packs the public signature `(c,z,h)`; the flagged branch serializes nonzero positions of the public hint vector `h` into the signature | FIPS 204 (signature components are public); source review: `packing.c:160-200` | timing-only |

> Adding an entry is a deliberate, reviewed act: it moves a finding from "flag"
> to "accepted", so it must carry a basis a reviewer can check. When unsure,
> leave it out → the harness stays `needs-analysis`.

## Limitation: inlining blurs finding attribution (build-dependent)

Finding attribution is **per build**. At `-O0 -fno-inline` Valgrind names the
real leak-site function (e.g. `poly_chknorm`); at `-O2`/`-Os` the inliner merges
inner functions into the caller, so the SAME accepted branch is attributed to a
parent frame (e.g. `crypto_sign_signature_ctx`). Because the corpus takes the
UNION of leak-site functions across the build matrix, an optimized-build parent
frame can make a harness `needs-analysis` even when its precise-attribution
debug build is cleanly accepted.

Do **NOT** "fix" this by registering the inlined parent (`crypto_sign_signature_ctx`):
a top-level frame is a catch-all that would accept anything inlined into it,
defeating default-deny. The correct resolution is to classify accepted-vs-leak on
the **precise-attribution debug build** (`-O0 -fno-inline`) and triage any
genuinely-distinct optimized-build frame on its own merits. `pack_sig` is now
registered separately because source review shows it packs the public signature
hint vector; `crypto_sign_signature_ctx` remains deliberately unregistered.

ML-DSA-65's debug/no-inline build shows only the registered rejection/public-output
functions. Optimized builds still add `crypto_sign_signature_ctx` as a coarse
parent frame, so accepting the harness requires an explicit review note or
triage override, not a registry-wide parent-function entry.
