# Accepted variable-time registry

A `ct` FAIL means a secret-derived value reached a branch/address — but **not
every such finding is a leak**. This registry records the functions where a
secret-dependent branch is an *analyzed-safe part of the scheme's design*, with a
per-function citation. `scripts/build_corpus_table.py` reads the table below to
auto-classify a ct-FAIL harness from its `finding_funcs`:

- **ALL** of a harness's leak-site functions are registered (for its family)
  → `accepted-variable-time`.
- **ANY** leak-site function is NOT registered → `needs-analysis`.

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

> Adding an entry is a deliberate, reviewed act: it moves a finding from "flag"
> to "accepted", so it must carry a basis a reviewer can check. When unsure,
> leave it out → the harness stays `needs-analysis`.
