# ct_matrix_flip — "the binary you test ≠ the binary you ship"

A minimal demo for **`ctkat ct-matrix`**: the *same* C source gets a different
constant-time verdict depending on the build configuration.

`src/flip.c` has two functions over an identical input/output shape:

| harness | what it does | constant-time? |
|---|---|---|
| `leaky_select` | picks the output with a **secret-dependent `if`** | **no** — leaks via a data-dependent branch |
| `safe_select`  | same result, written **branch-free with arithmetic** | yes |

## Run it

Valgrind is required, so run inside the Docker dev container (see the repo
README for why):

```bash
./scripts/dev.sh
# inside the container:
PYTHONPATH=. python -m ctkat ct-matrix -c examples/ct_matrix_flip/ctkat.yaml
```

## What you'll see

```
 harness   combo         cc    status
 leaky     gcc_debug     gcc   FAIL     ← secret branch visible at -O0
 leaky     gcc_release   gcc   PASS     ← gcc optimized the branch away at -O2
 leaky     gcc_size      gcc   PASS     ← ...and at -Os
 safe      gcc_debug     gcc   PASS
 safe      gcc_release   gcc   PASS
 safe      gcc_size      gcc   PASS
```

and the headline:

```
ct-matrix: harness 'leaky' has DIFFERENT CT results across builds (FAIL, PASS)
```

## The point

`leaky_select` is **leaky in the source at every optimization level** — the
data-dependent branch never goes away. But the structural CT check
(Valgrind/Memcheck) only *sees* it at `-O0`; once gcc lowers the branch to
branch-free code at `-O2`/`-Os`, the finding disappears. So a single `-O2` run
would report a clean PASS on code that still leaks.

That is the whole reason `ct-matrix` exists: a single-build CT result can be
misleading, because **the binary you tested is not necessarily the binary you
ship**. The artifact (`reports/ctkat_ct_matrix.csv` / `.json`) is observational
— it never feeds the `run` verdict gate; it just makes the build-sensitivity
visible.

## Honest caveat (and the lesson)

The exact level at which the flip happens is **compiler- and version-dependent**
(measured here on the project's Docker amd64 **gcc 13.3**). Run it with a
different compiler — e.g. add `clang` to `matrix.compilers` in `ctkat.yaml` — and
you may see the boundary move. That variability is not a bug in the demo; it *is*
the thing `ct-matrix` is built to surface.
