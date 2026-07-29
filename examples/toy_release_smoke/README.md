# Release smoke target

This shell-free, constant-time C target is intentionally small enough for the
packaging CI job. A wheel-only installation must be able to render and compile
its generic harness, run the KAT, execute Valgrind, sweep gcc/clang, run
asm-scan, and finish `ctkat screen` with a `robust` verdict.

It is release infrastructure, not a research-corpus row.
