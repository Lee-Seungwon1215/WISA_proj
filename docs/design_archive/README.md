# Original Design Archive

This folder preserves the **original design specification** that CT-KAT was
initially built from. The contents here are **frozen historical reference**.

## Rules

- **Do not modify** files in this folder.
- **Do not use** them as a source of truth for current behavior.
- **Do not list** them as discrepancies during code review — implementation
  intentionally diverged from the spec in several places (verdict labels,
  CSV columns, `secret_regions` API, classifier whitelist, harness/KAT split,
  etc.). Those divergences are deliberate, not bugs.

## What's authoritative instead

For current, accurate descriptions of CT-KAT, read these in order:

1. **Project root `README.md`** — overview, CLI, examples, limitations.
2. **`ctkat/` source** — the code is the single source of truth for behavior.
3. **`tests/`** — executable contracts pinning down expected outputs.

If something here conflicts with the current code, the current code wins.
The archive exists only to show original design intent and provide context
for "why does this exist at all?" questions.
