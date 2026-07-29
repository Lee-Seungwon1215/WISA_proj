# Contributing to CT-KAT

CT-KAT is a security-screening research artifact. A green test does not excuse
an unexplained semantic change: code, regression tests, documentation, and
artifact schema must move together.

## Development setup

Python 3.11–3.13 is supported.

```bash
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest
```

Structural constant-time checks require Linux, Valgrind, and a C compiler. The
repository image supplies gcc and clang:

```bash
docker compose build
docker compose run --rm ctkat-dev \
  python -m ctkat screen --config examples/toy_release_smoke/ctkat.yaml
```

## Required checks

Run these before opening a pull request:

```bash
python -m pytest --cov=ctkat
python scripts/check_corpus.py
python scripts/render_readme_corpus.py --check
python scripts/check_third_party.py
python scripts/check_example_configs.py
ruff check ctkat scripts tests
mypy ctkat
```

Packaging changes must additionally pass:

```bash
python -m build
python scripts/check_distribution.py dist
python -m twine check dist/*
```

## Config execution policy

- Prefer `argv`, which executes without a shell.
- `command` is for intentionally shell-dependent trusted workflows only. Add
  `allow_shell: true` after reviewing it.
- Set `execution_profile: untrusted` for downloaded or pull-request-provided
  configs. That profile rejects all shell-backed steps.
- Committed examples must remain shell-free; CI enforces this.

## Corpus and claims

- Never edit the generated README corpus table by hand. Update the source CSV
  and run `python scripts/render_readme_corpus.py --write`.
- Do not translate `PASS`, `CLEAN`, or `robust` into a proof of constant time.
- Preserve raw evidence and label confounds. A surprising result is not fixed
  by deleting it or writing a convenient override.
- Vendored source changes require updating `third_party.toml`, the associated
  `FETCH_INFO.md`, and `THIRD_PARTY_NOTICES.md`.

## Commit scope

Keep changes reviewable. The project roadmap in
`docs/ROADMAP_REJECTION_RECOVERY.md` defines the intended dependency order and
Go/No-Go gates.
