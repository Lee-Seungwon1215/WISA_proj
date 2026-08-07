# Locked dependency exports

`uv.lock` is the resolver lock. The two requirements files are header-free,
hash-locked pip exports so their bytes do not depend on an output path.

Regenerate with uv 0.11.17 from the repository root:

```bash
uv lock
uv export --frozen --no-header --no-dev --no-emit-project \
  --format requirements.txt --output-file requirements/runtime.lock
uv export --frozen --no-header --no-dev --extra dev --no-emit-project \
  --format requirements.txt --output-file requirements/artifact.lock
```

CI repeats both exports and compares them byte-for-byte. Docker installs the
runtime export with pip `--require-hashes`; the premeasurement artifact profile
uses the dev export through `uv sync --frozen --extra dev`.
