# Security policy

## Supported versions

CT-KAT is pre-1.0 research software. Security fixes are applied to the latest
commit on `main`; older snapshots are not maintained.

| Version | Supported |
|---|---|
| `main` / `0.11.x` alpha | yes |
| `0.10.x` and older | no |

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose a user,
invalidate published evidence, or enable command execution. Use the
repository's private GitHub security-advisory form:

<https://github.com/Lee-Seungwon1215/WISA_proj/security/advisories/new>

Include the affected commit/version, platform, minimal reproducer, expected
behavior, and impact. If the advisory form is unavailable, contact the
repository owner through the account listed on the repository without posting
the reproducer publicly.

## Untrusted configuration warning

CT-KAT configs can select source files, compilers, binaries, and build/KAT
programs. Prefer `argv` and set:

```yaml
execution_profile: untrusted
```

The untrusted profile rejects `build.command` and `kat.command`, including
commands that explicitly opt into a shell. It is a command-execution boundary,
not a complete sandbox: a selected compiler, source file, or executable can
still be malicious. Run external artifacts in a disposable, least-privileged
container or VM.

CT-KAT is a screening tool, not a constant-time proof or a substitute for a
coordinated cryptographic security review.
