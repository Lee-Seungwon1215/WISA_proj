# OpenSSL 3.5 PQ integration provenance

- Source: `https://github.com/openssl/openssl`
- Release: `openssl-3.5.7` (tagged 2026-06-09)
- Revision: `8cf17aaeb4599f8af87fefd810b5b5fee90fe69e`
- Release artifact:
  `https://github.com/openssl/openssl/releases/download/openssl-3.5.7/openssl-3.5.7.tar.gz`
- Artifact SHA-256:
  `a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8`
- Local source snapshot: none; CI downloads and verifies the exact release
  artifact before building it.
- Local adapter: `examples/openssl_pqc/openssl_pqc_smoke.c`

This is a production-API integration case. It deliberately does **not** add
one to CT-KAT's primary-upstream-lineage count: a wrapper/API surface is not a
new implementation merely because the caller changed.
