# PQClean Falcon-512 reference source provenance

- Source: `https://github.com/PQClean/PQClean`
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Upstream path: `crypto_sign/falcon-512/clean`
- Local path: `examples/pqc_falcon512/clean`
- License: MIT with the upstream patent notice; see
  `examples/pqc_falcon512/clean/LICENSE`
- Tree SHA-256: `151dc842c4c9a0aa74b692f475380f675c3f968febe2399f2f9e5e7b70e2fd6d`
- Local modifications: none; verified byte-identical to the recorded revision.
- Originally fetched: `2026-06-10`

This example is a Falcon reference-family target. It is a `needs-analysis`
boundary target, not prospective FN-DSA and not a constant-time implementation
claim.
Common SHAKE/randombytes dependencies are reused from the separately
inventoried `../pqc_mlkem768/common`.
