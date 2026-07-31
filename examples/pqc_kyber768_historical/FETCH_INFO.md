# `pq-crystals/kyber` historical reference provenance

- Upstream: `https://github.com/pq-crystals/kyber`
- Immutable revision: `a621b8dde405cc507cbcfc5f794570a4f98d69cc`
- Upstream path: `ref`
- Snapshot date: 2026-07-31
- Local path: `examples/pqc_kyber768_historical/ref`
- License: public domain/CC0 or Apache-2.0; see
  `examples/pqc_kyber768_historical/LICENSE` and per-file notices
- CT-KAT tree SHA-256:
  `3ca097d98e2a48fdd463740cfa0484cbc339bcd1f1f5f2ca0157762a0317ae4d`
- Local modifications inside `ref/`: none; the tree is byte-identical to the
  recorded upstream commit.

Security-relevant file hashes:

- `ref/poly.c`:
  `f23c985b837e406b273d2770ce614692db6d7bac08d1c1d506c26bc00956c49a`
- `ref/polyvec.c`:
  `3e0417f21fc27232a7f158def28f7165b26551ca077229298253f09f996acaba`

Commit chronology verified against the upstream Git history:

- `a621b8d…`: both KS1 and KS2 expressions present
- `dda29cc63af721981ee2c831cf00822e69be3220`: `poly_tomsg` KS1 fix
- `272125f6acc8e8b6850fd68ceb901a660ff48196`: compression KS2 fixes

Files outside `ref/` (`ctkat.yaml`, `ctkat_api.h`, documentation) are CT-KAT
adapters and are not part of the upstream snapshot.
