# ML-KEM-768 KyberSlash2-only target

This target swaps `poly_compress` and `polyvec_compress` for reconstructed
KyberSlash2 overlays while keeping the KyberSlash1 `poly_tomsg` fix.

Expected layers:

- deterministic KEM transcript: byte-identical to stock
- ordinary Memcheck branch/address check: `PASS`
- assembly candidates: `poly_compress` and `polyvec_compress`, apart from
  separately triaged public library arithmetic
- patched-Valgrind TIMECOP attribution: both compression functions
- physical timing/attack reproduction: not claimed by this target

The authoritative site and provenance contract lives in
`docs/ground_truth/kyberslash/ground_truth.yaml`.
