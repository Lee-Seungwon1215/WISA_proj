# PQClean Falcon-1024 reference target

This target is the degree-1024 peer of `../pqc_falcon512`. The imported tree is
byte-identical to PQClean commit
`202a8f96315f9ed219387a50f7e40d04af037ea8` and is explicitly classified as a
Falcon **reference-family** implementation, not as prospective FN-DSA or a
constant-time implementation.

The full signing harness taints encoded `f`, `g`, and `F` while excluding the
public header byte. `ctkat_split.yaml` isolates their 640/640/1024-byte encoded
regions. Structural runs use the same explicitly non-cryptographic,
deterministic randombytes interposer as the degree-512 peer. Physical timing is
intentionally absent until the frozen native
campaign can be run on a bare-metal Linux host.

See `../../docs/ground_truth/falcon/README.md` for the paired comparison and
evidence limits.
