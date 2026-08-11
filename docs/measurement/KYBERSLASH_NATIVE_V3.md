# KyberSlash native timing v3

V3 supersedes the six direct-operand measurements in v2. It does not rewrite
or reinterpret the v2 engineering artifacts. Those traces used class-specific
heap source addresses and an invalid setup-placebo coefficient (`45124` in the
frozen engineering corpus), so the placebo returned before the intended
arithmetic site. Their target statistics are setup-confounded and
non-promotable.

The four full-ML-KEM `kem_dec_chosen_ct` axes keep the v2 fixed-key public-input
contract. The six direct canaries now add all of the following:

1. both low/high public coefficients are computed for one common pool index;
2. an arithmetic mask selects the coefficient without a class-specific source
   pointer;
3. both classes write the same `ct_work` address and use the same `sk_fixed`
   address;
4. the placebo writes coefficient `1664` through that address and reaches a
   valid decapsulation/site path;
5. all 128 bin members, setup calls, and warm-up calls must return success
   before timing, while any measured failure aborts the process;
6. the linked binary must contain the expected vulnerable/patched division
   count and `CTKAT_KS_crypto_kem_dec` must call
   `ctkat_kyberslash_site_operation`;
7. the universal build seal binds source, binary, config, linked inputs,
   compiler, flags, and replay argv before the first sample and around every
   measured subprocess.

The frozen execution manifest is `docs/measurement/kyberslash_native_v3.yaml`.
It retains the v2 sample counts, coefficient bins, positive-control effects,
thresholds, and evidence boundary: this is a public operand-dependent latency
canary, not a full attack or key-recovery reproduction. Final evidence still
requires two reviewed physical x86_64 Linux hosts. Cortex-M evaluation is a
separate future campaign with its own board/clock/transport preregistration.
