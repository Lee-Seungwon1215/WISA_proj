#include "toy_kem.h"

#include <string.h>

/* `volatile` sink: prevents the compiler from optimizing the loop in
 * LEAKY_/SAFE_*_dec away at -O2. Required for the timing difference (or
 * lack thereof) to actually show up in measurements. */
static volatile uint32_t ctkat_sink;

/* Internal counter that makes successive enc() calls return distinct
 * ciphertexts. enc() is called once at setup (fixed ct) and then again
 * per class-1 iteration in the ct-leak harness; we need the latter to
 * actually vary so the leak signal is exercised. */
static uint32_t _enc_counter;

static int trivial_keypair(uint8_t *pk, uint8_t *sk) {
    /* Deterministic — the dudect harness only cares that pk/sk are valid
     * buffers, not their cryptographic strength. */
    for (size_t i = 0; i < 32; i++) {
        sk[i] = (uint8_t)i;
    }
    memcpy(pk, sk, 32);
    return 0;
}

static int trivial_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    /* Knuth multiplicative hash on the counter spreads the output across
     * the byte range so ct[0] hits both halves (<0x80 and >=0x80) with
     * roughly equal frequency in class 1. */
    _enc_counter += 1;
    uint32_t s = _enc_counter * 2654435761u;
    for (size_t i = 0; i < 32; i++) {
        ct[i] = pk[i] ^ (uint8_t)(s >> ((i & 3) * 8));
        s = s * 1103515245u + 12345u;
    }
    for (size_t i = 0; i < 32; i++) {
        ss[i] = (uint8_t)i;
    }
    return 0;
}

/* Both controls are instantiated from the exact same source shape.  The sole
 * compile-time toggle enables all input-dependent work, including the seeded
 * ct[0] branch.  The disabled form is a true input-independent negative
 * control: it neither branches on nor computes over the class-varying bytes.
 * A volatile local makes every slow-path iteration observable without relying
 * on signed overflow or on the optimizer preserving dead arithmetic. */
#define CTKAT_DEFINE_DEC(NAME, ENABLE_LEAK)                                      \
    int NAME(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {                \
        volatile uint32_t x = UINT32_C(1);                                       \
        if ((ENABLE_LEAK) && ct[0] >= UINT8_C(0x80)) {                           \
            for (uint32_t i = 0; i < UINT32_C(10000); i++) {                     \
                x = x * UINT32_C(17) + UINT32_C(3);                              \
            }                                                                    \
        }                                                                        \
        ctkat_sink = x;                                                          \
        for (size_t i = 0; i < 32; i++) {                                        \
            ss[i] = (ENABLE_LEAK) ? (uint8_t)(ct[i] ^ sk[i]) : (uint8_t)i;       \
        }                                                                        \
        return 0;                                                                \
    }

CTKAT_DEFINE_DEC(LEAKY_crypto_kem_dec, 1)
CTKAT_DEFINE_DEC(SAFE_crypto_kem_dec, 0)

int LEAKY_crypto_kem_keypair(uint8_t *pk, uint8_t *sk) { return trivial_keypair(pk, sk); }
int LEAKY_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) { return trivial_enc(ct, ss, pk); }

int SAFE_crypto_kem_keypair(uint8_t *pk, uint8_t *sk) { return trivial_keypair(pk, sk); }
int SAFE_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) { return trivial_enc(ct, ss, pk); }
