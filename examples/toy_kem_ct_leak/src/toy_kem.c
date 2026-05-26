#include "toy_kem.h"

#include <string.h>

/* `volatile` sink: prevents the compiler from optimizing the loop in
 * LEAKY_/SAFE_*_dec away at -O2. Required for the timing difference (or
 * lack thereof) to actually show up in measurements. */
static volatile int ctkat_sink;

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

/* LEAKY dec — runtime depends on ct[0]. Class-0 sees a fixed ct[0]; class-1
 * sees uniformly varying ct[0]. Roughly half of class-1 hits the slow path;
 * class-0 always sits on one side. The mean shifts → dudect picks it up. */
int LEAKY_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    int x = 1;
    if (ct[0] >= 0x80) {
        for (int i = 0; i < 10000; i++) {
            x = x * 17 + 3;
        }
    }
    ctkat_sink = x;
    for (size_t i = 0; i < 32; i++) {
        ss[i] = ct[i] ^ sk[i];
    }
    return 0;
}

/* SAFE dec — same loop count regardless of ct content. Stirs ct[0] into
 * the result without branching on it, so the optimizer can't shortcut. */
int SAFE_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    int x = 1;
    for (int i = 0; i < 10000; i++) {
        x = x * 17 + 3 + ct[0];
    }
    ctkat_sink = x;
    for (size_t i = 0; i < 32; i++) {
        ss[i] = ct[i] ^ sk[i];
    }
    return 0;
}

int LEAKY_crypto_kem_keypair(uint8_t *pk, uint8_t *sk) { return trivial_keypair(pk, sk); }
int LEAKY_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) { return trivial_enc(ct, ss, pk); }

int SAFE_crypto_kem_keypair(uint8_t *pk, uint8_t *sk) { return trivial_keypair(pk, sk); }
int SAFE_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) { return trivial_enc(ct, ss, pk); }
