#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <valgrind/memcheck.h>

#include "api.h"
#include "inner.h"

#define LOGN 9
#define N 512
#define NONCELEN 40
#define FALCON_EXPANDED_KEY_FPRS ((LOGN + 5) * N)

static int prepare_key(fpr expanded_key[FALCON_EXPANDED_KEY_FPRS]) {
    uint8_t pk[PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES];
    int8_t f[N], g[N], F[N], G[N];
    union {
        uint8_t b[72 * N];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    size_t u = 1;
    size_t v;

    if (PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk) != 0) {
        return -1;
    }
    if (sk[0] != 0x50 + LOGN) {
        return -1;
    }
    v = PQCLEAN_FALCON512_CLEAN_trim_i8_decode(
        f, LOGN, PQCLEAN_FALCON512_CLEAN_max_fg_bits[LOGN],
        sk + u, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON512_CLEAN_trim_i8_decode(
        g, LOGN, PQCLEAN_FALCON512_CLEAN_max_fg_bits[LOGN],
        sk + u, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON512_CLEAN_trim_i8_decode(
        F, LOGN, PQCLEAN_FALCON512_CLEAN_max_FG_bits[LOGN],
        sk + u, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0) {
        return -1;
    }
    u += v;
    if (u != PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES) {
        return -1;
    }
    if (!PQCLEAN_FALCON512_CLEAN_complete_private(G, f, g, F, LOGN, tmp.b)) {
        return -1;
    }
    PQCLEAN_FALCON512_CLEAN_expand_privkey(expanded_key, f, g, F, G, LOGN, tmp.b);
    return 0;
}

static void prepare_hm(uint16_t hm[N]) {
    static const uint8_t msg[64] = {0};
    static const uint8_t nonce[NONCELEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
    };
    union {
        uint8_t b[2 * N];
        uint64_t dummy_u64;
    } tmp;
    inner_shake256_context sc;

    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, nonce, sizeof(nonce));
    inner_shake256_inject(&sc, msg, sizeof(msg));
    inner_shake256_flip(&sc);
    PQCLEAN_FALCON512_CLEAN_hash_to_point_ct(&sc, hm, LOGN, tmp.b);
    inner_shake256_ctx_release(&sc);
}

int main(void) {
    puts("CTKAT-HARNESS-RAN: sign_core_tree");

    fpr expanded_key[FALCON_EXPANDED_KEY_FPRS];
    uint16_t hm[N];
    int16_t sig[N];
    union {
        uint8_t b[48 * N];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    unsigned char seed[48] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
    };
    inner_shake256_context rng;

    if (prepare_key(expanded_key) != 0) {
        return 2;
    }
    prepare_hm(hm);
    inner_shake256_init(&rng);
    inner_shake256_inject(&rng, seed, sizeof(seed));
    inner_shake256_flip(&rng);

    VALGRIND_MAKE_MEM_UNDEFINED(expanded_key, sizeof(expanded_key));

    PQCLEAN_FALCON512_CLEAN_sign_tree(sig, &rng, expanded_key, hm, LOGN, tmp.b);

    VALGRIND_MAKE_MEM_DEFINED(expanded_key, sizeof(expanded_key));
    VALGRIND_MAKE_MEM_DEFINED(sig, sizeof(sig));
    inner_shake256_ctx_release(&rng);

    volatile int16_t sink = 0;
    for (size_t i = 0; i < N; i++) {
        sink ^= sig[i];
    }
    (void)sink;
    return 0;
}
