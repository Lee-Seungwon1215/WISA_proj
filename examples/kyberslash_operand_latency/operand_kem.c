/* Direct KyberSlash operand-latency canary API.
 *
 * This is intentionally not ML-KEM.  It gives timing-harness-v2 a KEM-shaped
 * boundary so the exact same A/A, placebo, positive-control, affinity, and
 * official-dudect machinery can measure one frozen arithmetic site.  Full-KEM
 * attribution remains a separate experiment.
 */

#include "api.h"

#include <stddef.h>
#include <stdint.h>

int randombytes(uint8_t *output, size_t length);
uint32_t ctkat_kyberslash_site_operation(uint16_t coefficient);

int CTKAT_KS_crypto_kem_keypair(uint8_t *pk, uint8_t *sk) {
    if (randombytes(pk, CTKAT_KS_CRYPTO_PUBLICKEYBYTES) != 0 ||
        randombytes(sk, CTKAT_KS_CRYPTO_SECRETKEYBYTES) != 0) {
        return -1;
    }
    return 0;
}

int CTKAT_KS_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    if (randombytes(ct, CTKAT_KS_CRYPTO_CIPHERTEXTBYTES) != 0) {
        return -1;
    }
    for (size_t i = 0; i < CTKAT_KS_CRYPTO_BYTES; i++) {
        ss[i] = (uint8_t)(pk[i] ^ ct[i % CTKAT_KS_CRYPTO_CIPHERTEXTBYTES]);
    }
    return 0;
}

int CTKAT_KS_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    uint16_t coefficient = (uint16_t)ct[0] | ((uint16_t)ct[1] << 8);
    if (coefficient >= 3329U) {
        return -1;
    }
    uint32_t value = ctkat_kyberslash_site_operation(coefficient);
    for (size_t i = 0; i < CTKAT_KS_CRYPTO_BYTES; i++) {
        ss[i] = (uint8_t)((value >> ((i & 3U) * 8U)) ^ sk[i]);
    }
    return 0;
}
