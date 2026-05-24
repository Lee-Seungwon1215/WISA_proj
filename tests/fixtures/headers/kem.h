#ifndef CTKAT_FIXTURE_KEM_H
#define CTKAT_FIXTURE_KEM_H

#include <stddef.h>
#include <stdint.h>

#define CRYPTO_PUBLICKEYBYTES  1184
#define CRYPTO_SECRETKEYBYTES  2400
#define CRYPTO_CIPHERTEXTBYTES 1088
#define CRYPTO_BYTES           32

#if defined(__cplusplus)
extern "C" {
#endif

/* Multi-line declaration to exercise flattening. */
int crypto_kem_keypair(
    uint8_t *pk,
    uint8_t *sk
);

int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* PQClean-style namespaced wrapper — the inferrer should still recognize it
 * via suffix matching. */
int PQCLEAN_TOY_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#if defined(__cplusplus)
}
#endif

#endif
