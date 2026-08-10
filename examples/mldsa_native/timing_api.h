#ifndef CTKAT_MLDSA_TIMING_API_H
#define CTKAT_MLDSA_TIMING_API_H

#include <stddef.h>
#include <stdint.h>

#include "mldsa_native.h"

#define CTKAT_MLDSA_CRYPTO_SECRETKEYBYTES CRYPTO_SECRETKEYBYTES
#define CTKAT_MLDSA_CRYPTO_PUBLICKEYBYTES CRYPTO_PUBLICKEYBYTES
#define CTKAT_MLDSA_CRYPTO_BYTES CRYPTO_BYTES

int CTKAT_MLDSA_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int CTKAT_MLDSA_crypto_sign_signature(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *sk);
int CTKAT_MLDSA_crypto_sign_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *pk);

#endif
