#ifndef CTKAT_FIXTURE_SIGN_H
#define CTKAT_FIXTURE_SIGN_H

#include <stddef.h>
#include <stdint.h>

#define CRYPTO_PUBLICKEYBYTES 1312
#define CRYPTO_SECRETKEYBYTES 2528
#define CRYPTO_BYTES          2420

int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

int crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *msg, size_t msglen,
    const uint8_t *sk
);

int crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *msg, size_t msglen,
    const uint8_t *pk
);

#endif
