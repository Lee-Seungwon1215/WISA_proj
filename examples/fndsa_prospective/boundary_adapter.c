/*
 * Narrow source-boundary probes for the pinned c-fn-dsa implementation.
 * Local glue only: these functions are not part of the upstream API.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "boundary_api.h"
#include "sign_inner.h"

void
ctkat_fndsa_decode(const uint8_t *secret, uint8_t *decoded)
{
    int8_t coefficients[CTKAT_FNDSA_N];
    int8_t round_trip[CTKAT_FNDSA_N];
    uint8_t encoded[CTKAT_FNDSA_N];
#if CTKAT_FNDSA_LOGN == 9
    const unsigned nbits = 6;
#else
    const unsigned nbits = 5;
#endif

    /* Keep every coefficient well inside the valid range, then encode it.
       The decoder therefore receives a valid but secret-derived encoding. */
    for (size_t i = 0; i < CTKAT_FNDSA_N; i++) {
        coefficients[i] = (int8_t)((secret[i] & 15u) - 7);
    }
    size_t encoded_len = trim_i8_encode(
        CTKAT_FNDSA_LOGN, coefficients, nbits, encoded);
    size_t decoded_len = trim_i8_decode(
        CTKAT_FNDSA_LOGN, encoded, round_trip, nbits);
    if (decoded_len == encoded_len) {
        memcpy(decoded, round_trip, sizeof round_trip);
    } else {
        memset(decoded, 0, sizeof round_trip);
    }
}

void
ctkat_fndsa_sampler(const uint8_t *secret, uint8_t *sample)
{
    static const uint8_t seed[40] = {
        0x43, 0x54, 0x4b, 0x41, 0x54, 0x2d, 0x53, 0x41,
        0x4d, 0x50, 0x4c, 0x45, 0x52, 0x2d, 0x56, 0x31,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    };
    sampler_state state;
    state.logn = CTKAT_FNDSA_LOGN;
    shake_init(&state.pc, 256);
    shake_inject(&state.pc, seed, sizeof seed);
    shake_flip(&state.pc);

    int32_t centre = (int32_t)(secret[0] & 15u) - 7;
    fpr mu = fpr_of32(centre);
#if CTKAT_FNDSA_LOGN == 9
    fpr isigma = FPR(6956347512113097, -60);
#else
    fpr isigma = FPR(6846791885593314, -60);
#endif
    int32_t value = sampler_next(&state, mu, isigma);
    memcpy(sample, &value, sizeof value);
}

void
ctkat_fndsa_encode(const uint8_t *secret, uint8_t *encoded)
{
    int16_t coefficients[CTKAT_FNDSA_N];
    for (size_t i = 0; i < CTKAT_FNDSA_N; i++) {
        coefficients[i] = (int16_t)((secret[i] & 63u) - 31);
    }
    (void)comp_encode(
        CTKAT_FNDSA_LOGN,
        coefficients,
        encoded,
        CTKAT_FNDSA_ENCODING_BYTES);
}
