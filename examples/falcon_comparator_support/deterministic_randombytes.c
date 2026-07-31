/*
 * Deterministic randombytes interposer for Falcon structural/KAT probes.
 *
 * This is deliberately NOT a cryptographic RNG and MUST NOT be used in
 * production or physical-timing claims. Each harness is a fresh process, so
 * this fixed initial state makes key generation and signing reproducible.
 */

#include <stddef.h>
#include <stdint.h>

static uint64_t ctkat_falcon_prng = UINT64_C(0x46414c434f4e5631);

int
PQCLEAN_randombytes(uint8_t *output, size_t length)
{
    for (size_t i = 0; i < length; i++) {
        uint64_t value = ctkat_falcon_prng;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        ctkat_falcon_prng = value;
        output[i] = (uint8_t)(value >> 56);
    }
    return 0;
}
