#ifndef CTKAT_FNDSA_BOUNDARY_API_H
#define CTKAT_FNDSA_BOUNDARY_API_H

#include <stdint.h>

#include "fndsa.h"

#if CTKAT_FNDSA_LOGN == 9
#define CTKAT_FNDSA_N 512
#define CTKAT_FNDSA_ENCODING_BYTES (FNDSA_SIGNATURE_SIZE(9) - 41)
#elif CTKAT_FNDSA_LOGN == 10
#define CTKAT_FNDSA_N 1024
#define CTKAT_FNDSA_ENCODING_BYTES (FNDSA_SIGNATURE_SIZE(10) - 41)
#else
#error CTKAT_FNDSA_LOGN must be 9 or 10
#endif

void ctkat_fndsa_decode(const uint8_t *secret, uint8_t *decoded);
void ctkat_fndsa_sampler(const uint8_t *secret, uint8_t *sample);
void ctkat_fndsa_encode(const uint8_t *secret, uint8_t *encoded);

#endif
