#ifndef CTKAT_TOY_LOOKUP_H
#define CTKAT_TOY_LOOKUP_H

#include <stddef.h>
#include <stdint.h>

/* T-table-style: out[i] = sbox[secret[i]] — address depends on secret. */
void leaky_lookup(const uint8_t *secret, uint8_t *out, size_t n);

/* Constant address: index is the loop counter, not the secret. */
void safe_lookup(const uint8_t *secret, uint8_t *out, size_t n);

#endif
