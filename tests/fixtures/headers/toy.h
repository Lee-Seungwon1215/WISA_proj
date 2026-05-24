#ifndef CTKAT_FIXTURE_TOY_H
#define CTKAT_FIXTURE_TOY_H

#include <stddef.h>
#include <stdint.h>

/*
 * Toy comparison functions used by Phase 0 — the inferrer should mark
 * `secret` as secret (name match), `guess` as unknown (no keyword match),
 * and `len` as scalar.
 */
int bad_compare(const uint8_t *secret, const uint8_t *guess, size_t len);
int safe_compare(const uint8_t *secret, const uint8_t *guess, size_t len);

#endif
