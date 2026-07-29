#ifndef CTKAT_RELEASE_SMOKE_SAFE_COMPARE_H
#define CTKAT_RELEASE_SMOKE_SAFE_COMPARE_H

#include <stddef.h>
#include <stdint.h>

int safe_compare(const uint8_t *secret, const uint8_t *guess, size_t length);

#endif
