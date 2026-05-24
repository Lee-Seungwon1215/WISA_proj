#ifndef CTKAT_TOY_COMPARE_H
#define CTKAT_TOY_COMPARE_H

#include <stddef.h>
#include <stdint.h>

int bad_compare(const uint8_t *secret, const uint8_t *guess, size_t len);
int safe_compare(const uint8_t *secret, const uint8_t *guess, size_t len);

#endif
