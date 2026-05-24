#ifndef CTKAT_TOY_DUDECT_LEAKY_H
#define CTKAT_TOY_DUDECT_LEAKY_H

#include <stddef.h>
#include <stdint.h>

int leaky_function(const uint8_t *secret, size_t len);
int safe_function(const uint8_t *secret, size_t len);

#endif
