#include <stdint.h>

static volatile uint32_t ctkat_kyberslash_divisor = 3329U;

__attribute__((noinline, used))
uint32_t ctkat_kyberslash_site_operation(uint16_t coefficient) {
    uint32_t numerator = ((uint32_t)coefficient << 4) + 1664U;
    return (numerator / ctkat_kyberslash_divisor) & 15U;
}
