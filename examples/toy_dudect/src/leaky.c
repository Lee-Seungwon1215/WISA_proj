#include "leaky.h"

/* `volatile` sink so the compiler can't optimize the inner loops away even
 * at -O2. We want the timing difference to be visible to dudect. */
volatile int ctkat_sink;

/*
 * leaky_function: execution time depends on `secret[0]` —
 *   high byte (>= 0x80) takes the long path,
 *   low byte (< 0x80)  takes the short path.
 * dudect should flag a large |t| when class 0 (fixed secret) vs class 1
 * (random secret, average ≈ 50/50 long/short) are compared.
 */
int leaky_function(const uint8_t *secret, size_t len) {
    (void)len;
    int x = 1;
    if (secret[0] >= 0x80) {
        for (int i = 0; i < 10000; i++) {
            x = x * 17 + 3;
        }
    }
    ctkat_sink = x;
    return secret[0] >= 0x80;
}

/*
 * safe_function: always runs the same loop count and the secret is mixed
 * into the result without any data-dependent branch. dudect should report
 * a small |t|.
 */
int safe_function(const uint8_t *secret, size_t len) {
    (void)len;
    int x = 1;
    for (int i = 0; i < 10000; i++) {
        x = x * 17 + 3 + secret[0];
    }
    ctkat_sink = x;
    return x & 1;
}
