#include "flip.h"

/*
 * Secret-dependent BRANCH. `if (secret[i] & 1)` is a conditional jump on a
 * tainted value:
 *   -O0  -> real conditional jump kept       -> Valgrind FAIL
 *   -O2  -> lowered to branch-free code       -> Valgrind PASS
 *   -Os  -> lowered to branch-free code       -> Valgrind PASS
 * The data-dependent control flow is STILL in the source at every level; only
 * the structural CT check (Valgrind/Memcheck) stops being able to see it once
 * the optimizer removes the branch. The exact level at which it flips depends
 * on your compiler/version — that build-sensitivity is exactly what ct-matrix
 * is here to expose (measured on the project's Docker amd64 gcc 13.3).
 */
void leaky_select(const uint8_t *secret, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        uint8_t r;
        if (secret[i] & 1)
            r = 0x11;
        else
            r = 0x22;
        out[i] = r;
    }
}

/*
 * Branch-free select: `bit ? 0x11 : 0x22` written as arithmetic, so there is no
 * secret-dependent conditional jump to begin with. Constant-time at every
 * optimization level -> Valgrind PASS in every combo. (0x11 ^ 0x22 == 0x33.)
 */
void safe_select(const uint8_t *secret, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        uint8_t bit = (uint8_t)(secret[i] & 1u);
        out[i] = (uint8_t)(0x22u ^ (bit * 0x33u));
    }
}
