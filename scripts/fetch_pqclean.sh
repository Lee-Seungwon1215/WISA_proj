#!/usr/bin/env bash
# Fetch ML-KEM-768 (clean reference) + minimal common dependencies from
# PQClean via sparse-checkout. Idempotent: rerun to refresh from upstream.
#
#   ./scripts/fetch_pqclean.sh [destination]
#
# Default destination: examples/pqc_mlkem768/

set -euo pipefail

DEST="${1:-examples/pqc_mlkem768}"
PQCLEAN_REV="${PQCLEAN_REV:-master}"
PQCLEAN_URL="${PQCLEAN_URL:-https://github.com/PQClean/PQClean.git}"

# ML-KEM-768 vs Kyber768: PQClean renamed the scheme directory after FIPS 203.
# Try ml-kem-768 first; fall back to kyber768 if not present.
SCHEME_CANDIDATES=("crypto_kem/ml-kem-768" "crypto_kem/kyber768")

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> cloning PQClean (sparse, blob:none) into $WORK/pqclean"
git clone --depth 1 --filter=blob:none --sparse --branch "$PQCLEAN_REV" \
    "$PQCLEAN_URL" "$WORK/pqclean" >/dev/null

cd "$WORK/pqclean"
# Pull every candidate scheme dir + common; later we pick whichever exists.
git sparse-checkout set "${SCHEME_CANDIDATES[@]}" common >/dev/null

SCHEME_DIR=""
for cand in "${SCHEME_CANDIDATES[@]}"; do
    if [ -d "$cand/clean" ]; then
        SCHEME_DIR="$cand/clean"
        break
    fi
done
if [ -z "$SCHEME_DIR" ]; then
    echo "ERROR: could not locate ml-kem-768/clean or kyber768/clean in PQClean" >&2
    echo "Looked for: ${SCHEME_CANDIDATES[*]}" >&2
    exit 1
fi

cd - >/dev/null

# We need a randombytes implementation. PQClean stores test/build glue
# separately, so we'll write a minimal one ourselves if the upstream
# `common/` doesn't ship one usable directly.
mkdir -p "$DEST/clean" "$DEST/common"

echo "==> copying $SCHEME_DIR -> $DEST/clean/"
cp -f "$WORK/pqclean/$SCHEME_DIR"/* "$DEST/clean/"

echo "==> copying common/ (whole directory — schemes depend on compat.h, sha2, etc.)"
cp -rf "$WORK/pqclean/common/." "$DEST/common/"

# randombytes: PQClean's common/ may or may not ship one. If not, drop a
# minimal Linux getrandom-based shim.
if [ -f "$WORK/pqclean/common/randombytes.c" ]; then
    cp -f "$WORK/pqclean/common/randombytes.c" "$DEST/common/randombytes.c"
    cp -f "$WORK/pqclean/common/randombytes.h" "$DEST/common/randombytes.h"
    echo "   (used upstream randombytes.c)"
else
    cat > "$DEST/common/randombytes.h" <<'EOF'
#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H
#include <stddef.h>
#include <stdint.h>
int randombytes(uint8_t *out, size_t outlen);
#endif
EOF
    cat > "$DEST/common/randombytes.c" <<'EOF'
/* Minimal randombytes shim using Linux getrandom(2). */
#include "randombytes.h"
#include <errno.h>
#include <stddef.h>
#include <sys/random.h>

int randombytes(uint8_t *out, size_t outlen) {
    size_t off = 0;
    while (off < outlen) {
        ssize_t n = getrandom(out + off, outlen - off, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}
EOF
    echo "   (wrote minimal getrandom-based randombytes shim)"
fi

# Provenance — record what we pulled.
{
    echo "# Source"
    echo "Fetched from: $PQCLEAN_URL @ $PQCLEAN_REV"
    echo "Scheme dir : $SCHEME_DIR"
    echo "Fetched at : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""
    echo "# Files"
    find "$DEST/clean" "$DEST/common" -maxdepth 2 -type f | sort
} > "$DEST/FETCH_INFO.md"

echo
echo "==> done: $DEST"
ls "$DEST/clean"
echo "---"
ls "$DEST/common"
