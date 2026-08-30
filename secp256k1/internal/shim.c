// Implementation of the shim declared in shim.h.
//
// This file sees only the public libsecp256k1 headers, never the vendored
// sources — those are compiled separately by libsecp256k1.c. Keeping them apart
// means the compiler rejects any accidental use of an internal upstream
// function, and keeps libsecp256k1's internal macros out of this translation
// unit.

#include <string.h>

#include "shim.h"

/* ---------------------------------------------------------------- context */

secp256k1_context *shim_context_create(const unsigned char *seed32) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (ctx == NULL) {
        return NULL;
    }

    // Randomization blinds the scalar multiplications against side-channel
    // attacks. It is optional upstream, so a NULL seed is a valid request to
    // skip it rather than an error.
    if (seed32 != NULL && secp256k1_context_randomize(ctx, seed32) != 1) {
        secp256k1_context_destroy(ctx);
        return NULL;
    }

    return ctx;
}

void shim_context_destroy(secp256k1_context *ctx) {
    if (ctx != NULL) {
        secp256k1_context_destroy(ctx);
    }
}

void shim_selftest(void) {
    secp256k1_selftest();
}

/* ------------------------------------------------------------------- keys */

int shim_seckey_verify(
    const secp256k1_context *ctx,
    const unsigned char seckey32[SHIM_SECKEY_LEN]
) {
    return secp256k1_ec_seckey_verify(ctx, seckey32);
}