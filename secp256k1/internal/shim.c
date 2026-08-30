// Implementation of the shim declared in shim.h.
//
// This file sees only the public libsecp256k1 headers, never the vendored
// sources — those are compiled separately by libsecp256k1.c. Keeping them apart
// means the compiler rejects any accidental use of an internal upstream
// function, and keeps libsecp256k1's internal macros out of this translation
// unit.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shim.h"

/* ---------------------------------------------------------------- context */

// libsecp256k1's ARG_CHECK macro — used throughout the library to reject
// caller misuse, including entirely recoverable cases like signing with an
// already-consumed MuSig secnonce — is documented as returning 0, but that is
// only true once its illegal_callback has run. The library's own default
// callback logs the message and then calls abort(), which never lets that
// return 0 execute: it kills the calling process outright over what the API
// itself calls a normal, checkable failure.
//
// A library has no business doing that to its caller. This callback keeps
// the same stderr diagnostic for visibility during development, but drops
// the abort so every ARG_CHECK-guarded function actually reaches its
// documented `return 0` instead.
static void shim_illegal_callback(const char *message, void *data) {
    (void)data;
    fprintf(stderr, "[secp256k1 shim] rejected illegal argument: %s\n", message);
}

secp256k1_context *shim_context_create(const unsigned char *seed32) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (ctx == NULL) {
        return NULL;
    }

    secp256k1_context_set_illegal_callback(ctx, shim_illegal_callback, NULL);

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

int shim_pubkey_create(
    const secp256k1_context *ctx,
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    unsigned char *output,
    size_t *output_len,
    int compressed
) {
    secp256k1_pubkey pubkey;
    unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey32)) {
        return 0;
    }

    return secp256k1_ec_pubkey_serialize(ctx, output, output_len, &pubkey, flags);
}

int shim_pubkey_parse(
    const secp256k1_context *ctx,
    const unsigned char *pubkey,
    size_t pubkey_len,
    unsigned char *output,
    size_t *output_len,
    int compressed
) {
    secp256k1_pubkey parsed;
    unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    if (!secp256k1_ec_pubkey_parse(ctx, &parsed, pubkey, pubkey_len)) {
        return 0;
    }

    return secp256k1_ec_pubkey_serialize(ctx, output, output_len, &parsed, flags);
}

int shim_seckey_negate(
    const secp256k1_context *ctx,
    unsigned char seckey32[SHIM_SECKEY_LEN]
) {
    return secp256k1_ec_seckey_negate(ctx, seckey32);
}

int shim_pubkey_negate(
    const secp256k1_context *ctx,
    const unsigned char *pubkey,
    size_t pubkey_len,
    unsigned char *output,
    size_t *output_len,
    int compressed
) {
    secp256k1_pubkey parsed;
    unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    if (!secp256k1_ec_pubkey_parse(ctx, &parsed, pubkey, pubkey_len)) {
        return 0;
    }
    if (!secp256k1_ec_pubkey_negate(ctx, &parsed)) {
        return 0;
    }

    return secp256k1_ec_pubkey_serialize(ctx, output, output_len, &parsed, flags);
}

int shim_pubkey_combine(
    const secp256k1_context *ctx,
    const unsigned char *pubkeys,
    size_t pubkey_count,
    unsigned char *output,
    size_t *output_len,
    int compressed
) {
    secp256k1_pubkey parsed[SHIM_MAX_COMBINE_PUBKEYS];
    const secp256k1_pubkey *ins[SHIM_MAX_COMBINE_PUBKEYS];
    secp256k1_pubkey combined;
    unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
    size_t i;

    if (pubkey_count == 0 || pubkey_count > SHIM_MAX_COMBINE_PUBKEYS) {
        return 0;
    }

    for (i = 0; i < pubkey_count; i++) {
        const unsigned char *key = pubkeys + (i * SHIM_PUBKEY_COMPRESSED_LEN);
        if (!secp256k1_ec_pubkey_parse(ctx, &parsed[i], key, SHIM_PUBKEY_COMPRESSED_LEN)) {
            return 0;
        }
        ins[i] = &parsed[i];
    }

    if (!secp256k1_ec_pubkey_combine(ctx, &combined, ins, pubkey_count)) {
        return 0;
    }

    return secp256k1_ec_pubkey_serialize(ctx, output, output_len, &combined, flags);
}

int shim_pubkey_cmp(
    const secp256k1_context *ctx,
    const unsigned char *pubkey_a,
    size_t pubkey_a_len,
    const unsigned char *pubkey_b,
    size_t pubkey_b_len,
    int *result
) {
    secp256k1_pubkey a, b;

    if (!secp256k1_ec_pubkey_parse(ctx, &a, pubkey_a, pubkey_a_len)) {
        return 0;
    }
    if (!secp256k1_ec_pubkey_parse(ctx, &b, pubkey_b, pubkey_b_len)) {
        return 0;
    }

    *result = secp256k1_ec_pubkey_cmp(ctx, &a, &b);
    return 1;
}

int shim_pubkey_sort(
    const secp256k1_context *ctx,
    unsigned char *pubkeys,
    size_t pubkey_count
) {
    secp256k1_pubkey parsed[SHIM_MAX_COMBINE_PUBKEYS];
    secp256k1_pubkey *ptrs[SHIM_MAX_COMBINE_PUBKEYS];
    size_t i;

    if (pubkey_count == 0 || pubkey_count > SHIM_MAX_COMBINE_PUBKEYS) {
        return 0;
    }

    for (i = 0; i < pubkey_count; i++) {
        unsigned char *key = pubkeys + (i * SHIM_PUBKEY_COMPRESSED_LEN);
        if (!secp256k1_ec_pubkey_parse(ctx, &parsed[i], key, SHIM_PUBKEY_COMPRESSED_LEN)) {
            return 0;
        }
        ptrs[i] = &parsed[i];
    }

    if (!secp256k1_ec_pubkey_sort(ctx, (const secp256k1_pubkey **)ptrs, pubkey_count)) {
        return 0;
    }

    for (i = 0; i < pubkey_count; i++) {
        unsigned char *key = pubkeys + (i * SHIM_PUBKEY_COMPRESSED_LEN);
        size_t len = SHIM_PUBKEY_COMPRESSED_LEN;
        if (!secp256k1_ec_pubkey_serialize(ctx, key, &len, ptrs[i], SECP256K1_EC_COMPRESSED)) {
            return 0;
        }
    }

    return 1;
}

/* ----------------------------------------------------------------- tweaks */

int shim_seckey_tweak_add(
    const secp256k1_context *ctx,
    unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char tweak32[SHIM_TWEAK_LEN]
) {
    return secp256k1_ec_seckey_tweak_add(ctx, seckey32, tweak32);
}

int shim_seckey_tweak_mul(
    const secp256k1_context *ctx,
    unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char tweak32[SHIM_TWEAK_LEN]
) {
    return secp256k1_ec_seckey_tweak_mul(ctx, seckey32, tweak32);
}

int shim_pubkey_tweak_add(
    const secp256k1_context *ctx,
    const unsigned char *pubkey,
    size_t pubkey_len,
    const unsigned char tweak32[SHIM_TWEAK_LEN],
    unsigned char *output,
    size_t *output_len,
    int compressed
) {
    secp256k1_pubkey parsed;
    unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    if (!secp256k1_ec_pubkey_parse(ctx, &parsed, pubkey, pubkey_len)) {
        return 0;
    }
    if (!secp256k1_ec_pubkey_tweak_add(ctx, &parsed, tweak32)) {
        return 0;
    }

    return secp256k1_ec_pubkey_serialize(ctx, output, output_len, &parsed, flags);
}

int shim_pubkey_tweak_mul(
    const secp256k1_context *ctx,
    const unsigned char *pubkey,
    size_t pubkey_len,
    const unsigned char tweak32[SHIM_TWEAK_LEN],
    unsigned char *output,
    size_t *output_len,
    int compressed
) {
    secp256k1_pubkey parsed;
    unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    if (!secp256k1_ec_pubkey_parse(ctx, &parsed, pubkey, pubkey_len)) {
        return 0;
    }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &parsed, tweak32)) {
        return 0;
    }

    return secp256k1_ec_pubkey_serialize(ctx, output, output_len, &parsed, flags);
}

/* ------------------------------------------------------------------ ECDSA */

int shim_ecdsa_sign_compact(
    const secp256k1_context *ctx,
    const unsigned char msg32[SHIM_MESSAGE_LEN],
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char *aux_rand32,
    unsigned char output64[SHIM_SIGNATURE_COMPACT_LEN]
) {
    secp256k1_ecdsa_signature sig;

    // Passing NULL for noncefp selects the default nonce function, RFC 6979:
    // the nonce is derived deterministically from msg32 and seckey32, never
    // drawn from randomness. A random nonce that ever repeats leaks the secret
    // key outright (see the 2010 PS3 signing key compromise), so a
    // deterministic derivation removes that failure mode entirely. Passing
    // aux_rand32 through as ndata folds it additively into that derivation —
    // it is documented to accept exactly this, 32 bytes of extra entropy for
    // the default nonce function — without reintroducing randomness as a
    // single point of failure the way a random nonce would.
    if (!secp256k1_ecdsa_sign(ctx, &sig, msg32, seckey32, NULL, aux_rand32)) {
        return 0;
    }

    // secp256k1_ecdsa_sign always returns a low-S signature, so there is
    // nothing to normalize here.
    return secp256k1_ecdsa_signature_serialize_compact(ctx, output64, &sig);
}

int shim_ecdsa_verify_compact(
    const secp256k1_context *ctx,
    const unsigned char msg32[SHIM_MESSAGE_LEN],
    const unsigned char *pubkey,
    size_t pubkey_len,
    const unsigned char signature64[SHIM_SIGNATURE_COMPACT_LEN],
    int normalize
) {
    secp256k1_pubkey parsed_pubkey;
    secp256k1_ecdsa_signature sig;

    if (!secp256k1_ec_pubkey_parse(ctx, &parsed_pubkey, pubkey, pubkey_len)) {
        return 0;
    }
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, signature64)) {
        return 0;
    }

    // secp256k1_ecdsa_verify rejects a high-S signature outright rather than
    // normalizing it first, so that has to happen here when the caller asked
    // for it.
    if (normalize) {
        secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);
    }

    return secp256k1_ecdsa_verify(ctx, &sig, msg32, &parsed_pubkey);
}

int shim_ecdsa_sign_der(
    const secp256k1_context *ctx,
    const unsigned char msg32[SHIM_MESSAGE_LEN],
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char *aux_rand32,
    unsigned char *output,
    size_t *output_len
) {
    secp256k1_ecdsa_signature sig;

    if (!secp256k1_ecdsa_sign(ctx, &sig, msg32, seckey32, NULL, aux_rand32)) {
        return 0;
    }

    return secp256k1_ecdsa_signature_serialize_der(ctx, output, output_len, &sig);
}

int shim_ecdsa_verify_der(
    const secp256k1_context *ctx,
    const unsigned char msg32[SHIM_MESSAGE_LEN],
    const unsigned char *pubkey,
    size_t pubkey_len,
    const unsigned char *signature,
    size_t signature_len,
    int normalize
) {
    secp256k1_pubkey parsed_pubkey;
    secp256k1_ecdsa_signature sig;

    if (!secp256k1_ec_pubkey_parse(ctx, &parsed_pubkey, pubkey, pubkey_len)) {
        return 0;
    }
    if (!secp256k1_ecdsa_signature_parse_der(ctx, &sig, signature, signature_len)) {
        return 0;
    }

    if (normalize) {
        secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);
    }

    return secp256k1_ecdsa_verify(ctx, &sig, msg32, &parsed_pubkey);
}

/* -------------------------------------------------------- signature format */

int shim_ecdsa_signature_normalize(
    const secp256k1_context *ctx,
    const unsigned char signature64[SHIM_SIGNATURE_COMPACT_LEN],
    unsigned char output64[SHIM_SIGNATURE_COMPACT_LEN],
    int *was_high
) {
    secp256k1_ecdsa_signature sig, normalized;
    int high;

    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, signature64)) {
        return 0;
    }

    high = secp256k1_ecdsa_signature_normalize(ctx, &normalized, &sig);
    if (was_high != NULL) {
        *was_high = high;
    }

    return secp256k1_ecdsa_signature_serialize_compact(ctx, output64, &normalized);
}

int shim_ecdsa_signature_der_to_compact(
    const secp256k1_context *ctx,
    const unsigned char *signature,
    size_t signature_len,
    unsigned char output64[SHIM_SIGNATURE_COMPACT_LEN]
) {
    secp256k1_ecdsa_signature sig;

    if (!secp256k1_ecdsa_signature_parse_der(ctx, &sig, signature, signature_len)) {
        return 0;
    }

    return secp256k1_ecdsa_signature_serialize_compact(ctx, output64, &sig);
}

int shim_ecdsa_signature_compact_to_der(
    const secp256k1_context *ctx,
    const unsigned char signature64[SHIM_SIGNATURE_COMPACT_LEN],
    unsigned char *output,
    size_t *output_len
) {
    secp256k1_ecdsa_signature sig;

    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, signature64)) {
        return 0;
    }

    return secp256k1_ecdsa_signature_serialize_der(ctx, output, output_len, &sig);
}

/* -------------------------------------------------------------- recovery */

int shim_ecdsa_sign_recoverable(
    const secp256k1_context *ctx,
    const unsigned char msg32[SHIM_MESSAGE_LEN],
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char *aux_rand32,
    unsigned char output64[SHIM_SIGNATURE_COMPACT_LEN],
    int *recovery_id
) {
    secp256k1_ecdsa_recoverable_signature sig;

    if (!secp256k1_ecdsa_sign_recoverable(ctx, &sig, msg32, seckey32, NULL, aux_rand32)) {
        return 0;
    }

    return secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, output64, recovery_id, &sig);
}

int shim_ecdsa_recover(
    const secp256k1_context *ctx,
    const unsigned char msg32[SHIM_MESSAGE_LEN],
    const unsigned char signature64[SHIM_SIGNATURE_COMPACT_LEN],
    int recovery_id,
    unsigned char *output,
    size_t *output_len,
    int compressed
) {
    secp256k1_ecdsa_recoverable_signature sig;
    secp256k1_pubkey pubkey;
    unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig, signature64, recovery_id)) {
        return 0;
    }
    if (!secp256k1_ecdsa_recover(ctx, &pubkey, &sig, msg32)) {
        return 0;
    }

    return secp256k1_ec_pubkey_serialize(ctx, output, output_len, &pubkey, flags);
}

/* ------------------------------------------------------------ x-only keys */

int shim_xonly_pubkey_create(
    const secp256k1_context *ctx,
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    unsigned char output32[SHIM_XONLY_PUBKEY_LEN],
    int *parity
) {
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey xonly;

    // secp256k1_keypair only exists to carry state between these two calls;
    // it never leaves this function, matching the rest of the shim's rule
    // that no C struct crosses into Go.
    if (!secp256k1_keypair_create(ctx, &keypair, seckey32)) {
        return 0;
    }
    if (!secp256k1_keypair_xonly_pub(ctx, &xonly, parity, &keypair)) {
        return 0;
    }

    return secp256k1_xonly_pubkey_serialize(ctx, output32, &xonly);
}

int shim_xonly_pubkey_verify(
    const secp256k1_context *ctx,
    const unsigned char pubkey32[SHIM_XONLY_PUBKEY_LEN]
) {
    secp256k1_xonly_pubkey parsed;
    return secp256k1_xonly_pubkey_parse(ctx, &parsed, pubkey32);
}

int shim_xonly_pubkey_from_pubkey(
    const secp256k1_context *ctx,
    const unsigned char *pubkey,
    size_t pubkey_len,
    unsigned char output32[SHIM_XONLY_PUBKEY_LEN],
    int *parity
) {
    secp256k1_pubkey parsed;
    secp256k1_xonly_pubkey xonly;

    if (!secp256k1_ec_pubkey_parse(ctx, &parsed, pubkey, pubkey_len)) {
        return 0;
    }
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, parity, &parsed)) {
        return 0;
    }

    return secp256k1_xonly_pubkey_serialize(ctx, output32, &xonly);
}

int shim_xonly_pubkey_cmp(
    const secp256k1_context *ctx,
    const unsigned char pubkey_a32[SHIM_XONLY_PUBKEY_LEN],
    const unsigned char pubkey_b32[SHIM_XONLY_PUBKEY_LEN],
    int *result
) {
    secp256k1_xonly_pubkey a, b;

    if (!secp256k1_xonly_pubkey_parse(ctx, &a, pubkey_a32)) {
        return 0;
    }
    if (!secp256k1_xonly_pubkey_parse(ctx, &b, pubkey_b32)) {
        return 0;
    }

    *result = secp256k1_xonly_pubkey_cmp(ctx, &a, &b);
    return 1;
}

int shim_xonly_pubkey_tweak_add(
    const secp256k1_context *ctx,
    const unsigned char pubkey32[SHIM_XONLY_PUBKEY_LEN],
    const unsigned char tweak32[SHIM_TWEAK_LEN],
    unsigned char output32[SHIM_XONLY_PUBKEY_LEN],
    int *parity
) {
    secp256k1_xonly_pubkey internal;
    secp256k1_pubkey tweaked;
    secp256k1_xonly_pubkey tweaked_xonly;

    if (!secp256k1_xonly_pubkey_parse(ctx, &internal, pubkey32)) {
        return 0;
    }
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked, &internal, tweak32)) {
        return 0;
    }
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, parity, &tweaked)) {
        return 0;
    }

    return secp256k1_xonly_pubkey_serialize(ctx, output32, &tweaked_xonly);
}

int shim_xonly_pubkey_tweak_add_check(
    const secp256k1_context *ctx,
    const unsigned char output32[SHIM_XONLY_PUBKEY_LEN],
    int output_parity,
    const unsigned char internal32[SHIM_XONLY_PUBKEY_LEN],
    const unsigned char tweak32[SHIM_TWEAK_LEN]
) {
    secp256k1_xonly_pubkey internal;

    if (!secp256k1_xonly_pubkey_parse(ctx, &internal, internal32)) {
        return 0;
    }

    return secp256k1_xonly_pubkey_tweak_add_check(ctx, output32, output_parity, &internal, tweak32);
}

int shim_seckey_xonly_tweak_add(
    const secp256k1_context *ctx,
    unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char tweak32[SHIM_TWEAK_LEN]
) {
    secp256k1_keypair keypair;

    if (!secp256k1_keypair_create(ctx, &keypair, seckey32)) {
        return 0;
    }
    if (!secp256k1_keypair_xonly_tweak_add(ctx, &keypair, tweak32)) {
        return 0;
    }

    return secp256k1_keypair_sec(ctx, seckey32, &keypair);
}

/* -------------------------------------------------------- Schnorr signatures */

int shim_schnorr_sign(
    const secp256k1_context *ctx,
    const unsigned char *msg,
    size_t msg_len,
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char *aux_rand32,
    unsigned char output64[SHIM_SIGNATURE_COMPACT_LEN]
) {
    secp256k1_keypair keypair;
    secp256k1_schnorrsig_extraparams extraparams = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;

    if (!secp256k1_keypair_create(ctx, &keypair, seckey32)) {
        return 0;
    }

    // Leaving noncefp NULL selects the module's default nonce function,
    // deterministic from msg and the keypair; ndata carries aux_rand32
    // through as extra entropy folded into that derivation, the same
    // hedged-but-safe pattern as ECDSA's aux_rand.
    extraparams.ndata = (void *)aux_rand32;

    return secp256k1_schnorrsig_sign_custom(ctx, output64, msg, msg_len, &keypair, &extraparams);
}

int shim_schnorr_verify(
    const secp256k1_context *ctx,
    const unsigned char *msg,
    size_t msg_len,
    const unsigned char pubkey32[SHIM_XONLY_PUBKEY_LEN],
    const unsigned char signature64[SHIM_SIGNATURE_COMPACT_LEN]
) {
    secp256k1_xonly_pubkey pubkey;

    if (!secp256k1_xonly_pubkey_parse(ctx, &pubkey, pubkey32)) {
        return 0;
    }

    return secp256k1_schnorrsig_verify(ctx, signature64, msg, msg_len, &pubkey);
}

/* -------------------------------------------------------------------- ECDH */

int shim_ecdh(
    const secp256k1_context *ctx,
    const unsigned char *pubkey,
    size_t pubkey_len,
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    unsigned char output32[SHIM_SHARED_SECRET_LEN]
) {
    secp256k1_pubkey parsed;

    if (!secp256k1_ec_pubkey_parse(ctx, &parsed, pubkey, pubkey_len)) {
        return 0;
    }

    // Passing NULL for hashfp selects the default hash function, SHA-256 of
    // the compressed shared point, matching this function's documented
    // contract.
    return secp256k1_ecdh(ctx, output32, &parsed, seckey32, NULL, NULL);
}

/* ------------------------------------------------------------ ElligatorSwift */

int shim_ellswift_encode(
    const secp256k1_context *ctx,
    const unsigned char *pubkey,
    size_t pubkey_len,
    const unsigned char rnd32[32],
    unsigned char output64[SHIM_ELLSWIFT_LEN]
) {
    secp256k1_pubkey parsed;

    if (!secp256k1_ec_pubkey_parse(ctx, &parsed, pubkey, pubkey_len)) {
        return 0;
    }

    return secp256k1_ellswift_encode(ctx, output64, &parsed, rnd32);
}

int shim_ellswift_decode(
    const secp256k1_context *ctx,
    const unsigned char input64[SHIM_ELLSWIFT_LEN],
    unsigned char *output,
    size_t *output_len,
    int compressed
) {
    secp256k1_pubkey pubkey;
    unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    // secp256k1_ellswift_decode always returns 1: any 64 bytes decode to some
    // valid point.
    secp256k1_ellswift_decode(ctx, &pubkey, input64);

    return secp256k1_ec_pubkey_serialize(ctx, output, output_len, &pubkey, flags);
}

int shim_ellswift_create(
    const secp256k1_context *ctx,
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char *aux_rand32,
    unsigned char output64[SHIM_ELLSWIFT_LEN]
) {
    return secp256k1_ellswift_create(ctx, output64, seckey32, aux_rand32);
}

int shim_ellswift_xdh(
    const secp256k1_context *ctx,
    const unsigned char ell_a64[SHIM_ELLSWIFT_LEN],
    const unsigned char ell_b64[SHIM_ELLSWIFT_LEN],
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    int party,
    unsigned char output32[SHIM_HASH_LEN]
) {
    // The prefix hash function unconditionally reads 64 bytes from data, so a
    // NULL data pointer here would be undefined behavior, not "no prefix" —
    // an all-zero 64-byte prefix is the actual no-prefix case, reducing this
    // to plain SHA256(ell_a64 || ell_b64 || x), matching shim_ecdh's choice
    // of a fixed, library-provided hash over rolling a custom one.
    unsigned char zero_prefix[64] = {0};
    return secp256k1_ellswift_xdh(
        ctx, output32, ell_a64, ell_b64, seckey32, party,
        secp256k1_ellswift_xdh_hash_function_prefix, zero_prefix
    );
}

/* --------------------------------------------------------- MuSig2 key agg */

// secp256k1_musig_keyagg_cache (and the other MuSig opaque types below) are,
// in the vendored source, a struct wrapping nothing but a fixed unsigned char
// array. Casting the raw buffer this shim receives to that struct type is
// exactly the identity conversion the struct's own layout guarantees — not a
// reinterpretation across incompatible types — so it carries no aliasing
// hazard.

int shim_musig_pubkey_agg(
    const secp256k1_context *ctx,
    const unsigned char *pubkeys,
    size_t pubkey_count,
    unsigned char agg_pk32[SHIM_XONLY_PUBKEY_LEN],
    unsigned char keyagg_cache[SHIM_MUSIG_KEYAGG_CACHE_LEN]
) {
    secp256k1_pubkey parsed[SHIM_MAX_COMBINE_PUBKEYS];
    const secp256k1_pubkey *ins[SHIM_MAX_COMBINE_PUBKEYS];
    secp256k1_xonly_pubkey agg_pk;
    size_t i;

    if (pubkey_count == 0 || pubkey_count > SHIM_MAX_COMBINE_PUBKEYS) {
        return 0;
    }

    for (i = 0; i < pubkey_count; i++) {
        const unsigned char *key = pubkeys + (i * SHIM_PUBKEY_COMPRESSED_LEN);
        if (!secp256k1_ec_pubkey_parse(ctx, &parsed[i], key, SHIM_PUBKEY_COMPRESSED_LEN)) {
            return 0;
        }
        ins[i] = &parsed[i];
    }

    if (!secp256k1_musig_pubkey_agg(ctx, &agg_pk, (secp256k1_musig_keyagg_cache *)(void *)keyagg_cache, ins, pubkey_count)) {
        return 0;
    }

    return secp256k1_xonly_pubkey_serialize(ctx, agg_pk32, &agg_pk);
}

int shim_musig_pubkey_get(
    const secp256k1_context *ctx,
    const unsigned char keyagg_cache[SHIM_MUSIG_KEYAGG_CACHE_LEN],
    unsigned char *output,
    size_t *output_len,
    int compressed
) {
    secp256k1_pubkey agg_pk;
    unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    if (!secp256k1_musig_pubkey_get(ctx, &agg_pk, (secp256k1_musig_keyagg_cache *)(void *)keyagg_cache)) {
        return 0;
    }

    return secp256k1_ec_pubkey_serialize(ctx, output, output_len, &agg_pk, flags);
}

int shim_musig_pubkey_ec_tweak_add(
    const secp256k1_context *ctx,
    unsigned char keyagg_cache[SHIM_MUSIG_KEYAGG_CACHE_LEN],
    const unsigned char tweak32[SHIM_TWEAK_LEN],
    unsigned char *output,
    size_t *output_len,
    int compressed
) {
    secp256k1_pubkey tweaked;
    unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    if (!secp256k1_musig_pubkey_ec_tweak_add(ctx, &tweaked, (secp256k1_musig_keyagg_cache *)(void *)keyagg_cache, tweak32)) {
        return 0;
    }

    return secp256k1_ec_pubkey_serialize(ctx, output, output_len, &tweaked, flags);
}

int shim_musig_pubkey_xonly_tweak_add(
    const secp256k1_context *ctx,
    unsigned char keyagg_cache[SHIM_MUSIG_KEYAGG_CACHE_LEN],
    const unsigned char tweak32[SHIM_TWEAK_LEN],
    unsigned char *output,
    size_t *output_len,
    int compressed
) {
    secp256k1_pubkey tweaked;
    unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked, (secp256k1_musig_keyagg_cache *)(void *)keyagg_cache, tweak32)) {
        return 0;
    }

    return secp256k1_ec_pubkey_serialize(ctx, output, output_len, &tweaked, flags);
}

/* ------------------------------------------------------- MuSig2 nonce gen */

int shim_musig_nonce_gen(
    const secp256k1_context *ctx,
    unsigned char session_secrand32[32],
    const unsigned char *seckey32,
    const unsigned char *pubkey,
    size_t pubkey_len,
    const unsigned char *msg32,
    const unsigned char *keyagg_cache,
    const unsigned char *extra_input32,
    unsigned char secnonce[SHIM_MUSIG_SECNONCE_LEN],
    unsigned char pubnonce[SHIM_MUSIG_PUBNONCE_LEN]
) {
    secp256k1_pubkey parsed_pubkey;

    if (!secp256k1_ec_pubkey_parse(ctx, &parsed_pubkey, pubkey, pubkey_len)) {
        return 0;
    }

    return secp256k1_musig_nonce_gen(
        ctx,
        (secp256k1_musig_secnonce *)(void *)secnonce,
        (secp256k1_musig_pubnonce *)(void *)pubnonce,
        session_secrand32,
        seckey32,
        &parsed_pubkey,
        msg32,
        keyagg_cache ? (const secp256k1_musig_keyagg_cache *)(const void *)keyagg_cache : NULL,
        extra_input32
    );
}

int shim_musig_nonce_gen_counter(
    const secp256k1_context *ctx,
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    uint64_t nonrepeating_cnt,
    const unsigned char *msg32,
    const unsigned char *keyagg_cache,
    const unsigned char *extra_input32,
    unsigned char secnonce[SHIM_MUSIG_SECNONCE_LEN],
    unsigned char pubnonce[SHIM_MUSIG_PUBNONCE_LEN]
) {
    secp256k1_keypair keypair;

    if (!secp256k1_keypair_create(ctx, &keypair, seckey32)) {
        return 0;
    }

    return secp256k1_musig_nonce_gen_counter(
        ctx,
        (secp256k1_musig_secnonce *)(void *)secnonce,
        (secp256k1_musig_pubnonce *)(void *)pubnonce,
        nonrepeating_cnt,
        &keypair,
        msg32,
        keyagg_cache ? (const secp256k1_musig_keyagg_cache *)(const void *)keyagg_cache : NULL,
        extra_input32
    );
}

/* --------------------------------------------- MuSig2 nonce exchange/agg */

int shim_musig_pubnonce_parse(
    const secp256k1_context *ctx,
    const unsigned char input66[SHIM_MUSIG_PUBNONCE_SERIALIZED_LEN],
    unsigned char pubnonce[SHIM_MUSIG_PUBNONCE_LEN]
) {
    return secp256k1_musig_pubnonce_parse(ctx, (secp256k1_musig_pubnonce *)(void *)pubnonce, input66);
}

int shim_musig_pubnonce_serialize(
    const secp256k1_context *ctx,
    const unsigned char pubnonce[SHIM_MUSIG_PUBNONCE_LEN],
    unsigned char output66[SHIM_MUSIG_PUBNONCE_SERIALIZED_LEN]
) {
    return secp256k1_musig_pubnonce_serialize(ctx, output66, (const secp256k1_musig_pubnonce *)(const void *)pubnonce);
}

int shim_musig_aggnonce_parse(
    const secp256k1_context *ctx,
    const unsigned char input66[SHIM_MUSIG_AGGNONCE_SERIALIZED_LEN],
    unsigned char aggnonce[SHIM_MUSIG_AGGNONCE_LEN]
) {
    return secp256k1_musig_aggnonce_parse(ctx, (secp256k1_musig_aggnonce *)(void *)aggnonce, input66);
}

int shim_musig_aggnonce_serialize(
    const secp256k1_context *ctx,
    const unsigned char aggnonce[SHIM_MUSIG_AGGNONCE_LEN],
    unsigned char output66[SHIM_MUSIG_AGGNONCE_SERIALIZED_LEN]
) {
    return secp256k1_musig_aggnonce_serialize(ctx, output66, (const secp256k1_musig_aggnonce *)(const void *)aggnonce);
}

int shim_musig_nonce_agg(
    const secp256k1_context *ctx,
    const unsigned char *pubnonces,
    size_t pubnonce_count,
    unsigned char aggnonce[SHIM_MUSIG_AGGNONCE_LEN]
) {
    const secp256k1_musig_pubnonce *ins[SHIM_MAX_COMBINE_PUBKEYS];
    size_t i;

    if (pubnonce_count == 0 || pubnonce_count > SHIM_MAX_COMBINE_PUBKEYS) {
        return 0;
    }

    for (i = 0; i < pubnonce_count; i++) {
        const unsigned char *nonce = pubnonces + (i * SHIM_MUSIG_PUBNONCE_LEN);
        ins[i] = (const secp256k1_musig_pubnonce *)(const void *)nonce;
    }

    return secp256k1_musig_nonce_agg(ctx, (secp256k1_musig_aggnonce *)(void *)aggnonce, ins, pubnonce_count);
}

int shim_musig_nonce_process(
    const secp256k1_context *ctx,
    const unsigned char aggnonce[SHIM_MUSIG_AGGNONCE_LEN],
    const unsigned char msg32[SHIM_MESSAGE_LEN],
    const unsigned char keyagg_cache[SHIM_MUSIG_KEYAGG_CACHE_LEN],
    unsigned char session[SHIM_MUSIG_SESSION_LEN]
) {
    return secp256k1_musig_nonce_process(
        ctx,
        (secp256k1_musig_session *)(void *)session,
        (const secp256k1_musig_aggnonce *)(const void *)aggnonce,
        msg32,
        (const secp256k1_musig_keyagg_cache *)(const void *)keyagg_cache
    );
}

/* ----------------------------------------------------- MuSig2 partial sig */

int shim_musig_partial_sig_parse(
    const secp256k1_context *ctx,
    const unsigned char input32[SHIM_MUSIG_PARTIAL_SIG_SERIALIZED_LEN],
    unsigned char partial_sig[SHIM_MUSIG_PARTIAL_SIG_LEN]
) {
    return secp256k1_musig_partial_sig_parse(ctx, (secp256k1_musig_partial_sig *)(void *)partial_sig, input32);
}

int shim_musig_partial_sig_serialize(
    const secp256k1_context *ctx,
    const unsigned char partial_sig[SHIM_MUSIG_PARTIAL_SIG_LEN],
    unsigned char output32[SHIM_MUSIG_PARTIAL_SIG_SERIALIZED_LEN]
) {
    return secp256k1_musig_partial_sig_serialize(ctx, output32, (const secp256k1_musig_partial_sig *)(const void *)partial_sig);
}

int shim_musig_partial_sign(
    const secp256k1_context *ctx,
    unsigned char secnonce[SHIM_MUSIG_SECNONCE_LEN],
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char keyagg_cache[SHIM_MUSIG_KEYAGG_CACHE_LEN],
    const unsigned char session[SHIM_MUSIG_SESSION_LEN],
    unsigned char partial_sig[SHIM_MUSIG_PARTIAL_SIG_LEN]
) {
    secp256k1_keypair keypair;

    if (!secp256k1_keypair_create(ctx, &keypair, seckey32)) {
        return 0;
    }

    // Like shim_musig_nonce_gen writing directly into the caller's
    // secnonce/pubnonce buffers, this writes the partial signature's
    // internal representation straight into partial_sig — not the 32-byte
    // wire form, which shim_musig_partial_sig_serialize produces separately
    // when a caller actually needs to send it somewhere.
    return secp256k1_musig_partial_sign(
        ctx,
        (secp256k1_musig_partial_sig *)(void *)partial_sig,
        (secp256k1_musig_secnonce *)(void *)secnonce,
        &keypair,
        (const secp256k1_musig_keyagg_cache *)(const void *)keyagg_cache,
        (const secp256k1_musig_session *)(const void *)session
    );
}

int shim_musig_partial_sig_verify(
    const secp256k1_context *ctx,
    const unsigned char partial_sig[SHIM_MUSIG_PARTIAL_SIG_LEN],
    const unsigned char pubnonce[SHIM_MUSIG_PUBNONCE_LEN],
    const unsigned char *pubkey,
    size_t pubkey_len,
    const unsigned char keyagg_cache[SHIM_MUSIG_KEYAGG_CACHE_LEN],
    const unsigned char session[SHIM_MUSIG_SESSION_LEN]
) {
    secp256k1_pubkey parsed_pubkey;

    if (!secp256k1_ec_pubkey_parse(ctx, &parsed_pubkey, pubkey, pubkey_len)) {
        return 0;
    }

    return secp256k1_musig_partial_sig_verify(
        ctx,
        (const secp256k1_musig_partial_sig *)(const void *)partial_sig,
        (const secp256k1_musig_pubnonce *)(const void *)pubnonce,
        &parsed_pubkey,
        (const secp256k1_musig_keyagg_cache *)(const void *)keyagg_cache,
        (const secp256k1_musig_session *)(const void *)session
    );
}

int shim_musig_partial_sig_agg(
    const secp256k1_context *ctx,
    const unsigned char session[SHIM_MUSIG_SESSION_LEN],
    const unsigned char *partial_sigs,
    size_t partial_sig_count,
    unsigned char sig64[SHIM_SIGNATURE_COMPACT_LEN]
) {
    const secp256k1_musig_partial_sig *ins[SHIM_MAX_COMBINE_PUBKEYS];
    size_t i;

    if (partial_sig_count == 0 || partial_sig_count > SHIM_MAX_COMBINE_PUBKEYS) {
        return 0;
    }

    for (i = 0; i < partial_sig_count; i++) {
        const unsigned char *sig = partial_sigs + (i * SHIM_MUSIG_PARTIAL_SIG_LEN);
        ins[i] = (const secp256k1_musig_partial_sig *)(const void *)sig;
    }

    return secp256k1_musig_partial_sig_agg(
        ctx,
        sig64,
        (const secp256k1_musig_session *)(const void *)session,
        ins,
        partial_sig_count
    );
}