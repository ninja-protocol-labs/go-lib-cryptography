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