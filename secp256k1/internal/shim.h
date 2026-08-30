#ifndef NINJA_SECP256K1_SHIM_H
#define NINJA_SECP256K1_SHIM_H

#include <stddef.h>

#include "secp256k1.h"

// This shim collapses the multi-step libsecp256k1 sequences into one call each.
// Creating a public key upstream means ec_pubkey_create followed by
// ec_pubkey_serialize; doing that from Go would cost two cgo crossings and
// force the opaque secp256k1_pubkey struct into Go code. Every function here
// takes and returns plain byte buffers instead, so the Go side never holds a C
// struct and never has to free anything.
//
// That rule is why some upstream functions have no counterpart here. The
// keypair API (keypair_create, keypair_sec, keypair_pub) only exists to carry
// an opaque handle between calls, so the shim builds a keypair internally
// wherever one is needed and never surfaces it. Likewise
// ecdsa_recoverable_signature_convert is absent: a recoverable signature
// serializes to the same 64 bytes as a plain one plus a recovery id, so
// dropping the id is the whole conversion.
//
// Return convention follows upstream: 1 on success, 0 on failure. Buffers are
// caller-allocated; functions with a size_t *len take the capacity on entry and
// write the actual length on success.

#define SHIM_SECKEY_LEN 32
#define SHIM_PUBKEY_COMPRESSED_LEN 33
#define SHIM_PUBKEY_UNCOMPRESSED_LEN 65
#define SHIM_XONLY_PUBKEY_LEN 32
#define SHIM_SIGNATURE_COMPACT_LEN 64
#define SHIM_SIGNATURE_DER_MAX_LEN 72
#define SHIM_MESSAGE_LEN 32
#define SHIM_SHARED_SECRET_LEN 32
#define SHIM_TWEAK_LEN 32
#define SHIM_HASH_LEN 32

/* ---------------------------------------------------------------- context */

// Creates a context and randomizes it with seed32 to blind the scalar
// multiplications against side-channel attacks. Pass NULL to skip
// randomization. Returns NULL on failure.
secp256k1_context *shim_context_create(const unsigned char *seed32);

void shim_context_destroy(secp256k1_context *ctx);

// Runs the library's internal consistency checks. Aborts the process on
// failure, which is upstream's behaviour: a failing selftest means the build
// itself is broken.
void shim_selftest(void);

/* ------------------------------------------------------------------- keys */

int shim_seckey_verify(
    const secp256k1_context *ctx,
    const unsigned char seckey32[SHIM_SECKEY_LEN]
);

// Derives the public key for seckey32 and serializes it. compressed selects the
// 33-byte form over the 65-byte one.
int shim_pubkey_create(
    const secp256k1_context *ctx,
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    unsigned char *output,
    size_t *output_len,
    int compressed
);

// Parses a serialized public key and writes it back in the requested form,
// which doubles as validation and as a compressed/uncompressed converter.
int shim_pubkey_parse(
    const secp256k1_context *ctx,
    const unsigned char *pubkey,
    size_t pubkey_len,
    unsigned char *output,
    size_t *output_len,
    int compressed
);

// Negation flips the sign of the key, which Taproot needs when a derived point
// lands on the wrong y parity. The seckey variant mutates in place.

int shim_seckey_negate(
    const secp256k1_context *ctx,
    unsigned char seckey32[SHIM_SECKEY_LEN]
);

int shim_pubkey_negate(
    const secp256k1_context *ctx,
    const unsigned char *pubkey,
    size_t pubkey_len,
    unsigned char *output,
    size_t *output_len,
    int compressed
);

// Adds pubkey_count public keys together. Inputs must be compressed 33-byte
// keys laid out back to back; run them through shim_pubkey_parse first if they
// arrive uncompressed. Fails if the sum is the point at infinity.
int shim_pubkey_combine(
    const secp256k1_context *ctx,
    const unsigned char *pubkeys,
    size_t pubkey_count,
    unsigned char *output,
    size_t *output_len,
    int compressed
);

// Writes -1, 0 or 1 to result, ordering keys by their compressed serialization.
int shim_pubkey_cmp(
    const secp256k1_context *ctx,
    const unsigned char *pubkey_a,
    size_t pubkey_a_len,
    const unsigned char *pubkey_b,
    size_t pubkey_b_len,
    int *result
);

// Sorts pubkey_count compressed 33-byte keys in place. Multisig scripts depend
// on a deterministic key order, and this is the ordering upstream defines.
int shim_pubkey_sort(
    const secp256k1_context *ctx,
    unsigned char *pubkeys,
    size_t pubkey_count
);

/* ----------------------------------------------------------------- tweaks */

// Tweaks needed for BIP32 child key derivation. The seckey variants mutate
// seckey32 in place; the pubkey variants take a serialized key and write the
// tweaked result to output.

int shim_seckey_tweak_add(
    const secp256k1_context *ctx,
    unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char tweak32[SHIM_TWEAK_LEN]
);

int shim_seckey_tweak_mul(
    const secp256k1_context *ctx,
    unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char tweak32[SHIM_TWEAK_LEN]
);

int shim_pubkey_tweak_add(
    const secp256k1_context *ctx,
    const unsigned char *pubkey,
    size_t pubkey_len,
    const unsigned char tweak32[SHIM_TWEAK_LEN],
    unsigned char *output,
    size_t *output_len,
    int compressed
);

int shim_pubkey_tweak_mul(
    const secp256k1_context *ctx,
    const unsigned char *pubkey,
    size_t pubkey_len,
    const unsigned char tweak32[SHIM_TWEAK_LEN],
    unsigned char *output,
    size_t *output_len,
    int compressed
);

/* ------------------------------------------------- x-only keys (BIP340/341) */

// BIP340 uses x-only public keys: the 32-byte x coordinate with the y parity
// dropped. Where a parity out-parameter appears it receives 0 or 1, which is
// what lets the full key be reconstructed later.

int shim_xonly_pubkey_create(
    const secp256k1_context *ctx,
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    unsigned char output32[SHIM_XONLY_PUBKEY_LEN],
    int *parity
);

int shim_xonly_pubkey_verify(
    const secp256k1_context *ctx,
    const unsigned char pubkey32[SHIM_XONLY_PUBKEY_LEN]
);

int shim_xonly_pubkey_from_pubkey(
    const secp256k1_context *ctx,
    const unsigned char *pubkey,
    size_t pubkey_len,
    unsigned char output32[SHIM_XONLY_PUBKEY_LEN],
    int *parity
);

int shim_xonly_pubkey_cmp(
    const secp256k1_context *ctx,
    const unsigned char pubkey_a32[SHIM_XONLY_PUBKEY_LEN],
    const unsigned char pubkey_b32[SHIM_XONLY_PUBKEY_LEN],
    int *result
);

// The Taproot output key: tweaks an internal x-only key by tweak32 and returns
// the result as x-only plus its parity.
int shim_xonly_pubkey_tweak_add(
    const secp256k1_context *ctx,
    const unsigned char pubkey32[SHIM_XONLY_PUBKEY_LEN],
    const unsigned char tweak32[SHIM_TWEAK_LEN],
    unsigned char output32[SHIM_XONLY_PUBKEY_LEN],
    int *parity
);

// Verifies that output32 with output_parity really is internal32 tweaked by
// tweak32, without recomputing the tweak on the caller's side.
int shim_xonly_pubkey_tweak_add_check(
    const secp256k1_context *ctx,
    const unsigned char output32[SHIM_XONLY_PUBKEY_LEN],
    int output_parity,
    const unsigned char internal32[SHIM_XONLY_PUBKEY_LEN],
    const unsigned char tweak32[SHIM_TWEAK_LEN]
);

// The secret-key half of the Taproot tweak: mutates seckey32 so that its x-only
// public key matches shim_xonly_pubkey_tweak_add's output.
int shim_seckey_xonly_tweak_add(
    const secp256k1_context *ctx,
    unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char tweak32[SHIM_TWEAK_LEN]
);

/* ------------------------------------------------------------------ ECDSA */

// msg32 is always a hash, never a raw message: ECDSA signs a 32-byte digest.
// Signatures come out low-S normalized, which is what Bitcoin and Ethereum
// require.

int shim_ecdsa_sign_compact(
    const secp256k1_context *ctx,
    const unsigned char msg32[SHIM_MESSAGE_LEN],
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    unsigned char output64[SHIM_SIGNATURE_COMPACT_LEN]
);

int shim_ecdsa_sign_der(
    const secp256k1_context *ctx,
    const unsigned char msg32[SHIM_MESSAGE_LEN],
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    unsigned char *output,
    size_t *output_len
);

// Verification rejects high-S signatures, matching upstream. Set normalize to
// accept them by folding S into the lower half first — needed only for
// signatures produced by implementations that do not enforce low-S.
int shim_ecdsa_verify_compact(
    const secp256k1_context *ctx,
    const unsigned char msg32[SHIM_MESSAGE_LEN],
    const unsigned char *pubkey,
    size_t pubkey_len,
    const unsigned char signature64[SHIM_SIGNATURE_COMPACT_LEN],
    int normalize
);

int shim_ecdsa_verify_der(
    const secp256k1_context *ctx,
    const unsigned char msg32[SHIM_MESSAGE_LEN],
    const unsigned char *pubkey,
    size_t pubkey_len,
    const unsigned char *signature,
    size_t signature_len,
    int normalize
);

/* -------------------------------------------------------- signature format */

// Folds S into the lower half of the curve order. was_high receives 1 if the
// input needed normalizing, which is how a caller enforcing a low-S policy can
// reject the signature instead of fixing it. Pass NULL to ignore it.
int shim_ecdsa_signature_normalize(
    const secp256k1_context *ctx,
    const unsigned char signature64[SHIM_SIGNATURE_COMPACT_LEN],
    unsigned char output64[SHIM_SIGNATURE_COMPACT_LEN],
    int *was_high
);

// Conversions between the two wire formats, for signatures that arrive from
// elsewhere and have to be re-encoded without signing again.

int shim_ecdsa_signature_der_to_compact(
    const secp256k1_context *ctx,
    const unsigned char *signature,
    size_t signature_len,
    unsigned char output64[SHIM_SIGNATURE_COMPACT_LEN]
);

int shim_ecdsa_signature_compact_to_der(
    const secp256k1_context *ctx,
    const unsigned char signature64[SHIM_SIGNATURE_COMPACT_LEN],
    unsigned char *output,
    size_t *output_len
);

/* -------------------------------------------------------------- recovery */

int shim_ecdsa_sign_recoverable(
    const secp256k1_context *ctx,
    const unsigned char msg32[SHIM_MESSAGE_LEN],
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    unsigned char output64[SHIM_SIGNATURE_COMPACT_LEN],
    int *recovery_id
);

int shim_ecdsa_recover(
    const secp256k1_context *ctx,
    const unsigned char msg32[SHIM_MESSAGE_LEN],
    const unsigned char signature64[SHIM_SIGNATURE_COMPACT_LEN],
    int recovery_id,
    unsigned char *output,
    size_t *output_len,
    int compressed
);

/* --------------------------------------------------- Schnorr (BIP340) */

// Unlike ECDSA, BIP340 signs a message of any length, hashing it internally.
// aux_rand32 is optional auxiliary randomness; pass NULL to sign
// deterministically.
int shim_schnorr_sign(
    const secp256k1_context *ctx,
    const unsigned char *msg,
    size_t msg_len,
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char *aux_rand32,
    unsigned char output64[SHIM_SIGNATURE_COMPACT_LEN]
);

int shim_schnorr_verify(
    const secp256k1_context *ctx,
    const unsigned char *msg,
    size_t msg_len,
    const unsigned char pubkey32[SHIM_XONLY_PUBKEY_LEN],
    const unsigned char signature64[SHIM_SIGNATURE_COMPACT_LEN]
);

/* -------------------------------------------------------------------- ECDH */

// Produces SHA-256 of the compressed shared point, which is libsecp256k1's
// default hashing and what most protocols expect.
int shim_ecdh(
    const secp256k1_context *ctx,
    const unsigned char *pubkey,
    size_t pubkey_len,
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    unsigned char output32[SHIM_SHARED_SECRET_LEN]
);

/* ------------------------------------------------------------------ misc */

// SHA-256 with a BIP340 tag prefix: sha256(sha256(tag) || sha256(tag) || msg).
// Taproot builds its tweaks out of these, and getting the tag domain separation
// right matters, so it comes from the library rather than being reimplemented.
int shim_tagged_sha256(
    const secp256k1_context *ctx,
    const unsigned char *tag,
    size_t tag_len,
    const unsigned char *msg,
    size_t msg_len,
    unsigned char output32[SHIM_HASH_LEN]
);

// Zeroes a buffer without the compiler optimizing the write away. Only useful
// for scratch buffers living in C; secrets held in Go memory should be cleared
// on the Go side.
void shim_memzero(void *ptr, size_t len);

#endif /* NINJA_SECP256K1_SHIM_H */