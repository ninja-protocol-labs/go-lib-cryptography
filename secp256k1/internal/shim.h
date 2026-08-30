#ifndef NINJA_SECP256K1_SHIM_H
#define NINJA_SECP256K1_SHIM_H

#include <stddef.h>
#include <stdint.h>

#include "secp256k1.h"
#include "secp256k1_ecdh.h"
#include "secp256k1_ellswift.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_musig.h"
#include "secp256k1_recovery.h"
#include "secp256k1_schnorrsig.h"

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
#define SHIM_ELLSWIFT_LEN 64

// MuSig2 opaque state sizes. Each of these is, upstream, a struct wrapping
// nothing but a fixed byte array with no internal pointers — so unlike
// secp256k1_pubkey or secp256k1_keypair (which never leave shim.c), a plain
// [N]byte on the Go side has identical layout and can be round-tripped
// through a session's multiple calls, and across signers, unchanged.
//
// secnonce is the one exception the size table doesn't capture: upstream
// warns it must never be copied or reused once consumed by a signing call,
// on pain of leaking the secret key. It is safe to carry as a byte array
// between shim_musig_nonce_gen and shim_musig_partial_sign — just never
// duplicate or persist it beyond that single use.
#define SHIM_MUSIG_KEYAGG_CACHE_LEN 197
#define SHIM_MUSIG_SECNONCE_LEN 132
#define SHIM_MUSIG_PUBNONCE_LEN 132
#define SHIM_MUSIG_PUBNONCE_SERIALIZED_LEN 66
#define SHIM_MUSIG_AGGNONCE_LEN 132
#define SHIM_MUSIG_AGGNONCE_SERIALIZED_LEN 66
#define SHIM_MUSIG_SESSION_LEN 133
#define SHIM_MUSIG_PARTIAL_SIG_LEN 36
#define SHIM_MUSIG_PARTIAL_SIG_SERIALIZED_LEN 32

// shim_pubkey_combine and shim_pubkey_sort take their keys as a caller-owned
// stack array sized against this, rather than allocating: a cap high enough
// for any real key-aggregation scheme, low enough that even the maximum
// request cannot threaten the stack.
#define SHIM_MAX_COMBINE_PUBKEYS 64

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

// Negation flips the sign of the key, useful when a derived point needs to
// be normalized to a chosen y parity. The seckey variant mutates in place.

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

// Sorts pubkey_count compressed 33-byte keys in place, using the ordering
// upstream defines — the canonical order key-aggregation schemes rely on.
int shim_pubkey_sort(
    const secp256k1_context *ctx,
    unsigned char *pubkeys,
    size_t pubkey_count
);

/* ----------------------------------------------------------------- tweaks */

// Tweaks needed for additive/multiplicative key derivation schemes. The
// seckey variants mutate seckey32 in place; the pubkey variants take a
// serialized key and write the tweaked result to output.

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

/* ------------------------------------------------------------ x-only keys */

// x-only public keys are the 32-byte x coordinate with the y parity dropped.
// Where a parity out-parameter appears it receives 0 or 1, which is what lets
// the full key be reconstructed later.

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

// Tweaks an internal x-only key by tweak32 and returns the result as x-only
// plus its parity.
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

// The secret-key half of shim_xonly_pubkey_tweak_add: mutates seckey32 so
// that its x-only public key matches that function's output.
int shim_seckey_xonly_tweak_add(
    const secp256k1_context *ctx,
    unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char tweak32[SHIM_TWEAK_LEN]
);

/* ------------------------------------------------------------------ ECDSA */

// msg32 is always a hash, never a raw message: ECDSA signs a 32-byte digest.
// Signatures come out low-S normalized, matching the convention most
// downstream protocols require.
//
// The nonce is derived deterministically from msg32 and seckey32 (RFC 6979),
// never drawn from randomness, so a failing RNG can never cause the nonce to
// repeat and leak the key. aux_rand32 is optional extra entropy folded into
// that derivation for defense in depth against fault attacks; pass NULL for
// pure RFC 6979, or 32 bytes from any source (it need not be secret or even
// unpredictable) to make repeated signatures over the same input unlinkable.
// Either way the signature stays deterministic-safe: this is "hedged"
// signing, not a return to classic random-k ECDSA.

int shim_ecdsa_sign_compact(
    const secp256k1_context *ctx,
    const unsigned char msg32[SHIM_MESSAGE_LEN],
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char *aux_rand32,
    unsigned char output64[SHIM_SIGNATURE_COMPACT_LEN]
);

// aux_rand32 follows the same hedged-signing contract as
// shim_ecdsa_sign_compact: NULL for pure RFC 6979, or 32 bytes of extra
// entropy (need not be secret) to make repeated signatures unlinkable without
// giving up RFC 6979's protection against a failing RNG.
int shim_ecdsa_sign_der(
    const secp256k1_context *ctx,
    const unsigned char msg32[SHIM_MESSAGE_LEN],
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char *aux_rand32,
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

// aux_rand32 follows the same hedged-signing contract as
// shim_ecdsa_sign_compact.
int shim_ecdsa_sign_recoverable(
    const secp256k1_context *ctx,
    const unsigned char msg32[SHIM_MESSAGE_LEN],
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char *aux_rand32,
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

/* -------------------------------------------------------- Schnorr signatures */

// Unlike ECDSA, a Schnorr signature is over a message of any length, hashed
// internally.
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

/* ------------------------------------------------------------ ElligatorSwift */

// ElligatorSwift encodes a curve point as 64 bytes indistinguishable from
// uniform randomness, unlike the compressed/uncompressed forms which are
// always identifiable as a public key on the wire. Decoding recovers a
// regular point.

// rnd32 supplies the randomness used to pick among the encoding's several
// valid representations for the same point; the encoding itself is not
// stable even for identical inputs across library versions.
int shim_ellswift_encode(
    const secp256k1_context *ctx,
    const unsigned char *pubkey,
    size_t pubkey_len,
    const unsigned char rnd32[32],
    unsigned char output64[SHIM_ELLSWIFT_LEN]
);

int shim_ellswift_decode(
    const secp256k1_context *ctx,
    const unsigned char input64[SHIM_ELLSWIFT_LEN],
    unsigned char *output,
    size_t *output_len,
    int compressed
);

// Derives the ElligatorSwift encoding directly from seckey32, without a
// separate pubkey-create step. aux_rand32 is optional extra entropy for the
// encoding (not for the key itself); pass NULL to omit it.
int shim_ellswift_create(
    const secp256k1_context *ctx,
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char *aux_rand32,
    unsigned char output64[SHIM_ELLSWIFT_LEN]
);

// x-only Diffie-Hellman between two ElligatorSwift-encoded points: computes
// the shared secret as SHA-256(ell_a64 || ell_b64 || x), x being the shared
// point's x coordinate. ell_a64 and ell_b64 are fixed roles, not peer/own —
// party selects which one seckey32 corresponds to (0 for A, 1 for B), and
// that correspondence is the caller's responsibility; it is not checked.
int shim_ellswift_xdh(
    const secp256k1_context *ctx,
    const unsigned char ell_a64[SHIM_ELLSWIFT_LEN],
    const unsigned char ell_b64[SHIM_ELLSWIFT_LEN],
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    int party,
    unsigned char output32[SHIM_HASH_LEN]
);

/* --------------------------------------------------------- MuSig2 key agg */

// Aggregates pubkey_count public keys into a single x-only key, and
// initializes keyagg_cache — required for every later step in the same
// session (nonce generation, tweaking, signing, verification). Key order
// changes the result; sort the inputs with shim_pubkey_sort first if the
// aggregate must not depend on it. Shares SHIM_MAX_COMBINE_PUBKEYS with
// shim_pubkey_combine for the same reason: a fixed stack array instead of an
// allocation or an unbounded VLA.
int shim_musig_pubkey_agg(
    const secp256k1_context *ctx,
    const unsigned char *pubkeys,
    size_t pubkey_count,
    unsigned char agg_pk32[SHIM_XONLY_PUBKEY_LEN],
    unsigned char keyagg_cache[SHIM_MUSIG_KEYAGG_CACHE_LEN]
);

// Recovers the full (non-x-only) aggregate key from keyagg_cache. Needed
// before shim_musig_pubkey_ec_tweak_add, which tweaks the full point rather
// than the x-only one.
int shim_musig_pubkey_get(
    const secp256k1_context *ctx,
    const unsigned char keyagg_cache[SHIM_MUSIG_KEYAGG_CACHE_LEN],
    unsigned char *output,
    size_t *output_len,
    int compressed
);

// Tweaks the aggregate key in keyagg_cache by adding tweak32*G to the full
// point, mutating keyagg_cache in place so that later signing in this
// session produces a signature valid for the tweaked key. Use this over a
// plain shim_pubkey_tweak_add whenever the tweaked key will be signed for,
// not just computed.
int shim_musig_pubkey_ec_tweak_add(
    const secp256k1_context *ctx,
    unsigned char keyagg_cache[SHIM_MUSIG_KEYAGG_CACHE_LEN],
    const unsigned char tweak32[SHIM_TWEAK_LEN],
    unsigned char *output,
    size_t *output_len,
    int compressed
);

// Tweaks the aggregate key in keyagg_cache the way shim_xonly_pubkey_tweak_add
// tweaks a standalone x-only key, mutating keyagg_cache in place. Same
// sign-for-the-tweaked-key requirement as shim_musig_pubkey_ec_tweak_add.
int shim_musig_pubkey_xonly_tweak_add(
    const secp256k1_context *ctx,
    unsigned char keyagg_cache[SHIM_MUSIG_KEYAGG_CACHE_LEN],
    const unsigned char tweak32[SHIM_TWEAK_LEN],
    unsigned char *output,
    size_t *output_len,
    int compressed
);

/* ------------------------------------------------------- MuSig2 nonce gen */

// Starts a signing session by generating this signer's secret and public
// nonce. seckey, msg32, keyagg_cache, and extra_input32 are all optional
// (pass NULL/0-length to omit); supplying whichever of them are already known
// only strengthens the nonce against misuse, it never weakens it.
//
// session_secrand32 must be unique to this call and never reused — nonce
// reuse leaks the secret key outright. It is mutated in place: on success
// the library overwrites it, so the caller's buffer coming back zeroed is
// itself evidence the value was consumed and must not be reused.
//
// secnonce carries the same warning as the struct it wraps (see
// SHIM_MUSIG_SECNONCE_LEN above): never copy or reuse it once it has been
// consumed by shim_musig_partial_sign.
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
);

// Alternative to shim_musig_nonce_gen for callers without access to good
// randomness: nonrepeating_cnt replaces session_secrand32, and must never
// repeat for the same seckey (a counter that increments on every call is
// sufficient; unlike session_secrand32 it need not be secret or
// unpredictable, only unique). msg32, keyagg_cache, and extra_input32 remain
// optional as in shim_musig_nonce_gen.
int shim_musig_nonce_gen_counter(
    const secp256k1_context *ctx,
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    uint64_t nonrepeating_cnt,
    const unsigned char *msg32,
    const unsigned char *keyagg_cache,
    const unsigned char *extra_input32,
    unsigned char secnonce[SHIM_MUSIG_SECNONCE_LEN],
    unsigned char pubnonce[SHIM_MUSIG_PUBNONCE_LEN]
);

/* --------------------------------------------- MuSig2 nonce exchange/agg */

// A pubnonce or aggnonce as shim_musig_nonce_gen and shim_musig_nonce_agg
// produce and consume it is the library's 132-byte internal representation,
// not wire format — it is not meant to be sent to another signer as-is.
// These parse/serialize pairs convert to and from the 66-byte form that
// actually crosses a network: serialize before sending a nonce this signer
// produced, parse after receiving one from someone else.

int shim_musig_pubnonce_parse(
    const secp256k1_context *ctx,
    const unsigned char input66[SHIM_MUSIG_PUBNONCE_SERIALIZED_LEN],
    unsigned char pubnonce[SHIM_MUSIG_PUBNONCE_LEN]
);

int shim_musig_pubnonce_serialize(
    const secp256k1_context *ctx,
    const unsigned char pubnonce[SHIM_MUSIG_PUBNONCE_LEN],
    unsigned char output66[SHIM_MUSIG_PUBNONCE_SERIALIZED_LEN]
);

int shim_musig_aggnonce_parse(
    const secp256k1_context *ctx,
    const unsigned char input66[SHIM_MUSIG_AGGNONCE_SERIALIZED_LEN],
    unsigned char aggnonce[SHIM_MUSIG_AGGNONCE_LEN]
);

int shim_musig_aggnonce_serialize(
    const secp256k1_context *ctx,
    const unsigned char aggnonce[SHIM_MUSIG_AGGNONCE_LEN],
    unsigned char output66[SHIM_MUSIG_AGGNONCE_SERIALIZED_LEN]
);

// Aggregates pubnonce_count signers' public nonces (each already parsed into
// the 132-byte internal form) into one aggregate nonce. This can be done by
// an untrusted party: an incorrectly computed aggregate only invalidates the
// resulting signature, it does not compromise anyone's key. Shares
// SHIM_MAX_COMBINE_PUBKEYS with shim_pubkey_combine as the participant cap,
// for the same fixed-stack-array reason.
int shim_musig_nonce_agg(
    const secp256k1_context *ctx,
    const unsigned char *pubnonces,
    size_t pubnonce_count,
    unsigned char aggnonce[SHIM_MUSIG_AGGNONCE_LEN]
);

// Combines the aggregate nonce with the message and the key-aggregation
// state into a session, the object every remaining step (signing,
// verifying, and aggregating partial signatures) is keyed off of.
int shim_musig_nonce_process(
    const secp256k1_context *ctx,
    const unsigned char aggnonce[SHIM_MUSIG_AGGNONCE_LEN],
    const unsigned char msg32[SHIM_MESSAGE_LEN],
    const unsigned char keyagg_cache[SHIM_MUSIG_KEYAGG_CACHE_LEN],
    unsigned char session[SHIM_MUSIG_SESSION_LEN]
);

/* ----------------------------------------------------- MuSig2 partial sig */

int shim_musig_partial_sig_parse(
    const secp256k1_context *ctx,
    const unsigned char input32[SHIM_MUSIG_PARTIAL_SIG_SERIALIZED_LEN],
    unsigned char partial_sig[SHIM_MUSIG_PARTIAL_SIG_LEN]
);

int shim_musig_partial_sig_serialize(
    const secp256k1_context *ctx,
    const unsigned char partial_sig[SHIM_MUSIG_PARTIAL_SIG_LEN],
    unsigned char output32[SHIM_MUSIG_PARTIAL_SIG_SERIALIZED_LEN]
);

// Produces this signer's partial signature for the session. secnonce is
// consumed: on return it is overwritten (by the upstream implementation,
// as a best-effort guard against reuse), and this call fails outright if
// handed a secnonce that is already all zeros — meaning it was already used
// here before. It must have been generated (via shim_musig_nonce_gen or
// shim_musig_nonce_gen_counter) for this same seckey and session, or the
// library's illegal_callback fires rather than this function returning 0.
//
// This does not verify its own output, matching upstream's deviation from
// the specification it implements; call shim_musig_partial_sig_verify on the
// result if computation errors (not just malice) are a concern.
int shim_musig_partial_sign(
    const secp256k1_context *ctx,
    unsigned char secnonce[SHIM_MUSIG_SECNONCE_LEN],
    const unsigned char seckey32[SHIM_SECKEY_LEN],
    const unsigned char keyagg_cache[SHIM_MUSIG_KEYAGG_CACHE_LEN],
    const unsigned char session[SHIM_MUSIG_SESSION_LEN],
    unsigned char partial_sig[SHIM_MUSIG_PARTIAL_SIG_LEN]
);

// Verifies one signer's partial signature within a specific session. Correct
// operation of a MuSig2 session does not require calling this — if any
// partial signature is wrong, the final aggregate signature will simply fail
// to verify — but this pinpoints which signer's contribution was at fault,
// which the aggregate-only check cannot.
//
// pubnonce and pubkey must be the exact ones that went into aggnonce (via
// shim_musig_nonce_agg) and keyagg_cache (via shim_musig_pubkey_agg)
// respectively for this signer; passing a mismatched pair does not
// necessarily fail loudly; it risks verifying against the wrong signing
// session entirely.
int shim_musig_partial_sig_verify(
    const secp256k1_context *ctx,
    const unsigned char partial_sig[SHIM_MUSIG_PARTIAL_SIG_LEN],
    const unsigned char pubnonce[SHIM_MUSIG_PUBNONCE_LEN],
    const unsigned char *pubkey,
    size_t pubkey_len,
    const unsigned char keyagg_cache[SHIM_MUSIG_KEYAGG_CACHE_LEN],
    const unsigned char session[SHIM_MUSIG_SESSION_LEN]
);

// Combines partial_sig_count signers' partial signatures into a complete
// Schnorr signature — verifiable the same way any other Schnorr signature is
// (shim_schnorr_verify), against the aggregate key from
// shim_musig_pubkey_agg. Success here does not mean the result verifies: a
// single bad partial signature (from a computation error, not necessarily
// malice — this does not require dishonesty) still combines into a
// signature that fails verification, which is exactly why
// shim_musig_partial_sig_verify exists as a way to isolate the culprit.
// Shares SHIM_MAX_COMBINE_PUBKEYS with shim_pubkey_combine as the
// participant cap.
int shim_musig_partial_sig_agg(
    const secp256k1_context *ctx,
    const unsigned char session[SHIM_MUSIG_SESSION_LEN],
    const unsigned char *partial_sigs,
    size_t partial_sig_count,
    unsigned char sig64[SHIM_SIGNATURE_COMPACT_LEN]
);

#endif /* NINJA_SECP256K1_SHIM_H */