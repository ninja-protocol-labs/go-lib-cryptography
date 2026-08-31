#ifndef NINJA_BLS12_381_SHIM_H
#define NINJA_BLS12_381_SHIM_H

#include <stddef.h>
#include <stdint.h>

#include "blst.h"

// This shim is the whole C surface the Go side is allowed to see. Like the
// secp256k1 shim, it exists so Go never holds a C struct, never frees
// anything, and never pays two cgo crossings for what is conceptually one
// operation.
//
// Two representations cross this boundary, and which one a function takes is
// a deliberate choice rather than an accident:
//
//   - Wire format — the Zcash-compatible serialization applications actually
//     exchange: 48/96 bytes for a compressed/serialized G1 point, 96/192 for
//     G2. Used by the one-shot entry points (key derivation, sign, verify,
//     aggregate), where the caller has bytes and wants bytes.
//   - Opaque point blobs — blst's own in-memory affine form (blst_p1_affine,
//     blst_p2_affine), carried as raw fixed-size byte arrays. These are plain
//     limb arrays with no internal pointers and no allocation behind them, so
//     copying them around as bytes is safe; sizes below are asserted against
//     the real sizeof rather than assumed. Used by the batch and low-level
//     APIs (pairing engine, Miller loop, multi-scalar multiplication) where
//     re-parsing wire format on every call would defeat the point of batching.
//
// Return convention:
//   - Functions that can only succeed return void.
//   - Predicates return int, 1 for true and 0 for false.
//   - Functions that parse or verify return int carrying a SHIM_ERR_* code,
//     which is BLST_ERROR passed through unchanged so Go can map it without
//     seeing the C enum.
//
// All buffers are caller-allocated. Nothing here retains a pointer past
// return, and nothing calls back into Go — which is what lets shim.go mark
// the entire surface #cgo noescape/nocallback.

// ---------------------------------------------------------------------------
// Sizes
// ---------------------------------------------------------------------------

// Wire (serialized) lengths, per the Zcash-compatible encoding.
#define SHIM_SCALAR_LEN 32
#define SHIM_P1_COMPRESSED_LEN 48
#define SHIM_P1_SERIALIZED_LEN 96
#define SHIM_P2_COMPRESSED_LEN 96
#define SHIM_P2_SERIALIZED_LEN 192

// Opaque in-memory blob lengths. These mirror blst's own structs; the
// _Static_asserts below keep them from drifting if blst is bumped.
#define SHIM_P1_AFFINE_LEN 96
#define SHIM_P2_AFFINE_LEN 192
#define SHIM_P1_LEN 144
#define SHIM_P2_LEN 288
#define SHIM_FP12_LEN 576

// Precomputed Miller-loop lines: blst_fp6[68].
#define SHIM_LINES_LEN 19584

_Static_assert(sizeof(blst_scalar) == SHIM_SCALAR_LEN, "blst_scalar size drift");
_Static_assert(sizeof(blst_p1_affine) == SHIM_P1_AFFINE_LEN, "blst_p1_affine size drift");
_Static_assert(sizeof(blst_p2_affine) == SHIM_P2_AFFINE_LEN, "blst_p2_affine size drift");
_Static_assert(sizeof(blst_p1) == SHIM_P1_LEN, "blst_p1 size drift");
_Static_assert(sizeof(blst_p2) == SHIM_P2_LEN, "blst_p2 size drift");
_Static_assert(sizeof(blst_fp12) == SHIM_FP12_LEN, "blst_fp12 size drift");
_Static_assert(sizeof(blst_fp6[68]) == SHIM_LINES_LEN, "blst_fp6[68] size drift");

// ---------------------------------------------------------------------------
// Error codes — BLST_ERROR passed through unchanged.
// ---------------------------------------------------------------------------

#define SHIM_ERR_SUCCESS 0
#define SHIM_ERR_BAD_ENCODING 1
#define SHIM_ERR_POINT_NOT_ON_CURVE 2
#define SHIM_ERR_POINT_NOT_IN_GROUP 3
#define SHIM_ERR_AGGR_TYPE_MISMATCH 4
#define SHIM_ERR_VERIFY_FAIL 5
#define SHIM_ERR_PK_IS_INFINITY 6
#define SHIM_ERR_BAD_SCALAR 7

// ---------------------------------------------------------------------------
// Secret keys and scalars
// ---------------------------------------------------------------------------

// shim_keygen derives a secret key from ikm (>= 32 bytes of keying material,
// per the IETF BLS draft's KeyGen) and an optional info string. out receives
// the 32-byte big-endian scalar.
void shim_keygen(
    byte out[SHIM_SCALAR_LEN],
    const byte *ikm,
    size_t ikm_len,
    const byte *info,
    size_t info_len
);

// shim_sk_check reports whether sk decodes to a usable secret key, meaning a
// scalar in [1, r-1]. Zero and anything at or above the group order fail.
int shim_sk_check(
    const byte sk[SHIM_SCALAR_LEN]
);

// shim_scalar_from_be_bytes reduces an arbitrary-length big-endian input into
// a scalar. Returns 1 on success, 0 if the input does not reduce to a usable
// value.
int shim_scalar_from_be_bytes(
    byte out[SHIM_SCALAR_LEN],
    const byte *in,
    size_t in_len
);

// shim_sk_add, shim_sk_sub and shim_sk_mul combine two secret keys modulo the
// group order. Each returns 1 on success, 0 if the result would be zero (and
// therefore not a usable key).
int shim_sk_add(
    byte out[SHIM_SCALAR_LEN],
    const byte a[SHIM_SCALAR_LEN],
    const byte b[SHIM_SCALAR_LEN]
);

int shim_sk_sub(
    byte out[SHIM_SCALAR_LEN],
    const byte a[SHIM_SCALAR_LEN],
    const byte b[SHIM_SCALAR_LEN]
);

int shim_sk_mul(
    byte out[SHIM_SCALAR_LEN],
    const byte a[SHIM_SCALAR_LEN],
    const byte b[SHIM_SCALAR_LEN]
);

// shim_sk_inverse computes the multiplicative inverse of a modulo the group
// order.
void shim_sk_inverse(
    byte out[SHIM_SCALAR_LEN],
    const byte a[SHIM_SCALAR_LEN]
);

// ---------------------------------------------------------------------------
// Public key derivation
//
// blst distinguishes the two specification variants by where the public key
// lives: _in_g1 is minimal-pubkey-size (48-byte pubkey in G1, 96-byte
// signature in G2), _in_g2 is minimal-signature-size (96-byte pubkey in G2,
// 48-byte signature in G1). That suffix convention is kept verbatim here so
// there is no second naming scheme to translate between.
// ---------------------------------------------------------------------------

void shim_sk_to_pk_in_g1_compressed(
    byte out[SHIM_P1_COMPRESSED_LEN],
    const byte sk[SHIM_SCALAR_LEN]
);

void shim_sk_to_pk_in_g1_serialized(
    byte out[SHIM_P1_SERIALIZED_LEN],
    const byte sk[SHIM_SCALAR_LEN]
);

void shim_sk_to_pk_in_g2_compressed(
    byte out[SHIM_P2_COMPRESSED_LEN],
    const byte sk[SHIM_SCALAR_LEN]
);

void shim_sk_to_pk_in_g2_serialized(
    byte out[SHIM_P2_SERIALIZED_LEN],
    const byte sk[SHIM_SCALAR_LEN]
);

// ---------------------------------------------------------------------------
// G1 points: wire format <-> opaque affine blob
// ---------------------------------------------------------------------------

// shim_p1_uncompress parses a 48-byte compressed point; shim_p1_deserialize
// parses the 96-byte uncompressed form. Both check the encoding and that the
// point is on the curve, but neither checks subgroup membership — call
// shim_p1_affine_in_g1 for that. Returns a SHIM_ERR_* code.
int shim_p1_uncompress(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte in[SHIM_P1_COMPRESSED_LEN]
);

int shim_p1_deserialize(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte in[SHIM_P1_SERIALIZED_LEN]
);

void shim_p1_affine_compress(
    byte out[SHIM_P1_COMPRESSED_LEN],
    const byte p[SHIM_P1_AFFINE_LEN]
);

void shim_p1_affine_serialize(
    byte out[SHIM_P1_SERIALIZED_LEN],
    const byte p[SHIM_P1_AFFINE_LEN]
);

int shim_p1_affine_on_curve(
    const byte p[SHIM_P1_AFFINE_LEN]
);

int shim_p1_affine_in_g1(
    const byte p[SHIM_P1_AFFINE_LEN]
);

int shim_p1_affine_is_inf(
    const byte p[SHIM_P1_AFFINE_LEN]
);

int shim_p1_affine_is_equal(
    const byte a[SHIM_P1_AFFINE_LEN],
    const byte b[SHIM_P1_AFFINE_LEN]
);

void shim_p1_affine_generator(
    byte out[SHIM_P1_AFFINE_LEN]
);

// ---------------------------------------------------------------------------
// G2 points: wire format <-> opaque affine blob
// ---------------------------------------------------------------------------

int shim_p2_uncompress(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte in[SHIM_P2_COMPRESSED_LEN]
);

int shim_p2_deserialize(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte in[SHIM_P2_SERIALIZED_LEN]
);

void shim_p2_affine_compress(
    byte out[SHIM_P2_COMPRESSED_LEN],
    const byte p[SHIM_P2_AFFINE_LEN]
);

void shim_p2_affine_serialize(
    byte out[SHIM_P2_SERIALIZED_LEN],
    const byte p[SHIM_P2_AFFINE_LEN]
);

int shim_p2_affine_on_curve(
    const byte p[SHIM_P2_AFFINE_LEN]
);

int shim_p2_affine_in_g2(
    const byte p[SHIM_P2_AFFINE_LEN]
);

int shim_p2_affine_is_inf(
    const byte p[SHIM_P2_AFFINE_LEN]
);

int shim_p2_affine_is_equal(
    const byte a[SHIM_P2_AFFINE_LEN],
    const byte b[SHIM_P2_AFFINE_LEN]
);

void shim_p2_affine_generator(
    byte out[SHIM_P2_AFFINE_LEN]
);

// ---------------------------------------------------------------------------
// Point arithmetic
//
// These take and return affine blobs; the projective form blst works in
// internally never crosses the boundary, so the Go side has one point
// representation rather than two.
// ---------------------------------------------------------------------------

void shim_p1_add(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte a[SHIM_P1_AFFINE_LEN],
    const byte b[SHIM_P1_AFFINE_LEN]
);

void shim_p1_double(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte a[SHIM_P1_AFFINE_LEN]
);

// shim_p1_mult multiplies p by an arbitrary-width big-endian scalar. nbits is
// the scalar's width in bits, not bytes.
void shim_p1_mult(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte p[SHIM_P1_AFFINE_LEN],
    const byte *scalar,
    size_t nbits
);

void shim_p1_neg(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte p[SHIM_P1_AFFINE_LEN]
);

void shim_p2_add(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte a[SHIM_P2_AFFINE_LEN],
    const byte b[SHIM_P2_AFFINE_LEN]
);

void shim_p2_double(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte a[SHIM_P2_AFFINE_LEN]
);

void shim_p2_mult(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte p[SHIM_P2_AFFINE_LEN],
    const byte *scalar,
    size_t nbits
);

void shim_p2_neg(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte p[SHIM_P2_AFFINE_LEN]
);

// ---------------------------------------------------------------------------
// Hash to curve
//
// hash_to_* implements the RFC 9380 hash-to-curve (uniform, indifferentiable
// from a random oracle); encode_to_* implements the cheaper
// encode-to-curve, which is not. Signature schemes want hash_to_*; encode_to_*
// is exposed because blst does and some protocols specify it.
//
// dst is the domain separation tag. aug is the optional augmentation prefix
// used by the "augmented" BLS scheme; pass NULL/0 when unused.
// ---------------------------------------------------------------------------

void shim_hash_to_g1(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte *msg,
    size_t msg_len,
    const byte *dst,
    size_t dst_len,
    const byte *aug,
    size_t aug_len
);

void shim_encode_to_g1(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte *msg,
    size_t msg_len,
    const byte *dst,
    size_t dst_len,
    const byte *aug,
    size_t aug_len
);

void shim_hash_to_g2(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte *msg,
    size_t msg_len,
    const byte *dst,
    size_t dst_len,
    const byte *aug,
    size_t aug_len
);

void shim_encode_to_g2(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte *msg,
    size_t msg_len,
    const byte *dst,
    size_t dst_len,
    const byte *aug,
    size_t aug_len
);

// ---------------------------------------------------------------------------
// Signing
//
// The _pk_in_g1 variant has its public key in G1 and therefore signs into G2;
// _pk_in_g2 is the mirror image. Each comes in two forms: one that takes an
// already-hashed point (so a caller doing its own hash-to-curve pays for it
// once) and a one-shot that hashes the message internally.
// ---------------------------------------------------------------------------

void shim_sign_pk_in_g1(
    byte out_sig[SHIM_P2_AFFINE_LEN],
    const byte hash[SHIM_P2_AFFINE_LEN],
    const byte sk[SHIM_SCALAR_LEN]
);

void shim_sign_pk_in_g2(
    byte out_sig[SHIM_P1_AFFINE_LEN],
    const byte hash[SHIM_P1_AFFINE_LEN],
    const byte sk[SHIM_SCALAR_LEN]
);

void shim_sign_msg_pk_in_g1(
    byte out_sig[SHIM_P2_COMPRESSED_LEN],
    const byte sk[SHIM_SCALAR_LEN],
    const byte *msg,
    size_t msg_len,
    const byte *dst,
    size_t dst_len,
    const byte *aug,
    size_t aug_len
);

void shim_sign_msg_pk_in_g2(
    byte out_sig[SHIM_P1_COMPRESSED_LEN],
    const byte sk[SHIM_SCALAR_LEN],
    const byte *msg,
    size_t msg_len,
    const byte *dst,
    size_t dst_len,
    const byte *aug,
    size_t aug_len
);

// ---------------------------------------------------------------------------
// One-shot verification
//
// hash_or_encode selects hash-to-curve (1) or encode-to-curve (0), matching
// the signer's choice. Returns a SHIM_ERR_* code; SHIM_ERR_SUCCESS means the
// signature is valid.
// ---------------------------------------------------------------------------

int shim_core_verify_pk_in_g1(
    const byte pk[SHIM_P1_AFFINE_LEN],
    const byte sig[SHIM_P2_AFFINE_LEN],
    int hash_or_encode,
    const byte *msg,
    size_t msg_len,
    const byte *dst,
    size_t dst_len,
    const byte *aug,
    size_t aug_len
);

int shim_core_verify_pk_in_g2(
    const byte pk[SHIM_P2_AFFINE_LEN],
    const byte sig[SHIM_P1_AFFINE_LEN],
    int hash_or_encode,
    const byte *msg,
    size_t msg_len,
    const byte *dst,
    size_t dst_len,
    const byte *aug,
    size_t aug_len
);

// ---------------------------------------------------------------------------
// Aggregation
//
// The _compressed forms take n points laid out contiguously (n * the
// compressed length) rather than an array of pointers, so Go can pass a
// single flat slice. blst's own pointer-array calling convention is built
// internally.
// ---------------------------------------------------------------------------

int shim_p1s_aggregate_compressed(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte *points,
    size_t n
);

int shim_p2s_aggregate_compressed(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte *points,
    size_t n
);

int shim_p1s_aggregate_affine(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte *points,
    size_t n
);

int shim_p2s_aggregate_affine(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte *points,
    size_t n
);

// ---------------------------------------------------------------------------
// Pairing engine
//
// The pairing context is opaque and its size is decided by the build, not by
// the specification — hence shim_pairing_sizeof rather than a constant. The
// Go side allocates that many bytes once and passes the buffer back in on
// every call; the shim never allocates.
//
// shim_pairing_init copies the DST into the caller's buffer immediately after
// the context (which is why the buffer must be sizeof + dst_len bytes), so
// the context never points at Go memory.
// ---------------------------------------------------------------------------

size_t shim_pairing_sizeof(void);

void shim_pairing_init(
    byte *ctx,
    int hash_or_encode,
    const byte *dst,
    size_t dst_len
);

void shim_pairing_commit(
    byte *ctx
);

int shim_pairing_merge(
    byte *ctx,
    const byte *ctx1
);

// shim_pairing_finalverify checks the accumulated pairing. gtsig may be NULL
// when signatures were aggregated into the context itself.
int shim_pairing_finalverify(
    const byte *ctx,
    const byte *gtsig
);

int shim_pairing_aggregate_pk_in_g1(
    byte *ctx,
    const byte pk[SHIM_P1_AFFINE_LEN],
    const byte *sig,
    const byte *msg,
    size_t msg_len,
    const byte *aug,
    size_t aug_len
);

int shim_pairing_aggregate_pk_in_g2(
    byte *ctx,
    const byte pk[SHIM_P2_AFFINE_LEN],
    const byte *sig,
    const byte *msg,
    size_t msg_len,
    const byte *aug,
    size_t aug_len
);

// The chk_n_ variants run the subgroup checks blst otherwise leaves to the
// caller, which is what you want for anything arriving off the wire.
int shim_pairing_chk_n_aggr_pk_in_g1(
    byte *ctx,
    const byte pk[SHIM_P1_AFFINE_LEN],
    int pk_grpchk,
    const byte *sig,
    int sig_grpchk,
    const byte *msg,
    size_t msg_len,
    const byte *aug,
    size_t aug_len
);

int shim_pairing_chk_n_aggr_pk_in_g2(
    byte *ctx,
    const byte pk[SHIM_P2_AFFINE_LEN],
    int pk_grpchk,
    const byte *sig,
    int sig_grpchk,
    const byte *msg,
    size_t msg_len,
    const byte *aug,
    size_t aug_len
);

// The mul_n_ variants fold in a random scalar per entry, which is what makes
// batch verification sound against an adversary who picked the signatures.
int shim_pairing_mul_n_aggregate_pk_in_g1(
    byte *ctx,
    const byte pk[SHIM_P1_AFFINE_LEN],
    const byte *sig,
    const byte *scalar,
    size_t nbits,
    const byte *msg,
    size_t msg_len,
    const byte *aug,
    size_t aug_len
);

int shim_pairing_mul_n_aggregate_pk_in_g2(
    byte *ctx,
    const byte pk[SHIM_P2_AFFINE_LEN],
    const byte *sig,
    const byte *scalar,
    size_t nbits,
    const byte *msg,
    size_t msg_len,
    const byte *aug,
    size_t aug_len
);

int shim_pairing_chk_n_mul_n_aggr_pk_in_g1(
    byte *ctx,
    const byte pk[SHIM_P1_AFFINE_LEN],
    int pk_grpchk,
    const byte *sig,
    int sig_grpchk,
    const byte *scalar,
    size_t nbits,
    const byte *msg,
    size_t msg_len,
    const byte *aug,
    size_t aug_len
);

int shim_pairing_chk_n_mul_n_aggr_pk_in_g2(
    byte *ctx,
    const byte pk[SHIM_P2_AFFINE_LEN],
    int pk_grpchk,
    const byte *sig,
    int sig_grpchk,
    const byte *scalar,
    size_t nbits,
    const byte *msg,
    size_t msg_len,
    const byte *aug,
    size_t aug_len
);

// ---------------------------------------------------------------------------
// Low-level pairing primitives
//
// Everything above is enough for signature schemes; these are for protocols
// that build their own pairing equations.
// ---------------------------------------------------------------------------

void shim_miller_loop(
    byte out[SHIM_FP12_LEN],
    const byte q[SHIM_P2_AFFINE_LEN],
    const byte p[SHIM_P1_AFFINE_LEN]
);

// shim_miller_loop_n takes n G2 and n G1 points laid out contiguously.
void shim_miller_loop_n(
    byte out[SHIM_FP12_LEN],
    const byte *qs,
    const byte *ps,
    size_t n
);

void shim_final_exp(
    byte out[SHIM_FP12_LEN],
    const byte f[SHIM_FP12_LEN]
);

// shim_precompute_lines caches the G2-dependent half of a Miller loop, so a
// fixed Q can be paired against many P without redoing it.
void shim_precompute_lines(
    byte out[SHIM_LINES_LEN],
    const byte q[SHIM_P2_AFFINE_LEN]
);

void shim_miller_loop_lines(
    byte out[SHIM_FP12_LEN],
    const byte lines[SHIM_LINES_LEN],
    const byte p[SHIM_P1_AFFINE_LEN]
);

// shim_fp12_finalverify compares two Miller-loop results after the final
// exponentiation, without materializing either exponentiation's result.
int shim_fp12_finalverify(
    const byte a[SHIM_FP12_LEN],
    const byte b[SHIM_FP12_LEN]
);

void shim_fp12_mul(
    byte out[SHIM_FP12_LEN],
    const byte a[SHIM_FP12_LEN],
    const byte b[SHIM_FP12_LEN]
);

void shim_fp12_sqr(
    byte out[SHIM_FP12_LEN],
    const byte a[SHIM_FP12_LEN]
);

void shim_fp12_inverse(
    byte out[SHIM_FP12_LEN],
    const byte a[SHIM_FP12_LEN]
);

void shim_fp12_one(
    byte out[SHIM_FP12_LEN]
);

int shim_fp12_is_one(
    const byte a[SHIM_FP12_LEN]
);

int shim_fp12_is_equal(
    const byte a[SHIM_FP12_LEN],
    const byte b[SHIM_FP12_LEN]
);

int shim_fp12_in_group(
    const byte a[SHIM_FP12_LEN]
);

// shim_aggregated_in_g1/g2 turn an aggregated signature into the GT element
// shim_pairing_finalverify expects as its gtsig argument.
void shim_aggregated_in_g1(
    byte out[SHIM_FP12_LEN],
    const byte sig[SHIM_P1_AFFINE_LEN]
);

void shim_aggregated_in_g2(
    byte out[SHIM_FP12_LEN],
    const byte sig[SHIM_P2_AFFINE_LEN]
);

// ---------------------------------------------------------------------------
// Multi-scalar multiplication
//
// Same buffer discipline as the pairing engine: the scratch space Pippenger's
// algorithm needs is sized by a _sizeof call and allocated by the caller.
// Points and scalars are contiguous flat arrays; nbits is the width of each
// scalar in bits.
// ---------------------------------------------------------------------------

size_t shim_p1s_mult_pippenger_scratch_sizeof(
    size_t npoints
);

void shim_p1s_mult_pippenger(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte *points,
    size_t npoints,
    const byte *scalars,
    size_t nbits,
    byte *scratch
);

size_t shim_p2s_mult_pippenger_scratch_sizeof(
    size_t npoints
);

void shim_p2s_mult_pippenger(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte *points,
    size_t npoints,
    const byte *scalars,
    size_t nbits,
    byte *scratch
);

#endif
