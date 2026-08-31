#include "shim.h"

// ---------------------------------------------------------------------------
// Secret keys and scalars
// ---------------------------------------------------------------------------

void shim_keygen(
    byte out[SHIM_SCALAR_LEN],
    const byte *ikm,
    size_t ikm_len,
    const byte *info,
    size_t info_len
) {
    blst_scalar sk;
    blst_keygen(&sk, ikm, ikm_len, info, info_len);
    blst_bendian_from_scalar(out, &sk);
}

int shim_sk_check(
    const byte sk[SHIM_SCALAR_LEN]
) {
    blst_scalar s;
    blst_scalar_from_bendian(&s, sk);
    return blst_sk_check(&s) ? 1 : 0;
}

int shim_scalar_from_be_bytes(
    byte out[SHIM_SCALAR_LEN],
    const byte *in,
    size_t in_len
) {
    blst_scalar s;
    if (!blst_scalar_from_be_bytes(&s, in, in_len)) {
        return 0;
    }
    blst_bendian_from_scalar(out, &s);
    return 1;
}

int shim_sk_add(
    byte out[SHIM_SCALAR_LEN],
    const byte a[SHIM_SCALAR_LEN],
    const byte b[SHIM_SCALAR_LEN]
) {
    blst_scalar sa, sb, sout;
    blst_scalar_from_bendian(&sa, a);
    blst_scalar_from_bendian(&sb, b);
    if (!blst_sk_add_n_check(&sout, &sa, &sb)) {
        return 0;
    }
    blst_bendian_from_scalar(out, &sout);
    return 1;
}

int shim_sk_sub(
    byte out[SHIM_SCALAR_LEN],
    const byte a[SHIM_SCALAR_LEN],
    const byte b[SHIM_SCALAR_LEN]
) {
    blst_scalar sa, sb, sout;
    blst_scalar_from_bendian(&sa, a);
    blst_scalar_from_bendian(&sb, b);
    if (!blst_sk_sub_n_check(&sout, &sa, &sb)) {
        return 0;
    }
    blst_bendian_from_scalar(out, &sout);
    return 1;
}

int shim_sk_mul(
    byte out[SHIM_SCALAR_LEN],
    const byte a[SHIM_SCALAR_LEN],
    const byte b[SHIM_SCALAR_LEN]
) {
    blst_scalar sa, sb, sout;
    blst_scalar_from_bendian(&sa, a);
    blst_scalar_from_bendian(&sb, b);
    if (!blst_sk_mul_n_check(&sout, &sa, &sb)) {
        return 0;
    }
    blst_bendian_from_scalar(out, &sout);
    return 1;
}

void shim_sk_inverse(
    byte out[SHIM_SCALAR_LEN],
    const byte a[SHIM_SCALAR_LEN]
) {
    blst_scalar sa, sout;
    blst_scalar_from_bendian(&sa, a);
    blst_sk_inverse(&sout, &sa);
    blst_bendian_from_scalar(out, &sout);
}

// ---------------------------------------------------------------------------
// Public key derivation
// ---------------------------------------------------------------------------

void shim_sk_to_pk_in_g1_compressed(
    byte out[SHIM_P1_COMPRESSED_LEN],
    const byte sk[SHIM_SCALAR_LEN]
) {
    blst_scalar s;
    blst_scalar_from_bendian(&s, sk);
    blst_p1 pk;
    blst_sk_to_pk_in_g1(&pk, &s);
    blst_p1_affine pk_affine;
    blst_p1_to_affine(&pk_affine, &pk);
    blst_p1_affine_compress(out, &pk_affine);
}

void shim_sk_to_pk_in_g1_serialized(
    byte out[SHIM_P1_SERIALIZED_LEN],
    const byte sk[SHIM_SCALAR_LEN]
) {
    blst_scalar s;
    blst_scalar_from_bendian(&s, sk);
    blst_p1 pk;
    blst_sk_to_pk_in_g1(&pk, &s);
    blst_p1_affine pk_affine;
    blst_p1_to_affine(&pk_affine, &pk);
    blst_p1_affine_serialize(out, &pk_affine);
}

void shim_sk_to_pk_in_g2_compressed(
    byte out[SHIM_P2_COMPRESSED_LEN],
    const byte sk[SHIM_SCALAR_LEN]
) {
    blst_scalar s;
    blst_scalar_from_bendian(&s, sk);
    blst_p2 pk;
    blst_sk_to_pk_in_g2(&pk, &s);
    blst_p2_affine pk_affine;
    blst_p2_to_affine(&pk_affine, &pk);
    blst_p2_affine_compress(out, &pk_affine);
}

void shim_sk_to_pk_in_g2_serialized(
    byte out[SHIM_P2_SERIALIZED_LEN],
    const byte sk[SHIM_SCALAR_LEN]
) {
    blst_scalar s;
    blst_scalar_from_bendian(&s, sk);
    blst_p2 pk;
    blst_sk_to_pk_in_g2(&pk, &s);
    blst_p2_affine pk_affine;
    blst_p2_to_affine(&pk_affine, &pk);
    blst_p2_affine_serialize(out, &pk_affine);
}

// ---------------------------------------------------------------------------
// G1 points: wire format <-> opaque affine blob
//
// The opaque blob functions cast the raw byte buffer straight to/from
// blst_p1_affine* rather than copying field-by-field: the struct is a plain
// limb array with no internal pointers (asserted in shim.h), so it's exactly
// its own byte representation, and Go never interprets the bytes itself —
// only shim.c ever dereferences them as blst_p1_affine.
// ---------------------------------------------------------------------------

int shim_p1_uncompress(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte in[SHIM_P1_COMPRESSED_LEN]
) {
    return (int)blst_p1_uncompress((blst_p1_affine *)out, in);
}

int shim_p1_deserialize(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte in[SHIM_P1_SERIALIZED_LEN]
) {
    return (int)blst_p1_deserialize((blst_p1_affine *)out, in);
}

void shim_p1_affine_compress(
    byte out[SHIM_P1_COMPRESSED_LEN],
    const byte p[SHIM_P1_AFFINE_LEN]
) {
    blst_p1_affine_compress(out, (const blst_p1_affine *)p);
}

void shim_p1_affine_serialize(
    byte out[SHIM_P1_SERIALIZED_LEN],
    const byte p[SHIM_P1_AFFINE_LEN]
) {
    blst_p1_affine_serialize(out, (const blst_p1_affine *)p);
}

int shim_p1_affine_on_curve(
    const byte p[SHIM_P1_AFFINE_LEN]
) {
    return blst_p1_affine_on_curve((const blst_p1_affine *)p) ? 1 : 0;
}

int shim_p1_affine_in_g1(
    const byte p[SHIM_P1_AFFINE_LEN]
) {
    return blst_p1_affine_in_g1((const blst_p1_affine *)p) ? 1 : 0;
}

int shim_p1_affine_is_inf(
    const byte p[SHIM_P1_AFFINE_LEN]
) {
    return blst_p1_affine_is_inf((const blst_p1_affine *)p) ? 1 : 0;
}

int shim_p1_affine_is_equal(
    const byte a[SHIM_P1_AFFINE_LEN],
    const byte b[SHIM_P1_AFFINE_LEN]
) {
    return blst_p1_affine_is_equal(
        (const blst_p1_affine *)a,
        (const blst_p1_affine *)b
    ) ? 1 : 0;
}

void shim_p1_affine_generator(
    byte out[SHIM_P1_AFFINE_LEN]
) {
    *(blst_p1_affine *)out = *blst_p1_affine_generator();
}

// ---------------------------------------------------------------------------
// G2 points: wire format <-> opaque affine blob
// ---------------------------------------------------------------------------

int shim_p2_uncompress(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte in[SHIM_P2_COMPRESSED_LEN]
) {
    return (int)blst_p2_uncompress((blst_p2_affine *)out, in);
}

int shim_p2_deserialize(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte in[SHIM_P2_SERIALIZED_LEN]
) {
    return (int)blst_p2_deserialize((blst_p2_affine *)out, in);
}

void shim_p2_affine_compress(
    byte out[SHIM_P2_COMPRESSED_LEN],
    const byte p[SHIM_P2_AFFINE_LEN]
) {
    blst_p2_affine_compress(out, (const blst_p2_affine *)p);
}

void shim_p2_affine_serialize(
    byte out[SHIM_P2_SERIALIZED_LEN],
    const byte p[SHIM_P2_AFFINE_LEN]
) {
    blst_p2_affine_serialize(out, (const blst_p2_affine *)p);
}

int shim_p2_affine_on_curve(
    const byte p[SHIM_P2_AFFINE_LEN]
) {
    return blst_p2_affine_on_curve((const blst_p2_affine *)p) ? 1 : 0;
}

int shim_p2_affine_in_g2(
    const byte p[SHIM_P2_AFFINE_LEN]
) {
    return blst_p2_affine_in_g2((const blst_p2_affine *)p) ? 1 : 0;
}

int shim_p2_affine_is_inf(
    const byte p[SHIM_P2_AFFINE_LEN]
) {
    return blst_p2_affine_is_inf((const blst_p2_affine *)p) ? 1 : 0;
}

int shim_p2_affine_is_equal(
    const byte a[SHIM_P2_AFFINE_LEN],
    const byte b[SHIM_P2_AFFINE_LEN]
) {
    return blst_p2_affine_is_equal(
        (const blst_p2_affine *)a,
        (const blst_p2_affine *)b
    ) ? 1 : 0;
}

void shim_p2_affine_generator(
    byte out[SHIM_P2_AFFINE_LEN]
) {
    *(blst_p2_affine *)out = *blst_p2_affine_generator();
}

// ---------------------------------------------------------------------------
// Point arithmetic
// ---------------------------------------------------------------------------

void shim_p1_add(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte a[SHIM_P1_AFFINE_LEN],
    const byte b[SHIM_P1_AFFINE_LEN]
) {
    blst_p1 pa, pout;
    blst_p1_from_affine(&pa, (const blst_p1_affine *)a);
    blst_p1_add_or_double_affine(&pout, &pa, (const blst_p1_affine *)b);
    blst_p1_to_affine((blst_p1_affine *)out, &pout);
}

void shim_p1_double(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte a[SHIM_P1_AFFINE_LEN]
) {
    blst_p1 pa, pout;
    blst_p1_from_affine(&pa, (const blst_p1_affine *)a);
    blst_p1_double(&pout, &pa);
    blst_p1_to_affine((blst_p1_affine *)out, &pout);
}

void shim_p1_mult(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte p[SHIM_P1_AFFINE_LEN],
    const byte *scalar,
    size_t nbits
) {
    blst_p1 pp, pout;
    blst_p1_from_affine(&pp, (const blst_p1_affine *)p);
    blst_p1_mult(&pout, &pp, scalar, nbits);
    blst_p1_to_affine((blst_p1_affine *)out, &pout);
}

void shim_p1_neg(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte p[SHIM_P1_AFFINE_LEN]
) {
    blst_p1 pp;
    blst_p1_from_affine(&pp, (const blst_p1_affine *)p);
    blst_p1_cneg(&pp, 1);
    blst_p1_to_affine((blst_p1_affine *)out, &pp);
}

void shim_p2_add(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte a[SHIM_P2_AFFINE_LEN],
    const byte b[SHIM_P2_AFFINE_LEN]
) {
    blst_p2 pa, pout;
    blst_p2_from_affine(&pa, (const blst_p2_affine *)a);
    blst_p2_add_or_double_affine(&pout, &pa, (const blst_p2_affine *)b);
    blst_p2_to_affine((blst_p2_affine *)out, &pout);
}

void shim_p2_double(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte a[SHIM_P2_AFFINE_LEN]
) {
    blst_p2 pa, pout;
    blst_p2_from_affine(&pa, (const blst_p2_affine *)a);
    blst_p2_double(&pout, &pa);
    blst_p2_to_affine((blst_p2_affine *)out, &pout);
}

void shim_p2_mult(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte p[SHIM_P2_AFFINE_LEN],
    const byte *scalar,
    size_t nbits
) {
    blst_p2 pp, pout;
    blst_p2_from_affine(&pp, (const blst_p2_affine *)p);
    blst_p2_mult(&pout, &pp, scalar, nbits);
    blst_p2_to_affine((blst_p2_affine *)out, &pout);
}

void shim_p2_neg(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte p[SHIM_P2_AFFINE_LEN]
) {
    blst_p2 pp;
    blst_p2_from_affine(&pp, (const blst_p2_affine *)p);
    blst_p2_cneg(&pp, 1);
    blst_p2_to_affine((blst_p2_affine *)out, &pp);
}

// ---------------------------------------------------------------------------
// Hash to curve
// ---------------------------------------------------------------------------

void shim_hash_to_g1(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte *msg,
    size_t msg_len,
    const byte *dst,
    size_t dst_len,
    const byte *aug,
    size_t aug_len
) {
    blst_p1 p;
    blst_hash_to_g1(&p, msg, msg_len, dst, dst_len, aug, aug_len);
    blst_p1_to_affine((blst_p1_affine *)out, &p);
}

void shim_encode_to_g1(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte *msg,
    size_t msg_len,
    const byte *dst,
    size_t dst_len,
    const byte *aug,
    size_t aug_len
) {
    blst_p1 p;
    blst_encode_to_g1(&p, msg, msg_len, dst, dst_len, aug, aug_len);
    blst_p1_to_affine((blst_p1_affine *)out, &p);
}

void shim_hash_to_g2(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte *msg,
    size_t msg_len,
    const byte *dst,
    size_t dst_len,
    const byte *aug,
    size_t aug_len
) {
    blst_p2 p;
    blst_hash_to_g2(&p, msg, msg_len, dst, dst_len, aug, aug_len);
    blst_p2_to_affine((blst_p2_affine *)out, &p);
}

void shim_encode_to_g2(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte *msg,
    size_t msg_len,
    const byte *dst,
    size_t dst_len,
    const byte *aug,
    size_t aug_len
) {
    blst_p2 p;
    blst_encode_to_g2(&p, msg, msg_len, dst, dst_len, aug, aug_len);
    blst_p2_to_affine((blst_p2_affine *)out, &p);
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

void shim_sign_pk_in_g1(
    byte out_sig[SHIM_P2_AFFINE_LEN],
    const byte hash[SHIM_P2_AFFINE_LEN],
    const byte sk[SHIM_SCALAR_LEN]
) {
    blst_scalar s;
    blst_scalar_from_bendian(&s, sk);
    blst_p2 h, sig;
    blst_p2_from_affine(&h, (const blst_p2_affine *)hash);
    blst_sign_pk_in_g1(&sig, &h, &s);
    blst_p2_to_affine((blst_p2_affine *)out_sig, &sig);
}

void shim_sign_pk_in_g2(
    byte out_sig[SHIM_P1_AFFINE_LEN],
    const byte hash[SHIM_P1_AFFINE_LEN],
    const byte sk[SHIM_SCALAR_LEN]
) {
    blst_scalar s;
    blst_scalar_from_bendian(&s, sk);
    blst_p1 h, sig;
    blst_p1_from_affine(&h, (const blst_p1_affine *)hash);
    blst_sign_pk_in_g2(&sig, &h, &s);
    blst_p1_to_affine((blst_p1_affine *)out_sig, &sig);
}

void shim_sign_msg_pk_in_g1(
    byte out_sig[SHIM_P2_COMPRESSED_LEN],
    const byte sk[SHIM_SCALAR_LEN],
    const byte *msg,
    size_t msg_len,
    const byte *dst,
    size_t dst_len,
    const byte *aug,
    size_t aug_len
) {
    blst_scalar s;
    blst_scalar_from_bendian(&s, sk);
    blst_p2 h, sig;
    blst_hash_to_g2(&h, msg, msg_len, dst, dst_len, aug, aug_len);
    blst_sign_pk_in_g1(&sig, &h, &s);
    blst_p2_affine sig_affine;
    blst_p2_to_affine(&sig_affine, &sig);
    blst_p2_affine_compress(out_sig, &sig_affine);
}

void shim_sign_msg_pk_in_g2(
    byte out_sig[SHIM_P1_COMPRESSED_LEN],
    const byte sk[SHIM_SCALAR_LEN],
    const byte *msg,
    size_t msg_len,
    const byte *dst,
    size_t dst_len,
    const byte *aug,
    size_t aug_len
) {
    blst_scalar s;
    blst_scalar_from_bendian(&s, sk);
    blst_p1 h, sig;
    blst_hash_to_g1(&h, msg, msg_len, dst, dst_len, aug, aug_len);
    blst_sign_pk_in_g2(&sig, &h, &s);
    blst_p1_affine sig_affine;
    blst_p1_to_affine(&sig_affine, &sig);
    blst_p1_affine_compress(out_sig, &sig_affine);
}

// ---------------------------------------------------------------------------
// One-shot verification
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
) {
    return (int)blst_core_verify_pk_in_g1(
        (const blst_p1_affine *)pk,
        (const blst_p2_affine *)sig,
        hash_or_encode ? 1 : 0,
        msg, msg_len,
        dst, dst_len,
        aug, aug_len
    );
}

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
) {
    return (int)blst_core_verify_pk_in_g2(
        (const blst_p2_affine *)pk,
        (const blst_p1_affine *)sig,
        hash_or_encode ? 1 : 0,
        msg, msg_len,
        dst, dst_len,
        aug, aug_len
    );
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

int shim_p1s_aggregate_compressed(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte *points,
    size_t n
) {
    if (n == 0) {
        return (int)BLST_AGGR_TYPE_MISMATCH;
    }

    blst_p1_affine first;
    BLST_ERROR err = blst_p1_uncompress(&first, points);
    if (err != BLST_SUCCESS) {
        return (int)err;
    }
    if (!blst_p1_affine_in_g1(&first)) {
        return (int)BLST_POINT_NOT_IN_GROUP;
    }
    blst_p1 acc;
    blst_p1_from_affine(&acc, &first);

    for (size_t i = 1; i < n; i++) {
        blst_p1_affine pa;
        err = blst_p1_uncompress(&pa, points + i * SHIM_P1_COMPRESSED_LEN);
        if (err != BLST_SUCCESS) {
            return (int)err;
        }
        if (!blst_p1_affine_in_g1(&pa)) {
            return (int)BLST_POINT_NOT_IN_GROUP;
        }
        blst_p1_add_or_double_affine(&acc, &acc, &pa);
    }

    blst_p1_to_affine((blst_p1_affine *)out, &acc);
    return (int)BLST_SUCCESS;
}

int shim_p2s_aggregate_compressed(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte *points,
    size_t n
) {
    if (n == 0) {
        return (int)BLST_AGGR_TYPE_MISMATCH;
    }

    blst_p2_affine first;
    BLST_ERROR err = blst_p2_uncompress(&first, points);
    if (err != BLST_SUCCESS) {
        return (int)err;
    }
    if (!blst_p2_affine_in_g2(&first)) {
        return (int)BLST_POINT_NOT_IN_GROUP;
    }
    blst_p2 acc;
    blst_p2_from_affine(&acc, &first);

    for (size_t i = 1; i < n; i++) {
        blst_p2_affine pa;
        err = blst_p2_uncompress(&pa, points + i * SHIM_P2_COMPRESSED_LEN);
        if (err != BLST_SUCCESS) {
            return (int)err;
        }
        if (!blst_p2_affine_in_g2(&pa)) {
            return (int)BLST_POINT_NOT_IN_GROUP;
        }
        blst_p2_add_or_double_affine(&acc, &acc, &pa);
    }

    blst_p2_to_affine((blst_p2_affine *)out, &acc);
    return (int)BLST_SUCCESS;
}

int shim_p1s_aggregate_affine(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte *points,
    size_t n
) {
    if (n == 0) {
        return (int)BLST_AGGR_TYPE_MISMATCH;
    }
    blst_p1 acc;
    blst_p1_from_affine(&acc, (const blst_p1_affine *)points);
    for (size_t i = 1; i < n; i++) {
        const blst_p1_affine *pa =
            (const blst_p1_affine *)(points + i * SHIM_P1_AFFINE_LEN);
        blst_p1_add_or_double_affine(&acc, &acc, pa);
    }
    blst_p1_to_affine((blst_p1_affine *)out, &acc);
    return (int)BLST_SUCCESS;
}

int shim_p2s_aggregate_affine(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte *points,
    size_t n
) {
    if (n == 0) {
        return (int)BLST_AGGR_TYPE_MISMATCH;
    }
    blst_p2 acc;
    blst_p2_from_affine(&acc, (const blst_p2_affine *)points);
    for (size_t i = 1; i < n; i++) {
        const blst_p2_affine *pa =
            (const blst_p2_affine *)(points + i * SHIM_P2_AFFINE_LEN);
        blst_p2_add_or_double_affine(&acc, &acc, pa);
    }
    blst_p2_to_affine((blst_p2_affine *)out, &acc);
    return (int)BLST_SUCCESS;
}

// ---------------------------------------------------------------------------
// Pairing engine
// ---------------------------------------------------------------------------

size_t shim_pairing_sizeof(void) {
    return blst_pairing_sizeof();
}

void shim_pairing_init(
    byte *ctx,
    int hash_or_encode,
    const byte *dst,
    size_t dst_len
) {
    // blst_pairing_init stores the DST pointer as-is — it does not copy it —
    // and every aggregate call reads it back through that stored pointer for
    // the lifetime of the session. If dst pointed into Go memory, the context
    // would retain a live Go pointer past this call's return, which is
    // exactly what #cgo noescape below promises never happens. So, matching
    // blst's own Go binding (go_pairing_init in its cgo preamble), the bytes
    // are copied into the space right after the context — which callers are
    // required to allocate for exactly this — before blst ever sees them;
    // the pointer blst stores from here on is into this C-owned buffer, not
    // into Go's.
    if (dst != NULL) {
        byte *dst_copy = ctx + blst_pairing_sizeof();
        for (size_t i = 0; i < dst_len; i++) {
            dst_copy[i] = dst[i];
        }
        dst = dst_copy;
    }
    blst_pairing_init((blst_pairing *)ctx, hash_or_encode ? 1 : 0, dst, dst_len);
}

void shim_pairing_commit(
    byte *ctx
) {
    blst_pairing_commit((blst_pairing *)ctx);
}

int shim_pairing_merge(
    byte *ctx,
    const byte *ctx1
) {
    return (int)blst_pairing_merge((blst_pairing *)ctx, (const blst_pairing *)ctx1);
}

int shim_pairing_finalverify(
    const byte *ctx,
    const byte *gtsig
) {
    return blst_pairing_finalverify(
        (const blst_pairing *)ctx,
        gtsig ? (const blst_fp12 *)gtsig : NULL
    ) ? 1 : 0;
}

int shim_pairing_aggregate_pk_in_g1(
    byte *ctx,
    const byte pk[SHIM_P1_AFFINE_LEN],
    const byte *sig,
    const byte *msg,
    size_t msg_len,
    const byte *aug,
    size_t aug_len
) {
    return (int)blst_pairing_aggregate_pk_in_g1(
        (blst_pairing *)ctx,
        (const blst_p1_affine *)pk,
        sig ? (const blst_p2_affine *)sig : NULL,
        msg, msg_len,
        aug, aug_len
    );
}

int shim_pairing_aggregate_pk_in_g2(
    byte *ctx,
    const byte pk[SHIM_P2_AFFINE_LEN],
    const byte *sig,
    const byte *msg,
    size_t msg_len,
    const byte *aug,
    size_t aug_len
) {
    return (int)blst_pairing_aggregate_pk_in_g2(
        (blst_pairing *)ctx,
        (const blst_p2_affine *)pk,
        sig ? (const blst_p1_affine *)sig : NULL,
        msg, msg_len,
        aug, aug_len
    );
}

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
) {
    return (int)blst_pairing_chk_n_aggr_pk_in_g1(
        (blst_pairing *)ctx,
        (const blst_p1_affine *)pk, pk_grpchk ? 1 : 0,
        sig ? (const blst_p2_affine *)sig : NULL, sig_grpchk ? 1 : 0,
        msg, msg_len,
        aug, aug_len
    );
}

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
) {
    return (int)blst_pairing_chk_n_aggr_pk_in_g2(
        (blst_pairing *)ctx,
        (const blst_p2_affine *)pk, pk_grpchk ? 1 : 0,
        sig ? (const blst_p1_affine *)sig : NULL, sig_grpchk ? 1 : 0,
        msg, msg_len,
        aug, aug_len
    );
}

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
) {
    return (int)blst_pairing_mul_n_aggregate_pk_in_g1(
        (blst_pairing *)ctx,
        (const blst_p1_affine *)pk,
        sig ? (const blst_p2_affine *)sig : NULL,
        scalar, nbits,
        msg, msg_len,
        aug, aug_len
    );
}

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
) {
    return (int)blst_pairing_mul_n_aggregate_pk_in_g2(
        (blst_pairing *)ctx,
        (const blst_p2_affine *)pk,
        sig ? (const blst_p1_affine *)sig : NULL,
        scalar, nbits,
        msg, msg_len,
        aug, aug_len
    );
}

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
) {
    return (int)blst_pairing_chk_n_mul_n_aggr_pk_in_g1(
        (blst_pairing *)ctx,
        (const blst_p1_affine *)pk, pk_grpchk ? 1 : 0,
        sig ? (const blst_p2_affine *)sig : NULL, sig_grpchk ? 1 : 0,
        scalar, nbits,
        msg, msg_len,
        aug, aug_len
    );
}

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
) {
    return (int)blst_pairing_chk_n_mul_n_aggr_pk_in_g2(
        (blst_pairing *)ctx,
        (const blst_p2_affine *)pk, pk_grpchk ? 1 : 0,
        sig ? (const blst_p1_affine *)sig : NULL, sig_grpchk ? 1 : 0,
        scalar, nbits,
        msg, msg_len,
        aug, aug_len
    );
}

// ---------------------------------------------------------------------------
// Low-level pairing primitives
// ---------------------------------------------------------------------------

void shim_miller_loop(
    byte out[SHIM_FP12_LEN],
    const byte q[SHIM_P2_AFFINE_LEN],
    const byte p[SHIM_P1_AFFINE_LEN]
) {
    blst_miller_loop(
        (blst_fp12 *)out,
        (const blst_p2_affine *)q,
        (const blst_p1_affine *)p
    );
}

void shim_miller_loop_n(
    byte out[SHIM_FP12_LEN],
    const byte *qs,
    const byte *ps,
    size_t n
) {
    // blst_miller_loop_n wants NULL-terminated arrays of pointers, not flat
    // buffers, so the pointer arrays are built here rather than pushing that
    // convention across the cgo boundary.
    const blst_p2_affine **q_ptrs =
        __builtin_alloca((n + 1) * sizeof(blst_p2_affine *));
    const blst_p1_affine **p_ptrs =
        __builtin_alloca((n + 1) * sizeof(blst_p1_affine *));
    for (size_t i = 0; i < n; i++) {
        q_ptrs[i] = (const blst_p2_affine *)(qs + i * SHIM_P2_AFFINE_LEN);
        p_ptrs[i] = (const blst_p1_affine *)(ps + i * SHIM_P1_AFFINE_LEN);
    }
    q_ptrs[n] = NULL;
    p_ptrs[n] = NULL;
    blst_miller_loop_n((blst_fp12 *)out, q_ptrs, p_ptrs, n);
}

void shim_final_exp(
    byte out[SHIM_FP12_LEN],
    const byte f[SHIM_FP12_LEN]
) {
    blst_final_exp((blst_fp12 *)out, (const blst_fp12 *)f);
}

void shim_precompute_lines(
    byte out[SHIM_LINES_LEN],
    const byte q[SHIM_P2_AFFINE_LEN]
) {
    blst_precompute_lines((blst_fp6 *)out, (const blst_p2_affine *)q);
}

void shim_miller_loop_lines(
    byte out[SHIM_FP12_LEN],
    const byte lines[SHIM_LINES_LEN],
    const byte p[SHIM_P1_AFFINE_LEN]
) {
    blst_miller_loop_lines(
        (blst_fp12 *)out,
        (const blst_fp6 *)lines,
        (const blst_p1_affine *)p
    );
}

int shim_fp12_finalverify(
    const byte a[SHIM_FP12_LEN],
    const byte b[SHIM_FP12_LEN]
) {
    return blst_fp12_finalverify(
        (const blst_fp12 *)a,
        (const blst_fp12 *)b
    ) ? 1 : 0;
}

void shim_fp12_mul(
    byte out[SHIM_FP12_LEN],
    const byte a[SHIM_FP12_LEN],
    const byte b[SHIM_FP12_LEN]
) {
    blst_fp12_mul((blst_fp12 *)out, (const blst_fp12 *)a, (const blst_fp12 *)b);
}

void shim_fp12_sqr(
    byte out[SHIM_FP12_LEN],
    const byte a[SHIM_FP12_LEN]
) {
    blst_fp12_sqr((blst_fp12 *)out, (const blst_fp12 *)a);
}

void shim_fp12_inverse(
    byte out[SHIM_FP12_LEN],
    const byte a[SHIM_FP12_LEN]
) {
    blst_fp12_inverse((blst_fp12 *)out, (const blst_fp12 *)a);
}

void shim_fp12_one(
    byte out[SHIM_FP12_LEN]
) {
    *(blst_fp12 *)out = *blst_fp12_one();
}

int shim_fp12_is_one(
    const byte a[SHIM_FP12_LEN]
) {
    return blst_fp12_is_one((const blst_fp12 *)a) ? 1 : 0;
}

int shim_fp12_is_equal(
    const byte a[SHIM_FP12_LEN],
    const byte b[SHIM_FP12_LEN]
) {
    return blst_fp12_is_equal((const blst_fp12 *)a, (const blst_fp12 *)b) ? 1 : 0;
}

int shim_fp12_in_group(
    const byte a[SHIM_FP12_LEN]
) {
    return blst_fp12_in_group((const blst_fp12 *)a) ? 1 : 0;
}

void shim_aggregated_in_g1(
    byte out[SHIM_FP12_LEN],
    const byte sig[SHIM_P1_AFFINE_LEN]
) {
    blst_aggregated_in_g1((blst_fp12 *)out, (const blst_p1_affine *)sig);
}

void shim_aggregated_in_g2(
    byte out[SHIM_FP12_LEN],
    const byte sig[SHIM_P2_AFFINE_LEN]
) {
    blst_aggregated_in_g2((blst_fp12 *)out, (const blst_p2_affine *)sig);
}

// ---------------------------------------------------------------------------
// Multi-scalar multiplication
// ---------------------------------------------------------------------------

size_t shim_p1s_mult_pippenger_scratch_sizeof(
    size_t npoints
) {
    return blst_p1s_mult_pippenger_scratch_sizeof(npoints);
}

void shim_p1s_mult_pippenger(
    byte out[SHIM_P1_AFFINE_LEN],
    const byte *points,
    size_t npoints,
    const byte *scalars,
    size_t nbits,
    byte *scratch
) {
    const blst_p1_affine **point_ptrs =
        __builtin_alloca((npoints + 1) * sizeof(blst_p1_affine *));
    const byte **scalar_ptrs =
        __builtin_alloca((npoints + 1) * sizeof(byte *));
    size_t scalar_stride = (nbits + 7) / 8;
    for (size_t i = 0; i < npoints; i++) {
        point_ptrs[i] = (const blst_p1_affine *)(points + i * SHIM_P1_AFFINE_LEN);
        scalar_ptrs[i] = scalars + i * scalar_stride;
    }
    point_ptrs[npoints] = NULL;
    scalar_ptrs[npoints] = NULL;

    blst_p1 ret;
    blst_p1s_mult_pippenger(
        &ret, point_ptrs, npoints, scalar_ptrs, nbits, (limb_t *)scratch
    );
    blst_p1_to_affine((blst_p1_affine *)out, &ret);
}

size_t shim_p2s_mult_pippenger_scratch_sizeof(
    size_t npoints
) {
    return blst_p2s_mult_pippenger_scratch_sizeof(npoints);
}

void shim_p2s_mult_pippenger(
    byte out[SHIM_P2_AFFINE_LEN],
    const byte *points,
    size_t npoints,
    const byte *scalars,
    size_t nbits,
    byte *scratch
) {
    const blst_p2_affine **point_ptrs =
        __builtin_alloca((npoints + 1) * sizeof(blst_p2_affine *));
    const byte **scalar_ptrs =
        __builtin_alloca((npoints + 1) * sizeof(byte *));
    size_t scalar_stride = (nbits + 7) / 8;
    for (size_t i = 0; i < npoints; i++) {
        point_ptrs[i] = (const blst_p2_affine *)(points + i * SHIM_P2_AFFINE_LEN);
        scalar_ptrs[i] = scalars + i * scalar_stride;
    }
    point_ptrs[npoints] = NULL;
    scalar_ptrs[npoints] = NULL;

    blst_p2 ret;
    blst_p2s_mult_pippenger(
        &ret, point_ptrs, npoints, scalar_ptrs, nbits, (limb_t *)scratch
    );
    blst_p2_to_affine((blst_p2_affine *)out, &ret);
}