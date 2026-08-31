package internal

/*
#include "shim.h"
*/
import "C"

// Pairing engine + low-level pairing primitives. Everything through
// PairingChkNMulNAggrPkInG2 is enough for signature schemes (single or
// batch verification); MillerLoop and below are for protocols that build
// their own pairing equations.
//
// The pairing context is opaque and its size is decided by the build, not
// by the spec, so PairingSizeof tells the caller how big a []byte to
// allocate; PairingInit copies dst into the space right after it (see
// shim_pairing_init's doc comment in shim.h), so ctx must be at least
// PairingSizeof()+len(dst) bytes.

// PairingSizeof returns the size in bytes of a pairing context.
func PairingSizeof() int {
	return int(C.shim_pairing_sizeof())
}

// PairingInit initializes ctx (at least PairingSizeof()+len(dst) bytes) for
// a new pairing session. hashOrEncode selects hash-to-curve (true) or
// encode-to-curve (false) for every aggregate call made against this ctx.
func PairingInit(ctx []byte, hashOrEncode bool, dst []byte) {
	var dstPtr *C.byte
	if len(dst) > 0 {
		dstPtr = (*C.byte)(&dst[0])
	}
	var hoe C.int
	if hashOrEncode {
		hoe = 1
	}
	C.shim_pairing_init((*C.byte)(&ctx[0]), hoe, dstPtr, C.size_t(len(dst)))
}

// PairingCommit finalizes ctx's accumulated Miller loop products, required
// before PairingFinalVerify or PairingMerge.
func PairingCommit(ctx []byte) {
	C.shim_pairing_commit((*C.byte)(&ctx[0]))
}

// PairingMerge folds ctx1 (already committed) into ctx. Returns one of the
// Err* codes in shim.go.
func PairingMerge(ctx, ctx1 []byte) int {
	return int(C.shim_pairing_merge((*C.byte)(&ctx[0]), (*C.byte)(&ctx1[0])))
}

// PairingFinalVerify checks ctx's accumulated pairing. gtsig is the
// GT-element form of a signature aggregated separately from ctx (see
// AggregatedInG1/AggregatedInG2); pass nil when every signature was folded
// into ctx by the aggregate calls instead.
func PairingFinalVerify(ctx []byte, gtsig *[Fp12Len]byte) bool {
	var gtsigPtr *C.byte
	if gtsig != nil {
		gtsigPtr = (*C.byte)(&gtsig[0])
	}
	return C.shim_pairing_finalverify((*C.byte)(&ctx[0]), gtsigPtr) == 1
}

// PairingAggregatePkInG1 aggregates one pk/sig/message triple into ctx, for
// the pk-in-G1 scheme. sig may be nil to aggregate only the pk side (e.g.
// when the caller supplies gtsig to PairingFinalVerify separately). Returns
// one of the Err* codes in shim.go.
func PairingAggregatePkInG1(ctx []byte, pk *[P1AffineLen]byte, sig, msg, aug []byte) int {
	var sigPtr, msgPtr, augPtr *C.byte
	if len(sig) > 0 {
		sigPtr = (*C.byte)(&sig[0])
	}
	if len(msg) > 0 {
		msgPtr = (*C.byte)(&msg[0])
	}
	if len(aug) > 0 {
		augPtr = (*C.byte)(&aug[0])
	}
	code := C.shim_pairing_aggregate_pk_in_g1(
		(*C.byte)(&ctx[0]), (*C.byte)(&pk[0]),
		sigPtr, msgPtr, C.size_t(len(msg)), augPtr, C.size_t(len(aug)),
	)
	return int(code)
}

// PairingAggregatePkInG2 is PairingAggregatePkInG1's mirror in G2.
func PairingAggregatePkInG2(ctx []byte, pk *[P2AffineLen]byte, sig, msg, aug []byte) int {
	var sigPtr, msgPtr, augPtr *C.byte
	if len(sig) > 0 {
		sigPtr = (*C.byte)(&sig[0])
	}
	if len(msg) > 0 {
		msgPtr = (*C.byte)(&msg[0])
	}
	if len(aug) > 0 {
		augPtr = (*C.byte)(&aug[0])
	}
	code := C.shim_pairing_aggregate_pk_in_g2(
		(*C.byte)(&ctx[0]), (*C.byte)(&pk[0]),
		sigPtr, msgPtr, C.size_t(len(msg)), augPtr, C.size_t(len(aug)),
	)
	return int(code)
}

// PairingChkNAggrPkInG1 is PairingAggregatePkInG1 plus the subgroup checks
// blst otherwise leaves to the caller — what anything arriving off the wire
// wants.
func PairingChkNAggrPkInG1(ctx []byte, pk *[P1AffineLen]byte, pkGrpchk bool, sig []byte, sigGrpchk bool, msg, aug []byte) int {
	var sigPtr, msgPtr, augPtr *C.byte
	if len(sig) > 0 {
		sigPtr = (*C.byte)(&sig[0])
	}
	if len(msg) > 0 {
		msgPtr = (*C.byte)(&msg[0])
	}
	if len(aug) > 0 {
		augPtr = (*C.byte)(&aug[0])
	}
	var pkChk, sigChk C.int
	if pkGrpchk {
		pkChk = 1
	}
	if sigGrpchk {
		sigChk = 1
	}
	code := C.shim_pairing_chk_n_aggr_pk_in_g1(
		(*C.byte)(&ctx[0]), (*C.byte)(&pk[0]), pkChk,
		sigPtr, sigChk, msgPtr, C.size_t(len(msg)), augPtr, C.size_t(len(aug)),
	)
	return int(code)
}

// PairingChkNAggrPkInG2 is PairingChkNAggrPkInG1's mirror in G2.
func PairingChkNAggrPkInG2(ctx []byte, pk *[P2AffineLen]byte, pkGrpchk bool, sig []byte, sigGrpchk bool, msg, aug []byte) int {
	var sigPtr, msgPtr, augPtr *C.byte
	if len(sig) > 0 {
		sigPtr = (*C.byte)(&sig[0])
	}
	if len(msg) > 0 {
		msgPtr = (*C.byte)(&msg[0])
	}
	if len(aug) > 0 {
		augPtr = (*C.byte)(&aug[0])
	}
	var pkChk, sigChk C.int
	if pkGrpchk {
		pkChk = 1
	}
	if sigGrpchk {
		sigChk = 1
	}
	code := C.shim_pairing_chk_n_aggr_pk_in_g2(
		(*C.byte)(&ctx[0]), (*C.byte)(&pk[0]), pkChk,
		sigPtr, sigChk, msgPtr, C.size_t(len(msg)), augPtr, C.size_t(len(aug)),
	)
	return int(code)
}

// PairingMulNAggregatePkInG1 is PairingAggregatePkInG1 with a per-entry
// random scalar folded in, which is what makes batch verification sound
// against an adversary who picked the signatures. scalar is big-endian, up
// to ScalarLen bytes; nbits is its width in bits (see P1Mult's doc comment
// for the same convention).
func PairingMulNAggregatePkInG1(ctx []byte, pk *[P1AffineLen]byte, sig, scalar []byte, nbits int, msg, aug []byte) int {
	var sigPtr, scalarPtr, msgPtr, augPtr *C.byte
	if len(sig) > 0 {
		sigPtr = (*C.byte)(&sig[0])
	}
	if len(scalar) > 0 {
		scalarPtr = (*C.byte)(&scalar[0])
	}
	if len(msg) > 0 {
		msgPtr = (*C.byte)(&msg[0])
	}
	if len(aug) > 0 {
		augPtr = (*C.byte)(&aug[0])
	}
	code := C.shim_pairing_mul_n_aggregate_pk_in_g1(
		(*C.byte)(&ctx[0]), (*C.byte)(&pk[0]),
		sigPtr, scalarPtr, C.size_t(nbits),
		msgPtr, C.size_t(len(msg)), augPtr, C.size_t(len(aug)),
	)
	return int(code)
}

// PairingMulNAggregatePkInG2 is PairingMulNAggregatePkInG1's mirror in G2.
func PairingMulNAggregatePkInG2(ctx []byte, pk *[P2AffineLen]byte, sig, scalar []byte, nbits int, msg, aug []byte) int {
	var sigPtr, scalarPtr, msgPtr, augPtr *C.byte
	if len(sig) > 0 {
		sigPtr = (*C.byte)(&sig[0])
	}
	if len(scalar) > 0 {
		scalarPtr = (*C.byte)(&scalar[0])
	}
	if len(msg) > 0 {
		msgPtr = (*C.byte)(&msg[0])
	}
	if len(aug) > 0 {
		augPtr = (*C.byte)(&aug[0])
	}
	code := C.shim_pairing_mul_n_aggregate_pk_in_g2(
		(*C.byte)(&ctx[0]), (*C.byte)(&pk[0]),
		sigPtr, scalarPtr, C.size_t(nbits),
		msgPtr, C.size_t(len(msg)), augPtr, C.size_t(len(aug)),
	)
	return int(code)
}

// PairingChkNMulNAggrPkInG1 combines PairingChkNAggrPkInG1's subgroup
// checks with PairingMulNAggregatePkInG1's random-scalar batching — the
// form to use for batch-verifying signatures straight off the wire.
func PairingChkNMulNAggrPkInG1(ctx []byte, pk *[P1AffineLen]byte, pkGrpchk bool, sig []byte, sigGrpchk bool, scalar []byte, nbits int, msg, aug []byte) int {
	var sigPtr, scalarPtr, msgPtr, augPtr *C.byte
	if len(sig) > 0 {
		sigPtr = (*C.byte)(&sig[0])
	}
	if len(scalar) > 0 {
		scalarPtr = (*C.byte)(&scalar[0])
	}
	if len(msg) > 0 {
		msgPtr = (*C.byte)(&msg[0])
	}
	if len(aug) > 0 {
		augPtr = (*C.byte)(&aug[0])
	}
	var pkChk, sigChk C.int
	if pkGrpchk {
		pkChk = 1
	}
	if sigGrpchk {
		sigChk = 1
	}
	code := C.shim_pairing_chk_n_mul_n_aggr_pk_in_g1(
		(*C.byte)(&ctx[0]), (*C.byte)(&pk[0]), pkChk,
		sigPtr, sigChk, scalarPtr, C.size_t(nbits),
		msgPtr, C.size_t(len(msg)), augPtr, C.size_t(len(aug)),
	)
	return int(code)
}

// PairingChkNMulNAggrPkInG2 is PairingChkNMulNAggrPkInG1's mirror in G2.
func PairingChkNMulNAggrPkInG2(ctx []byte, pk *[P2AffineLen]byte, pkGrpchk bool, sig []byte, sigGrpchk bool, scalar []byte, nbits int, msg, aug []byte) int {
	var sigPtr, scalarPtr, msgPtr, augPtr *C.byte
	if len(sig) > 0 {
		sigPtr = (*C.byte)(&sig[0])
	}
	if len(scalar) > 0 {
		scalarPtr = (*C.byte)(&scalar[0])
	}
	if len(msg) > 0 {
		msgPtr = (*C.byte)(&msg[0])
	}
	if len(aug) > 0 {
		augPtr = (*C.byte)(&aug[0])
	}
	var pkChk, sigChk C.int
	if pkGrpchk {
		pkChk = 1
	}
	if sigGrpchk {
		sigChk = 1
	}
	code := C.shim_pairing_chk_n_mul_n_aggr_pk_in_g2(
		(*C.byte)(&ctx[0]), (*C.byte)(&pk[0]), pkChk,
		sigPtr, sigChk, scalarPtr, C.size_t(nbits),
		msgPtr, C.size_t(len(msg)), augPtr, C.size_t(len(aug)),
	)
	return int(code)
}

// Low-level pairing primitives — for protocols that build their own
// pairing equations rather than using the signature-scheme calls above.

// MillerLoop computes the Miller loop of (q, p).
func MillerLoop(q *[P2AffineLen]byte, p *[P1AffineLen]byte) [Fp12Len]byte {
	var out [Fp12Len]byte
	C.shim_miller_loop((*C.byte)(&out[0]), (*C.byte)(&q[0]), (*C.byte)(&p[0]))
	return out
}

// MillerLoopN computes the product of n Miller loops. qs/ps are n points
// each, laid out contiguously (n*P2AffineLen / n*P1AffineLen bytes); n is
// derived from qs's length and must agree with ps's.
func MillerLoopN(qs, ps []byte) [Fp12Len]byte {
	var out [Fp12Len]byte
	n := len(qs) / P2AffineLen
	var qsPtr, psPtr *C.byte
	if len(qs) > 0 {
		qsPtr = (*C.byte)(&qs[0])
	}
	if len(ps) > 0 {
		psPtr = (*C.byte)(&ps[0])
	}
	C.shim_miller_loop_n((*C.byte)(&out[0]), qsPtr, psPtr, C.size_t(n))
	return out
}

// FinalExp applies the final exponentiation to a raw Miller loop result.
func FinalExp(f *[Fp12Len]byte) [Fp12Len]byte {
	var out [Fp12Len]byte
	C.shim_final_exp((*C.byte)(&out[0]), (*C.byte)(&f[0]))
	return out
}

// PrecomputeLines caches the G2-dependent half of a Miller loop for q, so a
// fixed q can be paired against many p (via MillerLoopLines) without
// redoing that work each time.
func PrecomputeLines(q *[P2AffineLen]byte) [LinesLen]byte {
	var out [LinesLen]byte
	C.shim_precompute_lines((*C.byte)(&out[0]), (*C.byte)(&q[0]))
	return out
}

// MillerLoopLines computes the Miller loop of p against lines, as returned
// by PrecomputeLines.
func MillerLoopLines(lines *[LinesLen]byte, p *[P1AffineLen]byte) [Fp12Len]byte {
	var out [Fp12Len]byte
	C.shim_miller_loop_lines((*C.byte)(&out[0]), (*C.byte)(&lines[0]), (*C.byte)(&p[0]))
	return out
}

// Fp12FinalVerify compares two Miller-loop results after the final
// exponentiation, without materializing either exponentiation's result —
// the primitive PairingFinalVerify itself is built on.
func Fp12FinalVerify(a, b *[Fp12Len]byte) bool {
	return C.shim_fp12_finalverify((*C.byte)(&a[0]), (*C.byte)(&b[0])) == 1
}

func Fp12Mul(a, b *[Fp12Len]byte) [Fp12Len]byte {
	var out [Fp12Len]byte
	C.shim_fp12_mul((*C.byte)(&out[0]), (*C.byte)(&a[0]), (*C.byte)(&b[0]))
	return out
}

func Fp12Sqr(a *[Fp12Len]byte) [Fp12Len]byte {
	var out [Fp12Len]byte
	C.shim_fp12_sqr((*C.byte)(&out[0]), (*C.byte)(&a[0]))
	return out
}

func Fp12Inverse(a *[Fp12Len]byte) [Fp12Len]byte {
	var out [Fp12Len]byte
	C.shim_fp12_inverse((*C.byte)(&out[0]), (*C.byte)(&a[0]))
	return out
}

func Fp12One() [Fp12Len]byte {
	var out [Fp12Len]byte
	C.shim_fp12_one((*C.byte)(&out[0]))
	return out
}

func Fp12IsOne(a *[Fp12Len]byte) bool {
	return C.shim_fp12_is_one((*C.byte)(&a[0])) == 1
}

func Fp12IsEqual(a, b *[Fp12Len]byte) bool {
	return C.shim_fp12_is_equal((*C.byte)(&a[0]), (*C.byte)(&b[0])) == 1
}

func Fp12InGroup(a *[Fp12Len]byte) bool {
	return C.shim_fp12_in_group((*C.byte)(&a[0])) == 1
}

// AggregatedInG1 turns an aggregated G1 signature into the GT element
// PairingFinalVerify expects as its gtsig argument.
func AggregatedInG1(sig *[P1AffineLen]byte) [Fp12Len]byte {
	var out [Fp12Len]byte
	C.shim_aggregated_in_g1((*C.byte)(&out[0]), (*C.byte)(&sig[0]))
	return out
}

// AggregatedInG2 is AggregatedInG1's mirror for a G2 signature.
func AggregatedInG2(sig *[P2AffineLen]byte) [Fp12Len]byte {
	var out [Fp12Len]byte
	C.shim_aggregated_in_g2((*C.byte)(&out[0]), (*C.byte)(&sig[0]))
	return out
}
