// Package internal is the cgo boundary for the vendored blst.
//
// Everything that touches C lives here; the public bls12_381 package consumes
// this one through plain Go types only. Keeping the boundary in a single
// internal package means the exported API never leaks cgo details, and lets a
// pure-Go backend be swapped in later without touching callers.
package internal

/*
#cgo CFLAGS: -I${SRCDIR}/lib/blst/bindings
#cgo CFLAGS: -I${SRCDIR}/lib/blst/build
#cgo CFLAGS: -I${SRCDIR}/lib/blst/src
#cgo CFLAGS: -D__BLST_CGO__
#cgo CFLAGS: -fno-builtin-memcpy -fno-builtin-memset
// blst's own Go bindings gate this the same way: ADX (Intel's ADCX/ADOX,
// available on every x86_64 CPU since 2013's Haswell/Excavator) is faster
// than the portable fallback, at the cost of an illegal-instruction crash
// on anything older. -mno-avx keeps AVX-coded paths off so ADX-only chips
// (e.g. early Zen) aren't excluded by that instead.
#cgo amd64 CFLAGS: -D__ADX__ -mno-avx
// arm64 always uses its own assembly (selected by assembly.S itself via
// __aarch64__), no ADX-equivalent toggle needed. These are the platforms
// blst has no assembly for at all.
#cgo loong64 mips64 mips64le ppc64 ppc64le riscv64 s390x CFLAGS: -D__BLST_NO_ASM__

#include "shim.h"

// Without these, escape analysis has to assume every C function stashes the
// pointers it is handed, so each buffer crossing the boundary is forced onto
// the heap. No shim function retains a caller pointer past its return, and none
// calls back into Go, so both promises hold for the whole surface — including
// shim_pairing_init, which looks like an exception (the pairing context needs
// to remember a DST across many later calls) but isn't: it copies DST into
// the caller-owned ctx buffer itself before returning, precisely so nothing
// here ever needs to keep pointing at Go memory (see shim.c).
#cgo noescape shim_keygen
#cgo nocallback shim_keygen
#cgo noescape shim_sk_check
#cgo nocallback shim_sk_check
#cgo noescape shim_scalar_from_be_bytes
#cgo nocallback shim_scalar_from_be_bytes
#cgo noescape shim_sk_add
#cgo nocallback shim_sk_add
#cgo noescape shim_sk_sub
#cgo nocallback shim_sk_sub
#cgo noescape shim_sk_mul
#cgo nocallback shim_sk_mul
#cgo noescape shim_sk_inverse
#cgo nocallback shim_sk_inverse
#cgo noescape shim_sk_to_pk_in_g1_compressed
#cgo nocallback shim_sk_to_pk_in_g1_compressed
#cgo noescape shim_sk_to_pk_in_g1_serialized
#cgo nocallback shim_sk_to_pk_in_g1_serialized
#cgo noescape shim_sk_to_pk_in_g2_compressed
#cgo nocallback shim_sk_to_pk_in_g2_compressed
#cgo noescape shim_sk_to_pk_in_g2_serialized
#cgo nocallback shim_sk_to_pk_in_g2_serialized
#cgo noescape shim_p1_uncompress
#cgo nocallback shim_p1_uncompress
#cgo noescape shim_p1_deserialize
#cgo nocallback shim_p1_deserialize
#cgo noescape shim_p1_affine_compress
#cgo nocallback shim_p1_affine_compress
#cgo noescape shim_p1_affine_serialize
#cgo nocallback shim_p1_affine_serialize
#cgo noescape shim_p1_affine_on_curve
#cgo nocallback shim_p1_affine_on_curve
#cgo noescape shim_p1_affine_in_g1
#cgo nocallback shim_p1_affine_in_g1
#cgo noescape shim_p1_affine_is_inf
#cgo nocallback shim_p1_affine_is_inf
#cgo noescape shim_p1_affine_is_equal
#cgo nocallback shim_p1_affine_is_equal
#cgo noescape shim_p1_affine_generator
#cgo nocallback shim_p1_affine_generator
#cgo noescape shim_p1_add
#cgo nocallback shim_p1_add
#cgo noescape shim_p1_double
#cgo nocallback shim_p1_double
#cgo noescape shim_p1_mult
#cgo nocallback shim_p1_mult
#cgo noescape shim_p1_neg
#cgo nocallback shim_p1_neg
#cgo noescape shim_p2_uncompress
#cgo nocallback shim_p2_uncompress
#cgo noescape shim_p2_deserialize
#cgo nocallback shim_p2_deserialize
#cgo noescape shim_p2_affine_compress
#cgo nocallback shim_p2_affine_compress
#cgo noescape shim_p2_affine_serialize
#cgo nocallback shim_p2_affine_serialize
#cgo noescape shim_p2_affine_on_curve
#cgo nocallback shim_p2_affine_on_curve
#cgo noescape shim_p2_affine_in_g2
#cgo nocallback shim_p2_affine_in_g2
#cgo noescape shim_p2_affine_is_inf
#cgo nocallback shim_p2_affine_is_inf
#cgo noescape shim_p2_affine_is_equal
#cgo nocallback shim_p2_affine_is_equal
#cgo noescape shim_p2_affine_generator
#cgo nocallback shim_p2_affine_generator
#cgo noescape shim_p2_add
#cgo nocallback shim_p2_add
#cgo noescape shim_p2_double
#cgo nocallback shim_p2_double
#cgo noescape shim_p2_mult
#cgo nocallback shim_p2_mult
#cgo noescape shim_p2_neg
#cgo nocallback shim_p2_neg
*/
import "C"

// These mirror shim.h's SHIM_*_LEN macros. gopls/GoLand have been observed
// to mis-infer a cgo constant's type at call sites (see secp256k1's
// internal/shim.go for the same issue and fix), so — same fix — these are
// plain Go int literals, with the compile-time assertions below being what
// actually keeps them from drifting out of sync with the C headers.
const (
	ScalarLen       = 32
	P1CompressedLen = 48
	P1SerializedLen = 96
	P2CompressedLen = 96
	P2SerializedLen = 192
	P1AffineLen     = 96
	P2AffineLen     = 192
	Fp12Len         = 576
	LinesLen        = 19584
)

// These mirror shim.h's SHIM_ERR_* codes — BLST_ERROR passed through
// unchanged, so functions that parse or verify return one of these as a
// plain int rather than a Go error: the internal package stays a thin
// wrapper over blst's own result codes, and the public package (which does
// know what each one should mean to a caller) is what turns them into
// sentinel errors.
const (
	ErrSuccess = iota
	ErrBadEncoding
	ErrPointNotOnCurve
	ErrPointNotInGroup
	ErrAggrTypeMismatch
	ErrVerifyFail
	ErrPkIsInfinity
	ErrBadScalar
)

var (
	_ [ErrSuccess - int(C.SHIM_ERR_SUCCESS)]byte
	_ [int(C.SHIM_ERR_SUCCESS) - ErrSuccess]byte
	_ [ErrBadEncoding - int(C.SHIM_ERR_BAD_ENCODING)]byte
	_ [int(C.SHIM_ERR_BAD_ENCODING) - ErrBadEncoding]byte
	_ [ErrPointNotOnCurve - int(C.SHIM_ERR_POINT_NOT_ON_CURVE)]byte
	_ [int(C.SHIM_ERR_POINT_NOT_ON_CURVE) - ErrPointNotOnCurve]byte
	_ [ErrPointNotInGroup - int(C.SHIM_ERR_POINT_NOT_IN_GROUP)]byte
	_ [int(C.SHIM_ERR_POINT_NOT_IN_GROUP) - ErrPointNotInGroup]byte
	_ [ErrAggrTypeMismatch - int(C.SHIM_ERR_AGGR_TYPE_MISMATCH)]byte
	_ [int(C.SHIM_ERR_AGGR_TYPE_MISMATCH) - ErrAggrTypeMismatch]byte
	_ [ErrVerifyFail - int(C.SHIM_ERR_VERIFY_FAIL)]byte
	_ [int(C.SHIM_ERR_VERIFY_FAIL) - ErrVerifyFail]byte
	_ [ErrPkIsInfinity - int(C.SHIM_ERR_PK_IS_INFINITY)]byte
	_ [int(C.SHIM_ERR_PK_IS_INFINITY) - ErrPkIsInfinity]byte
	_ [ErrBadScalar - int(C.SHIM_ERR_BAD_SCALAR)]byte
	_ [int(C.SHIM_ERR_BAD_SCALAR) - ErrBadScalar]byte
)

// An array size expression only compiles if it is non-negative, so each
// pair — the difference taken in both directions — only compiles if the two
// sides are equal; any drift fails the build immediately.
var (
	_ [ScalarLen - int(C.SHIM_SCALAR_LEN)]byte
	_ [int(C.SHIM_SCALAR_LEN) - ScalarLen]byte
	_ [P1CompressedLen - int(C.SHIM_P1_COMPRESSED_LEN)]byte
	_ [int(C.SHIM_P1_COMPRESSED_LEN) - P1CompressedLen]byte
	_ [P1SerializedLen - int(C.SHIM_P1_SERIALIZED_LEN)]byte
	_ [int(C.SHIM_P1_SERIALIZED_LEN) - P1SerializedLen]byte
	_ [P2CompressedLen - int(C.SHIM_P2_COMPRESSED_LEN)]byte
	_ [int(C.SHIM_P2_COMPRESSED_LEN) - P2CompressedLen]byte
	_ [P2SerializedLen - int(C.SHIM_P2_SERIALIZED_LEN)]byte
	_ [int(C.SHIM_P2_SERIALIZED_LEN) - P2SerializedLen]byte
	_ [P1AffineLen - int(C.SHIM_P1_AFFINE_LEN)]byte
	_ [int(C.SHIM_P1_AFFINE_LEN) - P1AffineLen]byte
	_ [P2AffineLen - int(C.SHIM_P2_AFFINE_LEN)]byte
	_ [int(C.SHIM_P2_AFFINE_LEN) - P2AffineLen]byte
	_ [Fp12Len - int(C.SHIM_FP12_LEN)]byte
	_ [int(C.SHIM_FP12_LEN) - Fp12Len]byte
	_ [LinesLen - int(C.SHIM_LINES_LEN)]byte
	_ [int(C.SHIM_LINES_LEN) - LinesLen]byte
)
