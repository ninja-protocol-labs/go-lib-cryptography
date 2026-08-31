package internal

/*
#include "shim.h"
*/
import "C"

// Keygen derives a secret key scalar (big-endian) from ikm and info. See
// shim_keygen's doc comment in shim.h for the parameters' meaning.
func Keygen(ikm, info []byte) [ScalarLen]byte {
	var out [ScalarLen]byte

	var ikmPtr *C.byte
	if len(ikm) > 0 {
		ikmPtr = (*C.byte)(&ikm[0])
	}
	var infoPtr *C.byte
	if len(info) > 0 {
		infoPtr = (*C.byte)(&info[0])
	}

	C.shim_keygen(
		(*C.byte)(&out[0]),
		ikmPtr, C.size_t(len(ikm)),
		infoPtr, C.size_t(len(info)),
	)
	return out
}

// SkCheck reports whether sk is a usable secret key, meaning a scalar in
// [1, r-1] where r is the BLS12-381 subgroup order.
func SkCheck(sk *[ScalarLen]byte) bool {
	return C.shim_sk_check((*C.byte)(&sk[0])) == 1
}

// ScalarFromBEBytes reduces an arbitrary-length big-endian value into a
// scalar. The bool is false if the input does not reduce to a usable
// (non-zero) value.
func ScalarFromBEBytes(in []byte) ([ScalarLen]byte, bool) {
	var out [ScalarLen]byte
	var inPtr *C.byte
	if len(in) > 0 {
		inPtr = (*C.byte)(&in[0])
	}
	ok := C.shim_scalar_from_be_bytes((*C.byte)(&out[0]), inPtr, C.size_t(len(in))) == 1
	return out, ok
}

// SkAdd, SkSub and SkMul combine two secret keys modulo the subgroup order.
// The bool is false if the result would be the zero scalar (and therefore
// not a usable key).
func SkAdd(a, b *[ScalarLen]byte) ([ScalarLen]byte, bool) {
	var out [ScalarLen]byte
	ok := C.shim_sk_add((*C.byte)(&out[0]), (*C.byte)(&a[0]), (*C.byte)(&b[0])) == 1
	return out, ok
}

func SkSub(a, b *[ScalarLen]byte) ([ScalarLen]byte, bool) {
	var out [ScalarLen]byte
	ok := C.shim_sk_sub((*C.byte)(&out[0]), (*C.byte)(&a[0]), (*C.byte)(&b[0])) == 1
	return out, ok
}

func SkMul(a, b *[ScalarLen]byte) ([ScalarLen]byte, bool) {
	var out [ScalarLen]byte
	ok := C.shim_sk_mul((*C.byte)(&out[0]), (*C.byte)(&a[0]), (*C.byte)(&b[0])) == 1
	return out, ok
}

// SkInverse computes the multiplicative inverse of a modulo the subgroup
// order.
func SkInverse(a *[ScalarLen]byte) [ScalarLen]byte {
	var out [ScalarLen]byte
	C.shim_sk_inverse((*C.byte)(&out[0]), (*C.byte)(&a[0]))
	return out
}

// SkToPkInG1Compressed and SkToPkInG1Serialized derive the minimal-pubkey-
// size public key (in G1) for sk, in compressed (48-byte) or uncompressed
// (96-byte) form.
func SkToPkInG1Compressed(sk *[ScalarLen]byte) [P1CompressedLen]byte {
	var out [P1CompressedLen]byte
	C.shim_sk_to_pk_in_g1_compressed((*C.byte)(&out[0]), (*C.byte)(&sk[0]))
	return out
}

func SkToPkInG1Serialized(sk *[ScalarLen]byte) [P1SerializedLen]byte {
	var out [P1SerializedLen]byte
	C.shim_sk_to_pk_in_g1_serialized((*C.byte)(&out[0]), (*C.byte)(&sk[0]))
	return out
}

// SkToPkInG2Compressed and SkToPkInG2Serialized derive the minimal-
// signature-size public key (in G2) for sk, in compressed (96-byte) or
// uncompressed (192-byte) form.
func SkToPkInG2Compressed(sk *[ScalarLen]byte) [P2CompressedLen]byte {
	var out [P2CompressedLen]byte
	C.shim_sk_to_pk_in_g2_compressed((*C.byte)(&out[0]), (*C.byte)(&sk[0]))
	return out
}

func SkToPkInG2Serialized(sk *[ScalarLen]byte) [P2SerializedLen]byte {
	var out [P2SerializedLen]byte
	C.shim_sk_to_pk_in_g2_serialized((*C.byte)(&out[0]), (*C.byte)(&sk[0]))
	return out
}
