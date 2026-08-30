package internal

/*
#include "shim.h"
*/
import "C"

// SeckeyVerify reports whether seckey is a usable secret key, meaning it decodes
// to a scalar in [1, n-1]. Zero and anything at or above the curve order are
// rejected.
//
// The argument is a pointer to a fixed-size array rather than a slice: it makes
// the length a compile-time guarantee instead of a runtime check, and keeps the
// buffer on the caller's stack.
func SeckeyVerify(seckey *[SeckeyLen]byte) bool {
	return C.shim_seckey_verify(context(), (*C.uchar)(&seckey[0])) == 1
}

// PubkeyCreateCompressed derives the 33-byte compressed public key for seckey.
func PubkeyCreateCompressed(seckey *[SeckeyLen]byte) ([PubkeyCompressedLen]byte, bool) {
	var pub [PubkeyCompressedLen]byte
	length := C.size_t(len(pub))
	ok := C.shim_pubkey_create(context(), (*C.uchar)(&seckey[0]), (*C.uchar)(&pub[0]), &length, 1) == 1
	return pub, ok
}

// PubkeyCreateUncompressed derives the 65-byte uncompressed public key for
// seckey.
func PubkeyCreateUncompressed(seckey *[SeckeyLen]byte) ([PubkeyUncompressedLen]byte, bool) {
	var pub [PubkeyUncompressedLen]byte
	length := C.size_t(len(pub))
	ok := C.shim_pubkey_create(context(), (*C.uchar)(&seckey[0]), (*C.uchar)(&pub[0]), &length, 0) == 1
	return pub, ok
}

// PubkeyParseCompressed validates pubkey — either the 33-byte compressed or
// the 65-byte uncompressed encoding — and returns it re-serialized in
// compressed form.
//
// The input is a slice rather than a fixed array because its length is exactly
// what is being validated: unlike seckey or a tweak, there is no single correct
// size to bake into the type.
func PubkeyParseCompressed(pubkey []byte) ([PubkeyCompressedLen]byte, bool) {
	var out [PubkeyCompressedLen]byte
	if len(pubkey) == 0 {
		return out, false
	}
	length := C.size_t(len(out))
	ok := C.shim_pubkey_parse(context(), (*C.uchar)(&pubkey[0]), C.size_t(len(pubkey)), (*C.uchar)(&out[0]), &length, 1) == 1
	return out, ok
}

// PubkeyParseUncompressed validates pubkey — either the 33-byte compressed or
// the 65-byte uncompressed encoding — and returns it re-serialized in
// uncompressed form.
func PubkeyParseUncompressed(pubkey []byte) ([PubkeyUncompressedLen]byte, bool) {
	var out [PubkeyUncompressedLen]byte
	if len(pubkey) == 0 {
		return out, false
	}
	length := C.size_t(len(out))
	ok := C.shim_pubkey_parse(context(), (*C.uchar)(&pubkey[0]), C.size_t(len(pubkey)), (*C.uchar)(&out[0]), &length, 0) == 1
	return out, ok
}

// SeckeyNegate replaces seckey in place with n - seckey, where n is the curve
// order. Its point on the curve keeps the same x coordinate and flips y —
// used to normalize a key to a chosen y parity.
func SeckeyNegate(seckey *[SeckeyLen]byte) bool {
	return C.shim_seckey_negate(context(), (*C.uchar)(&seckey[0])) == 1
}

// PubkeyNegateCompressed is the public-key half of SeckeyNegate: it returns
// the compressed encoding of -pubkey, the point with the same x coordinate
// and the opposite y.
func PubkeyNegateCompressed(pubkey []byte) ([PubkeyCompressedLen]byte, bool) {
	var out [PubkeyCompressedLen]byte
	if len(pubkey) == 0 {
		return out, false
	}
	length := C.size_t(len(out))
	ok := C.shim_pubkey_negate(context(), (*C.uchar)(&pubkey[0]), C.size_t(len(pubkey)), (*C.uchar)(&out[0]), &length, 1) == 1
	return out, ok
}

// PubkeyNegateUncompressed is PubkeyNegateCompressed, uncompressed.
func PubkeyNegateUncompressed(pubkey []byte) ([PubkeyUncompressedLen]byte, bool) {
	var out [PubkeyUncompressedLen]byte
	if len(pubkey) == 0 {
		return out, false
	}
	length := C.size_t(len(out))
	ok := C.shim_pubkey_negate(context(), (*C.uchar)(&pubkey[0]), C.size_t(len(pubkey)), (*C.uchar)(&out[0]), &length, 0) == 1
	return out, ok
}

// PubkeyCombineCompressed adds pubkeys together, returning the compressed
// encoding of the sum. pubkeys is a slice of fixed-size compressed keys
// rather than [][]byte specifically so its backing array is contiguous: it
// crosses into C as one pointer, not one cgo call per key.
//
// At most MaxCombinePubkeys keys are accepted; combining zero keys, more than
// that, or a set that sums to the point at infinity all fail.
func PubkeyCombineCompressed(pubkeys [][PubkeyCompressedLen]byte) ([PubkeyCompressedLen]byte, bool) {
	var out [PubkeyCompressedLen]byte
	if len(pubkeys) == 0 || len(pubkeys) > MaxCombinePubkeys {
		return out, false
	}
	length := C.size_t(len(out))
	ok := C.shim_pubkey_combine(context(), (*C.uchar)(&pubkeys[0][0]), C.size_t(len(pubkeys)), (*C.uchar)(&out[0]), &length, 1) == 1
	return out, ok
}

// PubkeyCombineUncompressed is PubkeyCombineCompressed, returning the
// uncompressed encoding of the sum.
func PubkeyCombineUncompressed(pubkeys [][PubkeyCompressedLen]byte) ([PubkeyUncompressedLen]byte, bool) {
	var out [PubkeyUncompressedLen]byte
	if len(pubkeys) == 0 || len(pubkeys) > MaxCombinePubkeys {
		return out, false
	}
	length := C.size_t(len(out))
	ok := C.shim_pubkey_combine(context(), (*C.uchar)(&pubkeys[0][0]), C.size_t(len(pubkeys)), (*C.uchar)(&out[0]), &length, 0) == 1
	return out, ok
}

// PubkeyCmp orders a and b by their compressed serialization, returning -1, 0
// or 1. ok is false if either fails to parse.
func PubkeyCmp(a, b []byte) (int, bool) {
	if len(a) == 0 || len(b) == 0 {
		return 0, false
	}
	var result C.int
	ok := C.shim_pubkey_cmp(context(), (*C.uchar)(&a[0]), C.size_t(len(a)), (*C.uchar)(&b[0]), C.size_t(len(b)), &result) == 1
	return int(result), ok
}

// PubkeySortCompressed sorts pubkeys in place by the same ordering as
// PubkeyCmp — the canonical ordering key-aggregation schemes rely on for a
// deterministic key list. At most MaxCombinePubkeys keys are accepted.
func PubkeySortCompressed(pubkeys [][PubkeyCompressedLen]byte) bool {
	if len(pubkeys) == 0 || len(pubkeys) > MaxCombinePubkeys {
		return false
	}
	return C.shim_pubkey_sort(context(), (*C.uchar)(&pubkeys[0][0]), C.size_t(len(pubkeys))) == 1
}

// SeckeyTweakAdd replaces seckey in place with seckey + tweak mod n. This is
// the secret-key half of additive key derivation schemes.
func SeckeyTweakAdd(seckey *[SeckeyLen]byte, tweak *[TweakLen]byte) bool {
	return C.shim_seckey_tweak_add(context(), (*C.uchar)(&seckey[0]), (*C.uchar)(&tweak[0])) == 1
}

// SeckeyTweakMul replaces seckey in place with seckey * tweak mod n.
func SeckeyTweakMul(seckey *[SeckeyLen]byte, tweak *[TweakLen]byte) bool {
	return C.shim_seckey_tweak_mul(context(), (*C.uchar)(&seckey[0]), (*C.uchar)(&tweak[0])) == 1
}

// PubkeyTweakAddCompressed is the public-key half of SeckeyTweakAdd: the
// compressed encoding of pubkey + tweak*G.
func PubkeyTweakAddCompressed(pubkey []byte, tweak *[TweakLen]byte) ([PubkeyCompressedLen]byte, bool) {
	var out [PubkeyCompressedLen]byte
	if len(pubkey) == 0 {
		return out, false
	}
	length := C.size_t(len(out))
	ok := C.shim_pubkey_tweak_add(context(), (*C.uchar)(&pubkey[0]), C.size_t(len(pubkey)), (*C.uchar)(&tweak[0]), (*C.uchar)(&out[0]), &length, 1) == 1
	return out, ok
}

// PubkeyTweakAddUncompressed is PubkeyTweakAddCompressed, uncompressed.
func PubkeyTweakAddUncompressed(pubkey []byte, tweak *[TweakLen]byte) ([PubkeyUncompressedLen]byte, bool) {
	var out [PubkeyUncompressedLen]byte
	if len(pubkey) == 0 {
		return out, false
	}
	length := C.size_t(len(out))
	ok := C.shim_pubkey_tweak_add(context(), (*C.uchar)(&pubkey[0]), C.size_t(len(pubkey)), (*C.uchar)(&tweak[0]), (*C.uchar)(&out[0]), &length, 0) == 1
	return out, ok
}

// PubkeyTweakMulCompressed is the public-key half of SeckeyTweakMul: the
// compressed encoding of tweak*pubkey.
func PubkeyTweakMulCompressed(pubkey []byte, tweak *[TweakLen]byte) ([PubkeyCompressedLen]byte, bool) {
	var out [PubkeyCompressedLen]byte
	if len(pubkey) == 0 {
		return out, false
	}
	length := C.size_t(len(out))
	ok := C.shim_pubkey_tweak_mul(context(), (*C.uchar)(&pubkey[0]), C.size_t(len(pubkey)), (*C.uchar)(&tweak[0]), (*C.uchar)(&out[0]), &length, 1) == 1
	return out, ok
}

// PubkeyTweakMulUncompressed is PubkeyTweakMulCompressed, uncompressed.
func PubkeyTweakMulUncompressed(pubkey []byte, tweak *[TweakLen]byte) ([PubkeyUncompressedLen]byte, bool) {
	var out [PubkeyUncompressedLen]byte
	if len(pubkey) == 0 {
		return out, false
	}
	length := C.size_t(len(out))
	ok := C.shim_pubkey_tweak_mul(context(), (*C.uchar)(&pubkey[0]), C.size_t(len(pubkey)), (*C.uchar)(&tweak[0]), (*C.uchar)(&out[0]), &length, 0) == 1
	return out, ok
}
