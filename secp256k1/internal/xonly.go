package internal

/*
#include "shim.h"
*/
import "C"

// XonlyPubkeyCreate derives the x-only public key for seckey: the 32-byte x
// coordinate of seckey's point, with y forced even. parity reports which y
// the original, non-x-only point had (0 even, 1 odd) — the bit dropped by
// going x-only, needed to reconstruct the full point later.
func XonlyPubkeyCreate(seckey *[SeckeyLen]byte) ([XonlyPubkeyLen]byte, int, bool) {
	var out [XonlyPubkeyLen]byte
	var parity C.int
	ok := C.shim_xonly_pubkey_create(context(), (*C.uchar)(&seckey[0]), (*C.uchar)(&out[0]), &parity) == 1
	return out, int(parity), ok
}

// XonlyPubkeyVerify reports whether pubkey32 decodes to a valid point on the
// curve.
func XonlyPubkeyVerify(pubkey32 *[XonlyPubkeyLen]byte) bool {
	return C.shim_xonly_pubkey_verify(context(), (*C.uchar)(&pubkey32[0])) == 1
}

// XonlyPubkeyFromPubkey drops the y coordinate from a compressed or
// uncompressed pubkey, returning its x-only form and the parity of the y it
// dropped.
func XonlyPubkeyFromPubkey(pubkey []byte) ([XonlyPubkeyLen]byte, int, bool) {
	var out [XonlyPubkeyLen]byte
	if len(pubkey) == 0 {
		return out, 0, false
	}
	var parity C.int
	ok := C.shim_xonly_pubkey_from_pubkey(context(), (*C.uchar)(&pubkey[0]), C.size_t(len(pubkey)), (*C.uchar)(&out[0]), &parity) == 1
	return out, int(parity), ok
}

// XonlyPubkeyCmp orders a and b lexicographically, returning -1, 0 or 1.
func XonlyPubkeyCmp(a, b *[XonlyPubkeyLen]byte) (int, bool) {
	var result C.int
	ok := C.shim_xonly_pubkey_cmp(context(), (*C.uchar)(&a[0]), (*C.uchar)(&b[0]), &result) == 1
	return int(result), ok
}

// XonlyPubkeyTweakAdd adds tweak*G to the internal key pubkey32 and returns
// the result as an x-only key plus its parity — the public half of
// committing arbitrary auxiliary data (via tweak) into an otherwise
// ordinary-looking key.
func XonlyPubkeyTweakAdd(pubkey32 *[XonlyPubkeyLen]byte, tweak *[TweakLen]byte) ([XonlyPubkeyLen]byte, int, bool) {
	var out [XonlyPubkeyLen]byte
	var parity C.int
	ok := C.shim_xonly_pubkey_tweak_add(context(), (*C.uchar)(&pubkey32[0]), (*C.uchar)(&tweak[0]), (*C.uchar)(&out[0]), &parity) == 1
	return out, int(parity), ok
}

// XonlyPubkeyTweakAddCheck verifies that output32 (with outputParity) really
// is internal32 tweaked by tweak, without the caller having to recompute the
// tweak itself.
func XonlyPubkeyTweakAddCheck(output32 *[XonlyPubkeyLen]byte, outputParity int, internal32 *[XonlyPubkeyLen]byte, tweak *[TweakLen]byte) bool {
	return C.shim_xonly_pubkey_tweak_add_check(context(), (*C.uchar)(&output32[0]), C.int(outputParity), (*C.uchar)(&internal32[0]), (*C.uchar)(&tweak[0])) == 1
}

// SeckeyXonlyTweakAdd is the secret-key half of XonlyPubkeyTweakAdd: it
// replaces seckey in place so that its x-only public key matches
// XonlyPubkeyTweakAdd's output — what lets the tweaked key actually be
// signed with, rather than merely verified against.
func SeckeyXonlyTweakAdd(seckey *[SeckeyLen]byte, tweak *[TweakLen]byte) bool {
	return C.shim_seckey_xonly_tweak_add(context(), (*C.uchar)(&seckey[0]), (*C.uchar)(&tweak[0])) == 1
}
