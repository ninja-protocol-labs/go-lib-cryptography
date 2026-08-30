package internal

/*
#include "shim.h"
*/
import "C"

// ECDSASignCompact signs msg (a 32-byte digest, not a raw message) with
// seckey, using RFC 6979 deterministic nonce derivation. Signing the same
// msg/seckey pair twice always produces the identical signature.
func ECDSASignCompact(msg *[MessageLen]byte, seckey *[SeckeyLen]byte) ([SignatureCompactLen]byte, bool) {
	var sig [SignatureCompactLen]byte
	ok := C.shim_ecdsa_sign_compact(context(), (*C.uchar)(&msg[0]), (*C.uchar)(&seckey[0]), nil, (*C.uchar)(&sig[0])) == 1
	return sig, ok
}

// ECDSASignCompactHedged is ECDSASignCompact with auxRand folded into the
// nonce derivation as extra entropy, so repeated signatures over the same
// msg/seckey pair are unlinkable — matching what an HSM or any random-nonce
// signer produces — while staying immune to nonce reuse if auxRand turns out
// to be predictable or even attacker-known. auxRand need not be secret.
func ECDSASignCompactHedged(msg *[MessageLen]byte, seckey *[SeckeyLen]byte, auxRand *[32]byte) ([SignatureCompactLen]byte, bool) {
	var sig [SignatureCompactLen]byte
	ok := C.shim_ecdsa_sign_compact(context(), (*C.uchar)(&msg[0]), (*C.uchar)(&seckey[0]), (*C.uchar)(&auxRand[0]), (*C.uchar)(&sig[0])) == 1
	return sig, ok
}

// ECDSAVerifyCompact reports whether sig is a valid signature over msg (a
// 32-byte digest) by the key pubkey (compressed or uncompressed).
//
// A high-S signature is rejected unless normalize is set, in which case it is
// folded into low-S form before verifying — needed only for signatures from
// implementations that do not enforce low-S themselves.
func ECDSAVerifyCompact(msg *[MessageLen]byte, pubkey []byte, sig *[SignatureCompactLen]byte, normalize bool) bool {
	if len(pubkey) == 0 {
		return false
	}

	var norm C.int
	if normalize {
		norm = 1
	}

	return C.shim_ecdsa_verify_compact(
		context(),
		(*C.uchar)(&msg[0]),
		(*C.uchar)(&pubkey[0]), C.size_t(len(pubkey)),
		(*C.uchar)(&sig[0]),
		norm,
	) == 1
}
