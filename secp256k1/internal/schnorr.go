package internal

/*
#include "shim.h"
*/
import "C"

// SchnorrSign produces a Schnorr signature over msg (a message of any length,
// hashed internally — unlike ECDSA, which always takes a pre-hashed digest)
// with seckey, using the module's default deterministic nonce function.
// Signing the same msg/seckey pair twice always produces the identical
// signature.
func SchnorrSign(msg []byte, seckey *[SeckeyLen]byte) ([SignatureCompactLen]byte, bool) {
	var sig [SignatureCompactLen]byte
	var msgPtr *C.uchar
	if len(msg) > 0 {
		msgPtr = (*C.uchar)(&msg[0])
	}
	ok := C.shim_schnorr_sign(context(), msgPtr, C.size_t(len(msg)), (*C.uchar)(&seckey[0]), nil, (*C.uchar)(&sig[0])) == 1
	return sig, ok
}

// SchnorrSignHedged is SchnorrSign with auxRand folded into the nonce
// derivation as extra entropy, the same hedged-but-safe pattern as
// ECDSASignCompactHedged. auxRand need not be secret.
func SchnorrSignHedged(msg []byte, seckey *[SeckeyLen]byte, auxRand *[32]byte) ([SignatureCompactLen]byte, bool) {
	var sig [SignatureCompactLen]byte
	var msgPtr *C.uchar
	if len(msg) > 0 {
		msgPtr = (*C.uchar)(&msg[0])
	}
	ok := C.shim_schnorr_sign(context(), msgPtr, C.size_t(len(msg)), (*C.uchar)(&seckey[0]), (*C.uchar)(&auxRand[0]), (*C.uchar)(&sig[0])) == 1
	return sig, ok
}

// SchnorrVerify reports whether sig is a valid Schnorr signature over msg by
// the x-only key pubkey32.
func SchnorrVerify(msg []byte, pubkey32 *[XonlyPubkeyLen]byte, sig *[SignatureCompactLen]byte) bool {
	var msgPtr *C.uchar
	if len(msg) > 0 {
		msgPtr = (*C.uchar)(&msg[0])
	}
	return C.shim_schnorr_verify(context(), msgPtr, C.size_t(len(msg)), (*C.uchar)(&pubkey32[0]), (*C.uchar)(&sig[0])) == 1
}
