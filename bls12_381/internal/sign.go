package internal

/*
#include "shim.h"
*/
import "C"

// Signing and one-shot verification. The _pk_in_g1 variant carries its
// public key in G1 and therefore signs into G2; _pk_in_g2 is the mirror
// image (public key in G2, signature in G1) — this is what min-pk/min-sig
// mean throughout this package.

// SignPkInG1 signs an already-hashed G2 point with sk, for the pk-in-G1
// scheme. Callers that hash the message themselves (e.g. to reuse a hash
// across many signatures) use this; SignMsgPkInG1 below hashes internally.
func SignPkInG1(hash *[P2AffineLen]byte, sk *[ScalarLen]byte) [P2AffineLen]byte {
	var out [P2AffineLen]byte
	C.shim_sign_pk_in_g1((*C.byte)(&out[0]), (*C.byte)(&hash[0]), (*C.byte)(&sk[0]))
	return out
}

// SignPkInG2 is SignPkInG1's mirror: public key in G2, signature in G1.
func SignPkInG2(hash *[P1AffineLen]byte, sk *[ScalarLen]byte) [P1AffineLen]byte {
	var out [P1AffineLen]byte
	C.shim_sign_pk_in_g2((*C.byte)(&out[0]), (*C.byte)(&hash[0]), (*C.byte)(&sk[0]))
	return out
}

// SignMsgPkInG1 hashes msg to G2 (with the given dst/aug — see HashToG2)
// and signs it with sk, for the pk-in-G1 scheme, returning the compressed
// signature.
func SignMsgPkInG1(sk *[ScalarLen]byte, msg, dst, aug []byte) [P2CompressedLen]byte {
	var out [P2CompressedLen]byte

	var msgPtr, dstPtr, augPtr *C.byte
	if len(msg) > 0 {
		msgPtr = (*C.byte)(&msg[0])
	}
	if len(dst) > 0 {
		dstPtr = (*C.byte)(&dst[0])
	}
	if len(aug) > 0 {
		augPtr = (*C.byte)(&aug[0])
	}

	C.shim_sign_msg_pk_in_g1(
		(*C.byte)(&out[0]),
		(*C.byte)(&sk[0]),
		msgPtr, C.size_t(len(msg)),
		dstPtr, C.size_t(len(dst)),
		augPtr, C.size_t(len(aug)),
	)
	return out
}

// SignMsgPkInG2 is SignMsgPkInG1's mirror: public key in G2, compressed
// signature in G1.
func SignMsgPkInG2(sk *[ScalarLen]byte, msg, dst, aug []byte) [P1CompressedLen]byte {
	var out [P1CompressedLen]byte

	var msgPtr, dstPtr, augPtr *C.byte
	if len(msg) > 0 {
		msgPtr = (*C.byte)(&msg[0])
	}
	if len(dst) > 0 {
		dstPtr = (*C.byte)(&dst[0])
	}
	if len(aug) > 0 {
		augPtr = (*C.byte)(&aug[0])
	}

	C.shim_sign_msg_pk_in_g2(
		(*C.byte)(&out[0]),
		(*C.byte)(&sk[0]),
		msgPtr, C.size_t(len(msg)),
		dstPtr, C.size_t(len(dst)),
		augPtr, C.size_t(len(aug)),
	)
	return out
}

// CoreVerifyPkInG1 verifies sig against pk and msg for the pk-in-G1 scheme.
// hashOrEncode selects hash-to-curve (true) or encode-to-curve (false),
// which must match what the signer used. Returns one of the Err* codes in
// shim.go; ErrSuccess means the signature is valid.
func CoreVerifyPkInG1(pk *[P1AffineLen]byte, sig *[P2AffineLen]byte, hashOrEncode bool, msg, dst, aug []byte) int {
	var msgPtr, dstPtr, augPtr *C.byte
	if len(msg) > 0 {
		msgPtr = (*C.byte)(&msg[0])
	}
	if len(dst) > 0 {
		dstPtr = (*C.byte)(&dst[0])
	}
	if len(aug) > 0 {
		augPtr = (*C.byte)(&aug[0])
	}

	var hoe C.int
	if hashOrEncode {
		hoe = 1
	}

	code := C.shim_core_verify_pk_in_g1(
		(*C.byte)(&pk[0]),
		(*C.byte)(&sig[0]),
		hoe,
		msgPtr, C.size_t(len(msg)),
		dstPtr, C.size_t(len(dst)),
		augPtr, C.size_t(len(aug)),
	)
	return int(code)
}

// CoreVerifyPkInG2 is CoreVerifyPkInG1's mirror: public key in G2,
// signature in G1.
func CoreVerifyPkInG2(pk *[P2AffineLen]byte, sig *[P1AffineLen]byte, hashOrEncode bool, msg, dst, aug []byte) int {
	var msgPtr, dstPtr, augPtr *C.byte
	if len(msg) > 0 {
		msgPtr = (*C.byte)(&msg[0])
	}
	if len(dst) > 0 {
		dstPtr = (*C.byte)(&dst[0])
	}
	if len(aug) > 0 {
		augPtr = (*C.byte)(&aug[0])
	}

	var hoe C.int
	if hashOrEncode {
		hoe = 1
	}

	code := C.shim_core_verify_pk_in_g2(
		(*C.byte)(&pk[0]),
		(*C.byte)(&sig[0]),
		hoe,
		msgPtr, C.size_t(len(msg)),
		dstPtr, C.size_t(len(dst)),
		augPtr, C.size_t(len(aug)),
	)
	return int(code)
}
