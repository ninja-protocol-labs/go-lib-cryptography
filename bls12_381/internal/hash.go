package internal

/*
#include "shim.h"
*/
import "C"

// HashToG1 implements RFC 9380 hash-to-curve into G1 — the uniform,
// indifferentiable-from-a-random-oracle construction that signature schemes
// want. dst is the domain separation tag; aug is the optional augmentation
// prefix used by the "augmented" BLS scheme (pass nil when unused).
func HashToG1(msg, dst, aug []byte) [P1AffineLen]byte {
	var out [P1AffineLen]byte

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

	C.shim_hash_to_g1(
		(*C.byte)(&out[0]),
		msgPtr, C.size_t(len(msg)),
		dstPtr, C.size_t(len(dst)),
		augPtr, C.size_t(len(aug)),
	)
	return out
}

// EncodeToG1 implements the cheaper, non-uniform encode-to-curve from RFC
// 9380. Exposed because blst does and some protocols specify it — prefer
// HashToG1 unless a spec calls for this one specifically.
func EncodeToG1(msg, dst, aug []byte) [P1AffineLen]byte {
	var out [P1AffineLen]byte

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

	C.shim_encode_to_g1(
		(*C.byte)(&out[0]),
		msgPtr, C.size_t(len(msg)),
		dstPtr, C.size_t(len(dst)),
		augPtr, C.size_t(len(aug)),
	)
	return out
}

// HashToG2 is HashToG1's mirror into G2.
func HashToG2(msg, dst, aug []byte) [P2AffineLen]byte {
	var out [P2AffineLen]byte

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

	C.shim_hash_to_g2(
		(*C.byte)(&out[0]),
		msgPtr, C.size_t(len(msg)),
		dstPtr, C.size_t(len(dst)),
		augPtr, C.size_t(len(aug)),
	)
	return out
}

// EncodeToG2 is EncodeToG1's mirror into G2.
func EncodeToG2(msg, dst, aug []byte) [P2AffineLen]byte {
	var out [P2AffineLen]byte

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

	C.shim_encode_to_g2(
		(*C.byte)(&out[0]),
		msgPtr, C.size_t(len(msg)),
		dstPtr, C.size_t(len(dst)),
		augPtr, C.size_t(len(aug)),
	)
	return out
}
