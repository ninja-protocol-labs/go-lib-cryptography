package internal

/*
#include "shim.h"
*/
import "C"

// Aggregation. points is n points laid out contiguously (a flat slice, not
// an array of pointers) — n is derived from its length, so callers just
// concatenate their points. Returns one of the Err* codes in shim.go, plus
// ErrAggrTypeMismatch for an empty input (there is no point to return).

// P1sAggregateCompressed aggregates n compressed G1 points (points is
// n*P1CompressedLen bytes). Each point is checked for valid encoding and G1
// membership as it's parsed.
func P1sAggregateCompressed(points []byte) ([P1AffineLen]byte, int) {
	var out [P1AffineLen]byte
	n := len(points) / P1CompressedLen

	var pointsPtr *C.byte
	if len(points) > 0 {
		pointsPtr = (*C.byte)(&points[0])
	}

	code := C.shim_p1s_aggregate_compressed((*C.byte)(&out[0]), pointsPtr, C.size_t(n))
	return out, int(code)
}

// P2sAggregateCompressed is P1sAggregateCompressed's mirror in G2.
func P2sAggregateCompressed(points []byte) ([P2AffineLen]byte, int) {
	var out [P2AffineLen]byte
	n := len(points) / P2CompressedLen

	var pointsPtr *C.byte
	if len(points) > 0 {
		pointsPtr = (*C.byte)(&points[0])
	}

	code := C.shim_p2s_aggregate_compressed((*C.byte)(&out[0]), pointsPtr, C.size_t(n))
	return out, int(code)
}

// P1sAggregateAffine aggregates n already-parsed G1 affine points (points
// is n*P1AffineLen bytes). No validity/membership checks are done here —
// callers batching points they already trust (e.g. just parsed via
// P1Uncompress) use this to skip re-checking them.
func P1sAggregateAffine(points []byte) ([P1AffineLen]byte, int) {
	var out [P1AffineLen]byte
	n := len(points) / P1AffineLen

	var pointsPtr *C.byte
	if len(points) > 0 {
		pointsPtr = (*C.byte)(&points[0])
	}

	code := C.shim_p1s_aggregate_affine((*C.byte)(&out[0]), pointsPtr, C.size_t(n))
	return out, int(code)
}

// P2sAggregateAffine is P1sAggregateAffine's mirror in G2.
func P2sAggregateAffine(points []byte) ([P2AffineLen]byte, int) {
	var out [P2AffineLen]byte
	n := len(points) / P2AffineLen

	var pointsPtr *C.byte
	if len(points) > 0 {
		pointsPtr = (*C.byte)(&points[0])
	}

	code := C.shim_p2s_aggregate_affine((*C.byte)(&out[0]), pointsPtr, C.size_t(n))
	return out, int(code)
}
