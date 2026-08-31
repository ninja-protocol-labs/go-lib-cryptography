package internal

/*
#include "shim.h"
*/
import "C"

// Multi-scalar multiplication via Pippenger's algorithm. Same buffer
// discipline as the pairing engine: the *ScratchSizeof call tells the
// caller how big a []byte scratch buffer Pippenger's algorithm needs, sized
// for the actual point count.
//
// points/scalars are flat, contiguous arrays (npoints*P1AffineLen and
// npoints*ceil(nbits/8) bytes respectively) — every scalar shares the same
// width nbits, big-endian, capped at ScalarLen (32) bytes; see P1Mult's doc
// comment for why this is big-endian despite blst's own convention.

// P1sMultPippengerScratchSizeof returns the scratch buffer size (in bytes)
// P1sMultPippenger needs for npoints points.
func P1sMultPippengerScratchSizeof(npoints int) int {
	return int(C.shim_p1s_mult_pippenger_scratch_sizeof(C.size_t(npoints)))
}

// P1sMultPippenger computes the sum of scalars[i]*points[i] over npoints
// points, where npoints is derived from points's length. scratch must be
// at least P1sMultPippengerScratchSizeof(npoints) bytes.
func P1sMultPippenger(points []byte, scalars []byte, nbits int, scratch []byte) [P1AffineLen]byte {
	var out [P1AffineLen]byte
	npoints := len(points) / P1AffineLen

	var pointsPtr, scalarsPtr, scratchPtr *C.byte
	if len(points) > 0 {
		pointsPtr = (*C.byte)(&points[0])
	}
	if len(scalars) > 0 {
		scalarsPtr = (*C.byte)(&scalars[0])
	}
	if len(scratch) > 0 {
		scratchPtr = (*C.byte)(&scratch[0])
	}

	C.shim_p1s_mult_pippenger(
		(*C.byte)(&out[0]),
		pointsPtr, C.size_t(npoints),
		scalarsPtr, C.size_t(nbits),
		scratchPtr,
	)
	return out
}

// P2sMultPippengerScratchSizeof is P1sMultPippengerScratchSizeof's mirror
// in G2.
func P2sMultPippengerScratchSizeof(npoints int) int {
	return int(C.shim_p2s_mult_pippenger_scratch_sizeof(C.size_t(npoints)))
}

// P2sMultPippenger is P1sMultPippenger's mirror in G2.
func P2sMultPippenger(points []byte, scalars []byte, nbits int, scratch []byte) [P2AffineLen]byte {
	var out [P2AffineLen]byte
	npoints := len(points) / P2AffineLen

	var pointsPtr, scalarsPtr, scratchPtr *C.byte
	if len(points) > 0 {
		pointsPtr = (*C.byte)(&points[0])
	}
	if len(scalars) > 0 {
		scalarsPtr = (*C.byte)(&scalars[0])
	}
	if len(scratch) > 0 {
		scratchPtr = (*C.byte)(&scratch[0])
	}

	C.shim_p2s_mult_pippenger(
		(*C.byte)(&out[0]),
		pointsPtr, C.size_t(npoints),
		scalarsPtr, C.size_t(nbits),
		scratchPtr,
	)
	return out
}
