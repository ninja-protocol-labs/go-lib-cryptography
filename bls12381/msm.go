package bls12381

import "github.com/ninja-protocol-labs/go-lib-cryptography/bls12381/internal"

// MultiScalarMultG1 computes the sum of scalars[i]*points[i] via
// Pippenger's algorithm, faster than doing each Mul+Add individually for
// more than a handful of points. Every scalar is big-endian, up to 32
// bytes, sharing the same width nbits (in bits, not bytes). points and
// scalars must describe the same count.
func MultiScalarMultG1(points []G1Point, scalars [][]byte, nbits int) (G1Point, error) {
	var zero G1Point
	if len(points) != len(scalars) {
		return zero, ErrLengthMismatch
	}
	if len(points) == 0 {
		return zero, ErrLengthMismatch
	}

	stride := (nbits + 7) / 8
	pointBuf := make([]byte, 0, len(points)*internal.P1AffineLen)
	scalarBuf := make([]byte, 0, len(points)*stride)
	for i, p := range points {
		if len(scalars[i]) != stride {
			return zero, ErrLengthMismatch
		}
		pointBuf = append(pointBuf, p[:]...)
		scalarBuf = append(scalarBuf, scalars[i]...)
	}

	scratch := make([]byte, internal.P1sMultPippengerScratchSizeof(len(points)))
	return internal.P1sMultPippenger(pointBuf, scalarBuf, nbits, scratch), nil
}

// MultiScalarMultG2 is MultiScalarMultG1's mirror in G2.
func MultiScalarMultG2(points []G2Point, scalars [][]byte, nbits int) (G2Point, error) {
	var zero G2Point
	if len(points) != len(scalars) {
		return zero, ErrLengthMismatch
	}
	if len(points) == 0 {
		return zero, ErrLengthMismatch
	}

	stride := (nbits + 7) / 8
	pointBuf := make([]byte, 0, len(points)*internal.P2AffineLen)
	scalarBuf := make([]byte, 0, len(points)*stride)
	for i, p := range points {
		if len(scalars[i]) != stride {
			return zero, ErrLengthMismatch
		}
		pointBuf = append(pointBuf, p[:]...)
		scalarBuf = append(scalarBuf, scalars[i]...)
	}

	scratch := make([]byte, internal.P2sMultPippengerScratchSizeof(len(points)))
	return internal.P2sMultPippenger(pointBuf, scalarBuf, nbits, scratch), nil
}
