package bls12381

import "github.com/ninja-protocol-labs/go-lib-cryptography/bls12381/internal"

// MultiScalarMultG1 computes the sum of scalars[i]*points[i] via
// Pippenger's algorithm, faster than doing each Mul+Add individually for
// more than a handful of points. Every scalar is a big-endian 32-byte
// value; points and scalars must describe the same, non-empty count.
//
// As with G1Point.Mul, blst's bit-width argument is not part of this API:
// the scalar width is fixed by its type, so there is nothing left for it
// to describe.
func MultiScalarMultG1(points []G1Point, scalars [][SeckeyLen]byte) (G1Point, error) {
	var zero G1Point
	if len(points) != len(scalars) {
		return zero, ErrLengthMismatch
	}
	if len(points) == 0 {
		return zero, ErrLengthMismatch
	}

	pointBuf := make([]byte, 0, len(points)*internal.P1AffineLen)
	scalarBuf := make([]byte, 0, len(points)*SeckeyLen)
	for i, p := range points {
		pointBuf = append(pointBuf, p[:]...)
		scalarBuf = append(scalarBuf, scalars[i][:]...)
	}

	scratch := make([]byte, internal.P1sMultPippengerScratchSizeof(len(points)))
	return internal.P1sMultPippenger(pointBuf, scalarBuf, scalarBits, scratch), nil
}

// MultiScalarMultG2 is MultiScalarMultG1's mirror in G2.
func MultiScalarMultG2(points []G2Point, scalars [][SeckeyLen]byte) (G2Point, error) {
	var zero G2Point
	if len(points) != len(scalars) {
		return zero, ErrLengthMismatch
	}
	if len(points) == 0 {
		return zero, ErrLengthMismatch
	}

	pointBuf := make([]byte, 0, len(points)*internal.P2AffineLen)
	scalarBuf := make([]byte, 0, len(points)*SeckeyLen)
	for i, p := range points {
		pointBuf = append(pointBuf, p[:]...)
		scalarBuf = append(scalarBuf, scalars[i][:]...)
	}

	scratch := make([]byte, internal.P2sMultPippengerScratchSizeof(len(points)))
	return internal.P2sMultPippenger(pointBuf, scalarBuf, scalarBits, scratch), nil
}
