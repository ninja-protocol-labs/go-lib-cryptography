package bls12381

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// MultiScalarMultG1 computes the sum of scalars[i]*points[i] via
// gnark-crypto's Pippenger multi-exponentiation, faster than doing each
// Mul+Add individually for more than a handful of points. Every scalar is
// a big-endian 32-byte value, reduced modulo the group order r — which
// changes no result, since a point's order divides r. points and scalars
// must describe the same, non-empty set.
func MultiScalarMultG1(points []G1Point, scalars [][ScalarLen]byte) (G1Point, error) {
	var zero G1Point
	if len(points) != len(scalars) {
		return zero, ErrLengthMismatch
	}
	if len(points) == 0 {
		return zero, ErrLengthMismatch
	}

	gps := make([]bls12381.G1Affine, len(points))
	frs := make([]fr.Element, len(scalars))
	for i := range points {
		gps[i] = points[i].p
		frs[i].SetBytes(scalars[i][:])
	}

	var out G1Point
	if _, err := out.p.MultiExp(gps, frs, ecc.MultiExpConfig{}); err != nil {
		return zero, err
	}
	return out, nil
}

// MultiScalarMultG2 is MultiScalarMultG1's mirror in G2.
func MultiScalarMultG2(points []G2Point, scalars [][ScalarLen]byte) (G2Point, error) {
	var zero G2Point
	if len(points) != len(scalars) {
		return zero, ErrLengthMismatch
	}
	if len(points) == 0 {
		return zero, ErrLengthMismatch
	}

	gps := make([]bls12381.G2Affine, len(points))
	frs := make([]fr.Element, len(scalars))
	for i := range points {
		gps[i] = points[i].p
		frs[i].SetBytes(scalars[i][:])
	}

	var out G2Point
	if _, err := out.p.MultiExp(gps, frs, ecc.MultiExpConfig{}); err != nil {
		return zero, err
	}
	return out, nil
}
