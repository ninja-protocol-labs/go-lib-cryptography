package bn254bls

import "github.com/consensys/gnark-crypto/ecc/bn254"

// Signatures arrive over time — a set of validators attesting to the same
// block, say — so aggregation is a running sum rather than one pass over a
// slice. The accumulator is a Jacobian point, not the compressed bytes the
// signature types hold: reading those back would cost a square root to
// recover y on every Add, and returning to them a field inversion, which is
// the work this type exists to avoid. The compression happens once, in
// Signature.
//
// The zero value is an empty aggregator.

// SignatureAggregatorMinPk sums min-pk signatures as they arrive. The
// zero value is an empty aggregator.
type SignatureAggregatorMinPk struct {
	acc bn254.G2Jac
	n   int
}

// SignatureAggregatorMinSig is SignatureAggregatorMinPk for the min-sig
// scheme.
type SignatureAggregatorMinSig struct {
	acc bn254.G1Jac
	n   int
}

// Add includes sig in the running sum.
func (a *SignatureAggregatorMinPk) Add(sig *SignatureMinPk) error {
	var term bn254.G2Jac

	if sig == nil {
		return ErrAggregateFailed
	}

	p := sig.point()
	term.FromAffine(&p)
	a.acc.AddAssign(&term)
	a.n++
	return nil
}

// Add includes sig in the running sum.
func (a *SignatureAggregatorMinSig) Add(sig *SignatureMinSig) error {
	var term bn254.G1Jac

	if sig == nil {
		return ErrAggregateFailed
	}

	p := sig.point()
	term.FromAffine(&p)
	a.acc.AddAssign(&term)
	a.n++
	return nil
}

// Len returns how many signatures have been added.
func (a *SignatureAggregatorMinPk) Len() int {
	return a.n
}

// Len returns how many signatures have been added.
func (a *SignatureAggregatorMinSig) Len() int {
	return a.n
}

// Signature returns the running sum. It fails on an empty aggregator: the
// sum would be the point at infinity, which verifies for nothing.
func (a *SignatureAggregatorMinPk) Signature() (*SignatureMinPk, error) {
	var sum bn254.G2Affine

	if a.n == 0 {
		return nil, ErrAggregateFailed
	}

	sum.FromJacobian(&a.acc)
	return &SignatureMinPk{
		sig: sum.Bytes(),
	}, nil
}

// Signature returns the running sum. It fails on an empty aggregator: the
// sum would be the point at infinity, which verifies for nothing.
func (a *SignatureAggregatorMinSig) Signature() (*SignatureMinSig, error) {
	var sum bn254.G1Affine

	if a.n == 0 {
		return nil, ErrAggregateFailed
	}

	sum.FromJacobian(&a.acc)
	return &SignatureMinSig{
		sig: sum.Bytes(),
	}, nil
}
