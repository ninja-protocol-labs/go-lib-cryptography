package bls12377

import bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"

// AggregatePublicKeysMinPk sums a set of min-pk public keys into one. Each
// input is already validated (parsed via PublicKeyMinPkFromBytes or
// derived from a PrivateKey), so this only checks the set is non-empty.
func AggregatePublicKeysMinPk(pks []*PublicKeyMinPk) (*PublicKeyMinPk, error) {
	if len(pks) == 0 {
		return nil, ErrAggregateFailed
	}
	// Summed in Jacobian coordinates: the zero value is the point at
	// infinity, so the accumulator needs no special-casing for the first
	// term, and each addition avoids an inversion.
	var acc bls12377.G1Jac
	for _, pk := range pks {
		if pk == nil {
			return nil, ErrAggregateFailed
		}
		var term bls12377.G1Jac
		term.FromAffine(&pk.point)
		acc.AddAssign(&term)
	}
	var sum bls12377.G1Affine
	sum.FromJacobian(&acc)
	return &PublicKeyMinPk{point: sum}, nil
}

// AggregatePublicKeysMinSig is AggregatePublicKeysMinPk's mirror for
// min-sig public keys.
func AggregatePublicKeysMinSig(pks []*PublicKeyMinSig) (*PublicKeyMinSig, error) {
	if len(pks) == 0 {
		return nil, ErrAggregateFailed
	}
	var acc bls12377.G2Jac
	for _, pk := range pks {
		if pk == nil {
			return nil, ErrAggregateFailed
		}
		var term bls12377.G2Jac
		term.FromAffine(&pk.point)
		acc.AddAssign(&term)
	}
	var sum bls12377.G2Affine
	sum.FromJacobian(&acc)
	return &PublicKeyMinSig{point: sum}, nil
}

// AggregateSignaturesMinPk sums a set of min-pk signatures (each
// SignatureMinPkLen bytes, e.g. from SignMinPk) into one compressed
// signature. Unlike AggregatePublicKeysMinPk, each signature here is
// untrusted wire data — encoding, on-curve, and subgroup membership are
// all checked as it is parsed.
func AggregateSignaturesMinPk(sigs [][]byte) ([SignatureMinPkLen]byte, error) {
	var out [SignatureMinPkLen]byte
	if len(sigs) == 0 {
		return out, ErrAggregateFailed
	}
	var acc bls12377.G2Jac
	for _, sig := range sigs {
		if len(sig) != SignatureMinPkLen {
			return out, ErrInvalidSignature
		}
		var p bls12377.G2Affine
		if _, err := p.SetBytes(sig); err != nil {
			return out, ErrInvalidSignature
		}
		var term bls12377.G2Jac
		term.FromAffine(&p)
		acc.AddAssign(&term)
	}
	var sum bls12377.G2Affine
	sum.FromJacobian(&acc)
	return sum.Bytes(), nil
}

// AggregateSignaturesMinSig is AggregateSignaturesMinPk's mirror for
// min-sig signatures (each SignatureMinSigLen bytes).
func AggregateSignaturesMinSig(sigs [][]byte) ([SignatureMinSigLen]byte, error) {
	var out [SignatureMinSigLen]byte
	if len(sigs) == 0 {
		return out, ErrAggregateFailed
	}
	var acc bls12377.G1Jac
	for _, sig := range sigs {
		if len(sig) != SignatureMinSigLen {
			return out, ErrInvalidSignature
		}
		var p bls12377.G1Affine
		if _, err := p.SetBytes(sig); err != nil {
			return out, ErrInvalidSignature
		}
		var term bls12377.G1Jac
		term.FromAffine(&p)
		acc.AddAssign(&term)
	}
	var sum bls12377.G1Affine
	sum.FromJacobian(&acc)
	return sum.Bytes(), nil
}

// AggregateVerifyMinPk verifies an aggregated min-pk signature against
// distinct (pk, message) pairs — the general case where every signer
// signed their own message, unlike a single shared message. pks and msgs
// must have the same, non-zero length; msgs[i] is checked against pks[i].
// Uses DefaultDSTMinPk.
func AggregateVerifyMinPk(pks []*PublicKeyMinPk, msgs [][]byte, aggSig []byte) bool {
	return AggregateVerifyMinPkWithDST(pks, msgs, aggSig, []byte(DefaultDSTMinPk))
}

// AggregateVerifyMinPkWithDST is AggregateVerifyMinPk with a
// caller-supplied domain separation tag.
//
// The whole check is one product of pairings: ∏ e(pkᵢ, H(msgᵢ)) · e(-G1,
// aggSig) == 1, i.e. exactly the n+1 terms handed to PairingCheck below.
func AggregateVerifyMinPkWithDST(pks []*PublicKeyMinPk, msgs [][]byte, aggSig, dst []byte) bool {
	if len(pks) == 0 || len(pks) != len(msgs) || len(aggSig) != SignatureMinPkLen {
		return false
	}
	var sigPoint bls12377.G2Affine
	if _, err := sigPoint.SetBytes(aggSig); err != nil {
		return false
	}

	ps := make([]bls12377.G1Affine, 0, len(pks)+1)
	qs := make([]bls12377.G2Affine, 0, len(pks)+1)
	for i, pk := range pks {
		if pk == nil {
			return false
		}
		h, err := bls12377.HashToG2(msgs[i], dst)
		if err != nil {
			return false
		}
		ps = append(ps, pk.point)
		qs = append(qs, h)
	}
	ps = append(ps, g1GenNeg)
	qs = append(qs, sigPoint)

	ok, err := bls12377.PairingCheck(ps, qs)
	return err == nil && ok
}

// AggregateVerifyMinSig is AggregateVerifyMinPk's mirror for the min-sig
// scheme. Uses DefaultDSTMinSig.
func AggregateVerifyMinSig(pks []*PublicKeyMinSig, msgs [][]byte, aggSig []byte) bool {
	return AggregateVerifyMinSigWithDST(pks, msgs, aggSig, []byte(DefaultDSTMinSig))
}

// AggregateVerifyMinSigWithDST is AggregateVerifyMinSig with a
// caller-supplied domain separation tag.
func AggregateVerifyMinSigWithDST(pks []*PublicKeyMinSig, msgs [][]byte, aggSig, dst []byte) bool {
	if len(pks) == 0 || len(pks) != len(msgs) || len(aggSig) != SignatureMinSigLen {
		return false
	}
	var sigPoint bls12377.G1Affine
	if _, err := sigPoint.SetBytes(aggSig); err != nil {
		return false
	}

	ps := make([]bls12377.G1Affine, 0, len(pks)+1)
	qs := make([]bls12377.G2Affine, 0, len(pks)+1)
	for i, pk := range pks {
		if pk == nil {
			return false
		}
		h, err := bls12377.HashToG1(msgs[i], dst)
		if err != nil {
			return false
		}
		ps = append(ps, h)
		qs = append(qs, pk.point)
	}
	var sigNeg bls12377.G1Affine
	sigNeg.Neg(&sigPoint)
	ps = append(ps, sigNeg)
	qs = append(qs, g2Gen)

	ok, err := bls12377.PairingCheck(ps, qs)
	return err == nil && ok
}

// FastAggregateVerifyMinPk verifies an aggregated min-pk signature against
// a single shared message, signed by every key in pks — the common case
// (every validator attesting to the same block, etc.), cheaper than
// AggregateVerifyMinPk since the public keys are summed once instead of
// paired individually. Uses DefaultDSTMinPk.
func FastAggregateVerifyMinPk(pks []*PublicKeyMinPk, msg, aggSig []byte) bool {
	return FastAggregateVerifyMinPkWithDST(pks, msg, aggSig, []byte(DefaultDSTMinPk))
}

// FastAggregateVerifyMinPkWithDST is FastAggregateVerifyMinPk with a
// caller-supplied domain separation tag.
func FastAggregateVerifyMinPkWithDST(pks []*PublicKeyMinPk, msg, aggSig, dst []byte) bool {
	pk, err := AggregatePublicKeysMinPk(pks)
	if err != nil {
		return false
	}
	return VerifyMinPkWithDST(pk, msg, aggSig, dst)
}

// FastAggregateVerifyMinSig is FastAggregateVerifyMinPk's mirror for the
// min-sig scheme. Uses DefaultDSTMinSig.
func FastAggregateVerifyMinSig(pks []*PublicKeyMinSig, msg, aggSig []byte) bool {
	return FastAggregateVerifyMinSigWithDST(pks, msg, aggSig, []byte(DefaultDSTMinSig))
}

// FastAggregateVerifyMinSigWithDST is FastAggregateVerifyMinSig with a
// caller-supplied domain separation tag.
func FastAggregateVerifyMinSigWithDST(pks []*PublicKeyMinSig, msg, aggSig, dst []byte) bool {
	pk, err := AggregatePublicKeysMinSig(pks)
	if err != nil {
		return false
	}
	return VerifyMinSigWithDST(pk, msg, aggSig, dst)
}
