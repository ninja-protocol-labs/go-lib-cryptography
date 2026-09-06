package bls12377bls

import "github.com/consensys/gnark-crypto/ecc/bls12-377"

// Sums are accumulated in Jacobian coordinates: the zero value is the point
// at infinity, so the accumulator needs no special case for the first term,
// and each addition avoids an inversion.

// AggregatePublicKeysMinPk sums a set of min-pk public keys into one. Every
// input was validated when it was parsed or derived, so this only checks
// the set is non-empty.
func AggregatePublicKeysMinPk(pks []*PublicKeyMinPk) (*PublicKeyMinPk, error) {
	var (
		acc bls12377.G1Jac
		sum bls12377.G1Affine
	)

	if len(pks) == 0 {
		return nil, ErrAggregateFailed
	}

	for _, pk := range pks {
		if pk == nil {
			return nil, ErrAggregateFailed
		}

		var term bls12377.G1Jac
		p := pk.point()
		term.FromAffine(&p)
		acc.AddAssign(&term)
	}

	sum.FromJacobian(&acc)
	return &PublicKeyMinPk{
		key: sum.Bytes(),
	}, nil
}

func AggregatePublicKeysMinSig(pks []*PublicKeyMinSig) (*PublicKeyMinSig, error) {
	var (
		acc bls12377.G2Jac
		sum bls12377.G2Affine
	)

	if len(pks) == 0 {
		return nil, ErrAggregateFailed
	}

	for _, pk := range pks {
		if pk == nil {
			return nil, ErrAggregateFailed
		}

		var term bls12377.G2Jac
		p := pk.point()
		term.FromAffine(&p)
		acc.AddAssign(&term)
	}

	sum.FromJacobian(&acc)
	return &PublicKeyMinSig{
		key: sum.Bytes(),
	}, nil
}

// AggregateSignaturesMinPk sums a set of signatures in one pass. Use
// SignatureAggregatorMinPk directly when they arrive over time.
func AggregateSignaturesMinPk(sigs []*SignatureMinPk) (*SignatureMinPk, error) {
	var a SignatureAggregatorMinPk

	for _, sig := range sigs {
		if err := a.Add(sig); err != nil {
			return nil, err
		}
	}
	return a.Signature()
}

func AggregateSignaturesMinSig(sigs []*SignatureMinSig) (*SignatureMinSig, error) {
	var a SignatureAggregatorMinSig

	for _, sig := range sigs {
		if err := a.Add(sig); err != nil {
			return nil, err
		}
	}
	return a.Signature()
}

// AggregateVerifyMinPk verifies an aggregated signature against distinct
// (public key, message) pairs — the general case, where every signer signed
// their own message. pks and msgs must have the same, non-zero length, and
// msgs[i] is checked against pks[i]. Uses DefaultDSTMinPk.
//
// The whole check is one product of pairings:
// ∏ e(pkᵢ, H(msgᵢ)) · e(-G1, sig) == 1.
func AggregateVerifyMinPk(pks []*PublicKeyMinPk, msgs [][]byte, sig *SignatureMinPk) bool {
	return AggregateVerifyMinPkWithDST(pks, msgs, sig, []byte(DefaultDSTMinPk))
}

func AggregateVerifyMinPkWithDST(pks []*PublicKeyMinPk, msgs [][]byte, sig *SignatureMinPk, dst []byte) bool {
	if len(pks) == 0 || len(pks) != len(msgs) || sig == nil {
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

		ps = append(ps, pk.point())
		qs = append(qs, h)
	}
	ps = append(ps, g1GenNeg)
	qs = append(qs, sig.point())

	ok, err := bls12377.PairingCheck(ps, qs)
	return err == nil && ok
}

// AggregateVerifyMinSig is AggregateVerifyMinPk's mirror. Uses
// DefaultDSTMinSig.
func AggregateVerifyMinSig(pks []*PublicKeyMinSig, msgs [][]byte, sig *SignatureMinSig) bool {
	return AggregateVerifyMinSigWithDST(pks, msgs, sig, []byte(DefaultDSTMinSig))
}

func AggregateVerifyMinSigWithDST(pks []*PublicKeyMinSig, msgs [][]byte, sig *SignatureMinSig, dst []byte) bool {
	var sigNeg bls12377.G1Affine

	if len(pks) == 0 || len(pks) != len(msgs) || sig == nil {
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
		qs = append(qs, pk.point())
	}

	p := sig.point()
	sigNeg.Neg(&p)
	ps = append(ps, sigNeg)
	qs = append(qs, g2Gen)

	ok, err := bls12377.PairingCheck(ps, qs)
	return err == nil && ok
}

// FastAggregateVerifyMinPk verifies an aggregated signature over a single
// shared message signed by every key in pks — the common case, and cheaper
// than AggregateVerifyMinPk because the keys are summed once instead of
// paired individually. Uses DefaultDSTMinPk.
//
// This is only sound when every key in pks is known to have a matching
// private key. The default ciphersuite is the basic scheme, which does not
// establish that: an attacker who registers pk' = x·G - Σpkᵢ can produce an
// aggregate signature that verifies for a message the honest signers never
// saw (the rogue key attack). Applications taking public keys from
// untrusted parties must bind each key to a proof of possession — the
// _POP_ ciphersuite, via the WithDST variants — and check those proofs
// before calling this.
func FastAggregateVerifyMinPk(pks []*PublicKeyMinPk, msg []byte, sig *SignatureMinPk) bool {
	return FastAggregateVerifyMinPkWithDST(pks, msg, sig, []byte(DefaultDSTMinPk))
}

func FastAggregateVerifyMinPkWithDST(pks []*PublicKeyMinPk, msg []byte, sig *SignatureMinPk, dst []byte) bool {
	pk, err := AggregatePublicKeysMinPk(pks)
	if err != nil {
		return false
	}
	return VerifyMinPkWithDST(pk, msg, sig, dst)
}

// FastAggregateVerifyMinSig is FastAggregateVerifyMinPk's mirror, and
// carries the same rogue key caveat. Uses DefaultDSTMinSig.
func FastAggregateVerifyMinSig(pks []*PublicKeyMinSig, msg []byte, sig *SignatureMinSig) bool {
	return FastAggregateVerifyMinSigWithDST(pks, msg, sig, []byte(DefaultDSTMinSig))
}

func FastAggregateVerifyMinSigWithDST(pks []*PublicKeyMinSig, msg []byte, sig *SignatureMinSig, dst []byte) bool {
	pk, err := AggregatePublicKeysMinSig(pks)
	if err != nil {
		return false
	}
	return VerifyMinSigWithDST(pk, msg, sig, dst)
}
