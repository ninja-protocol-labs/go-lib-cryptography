package bls12381

import "github.com/ninja-protocol-labs/go-lib-cryptography/bls12381/internal"

// AggregatePublicKeysMinPk sums a set of min-pk public keys into one. Each
// input is already validated (parsed via PublicKeyMinPkFromBytes or
// derived from a PrivateKey), so this only checks the set is non-empty.
func AggregatePublicKeysMinPk(pks []*PublicKeyMinPk) (*PublicKeyMinPk, error) {
	if len(pks) == 0 {
		return nil, ErrAggregateFailed
	}
	buf := make([]byte, 0, len(pks)*internal.P1AffineLen)
	for _, pk := range pks {
		if pk == nil {
			return nil, ErrAggregateFailed
		}
		buf = append(buf, pk.point[:]...)
	}
	point, code := internal.P1sAggregateAffine(buf)
	if code != internal.ErrSuccess {
		return nil, ErrAggregateFailed
	}
	return &PublicKeyMinPk{point: point}, nil
}

// AggregatePublicKeysMinSig is AggregatePublicKeysMinPk's mirror for
// min-sig public keys.
func AggregatePublicKeysMinSig(pks []*PublicKeyMinSig) (*PublicKeyMinSig, error) {
	if len(pks) == 0 {
		return nil, ErrAggregateFailed
	}
	buf := make([]byte, 0, len(pks)*internal.P2AffineLen)
	for _, pk := range pks {
		if pk == nil {
			return nil, ErrAggregateFailed
		}
		buf = append(buf, pk.point[:]...)
	}
	point, code := internal.P2sAggregateAffine(buf)
	if code != internal.ErrSuccess {
		return nil, ErrAggregateFailed
	}
	return &PublicKeyMinSig{point: point}, nil
}

// AggregateSignaturesMinPk sums a set of min-pk signatures (each
// SignatureMinPkLen bytes, e.g. from SignMinPk) into one compressed
// signature. Unlike AggregatePublicKeysMinPk, each signature here is
// untrusted wire data — encoding, on-curve, and subgroup membership are all
// checked as it's parsed.
func AggregateSignaturesMinPk(sigs [][]byte) ([SignatureMinPkLen]byte, error) {
	var out [SignatureMinPkLen]byte
	if len(sigs) == 0 {
		return out, ErrAggregateFailed
	}
	buf := make([]byte, 0, len(sigs)*internal.P2CompressedLen)
	for _, sig := range sigs {
		if len(sig) != internal.P2CompressedLen {
			return out, ErrInvalidSignature
		}
		buf = append(buf, sig...)
	}
	point, code := internal.P2sAggregateCompressed(buf)
	if code != internal.ErrSuccess {
		return out, ErrAggregateFailed
	}
	return internal.P2AffineCompress(&point), nil
}

// AggregateSignaturesMinSig is AggregateSignaturesMinPk's mirror for
// min-sig signatures (each SignatureMinSigLen bytes).
func AggregateSignaturesMinSig(sigs [][]byte) ([SignatureMinSigLen]byte, error) {
	var out [SignatureMinSigLen]byte
	if len(sigs) == 0 {
		return out, ErrAggregateFailed
	}
	buf := make([]byte, 0, len(sigs)*internal.P1CompressedLen)
	for _, sig := range sigs {
		if len(sig) != internal.P1CompressedLen {
			return out, ErrInvalidSignature
		}
		buf = append(buf, sig...)
	}
	point, code := internal.P1sAggregateCompressed(buf)
	if code != internal.ErrSuccess {
		return out, ErrAggregateFailed
	}
	return internal.P1AffineCompress(&point), nil
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
func AggregateVerifyMinPkWithDST(pks []*PublicKeyMinPk, msgs [][]byte, aggSig, dst []byte) bool {
	if len(pks) == 0 || len(pks) != len(msgs) || len(aggSig) != internal.P2CompressedLen {
		return false
	}

	var compressed [internal.P2CompressedLen]byte
	copy(compressed[:], aggSig)
	sigPoint, code := internal.P2Uncompress(&compressed)
	if code != internal.ErrSuccess || !internal.P2AffineInG2(&sigPoint) {
		return false
	}

	ctx := make([]byte, internal.PairingSizeof()+len(dst))
	internal.PairingInit(ctx, true, dst)
	for i, pk := range pks {
		if pk == nil {
			return false
		}
		if code := internal.PairingAggregatePkInG1(ctx, &pk.point, nil, msgs[i], nil); code != internal.ErrSuccess {
			return false
		}
	}
	internal.PairingCommit(ctx)

	gtsig := internal.AggregatedInG2(&sigPoint)
	return internal.PairingFinalVerify(ctx, &gtsig)
}

// AggregateVerifyMinSig is AggregateVerifyMinPk's mirror for the min-sig
// scheme. Uses DefaultDSTMinSig.
func AggregateVerifyMinSig(pks []*PublicKeyMinSig, msgs [][]byte, aggSig []byte) bool {
	return AggregateVerifyMinSigWithDST(pks, msgs, aggSig, []byte(DefaultDSTMinSig))
}

// AggregateVerifyMinSigWithDST is AggregateVerifyMinSig with a
// caller-supplied domain separation tag.
func AggregateVerifyMinSigWithDST(pks []*PublicKeyMinSig, msgs [][]byte, aggSig, dst []byte) bool {
	if len(pks) == 0 || len(pks) != len(msgs) || len(aggSig) != internal.P1CompressedLen {
		return false
	}

	var compressed [internal.P1CompressedLen]byte
	copy(compressed[:], aggSig)
	sigPoint, code := internal.P1Uncompress(&compressed)
	if code != internal.ErrSuccess || !internal.P1AffineInG1(&sigPoint) {
		return false
	}

	ctx := make([]byte, internal.PairingSizeof()+len(dst))
	internal.PairingInit(ctx, true, dst)
	for i, pk := range pks {
		if pk == nil {
			return false
		}
		if code := internal.PairingAggregatePkInG2(ctx, &pk.point, nil, msgs[i], nil); code != internal.ErrSuccess {
			return false
		}
	}
	internal.PairingCommit(ctx)

	gtsig := internal.AggregatedInG1(&sigPoint)
	return internal.PairingFinalVerify(ctx, &gtsig)
}

// FastAggregateVerifyMinPk verifies an aggregated min-pk signature against
// a single shared message, signed by every key in pks — the common case
// (all validators attesting to the same block, etc.), cheaper than
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
