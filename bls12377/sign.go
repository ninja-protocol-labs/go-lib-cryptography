package bls12377

import bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"

// The two generators, and their negations. Verification pairs a signature
// against the negated generator so that the whole check collapses into a
// single product-of-pairings equal to one, which is what gnark-crypto's
// PairingCheck computes.
var (
	g1Gen, g1GenNeg bls12377.G1Affine
	g2Gen, g2GenNeg bls12377.G2Affine
)

func init() {
	_, _, g1Gen, g2Gen = bls12377.Generators()
	g1GenNeg.Neg(&g1Gen)
	g2GenNeg.Neg(&g2Gen)
}

// SignMinPk signs msg under the min-pk scheme: the signature is
// priv*HashToG2(msg), a compressed G2 point. Uses DefaultDSTMinPk.
//
// Unlike bls12381's SignMinPk this returns an error, because
// hash-to-curve here is a Go function that can fail (see
// ErrHashToCurveFailed) rather than a blst call that cannot.
func SignMinPk(priv *PrivateKey, msg []byte) ([SignatureMinPkLen]byte, error) {
	return SignMinPkWithDST(priv, msg, []byte(DefaultDSTMinPk))
}

// SignMinPkWithDST is SignMinPk with a caller-supplied domain separation
// tag.
func SignMinPkWithDST(priv *PrivateKey, msg, dst []byte) ([SignatureMinPkLen]byte, error) {
	var out [SignatureMinPkLen]byte
	if priv == nil {
		return out, ErrInvalidPrivateKey
	}
	h, err := bls12377.HashToG2(msg, dst)
	if err != nil {
		return out, ErrHashToCurveFailed
	}
	var sig bls12377.G2Affine
	sig.ScalarMultiplication(&h, priv.scalar())
	return sig.Bytes(), nil
}

// SignMinSig signs msg under the min-sig scheme: the signature is
// priv*HashToG1(msg), a compressed G1 point. Uses DefaultDSTMinSig.
func SignMinSig(priv *PrivateKey, msg []byte) ([SignatureMinSigLen]byte, error) {
	return SignMinSigWithDST(priv, msg, []byte(DefaultDSTMinSig))
}

// SignMinSigWithDST is SignMinSig with a caller-supplied domain
// separation tag.
func SignMinSigWithDST(priv *PrivateKey, msg, dst []byte) ([SignatureMinSigLen]byte, error) {
	var out [SignatureMinSigLen]byte
	if priv == nil {
		return out, ErrInvalidPrivateKey
	}
	h, err := bls12377.HashToG1(msg, dst)
	if err != nil {
		return out, ErrHashToCurveFailed
	}
	var sig bls12377.G1Affine
	sig.ScalarMultiplication(&h, priv.scalar())
	return sig.Bytes(), nil
}

// VerifyMinPk checks a min-pk signature: e(pk, HashToG2(msg)) == e(G1,
// sig). Uses DefaultDSTMinPk.
func VerifyMinPk(pub *PublicKeyMinPk, msg, sig []byte) bool {
	return VerifyMinPkWithDST(pub, msg, sig, []byte(DefaultDSTMinPk))
}

// VerifyMinPkWithDST is VerifyMinPk with a caller-supplied domain
// separation tag.
func VerifyMinPkWithDST(pub *PublicKeyMinPk, msg, sig, dst []byte) bool {
	if pub == nil || len(sig) != SignatureMinPkLen {
		return false
	}
	var sigPoint bls12377.G2Affine
	if _, err := sigPoint.SetBytes(sig); err != nil {
		return false
	}
	h, err := bls12377.HashToG2(msg, dst)
	if err != nil {
		return false
	}
	ok, err := bls12377.PairingCheck(
		[]bls12377.G1Affine{pub.point, g1GenNeg},
		[]bls12377.G2Affine{h, sigPoint},
	)
	return err == nil && ok
}

// VerifyMinSig checks a min-sig signature: e(HashToG1(msg), pk) == e(sig,
// G2). Uses DefaultDSTMinSig.
func VerifyMinSig(pub *PublicKeyMinSig, msg, sig []byte) bool {
	return VerifyMinSigWithDST(pub, msg, sig, []byte(DefaultDSTMinSig))
}

// VerifyMinSigWithDST is VerifyMinSig with a caller-supplied domain
// separation tag.
func VerifyMinSigWithDST(pub *PublicKeyMinSig, msg, sig, dst []byte) bool {
	if pub == nil || len(sig) != SignatureMinSigLen {
		return false
	}
	var sigPoint bls12377.G1Affine
	if _, err := sigPoint.SetBytes(sig); err != nil {
		return false
	}
	h, err := bls12377.HashToG1(msg, dst)
	if err != nil {
		return false
	}
	var sigNeg bls12377.G1Affine
	sigNeg.Neg(&sigPoint)
	ok, err := bls12377.PairingCheck(
		[]bls12377.G1Affine{h, sigNeg},
		[]bls12377.G2Affine{pub.point, g2Gen},
	)
	return err == nil && ok
}
