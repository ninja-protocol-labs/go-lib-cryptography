package bls12381

import "github.com/consensys/gnark-crypto/ecc/bls12-381"

// The generators, and the negations verification needs. Pairing the
// signature against a negated generator collapses the check into one
// product of pairings equal to 1, which is what PairingCheck computes.
var (
	g1Gen, g1GenNeg bls12381.G1Affine
	g2Gen, g2GenNeg bls12381.G2Affine
)

func init() {
	_, _, g1Gen, g2Gen = bls12381.Generators()
	g1GenNeg.Neg(&g1Gen)
	g2GenNeg.Neg(&g2Gen)
}

// SignMinPk signs msg under the min-pk scheme: the signature is
// k*HashToG2(msg), a compressed G2 point. Uses DefaultDSTMinPk.
func SignMinPk(k *PrivateKeyMinPk, msg []byte) (*SignatureMinPk, error) {
	return SignMinPkWithDST(k, msg, []byte(DefaultDSTMinPk))
}

// SignMinPkWithDST is SignMinPk with a caller-supplied domain separation
// tag, for a ciphersuite other than the default.
func SignMinPkWithDST(k *PrivateKeyMinPk, msg, dst []byte) (*SignatureMinPk, error) {
	var sig bls12381.G2Affine

	if k == nil {
		return nil, ErrInvalidPrivateKey
	}

	h, err := bls12381.HashToG2(msg, dst)
	if err != nil {
		return nil, ErrHashToCurveFailed
	}

	sig.ScalarMultiplication(&h, k.scalar())
	return &SignatureMinPk{
		sig: sig.Bytes(),
	}, nil
}

// SignMinSig is SignMinPk's mirror: the signature is k*HashToG1(msg), a
// compressed G1 point. Uses DefaultDSTMinSig.
func SignMinSig(k *PrivateKeyMinSig, msg []byte) (*SignatureMinSig, error) {
	return SignMinSigWithDST(k, msg, []byte(DefaultDSTMinSig))
}

func SignMinSigWithDST(k *PrivateKeyMinSig, msg, dst []byte) (*SignatureMinSig, error) {
	var sig bls12381.G1Affine

	if k == nil {
		return nil, ErrInvalidPrivateKey
	}

	h, err := bls12381.HashToG1(msg, dst)
	if err != nil {
		return nil, ErrHashToCurveFailed
	}

	sig.ScalarMultiplication(&h, k.scalar())
	return &SignatureMinSig{
		sig: sig.Bytes(),
	}, nil
}

// VerifyMinPk checks e(pk, HashToG2(msg)) == e(G1, sig). Uses
// DefaultDSTMinPk.
func VerifyMinPk(k *PublicKeyMinPk, msg []byte, sig *SignatureMinPk) bool {
	return VerifyMinPkWithDST(k, msg, sig, []byte(DefaultDSTMinPk))
}

// VerifyMinPkWithDST is VerifyMinPk with a caller-supplied tag. It must
// match the signer's, or every signature is rejected.
func VerifyMinPkWithDST(k *PublicKeyMinPk, msg []byte, sig *SignatureMinPk, dst []byte) bool {
	if k == nil || sig == nil {
		return false
	}

	h, err := bls12381.HashToG2(msg, dst)
	if err != nil {
		return false
	}

	ok, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{k.point(), g1GenNeg},
		[]bls12381.G2Affine{h, sig.point()},
	)
	return err == nil && ok
}

// VerifyMinSig checks e(HashToG1(msg), pk) == e(sig, G2). Uses
// DefaultDSTMinSig.
func VerifyMinSig(k *PublicKeyMinSig, msg []byte, sig *SignatureMinSig) bool {
	return VerifyMinSigWithDST(k, msg, sig, []byte(DefaultDSTMinSig))
}

func VerifyMinSigWithDST(k *PublicKeyMinSig, msg []byte, sig *SignatureMinSig, dst []byte) bool {
	var sigNeg bls12381.G1Affine

	if k == nil || sig == nil {
		return false
	}

	h, err := bls12381.HashToG1(msg, dst)
	if err != nil {
		return false
	}

	p := sig.point()
	sigNeg.Neg(&p)

	ok, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{h, sigNeg},
		[]bls12381.G2Affine{k.point(), g2Gen},
	)
	return err == nil && ok
}
