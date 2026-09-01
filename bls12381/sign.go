package bls12381

import "github.com/ninja-protocol-labs/go-lib-cryptography/bls12381/internal"

// SignMinPk signs msg with priv under the min-pk scheme (signature in G2),
// using DefaultDSTMinPk.
func SignMinPk(priv *PrivateKey, msg []byte) [SignatureMinPkLen]byte {
	return SignMinPkWithDST(priv, msg, []byte(DefaultDSTMinPk))
}

// SignMinPkWithDST is SignMinPk with a caller-supplied domain separation
// tag, for applications that need a ciphersuite other than the default.
func SignMinPkWithDST(priv *PrivateKey, msg, dst []byte) [SignatureMinPkLen]byte {
	return internal.SignMsgPkInG1(&priv.key, msg, dst, nil)
}

// SignMinSig signs msg with priv under the min-sig scheme (signature in
// G1), using DefaultDSTMinSig.
func SignMinSig(priv *PrivateKey, msg []byte) [SignatureMinSigLen]byte {
	return SignMinSigWithDST(priv, msg, []byte(DefaultDSTMinSig))
}

// SignMinSigWithDST is SignMinSig with a caller-supplied domain separation
// tag.
func SignMinSigWithDST(priv *PrivateKey, msg, dst []byte) [SignatureMinSigLen]byte {
	return internal.SignMsgPkInG2(&priv.key, msg, dst, nil)
}

// VerifyMinPk verifies sig (SignatureMinPkLen bytes) over msg against pub,
// using DefaultDSTMinPk. Reports false for any malformed input — a bad
// encoding is not distinguished from a genuinely invalid signature.
func VerifyMinPk(pub *PublicKeyMinPk, msg, sig []byte) bool {
	return VerifyMinPkWithDST(pub, msg, sig, []byte(DefaultDSTMinPk))
}

// VerifyMinPkWithDST is VerifyMinPk with a caller-supplied domain
// separation tag — it must match whatever the signer used, or every
// signature will be rejected.
func VerifyMinPkWithDST(pub *PublicKeyMinPk, msg, sig, dst []byte) bool {
	if pub == nil || len(sig) != internal.P2CompressedLen {
		return false
	}
	var compressed [internal.P2CompressedLen]byte
	copy(compressed[:], sig)
	sigPoint, code := internal.P2Uncompress(&compressed)
	if code != internal.ErrSuccess {
		return false
	}
	return internal.CoreVerifyPkInG1(&pub.point, &sigPoint, true, msg, dst, nil) == internal.ErrSuccess
}

// VerifyMinSig verifies sig (SignatureMinSigLen bytes) over msg against pub,
// using DefaultDSTMinSig.
func VerifyMinSig(pub *PublicKeyMinSig, msg, sig []byte) bool {
	return VerifyMinSigWithDST(pub, msg, sig, []byte(DefaultDSTMinSig))
}

// VerifyMinSigWithDST is VerifyMinSig with a caller-supplied domain
// separation tag.
func VerifyMinSigWithDST(pub *PublicKeyMinSig, msg, sig, dst []byte) bool {
	if pub == nil || len(sig) != internal.P1CompressedLen {
		return false
	}
	var compressed [internal.P1CompressedLen]byte
	copy(compressed[:], sig)
	sigPoint, code := internal.P1Uncompress(&compressed)
	if code != internal.ErrSuccess {
		return false
	}
	return internal.CoreVerifyPkInG2(&pub.point, &sigPoint, true, msg, dst, nil) == internal.ErrSuccess
}
