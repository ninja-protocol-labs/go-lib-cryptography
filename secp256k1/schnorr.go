package secp256k1

import "github.com/ninja-protocol-labs/go-lib-cryptography/secp256k1/internal"

// Schnorr signing and verification, over x-only public keys.
//
// Unlike ECDSA, Schnorr signs a message of any length directly — it hashes
// internally as part of the scheme itself, not as a preprocessing step this
// package adds, so there is no separate SignDigest here.
//
// Verification takes the ordinary (compressed) PublicKey, not a bare x-only
// value: dropping the y coordinate is part of what verifying a Schnorr
// signature does, not something the caller should have to do first.

// SignSchnorr signs msg with priv.
func SignSchnorr(priv *PrivateKey, msg []byte) ([]byte, error) {
	sig, ok := internal.SchnorrSign(msg, &priv.key)
	if !ok {
		return nil, ErrSigningFailed
	}
	return sig[:], nil
}

// SignSchnorrHedged is SignSchnorr with auxRand folded into the nonce
// derivation as extra entropy, so repeated signatures over the same input
// are unlinkable, without giving up the deterministic-nonce protection
// against a failing RNG. auxRand need not be secret.
func SignSchnorrHedged(priv *PrivateKey, msg []byte, auxRand *[32]byte) ([]byte, error) {
	sig, ok := internal.SchnorrSignHedged(msg, &priv.key, auxRand)
	if !ok {
		return nil, ErrSigningFailed
	}
	return sig[:], nil
}

// VerifySchnorr reports whether sig is a valid Schnorr signature over msg by
// pub.
func VerifySchnorr(pub *PublicKey, msg, sig []byte) bool {
	if len(sig) != internal.SignatureCompactLen {
		return false
	}
	xonly, _, ok := internal.XonlyPubkeyFromPubkey(pub.key[:])
	if !ok {
		return false
	}
	var fixed [internal.SignatureCompactLen]byte
	copy(fixed[:], sig)
	return internal.SchnorrVerify(msg, &xonly, &fixed)
}
