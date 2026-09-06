package secp256r1

import (
	"crypto/ecdsa"
	"crypto/rand"
)

// Signing is not deterministic: crypto/ecdsa mixes fresh entropy with the
// key and digest for every signature, so the same input signs differently
// each time and signing fails if the entropy source does.

// Sign returns a signature over the 32-byte digest d.
func Sign(k *PrivateKey, d []byte) (*Signature, error) {
	if k == nil {
		return nil, ErrInvalidPrivateKey
	}
	if len(d) != DigestLen {
		return nil, ErrInvalidDigest
	}

	// k.key was validated at construction, so this cannot fail.
	priv, _ := ecdsa.ParseRawPrivateKey(curve(), k.key[:])

	r, s, err := ecdsa.Sign(rand.Reader, priv, d)
	if err != nil {
		return nil, ErrSigningFailed
	}
	return signatureFromScalars(r, s)
}

// Verify reports whether sig is k's signature over d.
func Verify(k *PublicKey, d []byte, sig *Signature) bool {
	if k == nil || sig == nil || len(d) != DigestLen {
		return false
	}

	// k.key was validated at construction, so this cannot fail.
	u := k.BytesUncompressed()
	pub, _ := ecdsa.ParseUncompressedPublicKey(curve(), u[:])

	r, s := sig.scalars()
	return ecdsa.Verify(pub, d, r, s)
}
