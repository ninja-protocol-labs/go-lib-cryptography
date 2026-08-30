package x25519

import (
	"crypto/sha256"
)

// ECDH computes the shared secret between k and pub via crypto/ecdh's
// X25519 implementation (RFC 7748, Section 6.1), then returns SHA-256 of
// the raw 32-byte result — not that raw result itself, so that every
// curve package in this library hands back the same shape of value (a
// fixed 32-byte secret suitable for direct use as key material) regardless
// of what a given curve's underlying DH primitive happens to produce. See
// secp256r1.PrivateKey.ECDH for the same rationale.
//
// This is the one place X25519 can legitimately fail on well-formed
// input: crypto/ecdh rejects an all-zero result, which a small-order or
// otherwise adversarially chosen pub can produce even though it passed
// PublicKeyFromBytes (which cannot check for this — see the package doc).
func (k *PrivateKey) ECDH(pub *PublicKey) ([32]byte, error) {
	priv, err := curve().NewPrivateKey(k.key[:])
	if err != nil {
		return [32]byte{}, ErrECDHFailed
	}
	remote, err := curve().NewPublicKey(pub.key[:])
	if err != nil {
		return [32]byte{}, ErrECDHFailed
	}

	shared, err := priv.ECDH(remote)
	if err != nil {
		return [32]byte{}, ErrECDHFailed
	}
	return sha256.Sum256(shared), nil
}
