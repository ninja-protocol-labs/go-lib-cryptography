package secp256r1

import (
	"crypto/ecdh"
	"crypto/sha256"
)

// ECDH computes the shared secret between k and pub via crypto/ecdh's
// constant-time Diffie-Hellman implementation, then returns SHA-256 of the
// resulting X-coordinate — not the raw X-coordinate crypto/ecdh itself
// returns, so that every curve package in this library hands back the same
// shape of value (a fixed 32-byte secret suitable for direct use as key
// material) regardless of what a given curve's underlying DH primitive
// happens to produce.
func (k *PrivateKey) ECDH(pub *PublicKey) ([32]byte, error) {
	priv, err := ecdh.P256().NewPrivateKey(k.key[:])
	if err != nil {
		return [32]byte{}, ErrECDHFailed
	}

	uncompressed, err := pub.BytesUncompressed()
	if err != nil {
		return [32]byte{}, ErrECDHFailed
	}
	remote, err := ecdh.P256().NewPublicKey(uncompressed[:])
	if err != nil {
		return [32]byte{}, ErrECDHFailed
	}

	shared, err := priv.ECDH(remote)
	if err != nil {
		return [32]byte{}, ErrECDHFailed
	}
	return sha256.Sum256(shared), nil
}
