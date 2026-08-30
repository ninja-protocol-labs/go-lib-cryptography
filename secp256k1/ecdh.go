package secp256k1

import "github.com/ninja-protocol-labs/go-lib-cryptography/secp256k1/internal"

// ECDH computes the shared secret between k and pub: SHA-256 of the
// compressed encoding of the point k.key * pub.key. Both sides of a key
// exchange arrive at the same value, since k.key*pub.key == pub.key*k.key
// as scalar multiples of the same point.
func (k *PrivateKey) ECDH(pub *PublicKey) ([32]byte, error) {
	secret, ok := internal.ECDH(pub.key[:], &k.key)
	if !ok {
		return [32]byte{}, ErrECDHFailed
	}
	return secret, nil
}
