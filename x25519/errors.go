package x25519

import "errors"

var (
	ErrInvalidPrivateKey = errors.New("x25519: invalid private key")
	ErrInvalidPublicKey  = errors.New("x25519: invalid public key")

	// ErrECDHFailed means the exchange produced an all-zero secret, which
	// a small-order public key can force.
	ErrECDHFailed = errors.New("x25519: key exchange failed")
)
