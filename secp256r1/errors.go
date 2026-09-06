package secp256r1

import "errors"

var (
	ErrInvalidPrivateKey = errors.New("secp256r1: invalid private key")
	ErrInvalidPublicKey  = errors.New("secp256r1: invalid public key")
	ErrInvalidSignature  = errors.New("secp256r1: invalid signature")
	ErrInvalidDigest     = errors.New("secp256r1: invalid digest")
	ErrSigningFailed     = errors.New("secp256r1: signing failed")

	// ErrECDHFailed means the exchange produced no usable secret.
	ErrECDHFailed = errors.New("secp256r1: key exchange failed")
)
