package secp256k1

import "errors"

var (
	ErrInvalidPrivateKey = errors.New("secp256k1: invalid private key")
	ErrInvalidPublicKey  = errors.New("secp256k1: invalid public key")
	ErrInvalidDigest     = errors.New("secp256k1: invalid digest")
	ErrInvalidSignature  = errors.New("secp256k1: invalid signature")
	ErrRecoveryFailed    = errors.New("secp256k1: public key recovery failed")
)
