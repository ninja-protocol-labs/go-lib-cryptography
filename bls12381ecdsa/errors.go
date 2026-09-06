package bls12381ecdsa

import "errors"

var (
	ErrInvalidPrivateKey = errors.New("bls12381ecdsa: invalid private key")
	ErrInvalidPublicKey  = errors.New("bls12381ecdsa: invalid public key")
	ErrInvalidSignature  = errors.New("bls12381ecdsa: invalid signature")
	ErrSigningFailed     = errors.New("bls12381ecdsa: signing failed")
)
