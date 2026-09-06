package bls12381edwards

import "errors"

var (
	ErrInvalidPrivateKey = errors.New("bls12381edwards: invalid private key")
	ErrInvalidPublicKey  = errors.New("bls12381edwards: invalid public key")
	ErrInvalidSignature  = errors.New("bls12381edwards: invalid signature")
	ErrHashRequired      = errors.New("bls12381edwards: hash function required")
	ErrSigningFailed     = errors.New("bls12381edwards: signing failed")
)
