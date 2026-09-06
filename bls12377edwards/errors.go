package bls12377edwards

import "errors"

var (
	ErrInvalidPrivateKey = errors.New("bls12377edwards: invalid private key")
	ErrInvalidPublicKey  = errors.New("bls12377edwards: invalid public key")
	ErrInvalidSignature  = errors.New("bls12377edwards: invalid signature")
	ErrHashRequired      = errors.New("bls12377edwards: hash function required")
	ErrSigningFailed     = errors.New("bls12377edwards: signing failed")
)
