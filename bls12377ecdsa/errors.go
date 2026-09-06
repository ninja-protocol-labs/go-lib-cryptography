package bls12377ecdsa

import "errors"

var (
	ErrInvalidPrivateKey = errors.New("bls12377ecdsa: invalid private key")
	ErrInvalidPublicKey  = errors.New("bls12377ecdsa: invalid public key")
	ErrInvalidSignature  = errors.New("bls12377ecdsa: invalid signature")
	ErrSigningFailed     = errors.New("bls12377ecdsa: signing failed")
)
