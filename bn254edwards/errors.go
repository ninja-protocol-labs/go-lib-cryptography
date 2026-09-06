package bn254edwards

import "errors"

var (
	ErrInvalidPrivateKey = errors.New("bn254edwards: invalid private key")
	ErrInvalidPublicKey  = errors.New("bn254edwards: invalid public key")
	ErrInvalidSignature  = errors.New("bn254edwards: invalid signature")
	ErrHashRequired      = errors.New("bn254edwards: hash function required")
	ErrSigningFailed     = errors.New("bn254edwards: signing failed")
)
