package bn254ecdsa

import "errors"

var (
	ErrInvalidPrivateKey = errors.New("bn254ecdsa: invalid private key")
	ErrInvalidPublicKey  = errors.New("bn254ecdsa: invalid public key")
	ErrInvalidSignature  = errors.New("bn254ecdsa: invalid signature")
	ErrSigningFailed     = errors.New("bn254ecdsa: signing failed")
)
