package bls12377ecdsa

import "errors"

// Sentinel errors.
var (
	// ErrInvalidPrivateKey means the bytes are not SeckeyLen long, or
	// the scalar they encode is zero or at least r, the group order.
	ErrInvalidPrivateKey = errors.New("bls12377ecdsa: invalid private key")

	// ErrInvalidPublicKey means the bytes are not a compressed point in
	// BLS12-377's G1. A non-canonical encoding is rejected rather than
	// reduced, so a key re-encodes to exactly the bytes it was parsed from.
	ErrInvalidPublicKey = errors.New("bls12377ecdsa: invalid public key")

	// ErrInvalidSignature means the bytes are not SignatureLen long, or r
	// or s is out of range. The check happens when the signature is used
	// rather than when it is parsed; see SignatureFromBytes.
	ErrInvalidSignature = errors.New("bls12377ecdsa: invalid signature")

	// ErrSigningFailed means no signature could be produced. Nonce
	// generation is hedged with fresh entropy, so in practice this is the
	// entropy source failing.
	ErrSigningFailed = errors.New("bls12377ecdsa: signing failed")
)
