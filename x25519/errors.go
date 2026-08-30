package x25519

import "errors"

// Sentinel errors for the functions that return one — parsing and ECDH.
var (
	// ErrInvalidPrivateKey means the given bytes are not a 32-byte scalar.
	// X25519 imposes no [1, n-1]-style range on top of that — any 32
	// bytes are a valid X25519 private key — so this is a length check
	// only.
	ErrInvalidPrivateKey = errors.New("x25519: invalid private key")

	// ErrInvalidPublicKey means the given bytes are not a 32-byte
	// u-coordinate. X25519's Montgomery-ladder design accepts any
	// 32-byte value here — there is no on-curve check to fail — so this
	// is a length check only.
	ErrInvalidPublicKey = errors.New("x25519: invalid public key")

	// ErrECDHFailed means the computed shared secret was the all-zero
	// value — crypto/ecdh's defense against a small-order or otherwise
	// adversarially chosen peer public key landing the result on the
	// identity. This is the one way X25519's ECDH can legitimately fail
	// even though NewPublicKey accepted the input.
	ErrECDHFailed = errors.New("x25519: ECDH failed")
)
