package x25519

import "errors"

var (
	// ErrInvalidPrivateKey means the bytes are not SeckeyLen long. Every
	// 32-byte string is a usable scalar once clamped, so there is nothing
	// else to reject.
	ErrInvalidPrivateKey = errors.New("x25519: invalid private key")

	// ErrInvalidPublicKey means the bytes are not PubkeyLen long. Length
	// is all that is checked: every 32-byte string names some u-coordinate,
	// and the low-order points that would force a shared secret are
	// rejected by ECDH rather than here — see ErrECDHFailed.
	ErrInvalidPublicKey = errors.New("x25519: invalid public key")

	// ErrECDHFailed means the exchange produced an all-zero secret, which
	// a small-order public key can force.
	ErrECDHFailed = errors.New("x25519: key exchange failed")
)
