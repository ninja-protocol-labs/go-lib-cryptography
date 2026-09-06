// Package x25519 is the public API for X25519 (RFC 7748) key exchange
// over Curve25519, wrapping crypto/ecdh.
//
// X25519 is a Diffie-Hellman function only; there is no signing scheme
// here the way there is in ed25519. Curve25519 underlies both, but an
// X25519 key is not an Ed25519 key — RFC 7748 and RFC 8032 differ in
// encoding and in scalar clamping — and this package converts between
// neither.
//
// PublicKeyFromBytes is a length check only: X25519's Montgomery ladder
// has no on-curve test to perform, and any 32-byte u-coordinate is
// accepted, adversarial or not. ECDH is where that is handled.
package x25519

const (
	// SeckeyLen is the byte length of a private key: a clamped scalar.
	SeckeyLen = 32

	// PubkeyLen is the byte length of a public key: a u-coordinate.
	PubkeyLen = 32

	// SharedSecretLen is the byte length of what ECDH returns.
	SharedSecretLen = 32
)
