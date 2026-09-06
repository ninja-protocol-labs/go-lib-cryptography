package x25519

import "github.com/ninja-protocol-labs/go-lib-cryptography/encoding"

// PublicKey is an X25519 public key: a u-coordinate, little-endian.
//
// Every 32-byte string is one, so parsing checks only the length. A
// low-order point is a valid encoding that produces a shared secret with
// no secrecy in it, and ECDH is what rejects that.
type PublicKey struct {
	key [PubkeyLen]byte
}

// PublicKeyFromBytes wraps a u-coordinate. See the package doc for why
// this is a length check only.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	var k [PubkeyLen]byte

	if _, err := curve().NewPublicKey(b); err != nil {
		return nil, ErrInvalidPublicKey
	}

	copy(k[:], b)
	return &PublicKey{
		key: k,
	}, nil
}

// Bytes returns the u-coordinate, as a copy.
func (k *PublicKey) Bytes() [PubkeyLen]byte {
	return k.key
}

// Equal reports whether o is the same key. It is nil-safe.
func (k *PublicKey) Equal(o *PublicKey) bool {
	if o == nil {
		return false
	}
	return k.key == o.key
}

// IsZero catches a `var k PublicKey`; no constructor returns one.
func (k *PublicKey) IsZero() bool {
	return k == nil || *k == PublicKey{}
}

// String returns the u-coordinate as lowercase hex.
func (k *PublicKey) String() string {
	return encoding.Hex.Encode(k.key[:])
}
