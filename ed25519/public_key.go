package ed25519

import "github.com/ninja-protocol-labs/go-lib-cryptography/encoding"

// PublicKey is an Ed25519 public key: a compressed curve point.
type PublicKey struct {
	key [PubkeyLen]byte
}

// PublicKeyFromBytes wraps a public key. See the package doc for why this
// is a length check only, not on-curve validation.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	var k [PubkeyLen]byte

	if len(b) != PubkeyLen {
		return nil, ErrInvalidPublicKey
	}

	copy(k[:], b)
	return &PublicKey{
		key: k,
	}, nil
}

// Bytes returns the encoded public key, as a copy.
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

// IsZero catches a `var k PublicKey`.
func (k *PublicKey) IsZero() bool {
	return k == nil || *k == PublicKey{}
}

// String returns the public key as lowercase hex.
func (k *PublicKey) String() string {
	return encoding.Hex.Encode(k.key[:])
}
