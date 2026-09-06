package sr25519

import (
	"github.com/ChainSafe/go-schnorrkel"
	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// PublicKey is a compressed Ristretto point — the same encoding
// Substrate accounts are written in.
type PublicKey struct {
	key [PubkeyLen]byte
}

// PublicKeyFromBytes parses a compressed Ristretto point.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	var k [PubkeyLen]byte

	if len(b) != PubkeyLen {
		return nil, ErrInvalidPublicKey
	}

	copy(k[:], b)
	if _, err := schnorrkel.NewPublicKey(k); err != nil {
		return nil, ErrInvalidPublicKey
	}

	return &PublicKey{
		key: k,
	}, nil
}

// Bytes returns the compressed point, as a copy.
func (k *PublicKey) Bytes() [PubkeyLen]byte {
	return k.key
}

// Equal reports whether o is the same point. It is nil-safe.
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

// String returns the compressed point as lowercase hex.
func (k *PublicKey) String() string {
	return encoding.Hex.Encode(k.key[:])
}

// schnorrkelKey rebuilds schnorrkel's PublicKey; k.key decoded at
// construction, so the error cannot fire.
func (k *PublicKey) schnorrkelKey() *schnorrkel.PublicKey {
	pub, _ := schnorrkel.NewPublicKey(k.key)
	return pub
}
