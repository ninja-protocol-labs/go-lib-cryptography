package ed448

import "github.com/ninja-protocol-labs/go-lib-cryptography/encoding"

type PublicKey struct {
	key [PubkeyLen]byte
}

// PublicKeyFromBytes wraps a public key. See the package doc for why this
// is a length check only, not point validation.
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

func (k *PublicKey) Bytes() [PubkeyLen]byte {
	return k.key
}

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

func (k *PublicKey) String() string {
	return encoding.Hex.Encode(k.key[:])
}
