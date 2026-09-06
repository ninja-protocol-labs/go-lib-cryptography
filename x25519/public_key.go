package x25519

import "github.com/ninja-protocol-labs/go-lib-cryptography/encoding"

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

func (k *PublicKey) Bytes() [PubkeyLen]byte {
	return k.key
}

func (k *PublicKey) Equal(o *PublicKey) bool {
	if o == nil {
		return false
	}
	return k.key == o.key
}

func (k *PublicKey) IsZero() bool {
	return k == nil || *k == PublicKey{}
}

func (k *PublicKey) String() string {
	return encoding.Hex.Encode(k.key[:])
}
