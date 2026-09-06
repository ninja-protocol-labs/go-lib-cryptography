package sr25519

import (
	"github.com/ChainSafe/go-schnorrkel"
	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

type PublicKey struct {
	key [PubkeyLen]byte
}

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

// schnorrkelKey rebuilds schnorrkel's PublicKey; k.key decoded at
// construction, so the error cannot fire.
func (k *PublicKey) schnorrkelKey() *schnorrkel.PublicKey {
	pub, _ := schnorrkel.NewPublicKey(k.key)
	return pub
}
