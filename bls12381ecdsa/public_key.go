package bls12381ecdsa

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/ecdsa"
	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

type PublicKey struct {
	key ecdsa.PublicKey
}

// PublicKeyFromBytes parses a compressed G1 point.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	var k ecdsa.PublicKey

	if len(b) != PubkeyLen {
		return nil, ErrInvalidPublicKey
	}
	if _, err := k.SetBytes(b); err != nil {
		return nil, ErrInvalidPublicKey
	}

	return &PublicKey{
		key: k,
	}, nil
}

func (k *PublicKey) Bytes() [PubkeyLen]byte {
	var b [PubkeyLen]byte

	copy(b[:], k.key.Bytes())
	return b
}

func (k *PublicKey) Equal(o *PublicKey) bool {
	if o == nil {
		return false
	}
	return k.key.Equal(&o.key)
}

// IsZero catches a `var k PublicKey`; no constructor returns one.
func (k *PublicKey) IsZero() bool {
	return k == nil || *k == PublicKey{}
}

func (k *PublicKey) String() string {
	b := k.Bytes()
	return encoding.Hex.Encode(b[:])
}
