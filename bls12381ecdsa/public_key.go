package bls12381ecdsa

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/ecdsa"
	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

type PublicKey struct {
	key [PubkeyLen]byte
}

// PublicKeyFromBytes parses a compressed G1 point.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	var (
		k   [PubkeyLen]byte
		pub ecdsa.PublicKey
	)

	if len(b) != PubkeyLen {
		return nil, ErrInvalidPublicKey
	}
	if _, err := pub.SetBytes(b); err != nil {
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

// IsZero catches a `var k PublicKey`; no constructor returns one.
func (k *PublicKey) IsZero() bool {
	return k == nil || *k == PublicKey{}
}

// verifier is k in the form gnark takes; k.key was parsed at
// construction, so the error cannot fire.
func (k *PublicKey) verifier() *ecdsa.PublicKey {
	var pub ecdsa.PublicKey

	_, _ = pub.SetBytes(k.key[:])
	return &pub
}

func (k *PublicKey) String() string {
	return encoding.Hex.Encode(k.key[:])
}
