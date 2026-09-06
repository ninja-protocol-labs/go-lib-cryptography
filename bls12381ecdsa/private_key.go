package bls12381ecdsa

import (
	"crypto/rand"
	"crypto/subtle"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/ecdsa"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// order is r, the order of the group a scalar lives in.
var order = fr.Modulus()

type PrivateKey struct {
	key ecdsa.PrivateKey
}

func GeneratePrivateKey() (*PrivateKey, error) {
	k, err := ecdsa.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		key: *k,
	}, nil
}

// PrivateKeyFromBytes parses a big-endian scalar in [1, r-1].
//
// gnark-crypto's own serialization is public key ∥ scalar, and its parser
// trusts the public key half rather than checking it against the scalar.
// This takes just the scalar — the same shape as every other private key
// in this module — and derives the public half itself, so a mismatched
// pair cannot be constructed.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	var (
		k   ecdsa.PrivateKey
		pub bls12381.G1Affine
	)

	if len(b) != SeckeyLen {
		return nil, ErrInvalidPrivateKey
	}

	s := new(big.Int).SetBytes(b)
	if s.Sign() == 0 || s.Cmp(order) >= 0 {
		return nil, ErrInvalidPrivateKey
	}

	pub.ScalarMultiplicationBase(s)
	pubBytes := pub.Bytes()

	buf := make([]byte, 0, PubkeyLen+SeckeyLen)
	buf = append(buf, pubBytes[:]...)
	buf = append(buf, b...)
	if _, err := k.SetBytes(buf); err != nil {
		return nil, ErrInvalidPrivateKey
	}

	return &PrivateKey{
		key: k,
	}, nil
}

// Bytes returns the big-endian scalar, without the cached public key
// gnark-crypto's own serialization prepends.
func (k *PrivateKey) Bytes() [SeckeyLen]byte {
	var b [SeckeyLen]byte

	full := k.key.Bytes()
	copy(b[:], full[PubkeyLen:])
	return b
}

func (k *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{
		key: k.key.PublicKey,
	}
}

func (k *PrivateKey) Equal(o *PrivateKey) bool {
	if o == nil {
		return false
	}

	a, b := k.Bytes(), o.Bytes()
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// IsZero catches a `var k PrivateKey`; no constructor returns one.
func (k *PrivateKey) IsZero() bool {
	return k == nil || *k == PrivateKey{}
}
