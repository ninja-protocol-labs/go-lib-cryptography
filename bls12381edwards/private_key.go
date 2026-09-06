package bls12381edwards

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards/eddsa"
)

type PrivateKey struct {
	key eddsa.PrivateKey
}

func GeneratePrivateKey() (*PrivateKey, error) {
	k, err := eddsa.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		key: *k,
	}, nil
}

// PrivateKeyFromSeed expands a seed into a key pair deterministically: the
// scalar and the nonce source are the two halves of BLAKE2b-512(seed),
// with RFC 8032's clamping applied to the scalar. The same seed always
// yields the same key.
func PrivateKeyFromSeed(b []byte) (*PrivateKey, error) {
	if len(b) != SeedLen {
		return nil, ErrInvalidPrivateKey
	}

	k, err := eddsa.GenerateKey(bytes.NewReader(b))
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}

	return &PrivateKey{
		key: *k,
	}, nil
}

// PrivateKeyFromBytes parses what Bytes produces: public key ∥ scalar ∥
// nonce source. The scalar's clamping and its agreement with the public
// key are both checked.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	var k eddsa.PrivateKey

	if len(b) != SeckeyLen {
		return nil, ErrInvalidPrivateKey
	}
	if _, err := k.SetBytes(b); err != nil {
		return nil, ErrInvalidPrivateKey
	}

	return &PrivateKey{
		key: k,
	}, nil
}

// Bytes returns public key ∥ scalar ∥ nonce source, not the seed. See the
// package doc.
func (k *PrivateKey) Bytes() [SeckeyLen]byte {
	var b [SeckeyLen]byte

	copy(b[:], k.key.Bytes())
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
