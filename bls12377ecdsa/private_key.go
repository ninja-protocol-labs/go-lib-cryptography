package bls12377ecdsa

import (
	"crypto/rand"
	"crypto/subtle"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/ecdsa"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
)

// order is r, the order of the group a scalar lives in.
var order = fr.Modulus()

type PrivateKey struct {
	key [SeckeyLen]byte
	pub [PubkeyLen]byte
}

// newPrivateKey validates a scalar and derives its point once, so
// PublicKey is a field read. Every constructor goes through here.
func newPrivateKey(key [SeckeyLen]byte) (*PrivateKey, error) {
	var p bls12377.G1Affine

	s := new(big.Int).SetBytes(key[:])
	if s.Sign() == 0 || s.Cmp(order) >= 0 {
		return nil, ErrInvalidPrivateKey
	}

	p.ScalarMultiplicationBase(s)
	return &PrivateKey{
		key: key,
		pub: p.Bytes(),
	}, nil
}

func GeneratePrivateKey() (*PrivateKey, error) {
	var key [SeckeyLen]byte

	k, err := ecdsa.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// gnark serializes as public key ∥ scalar; only the scalar is stored.
	full := k.Bytes()
	copy(key[:], full[PubkeyLen:])
	return newPrivateKey(key)
}

// PrivateKeyFromBytes parses a big-endian scalar in [1, r-1]. gnark's own
// parser trusts the public key half of its serialization rather than
// checking it against the scalar, so this takes the scalar alone and
// derives the point itself.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	var key [SeckeyLen]byte

	if len(b) != SeckeyLen {
		return nil, ErrInvalidPrivateKey
	}

	copy(key[:], b)
	return newPrivateKey(key)
}

func (k *PrivateKey) Bytes() [SeckeyLen]byte {
	return k.key
}

func (k *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{
		key: k.pub,
	}
}

func (k *PrivateKey) Equal(o *PrivateKey) bool {
	if o == nil {
		return false
	}
	return subtle.ConstantTimeCompare(k.key[:], o.key[:]) == 1
}

func (k *PrivateKey) IsZero() bool {
	return k == nil || *k == PrivateKey{}
}

// signer is k in the form gnark takes, rebuilt from the stored scalar and
// point; both were validated at construction, so the error cannot fire.
func (k *PrivateKey) signer() *ecdsa.PrivateKey {
	var priv ecdsa.PrivateKey

	buf := make([]byte, 0, PubkeyLen+SeckeyLen)
	buf = append(buf, k.pub[:]...)
	buf = append(buf, k.key[:]...)
	_, _ = priv.SetBytes(buf)
	return &priv
}
