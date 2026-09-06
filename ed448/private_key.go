package ed448

import (
	"crypto/rand"
	"crypto/subtle"

	ed "github.com/cloudflare/circl/sign/ed448"
)

type PrivateKey struct {
	key [SeckeyLen]byte
	pub [PubkeyLen]byte

	// exp is the (seed ∥ public key) form the signing functions take,
	// expanded once here rather than per call.
	exp [ExpandedLen]byte
}

func GeneratePrivateKey() (*PrivateKey, error) {
	var (
		seed [SeckeyLen]byte
		pub  [PubkeyLen]byte
		exp  [ExpandedLen]byte
	)

	pk, priv, err := ed.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	copy(seed[:], priv.Seed())
	copy(pub[:], pk)
	copy(exp[:], priv)
	return &PrivateKey{
		key: seed,
		pub: pub,
		exp: exp,
	}, nil
}

func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	var (
		seed [SeckeyLen]byte
		pub  [PubkeyLen]byte
		exp  [ExpandedLen]byte
	)

	if len(b) != SeckeyLen {
		return nil, ErrInvalidPrivateKey
	}

	copy(seed[:], b)
	priv := ed.NewKeyFromSeed(seed[:])
	copy(pub[:], priv.Public().(ed.PublicKey))
	copy(exp[:], priv)
	return &PrivateKey{
		key: seed,
		pub: pub,
		exp: exp,
	}, nil
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

func (k *PrivateKey) expand() ed.PrivateKey {
	return k.exp[:]
}
