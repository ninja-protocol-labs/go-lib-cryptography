package secp256k1

import (
	"crypto/subtle"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type PrivateKey struct {
	key [SeckeyLen]byte
	pub [PubkeyCompressedLen]byte
}

func GeneratePrivateKey() (*PrivateKey, error) {
	var (
		k [SeckeyLen]byte
		p [PubkeyCompressedLen]byte
	)

	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	priv.Key.PutBytes(&k)
	copy(p[:], priv.PubKey().SerializeCompressed())
	return &PrivateKey{
		key: k,
		pub: p,
	}, nil
}

func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	var (
		k [SeckeyLen]byte
		p [PubkeyCompressedLen]byte
		s secp256k1.ModNScalar
	)

	if len(b) != SeckeyLen {
		return nil, ErrInvalidPrivateKey
	}

	// SetBytes reports overflow (b >= n); PrivKeyFromBytes reduces silently.
	copy(k[:], b)
	if s.SetBytes(&k) != 0 || s.IsZero() {
		return nil, ErrInvalidPrivateKey
	}

	copy(p[:], secp256k1.NewPrivateKey(&s).PubKey().SerializeCompressed())
	return &PrivateKey{
		key: k,
		pub: p,
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

// IsZero catches a `var k PrivateKey`; no constructor returns one.
func (k *PrivateKey) IsZero() bool {
	if k == nil {
		return true
	}

	var z [SeckeyLen]byte
	return subtle.ConstantTimeCompare(k.key[:], z[:]) == 1
}

func (k *PrivateKey) Public() *PublicKey {
	return k.PublicKey()
}

// scalar is k in the form dcrd's signing takes.
func (k *PrivateKey) scalar() *secp256k1.PrivateKey {
	var s secp256k1.ModNScalar
	s.SetBytes(&k.key)
	return secp256k1.NewPrivateKey(&s)
}
