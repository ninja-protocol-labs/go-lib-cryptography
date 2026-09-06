package secp256k1

import (
	"crypto/subtle"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// PrivateKey is a secp256k1 scalar, with the public key it derives to
// computed once at construction rather than on every use.
type PrivateKey struct {
	key [SeckeyLen]byte
	pub [PubkeyCompressedLen]byte
}

// GeneratePrivateKey returns a new key from crypto/rand.
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

// PrivateKeyFromBytes parses a big-endian scalar, rejecting zero and
// anything at or above the curve order.
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

// Bytes returns the scalar big-endian, as a copy. It is secret: do not
// log it, and clear it when done.
func (k *PrivateKey) Bytes() [SeckeyLen]byte {
	return k.key
}

// PublicKey returns the key this scalar derives to. It was computed at
// construction, so this is a field read rather than a curve operation.
func (k *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{
		key: k.pub,
	}
}

// Equal reports whether o holds the same scalar. It is nil-safe, and
// constant-time because the value is secret.
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

// scalar is k in the form dcrd's signing takes.
func (k *PrivateKey) scalar() *secp256k1.PrivateKey {
	var s secp256k1.ModNScalar
	s.SetBytes(&k.key)
	return secp256k1.NewPrivateKey(&s)
}
