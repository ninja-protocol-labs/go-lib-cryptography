package ed448

import (
	"crypto/rand"
	"crypto/subtle"

	ed "github.com/cloudflare/circl/sign/ed448"
)

// PrivateKey is a 57-byte seed seed, with the public key it derives to and the
// expanded form the signing functions take both computed once at
// construction.
type PrivateKey struct {
	key [SeckeyLen]byte
	pub [PubkeyLen]byte

	// exp is the (seed ∥ public key) form the signing functions take,
	// expanded once here rather than per call.
	exp [ExpandedLen]byte
}

// GeneratePrivateKey returns a new key from crypto/rand.
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

// PrivateKeyFromBytes expands a seed into a key, deriving the public key
// and the signing form once.
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

// Bytes returns the seed, as a copy — not the expanded form. It is
// secret: do not log it, and clear it when done.
func (k *PrivateKey) Bytes() [SeckeyLen]byte {
	return k.key
}

// PublicKey returns the key this seed derives to. It was computed at
// construction, so this is a field read.
func (k *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{
		key: k.pub,
	}
}

// Equal reports whether o holds the same seed. It is nil-safe, and
// constant-time because the value is secret.
func (k *PrivateKey) Equal(o *PrivateKey) bool {
	if o == nil {
		return false
	}
	return subtle.ConstantTimeCompare(k.key[:], o.key[:]) == 1
}

// IsZero catches a `var k PrivateKey`; no constructor returns one.
func (k *PrivateKey) IsZero() bool {
	return k == nil || *k == PrivateKey{}
}

func (k *PrivateKey) expand() ed.PrivateKey {
	return k.exp[:]
}
