package ed25519

import (
	ed "crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
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

	// GenerateKey hands back the public key as well, so there is no need
	// to expand the seed for it.
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

// PrivateKeyFromBytes wraps a seed. Any 32 bytes are a valid Ed25519 seed
// — there is no [1, n-1] range to reject, unlike a secp256k1 scalar — so
// this checks length only.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	var (
		seed [SeckeyLen]byte
		pub  [PubkeyLen]byte
		exp  [ExpandedLen]byte
	)

	if len(b) != SeckeyLen {
		return nil, ErrInvalidPrivateKey
	}

	// Expanded once, here, so PublicKey is a field read rather than a
	// key expansion per call.
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

// PublicKey returns the public key derived when k was constructed. This
// cannot fail: every seed expands, via SHA-512, to a valid public key,
// with no validity check in between.
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

// IsZero catches a `var k PrivateKey`. Unlike the other key packages this
// is not "no constructor returns one" — the all-zero seed is a valid
// Ed25519 key — so it means only that k was never initialised.
func (k *PrivateKey) IsZero() bool {
	return k == nil || *k == PrivateKey{}
}

func (k *PrivateKey) expand() ed.PrivateKey {
	return k.exp[:]
}
