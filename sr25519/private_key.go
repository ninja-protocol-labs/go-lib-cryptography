package sr25519

import (
	"crypto/subtle"

	"github.com/ChainSafe/go-schnorrkel"
)

// PrivateKey is the expanded 32-byte scalar schnorrkel signs with, with
// the public key it derives to computed once at construction.
//
// It is not a Substrate seed. See the package doc: handing a seed to
// PrivateKeyFromBytes yields a different, working key with no error.
type PrivateKey struct {
	key [SeckeyLen]byte
	pub [PubkeyLen]byte
}

// newPrivateKey validates a scalar and derives its point once, so
// PublicKey cannot fail. Every constructor goes through here.
func newPrivateKey(key [SeckeyLen]byte) (*PrivateKey, error) {
	s, err := schnorrkel.ScalarFromBytes(key)
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}

	zero, err := schnorrkel.ScalarFromBytes([SeckeyLen]byte{})
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}

	// Zero maps to the point at infinity, which Verify and VerifyVRF
	// refuse anyway.
	if s.Equal(zero) == 1 {
		return nil, ErrInvalidPrivateKey
	}

	pub, err := schnorrkel.NewSecretKey(key, [32]byte{}).Public()
	if err != nil {
		return nil, ErrPublicKeyDerivationFailed
	}

	return &PrivateKey{
		key: key,
		pub: pub.Encode(),
	}, nil
}

// GeneratePrivateKey returns a new key from crypto/rand.
func GeneratePrivateKey() (*PrivateKey, error) {
	sk, pk, err := schnorrkel.GenerateKeypair()
	if err != nil {
		return nil, err
	}

	// GenerateKeypair reports a failed public key as a nil pointer rather
	// than an error.
	if sk == nil || pk == nil {
		return nil, ErrPublicKeyDerivationFailed
	}

	return &PrivateKey{
		key: sk.Encode(),
		pub: pk.Encode(),
	}, nil
}

// PrivateKeyFromBytes parses an expanded scalar, rejecting zero and
// anything at or above the group order.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	var k [SeckeyLen]byte

	if len(b) != SeckeyLen {
		return nil, ErrInvalidPrivateKey
	}

	copy(k[:], b)
	return newPrivateKey(k)
}

// Bytes returns the expanded scalar, as a copy. It is secret: do not log
// it, and clear it when done.
func (k *PrivateKey) Bytes() [SeckeyLen]byte {
	return k.key
}

// PublicKey returns the point this scalar derives to. It was computed at
// construction, so this is a field read.
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
	return k == nil || *k == PrivateKey{}
}

// secretKey wraps k's scalar with a zeroed, unused nonce.
func (k *PrivateKey) secretKey() *schnorrkel.SecretKey {
	return schnorrkel.NewSecretKey(k.key, [32]byte{})
}
