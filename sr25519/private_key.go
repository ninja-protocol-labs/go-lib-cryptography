package sr25519

import (
	"crypto/subtle"

	"github.com/ChainSafe/go-schnorrkel"
)

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

func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	var k [SeckeyLen]byte

	if len(b) != SeckeyLen {
		return nil, ErrInvalidPrivateKey
	}

	copy(k[:], b)
	return newPrivateKey(k)
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

// secretKey wraps k's scalar with a zeroed, unused nonce.
func (k *PrivateKey) secretKey() *schnorrkel.SecretKey {
	return schnorrkel.NewSecretKey(k.key, [32]byte{})
}
