package x25519

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
)

func curve() ecdh.Curve { return ecdh.X25519() }

type PrivateKey struct {
	key [SeckeyLen]byte
	pub [PubkeyLen]byte
}

func GeneratePrivateKey() (*PrivateKey, error) {
	var (
		key [SeckeyLen]byte
		pub [PubkeyLen]byte
	)

	priv, err := curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	copy(key[:], priv.Bytes())
	copy(pub[:], priv.PublicKey().Bytes())
	return &PrivateKey{
		key: key,
		pub: pub,
	}, nil
}

func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	var (
		key [SeckeyLen]byte
		pub [PubkeyLen]byte
	)

	priv, err := curve().NewPrivateKey(b)
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}

	copy(key[:], b)
	copy(pub[:], priv.PublicKey().Bytes())
	return &PrivateKey{
		key: key,
		pub: pub,
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

// ECDH computes the shared secret between k and pub (RFC 7748 §6.1) and
// returns SHA-256 of it, so every curve package here hands back the same
// shape of value regardless of what its DH primitive produces. See
// secp256r1.PrivateKey.ECDH for the same reasoning.
//
// This is the one place X25519 fails on well-formed input: crypto/ecdh
// rejects an all-zero result, which a small-order pub can force even
// though it passed PublicKeyFromBytes.
func (k *PrivateKey) ECDH(pub *PublicKey) ([SharedSecretLen]byte, error) {
	if k == nil || pub == nil {
		return [SharedSecretLen]byte{}, ErrECDHFailed
	}

	// Both were accepted at construction, so neither parse can fail.
	priv, _ := curve().NewPrivateKey(k.key[:])
	remote, _ := curve().NewPublicKey(pub.key[:])

	shared, err := priv.ECDH(remote)
	if err != nil {
		return [SharedSecretLen]byte{}, ErrECDHFailed
	}
	return sha256.Sum256(shared), nil
}
