package secp256r1

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"math/big"
)

func curve() elliptic.Curve { return elliptic.P256() }

type PrivateKey struct {
	key [SeckeyLen]byte
	pub [PubkeyCompressedLen]byte
	unc [PubkeyUncompressedLen]byte
}

// newPrivateKey validates a scalar and derives its point once, so
// PublicKey cannot fail. Every constructor goes through here.
func newPrivateKey(key [SeckeyLen]byte) (*PrivateKey, error) {
	var pub [PubkeyCompressedLen]byte

	priv, err := ecdsa.ParseRawPrivateKey(curve(), key[:])
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}

	// PublicKey.Bytes returns a validated uncompressed SEC 1 point, so
	// splitUncompressed needs no checks of its own.
	uncompressed, err := priv.PublicKey.Bytes()
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}

	x, y := splitUncompressed(uncompressed)
	copy(pub[:], elliptic.MarshalCompressed(curve(), x, y))
	return &PrivateKey{
		key: key,
		pub: pub,
		unc: joinUncompressed(x, y),
	}, nil
}

func GeneratePrivateKey() (*PrivateKey, error) {
	var key [SeckeyLen]byte

	priv, err := ecdsa.GenerateKey(curve(), rand.Reader)
	if err != nil {
		return nil, err
	}

	b, err := priv.Bytes()
	if err != nil {
		return nil, err
	}

	copy(key[:], b)
	return newPrivateKey(key)
}

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
		unc: k.unc,
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

// ECDH computes the shared secret between k and pub and returns SHA-256 of
// the resulting X coordinate, so every curve package here hands back the
// same shape of value regardless of what its DH primitive produces.
func (k *PrivateKey) ECDH(pub *PublicKey) ([SharedSecretLen]byte, error) {
	if k == nil || pub == nil {
		return [SharedSecretLen]byte{}, ErrECDHFailed
	}

	priv, err := ecdh.P256().NewPrivateKey(k.key[:])
	if err != nil {
		return [SharedSecretLen]byte{}, ErrECDHFailed
	}

	uncompressed := pub.BytesUncompressed()
	remote, err := ecdh.P256().NewPublicKey(uncompressed[:])
	if err != nil {
		return [SharedSecretLen]byte{}, ErrECDHFailed
	}

	shared, err := priv.ECDH(remote)
	if err != nil {
		return [SharedSecretLen]byte{}, ErrECDHFailed
	}
	return sha256.Sum256(shared), nil
}

// joinUncompressed builds 0x04 ∥ X ∥ Y and splitUncompressed reads it
// back, both avoiding the deprecated elliptic.Marshal and Unmarshal.
func joinUncompressed(x, y *big.Int) [PubkeyUncompressedLen]byte {
	var b [PubkeyUncompressedLen]byte

	b[0] = 4
	x.FillBytes(b[1 : 1+SeckeyLen])
	y.FillBytes(b[1+SeckeyLen:])
	return b
}

// splitUncompressed reads X and Y out of 0x04 ∥ X ∥ Y. The caller must
// already know b is a well-formed on-curve point; this exists only to
// avoid the deprecated elliptic.Unmarshal.
func splitUncompressed(b []byte) (x, y *big.Int) {
	return new(big.Int).SetBytes(b[1 : 1+SeckeyLen]),
		new(big.Int).SetBytes(b[1+SeckeyLen:])
}
