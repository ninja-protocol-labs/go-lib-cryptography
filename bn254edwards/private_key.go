package bn254edwards

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

// key holds gnark's own serialization: public key ∥ scalar ∥ nonce source.
// pub repeats its first section so PublicKey is a field read, matching
// every other key package here.
type PrivateKey struct {
	key [SeckeyLen]byte
	pub [PubkeyLen]byte
}

func GeneratePrivateKey() (*PrivateKey, error) {
	var (
		b   [SeckeyLen]byte
		pub [PubkeyLen]byte
	)

	k, err := eddsa.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	copy(b[:], k.Bytes())
	copy(pub[:], b[:PubkeyLen])
	return &PrivateKey{
		key: b,
		pub: pub,
	}, nil
}

// PrivateKeyFromSeed expands a seed deterministically: the scalar and the
// nonce source are the two halves of BLAKE2b-512(seed), with RFC 8032's
// clamping applied to the scalar.
func PrivateKeyFromSeed(b []byte) (*PrivateKey, error) {
	var (
		out [SeckeyLen]byte
		pub [PubkeyLen]byte
	)

	if len(b) != SeedLen {
		return nil, ErrInvalidPrivateKey
	}

	k, err := eddsa.GenerateKey(bytes.NewReader(b))
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}

	copy(out[:], k.Bytes())
	copy(pub[:], out[:PubkeyLen])
	return &PrivateKey{
		key: out,
		pub: pub,
	}, nil
}

// PrivateKeyFromBytes parses what Bytes produces. The scalar's clamping
// and its agreement with the public key are both checked.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	var (
		out [SeckeyLen]byte
		pub [PubkeyLen]byte
		k   eddsa.PrivateKey
	)

	if len(b) != SeckeyLen {
		return nil, ErrInvalidPrivateKey
	}
	if _, err := k.SetBytes(b); err != nil {
		return nil, ErrInvalidPrivateKey
	}

	copy(out[:], b)
	copy(pub[:], out[:PubkeyLen])
	return &PrivateKey{
		key: out,
		pub: pub,
	}, nil
}

// Bytes returns public key ∥ scalar ∥ nonce source, not the seed. See the
// package doc.
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

// signer is k in the form gnark takes; k.key was parsed at construction,
// so the error cannot fire.
func (k *PrivateKey) signer() *eddsa.PrivateKey {
	var priv eddsa.PrivateKey

	_, _ = priv.SetBytes(k.key[:])
	return &priv
}
