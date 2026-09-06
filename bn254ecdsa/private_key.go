package bn254ecdsa

import (
	"crypto/rand"
	"crypto/subtle"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/ecdsa"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// order is r, the order of the group a scalar lives in.
var order = fr.Modulus()

// PrivateKey is a scalar modulo r, BN254's group order, with the public
// key it derives to computed once at construction rather than on every
// use.
type PrivateKey struct {
	key [SeckeyLen]byte
	pub [PubkeyLen]byte
}

// newPrivateKey validates a scalar and derives its point once, so
// PublicKey is a field read. Every constructor goes through here.
func newPrivateKey(key [SeckeyLen]byte) (*PrivateKey, error) {
	var p bn254.G1Affine

	s := new(big.Int).SetBytes(key[:])
	if s.Sign() == 0 || s.Cmp(order) >= 0 {
		return nil, ErrInvalidPrivateKey
	}

	p.ScalarMultiplicationBase(s)
	return &PrivateKey{
		key: key,
		pub: p.Bytes(),
	}, nil
}

// GeneratePrivateKey returns a new key from crypto/rand.
func GeneratePrivateKey() (*PrivateKey, error) {
	var key [SeckeyLen]byte

	k, err := ecdsa.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// gnark serializes as public key ∥ scalar; only the scalar is stored.
	full := k.Bytes()
	copy(key[:], full[PubkeyLen:])
	return newPrivateKey(key)
}

// PrivateKeyFromBytes parses a big-endian scalar in [1, r-1]. gnark's own
// parser trusts the public key half of its serialization rather than
// checking it against the scalar, so this takes the scalar alone and
// derives the point itself.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	var key [SeckeyLen]byte

	if len(b) != SeckeyLen {
		return nil, ErrInvalidPrivateKey
	}

	copy(key[:], b)
	return newPrivateKey(key)
}

// Bytes returns the scalar big-endian, as a copy. It is secret: do not
// log it, and clear it when done.
func (k *PrivateKey) Bytes() [SeckeyLen]byte {
	return k.key
}

// PublicKey returns the G1 point this scalar derives to. It was computed
// at construction, so this is a field read rather than a scalar
// multiplication.
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

// IsZero catches a `var k PrivateKey`; no constructor returns one, since
// zero is not a valid scalar.
func (k *PrivateKey) IsZero() bool {
	return k == nil || *k == PrivateKey{}
}

// signer is k in the form gnark takes, rebuilt from the stored scalar and
// point; both were validated at construction, so the error cannot fire.
func (k *PrivateKey) signer() *ecdsa.PrivateKey {
	var priv ecdsa.PrivateKey

	buf := make([]byte, 0, PubkeyLen+SeckeyLen)
	buf = append(buf, k.pub[:]...)
	buf = append(buf, k.key[:]...)
	_, _ = priv.SetBytes(buf)
	return &priv
}
