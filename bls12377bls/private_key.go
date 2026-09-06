package bls12377bls

import (
	"crypto/subtle"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
)

// order is r, the order of G1, G2 and GT.
var order = fr.Modulus()

// A private key is the same scalar under either scheme; the two types
// exist so a key is bound to one at the moment it is made, rather than at
// each call. Each carries the public key it derives, so PublicKey is a
// field read that costs no scalar multiplication.

// PrivateKeyMinPk is a scalar bound to the min-pk scheme, where the public
// key is the small G1 point and the signature the larger G2 one.
type PrivateKeyMinPk struct {
	key [SeckeyLen]byte
	pub [PubkeyMinPkLen]byte
}

// PrivateKeyMinSig is a scalar bound to the min-sig scheme, where the
// groups are the other way round: the signature is the small G1 point and
// the public key the larger G2 one.
type PrivateKeyMinSig struct {
	key [SeckeyLen]byte
	pub [PubkeyMinSigLen]byte
}

// parseScalar validates b as a scalar in [1, r-1].
func parseScalar(b []byte) ([SeckeyLen]byte, *big.Int, error) {
	var k [SeckeyLen]byte

	if len(b) != SeckeyLen {
		return k, nil, ErrInvalidPrivateKey
	}

	s := new(big.Int).SetBytes(b)
	if s.Sign() == 0 || s.Cmp(order) >= 0 {
		return k, nil, ErrInvalidPrivateKey
	}

	copy(k[:], b)
	return k, s, nil
}

// randomScalar draws a uniform scalar in [1, r-1]. Zero is the one value
// in range that is not a key; redrawing costs nothing at probability 2⁻²⁵⁵.
func randomScalar() ([SeckeyLen]byte, *big.Int, error) {
	for {
		var e fr.Element
		if _, err := e.SetRandom(); err != nil {
			return [SeckeyLen]byte{}, nil, err
		}
		if e.IsZero() {
			continue
		}

		k := e.Bytes()
		return k, new(big.Int).SetBytes(k[:]), nil
	}
}

// GeneratePrivateKeyMinPk returns a new min-pk key from crypto/rand.
func GeneratePrivateKeyMinPk() (*PrivateKeyMinPk, error) {
	var p bls12377.G1Affine

	k, s, err := randomScalar()
	if err != nil {
		return nil, err
	}

	p.ScalarMultiplicationBase(s)
	return &PrivateKeyMinPk{
		key: k,
		pub: p.Bytes(),
	}, nil
}

// GeneratePrivateKeyMinSig is GeneratePrivateKeyMinPk for the min-sig
// scheme.
func GeneratePrivateKeyMinSig() (*PrivateKeyMinSig, error) {
	var p bls12377.G2Affine

	k, s, err := randomScalar()
	if err != nil {
		return nil, err
	}

	p.ScalarMultiplicationBase(s)
	return &PrivateKeyMinSig{
		key: k,
		pub: p.Bytes(),
	}, nil
}

// PrivateKeyMinPkFromBytes parses a big-endian scalar in [1, r-1] and
// derives the G1 public key from it.
func PrivateKeyMinPkFromBytes(b []byte) (*PrivateKeyMinPk, error) {
	var p bls12377.G1Affine

	k, s, err := parseScalar(b)
	if err != nil {
		return nil, err
	}

	p.ScalarMultiplicationBase(s)
	return &PrivateKeyMinPk{
		key: k,
		pub: p.Bytes(),
	}, nil
}

// PrivateKeyMinSigFromBytes is PrivateKeyMinPkFromBytes for the min-sig
// scheme.
func PrivateKeyMinSigFromBytes(b []byte) (*PrivateKeyMinSig, error) {
	var p bls12377.G2Affine

	k, s, err := parseScalar(b)
	if err != nil {
		return nil, err
	}

	p.ScalarMultiplicationBase(s)
	return &PrivateKeyMinSig{
		key: k,
		pub: p.Bytes(),
	}, nil
}

// Bytes returns the scalar big-endian, as a copy. It is secret: do not log
// it, and clear it when done.
func (k *PrivateKeyMinPk) Bytes() [SeckeyLen]byte {
	return k.key
}

// Bytes returns the scalar big-endian, as a copy. It is secret: do not log
// it, and clear it when done.
func (k *PrivateKeyMinSig) Bytes() [SeckeyLen]byte {
	return k.key
}

// PublicKey returns the G1 point this scalar derives to. It was computed
// at construction, so this is a field read.
func (k *PrivateKeyMinPk) PublicKey() *PublicKeyMinPk {
	return &PublicKeyMinPk{
		key: k.pub,
	}
}

// PublicKey returns the G2 point this scalar derives to. It was computed
// at construction, so this is a field read.
func (k *PrivateKeyMinSig) PublicKey() *PublicKeyMinSig {
	return &PublicKeyMinSig{
		key: k.pub,
	}
}

// Equal reports whether o holds the same scalar. It is nil-safe, and
// constant-time because the value is secret.
func (k *PrivateKeyMinPk) Equal(o *PrivateKeyMinPk) bool {
	if o == nil {
		return false
	}
	return subtle.ConstantTimeCompare(k.key[:], o.key[:]) == 1
}

// Equal reports whether o holds the same scalar. It is nil-safe, and
// constant-time because the value is secret.
func (k *PrivateKeyMinSig) Equal(o *PrivateKeyMinSig) bool {
	if o == nil {
		return false
	}
	return subtle.ConstantTimeCompare(k.key[:], o.key[:]) == 1
}

// IsZero catches a `var k PrivateKeyMinPk`; no constructor returns one.
func (k *PrivateKeyMinPk) IsZero() bool {
	var z [SeckeyLen]byte

	if k == nil {
		return true
	}
	return subtle.ConstantTimeCompare(k.key[:], z[:]) == 1
}

// IsZero catches a `var k PrivateKeyMinSig`; no constructor returns one.
func (k *PrivateKeyMinSig) IsZero() bool {
	var z [SeckeyLen]byte

	if k == nil {
		return true
	}
	return subtle.ConstantTimeCompare(k.key[:], z[:]) == 1
}

// scalar is k in the form gnark's scalar multiplication takes.
func (k *PrivateKeyMinPk) scalar() *big.Int {
	return new(big.Int).SetBytes(k.key[:])
}

func (k *PrivateKeyMinSig) scalar() *big.Int {
	return new(big.Int).SetBytes(k.key[:])
}
