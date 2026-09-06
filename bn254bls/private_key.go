package bn254bls

import (
	"crypto/subtle"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// order is r, the order of G1, G2 and GT.
var order = fr.Modulus()

// A private key is the same scalar under either scheme; the two types
// exist so a key is bound to one at the moment it is made, rather than at
// each call. Each carries the public key it derives, so PublicKey is a
// field read that costs no scalar multiplication.

type PrivateKeyMinPk struct {
	key [SeckeyLen]byte
	pub [PubkeyMinPkLen]byte
}

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

func GeneratePrivateKeyMinPk() (*PrivateKeyMinPk, error) {
	var p bn254.G1Affine

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

func GeneratePrivateKeyMinSig() (*PrivateKeyMinSig, error) {
	var p bn254.G2Affine

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

func PrivateKeyMinPkFromBytes(b []byte) (*PrivateKeyMinPk, error) {
	var p bn254.G1Affine

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

func PrivateKeyMinSigFromBytes(b []byte) (*PrivateKeyMinSig, error) {
	var p bn254.G2Affine

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

func (k *PrivateKeyMinPk) Bytes() [SeckeyLen]byte {
	return k.key
}

func (k *PrivateKeyMinSig) Bytes() [SeckeyLen]byte {
	return k.key
}

func (k *PrivateKeyMinPk) PublicKey() *PublicKeyMinPk {
	return &PublicKeyMinPk{
		key: k.pub,
	}
}

func (k *PrivateKeyMinSig) PublicKey() *PublicKeyMinSig {
	return &PublicKeyMinSig{
		key: k.pub,
	}
}

func (k *PrivateKeyMinPk) Equal(o *PrivateKeyMinPk) bool {
	if o == nil {
		return false
	}
	return subtle.ConstantTimeCompare(k.key[:], o.key[:]) == 1
}

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
