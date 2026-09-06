package bls12381bls

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// PublicKeyMinPk is a point in G1 — the smaller group, which is what
// min-pk chooses to make public keys cheap to store and transmit.
type PublicKeyMinPk struct {
	key [PubkeyMinPkLen]byte
}

// PublicKeyMinSig is a point in G2, twice the size, which is the price
// min-sig pays for its smaller signatures.
type PublicKeyMinSig struct {
	key [PubkeyMinSigLen]byte
}

// PublicKeyMinPkFromBytes parses a compressed G1 point, checking the
// encoding, that it is on the curve, and that it is in the prime-order
// subgroup. The identity is rejected: it verifies against every message.
func PublicKeyMinPkFromBytes(b []byte) (*PublicKeyMinPk, error) {
	var p bls12381.G1Affine

	if len(b) != PubkeyMinPkLen {
		return nil, ErrInvalidPublicKey
	}
	if _, err := p.SetBytes(b); err != nil {
		return nil, ErrInvalidPublicKey
	}
	if p.IsInfinity() {
		return nil, ErrInvalidPublicKey
	}

	return &PublicKeyMinPk{
		key: p.Bytes(),
	}, nil
}

// PublicKeyMinSigFromBytes is PublicKeyMinPkFromBytes for the min-sig
// scheme, over a compressed G2 point.
func PublicKeyMinSigFromBytes(b []byte) (*PublicKeyMinSig, error) {
	var p bls12381.G2Affine

	if len(b) != PubkeyMinSigLen {
		return nil, ErrInvalidPublicKey
	}
	if _, err := p.SetBytes(b); err != nil {
		return nil, ErrInvalidPublicKey
	}
	if p.IsInfinity() {
		return nil, ErrInvalidPublicKey
	}

	return &PublicKeyMinSig{
		key: p.Bytes(),
	}, nil
}

// Bytes returns the compressed G1 encoding, as a copy.
func (k *PublicKeyMinPk) Bytes() [PubkeyMinPkLen]byte {
	return k.key
}

// Bytes returns the compressed G2 encoding, as a copy.
func (k *PublicKeyMinSig) Bytes() [PubkeyMinSigLen]byte {
	return k.key
}

// Equal reports whether o is the same point. It is nil-safe.
func (k *PublicKeyMinPk) Equal(o *PublicKeyMinPk) bool {
	if o == nil {
		return false
	}
	return k.key == o.key
}

// Equal reports whether o is the same point. It is nil-safe.
func (k *PublicKeyMinSig) Equal(o *PublicKeyMinSig) bool {
	if o == nil {
		return false
	}
	return k.key == o.key
}

// IsZero catches a `var k PublicKeyMinPk`; no constructor returns one.
func (k *PublicKeyMinPk) IsZero() bool {
	return k == nil || *k == PublicKeyMinPk{}
}

// IsZero catches a `var k PublicKeyMinSig`; no constructor returns one.
func (k *PublicKeyMinSig) IsZero() bool {
	return k == nil || *k == PublicKeyMinSig{}
}

// String returns the compressed encoding as lowercase hex.
func (k *PublicKeyMinPk) String() string {
	return encoding.Hex.Encode(k.key[:])
}

// String returns the compressed encoding as lowercase hex.
func (k *PublicKeyMinSig) String() string {
	return encoding.Hex.Encode(k.key[:])
}

// point is k in the form gnark takes; k.key was parsed at construction, so
// the error cannot fire.
func (k *PublicKeyMinPk) point() bls12381.G1Affine {
	var p bls12381.G1Affine

	_, _ = p.SetBytes(k.key[:])
	return p
}

func (k *PublicKeyMinSig) point() bls12381.G2Affine {
	var p bls12381.G2Affine

	_, _ = p.SetBytes(k.key[:])
	return p
}
