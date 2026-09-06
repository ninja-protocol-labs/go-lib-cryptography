package bn254bls

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

type PublicKeyMinPk struct {
	key [PubkeyMinPkLen]byte
}

type PublicKeyMinSig struct {
	key [PubkeyMinSigLen]byte
}

// PublicKeyMinPkFromBytes parses a compressed G1 point, checking the
// encoding, that it is on the curve, and that it is in the prime-order
// subgroup. The identity is rejected: it verifies against every message.
func PublicKeyMinPkFromBytes(b []byte) (*PublicKeyMinPk, error) {
	var p bn254.G1Affine

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

func PublicKeyMinSigFromBytes(b []byte) (*PublicKeyMinSig, error) {
	var p bn254.G2Affine

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

func (k *PublicKeyMinPk) Bytes() [PubkeyMinPkLen]byte {
	return k.key
}

func (k *PublicKeyMinSig) Bytes() [PubkeyMinSigLen]byte {
	return k.key
}

func (k *PublicKeyMinPk) Equal(o *PublicKeyMinPk) bool {
	if o == nil {
		return false
	}
	return k.key == o.key
}

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

func (k *PublicKeyMinSig) IsZero() bool {
	return k == nil || *k == PublicKeyMinSig{}
}

func (k *PublicKeyMinPk) String() string {
	return encoding.Hex.Encode(k.key[:])
}

func (k *PublicKeyMinSig) String() string {
	return encoding.Hex.Encode(k.key[:])
}

// point is k in the form gnark takes; k.key was parsed at construction, so
// the error cannot fire.
func (k *PublicKeyMinPk) point() bn254.G1Affine {
	var p bn254.G1Affine

	_, _ = p.SetBytes(k.key[:])
	return p
}

func (k *PublicKeyMinSig) point() bn254.G2Affine {
	var p bn254.G2Affine

	_, _ = p.SetBytes(k.key[:])
	return p
}
