package bls12381edwards

import (
	"bytes"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards/eddsa"
	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

type PublicKey struct {
	key eddsa.PublicKey
}

// PublicKeyFromBytes parses a compressed point, checking that it is on the
// curve, is not the identity, and lies in the prime-order subgroup.
//
// gnark-crypto's SetBytes rejects the identity and anything outside the
// prime-order subgroup. The on-curve check is this package's addition:
// SetBytes recovers x from y through the curve equation and does not
// report a failed square root, so a bad y yields a point that is simply
// not on the curve, and the subgroup test it then runs is only meaningful
// for points that are.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	var k eddsa.PublicKey

	if len(b) != PubkeyLen {
		return nil, ErrInvalidPublicKey
	}
	if _, err := k.SetBytes(b); err != nil {
		return nil, ErrInvalidPublicKey
	}
	if !k.A.IsOnCurve() || k.A.IsZero() || !k.A.IsInSubGroup() {
		return nil, ErrInvalidPublicKey
	}

	// SetBytes reduces a y coordinate that is not already in 𝔽r rather
	// than rejecting it, so distinct byte strings can name the same point.
	// Re-encoding and comparing is what rules that out.
	if !bytes.Equal(k.Bytes(), b) {
		return nil, ErrInvalidPublicKey
	}

	return &PublicKey{
		key: k,
	}, nil
}

func (k *PublicKey) Bytes() [PubkeyLen]byte {
	var b [PubkeyLen]byte

	copy(b[:], k.key.Bytes())
	return b
}

func (k *PublicKey) Equal(o *PublicKey) bool {
	if o == nil {
		return false
	}
	return k.key.Equal(&o.key)
}

// IsZero catches a `var k PublicKey`; no constructor returns one.
func (k *PublicKey) IsZero() bool {
	return k == nil || *k == PublicKey{}
}

func (k *PublicKey) String() string {
	b := k.Bytes()
	return encoding.Hex.Encode(b[:])
}
