package bls12377edwards

import (
	"bytes"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards/eddsa"
	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// PublicKey is a point on BLS12-377's companion curve, stored in the compressed encoding it
// was parsed from. Non-canonical encodings are rejected, so the stored
// bytes and the point identify each other.
type PublicKey struct {
	key [PubkeyLen]byte
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
	var (
		out [PubkeyLen]byte
		k   eddsa.PublicKey
	)

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

	copy(out[:], b)
	return &PublicKey{
		key: out,
	}, nil
}

// Bytes returns the compressed encoding, as a copy.
func (k *PublicKey) Bytes() [PubkeyLen]byte {
	return k.key
}

// Equal reports whether o is the same point. It is nil-safe.
func (k *PublicKey) Equal(o *PublicKey) bool {
	if o == nil {
		return false
	}
	return k.key == o.key
}

// IsZero catches a `var k PublicKey`; no constructor returns one.
func (k *PublicKey) IsZero() bool {
	return k == nil || *k == PublicKey{}
}

// String returns the compressed encoding as lowercase hex.
func (k *PublicKey) String() string {
	return encoding.Hex.Encode(k.key[:])
}

// verifier is k in the form gnark takes; k.key was parsed at
// construction, so the error cannot fire.
func (k *PublicKey) verifier() *eddsa.PublicKey {
	var pub eddsa.PublicKey

	_, _ = pub.SetBytes(k.key[:])
	return &pub
}
