package secp256k1

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

type Signature struct {
	r [SignatureScalarLen]byte
	s [SignatureScalarLen]byte
}

// SignatureFromBytes parses r ∥ s, rejecting scalars outside [1, n-1].
// High-s is a verification policy, not an encoding error, so it is left to
// Verify.
func SignatureFromBytes(b []byte) (*Signature, error) {
	var (
		sig  Signature
		r, s secp256k1.ModNScalar
	)

	if len(b) != SignatureCompactLen {
		return nil, ErrInvalidSignature
	}

	copy(sig.r[:], b[:SignatureScalarLen])
	copy(sig.s[:], b[SignatureScalarLen:])
	if r.SetBytes(&sig.r) != 0 || s.SetBytes(&sig.s) != 0 {
		return nil, ErrInvalidSignature
	}
	if r.IsZero() || s.IsZero() {
		return nil, ErrInvalidSignature
	}

	return &sig, nil
}

func SignatureFromDER(b []byte) (*Signature, error) {
	var sig Signature

	parsed, err := ecdsa.ParseDERSignature(b)
	if err != nil {
		return nil, ErrInvalidSignature
	}

	r, s := parsed.R(), parsed.S()
	if r.IsZero() || s.IsZero() {
		return nil, ErrInvalidSignature
	}

	r.PutBytes(&sig.r)
	s.PutBytes(&sig.s)
	return &sig, nil
}

func (sig *Signature) Bytes() [SignatureCompactLen]byte {
	var b [SignatureCompactLen]byte

	copy(b[:SignatureScalarLen], sig.r[:])
	copy(b[SignatureScalarLen:], sig.s[:])
	return b
}

func (sig *Signature) DER() []byte {
	r, s := sig.scalars()
	return ecdsa.NewSignature(&r, &s).Serialize()
}

func (sig *Signature) Equal(other *Signature) bool {
	if other == nil {
		return false
	}
	return sig.r == other.r && sig.s == other.s
}

// scalars is sig in the form dcrd takes; both halves were range-checked at
// construction, so the overflow flags cannot fire.
func (sig *Signature) scalars() (secp256k1.ModNScalar, secp256k1.ModNScalar) {
	var r, s secp256k1.ModNScalar
	r.SetBytes(&sig.r)
	s.SetBytes(&sig.s)
	return r, s
}
