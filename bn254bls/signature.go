package bn254bls

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// A signature lives in whichever group the scheme did not give the public
// key: G2 under min-pk, G1 under min-sig.

// SignatureMinPk is a point in G2, the larger group min-pk leaves for
// signatures.
type SignatureMinPk struct {
	sig [SignatureMinPkLen]byte
}

// SignatureMinSig is a point in G1 — half the size, which is what min-sig
// exists for.
type SignatureMinSig struct {
	sig [SignatureMinSigLen]byte
}

// SignatureMinPkFromBytes parses a compressed G2 point, checking the
// encoding, that it is on the curve, and that it is in the prime-order
// subgroup.
func SignatureMinPkFromBytes(b []byte) (*SignatureMinPk, error) {
	var p bn254.G2Affine

	if len(b) != SignatureMinPkLen {
		return nil, ErrInvalidSignature
	}
	if _, err := p.SetBytes(b); err != nil {
		return nil, ErrInvalidSignature
	}

	return &SignatureMinPk{
		sig: p.Bytes(),
	}, nil
}

// SignatureMinSigFromBytes is SignatureMinPkFromBytes for the min-sig
// scheme, over a compressed G1 point.
func SignatureMinSigFromBytes(b []byte) (*SignatureMinSig, error) {
	var p bn254.G1Affine

	if len(b) != SignatureMinSigLen {
		return nil, ErrInvalidSignature
	}
	if _, err := p.SetBytes(b); err != nil {
		return nil, ErrInvalidSignature
	}

	return &SignatureMinSig{
		sig: p.Bytes(),
	}, nil
}

// Bytes returns the compressed G2 encoding, as a copy.
func (s *SignatureMinPk) Bytes() [SignatureMinPkLen]byte {
	return s.sig
}

// Bytes returns the compressed G1 encoding, as a copy.
func (s *SignatureMinSig) Bytes() [SignatureMinSigLen]byte {
	return s.sig
}

// Equal reports whether o is the same point. It is nil-safe, and not
// constant-time — a signature is public.
func (s *SignatureMinPk) Equal(o *SignatureMinPk) bool {
	if o == nil {
		return false
	}
	return s.sig == o.sig
}

// Equal reports whether o is the same point. It is nil-safe, and not
// constant-time — a signature is public.
func (s *SignatureMinSig) Equal(o *SignatureMinSig) bool {
	if o == nil {
		return false
	}
	return s.sig == o.sig
}

// IsZero catches a `var s SignatureMinPk`; no constructor returns one.
func (s *SignatureMinPk) IsZero() bool {
	return s == nil || *s == SignatureMinPk{}
}

// IsZero catches a `var s SignatureMinSig`; no constructor returns one.
func (s *SignatureMinSig) IsZero() bool {
	return s == nil || *s == SignatureMinSig{}
}

// String returns the compressed encoding as lowercase hex.
func (s *SignatureMinPk) String() string {
	return encoding.Hex.Encode(s.sig[:])
}

// String returns the compressed encoding as lowercase hex.
func (s *SignatureMinSig) String() string {
	return encoding.Hex.Encode(s.sig[:])
}

// point is s in the form gnark takes; s.sig was parsed at construction, so
// the error cannot fire.
func (s *SignatureMinPk) point() bn254.G2Affine {
	var p bn254.G2Affine

	_, _ = p.SetBytes(s.sig[:])
	return p
}

func (s *SignatureMinSig) point() bn254.G1Affine {
	var p bn254.G1Affine

	_, _ = p.SetBytes(s.sig[:])
	return p
}
