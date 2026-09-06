package bls12377bls

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// A signature lives in whichever group the scheme did not give the public
// key: G2 under min-pk, G1 under min-sig.

type SignatureMinPk struct {
	sig [SignatureMinPkLen]byte
}

type SignatureMinSig struct {
	sig [SignatureMinSigLen]byte
}

// SignatureMinPkFromBytes parses a compressed G2 point, checking the
// encoding, that it is on the curve, and that it is in the prime-order
// subgroup.
func SignatureMinPkFromBytes(b []byte) (*SignatureMinPk, error) {
	var p bls12377.G2Affine

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

func SignatureMinSigFromBytes(b []byte) (*SignatureMinSig, error) {
	var p bls12377.G1Affine

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

func (s *SignatureMinPk) Bytes() [SignatureMinPkLen]byte {
	return s.sig
}

func (s *SignatureMinSig) Bytes() [SignatureMinSigLen]byte {
	return s.sig
}

func (s *SignatureMinPk) Equal(o *SignatureMinPk) bool {
	if o == nil {
		return false
	}
	return s.sig == o.sig
}

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

func (s *SignatureMinSig) IsZero() bool {
	return s == nil || *s == SignatureMinSig{}
}

func (s *SignatureMinPk) String() string {
	return encoding.Hex.Encode(s.sig[:])
}

func (s *SignatureMinSig) String() string {
	return encoding.Hex.Encode(s.sig[:])
}

// point is s in the form gnark takes; s.sig was parsed at construction, so
// the error cannot fire.
func (s *SignatureMinPk) point() bls12377.G2Affine {
	var p bls12377.G2Affine

	_, _ = p.SetBytes(s.sig[:])
	return p
}

func (s *SignatureMinSig) point() bls12377.G1Affine {
	var p bls12377.G1Affine

	_, _ = p.SetBytes(s.sig[:])
	return p
}
