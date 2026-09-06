package bls12377edwards

import "github.com/ninja-protocol-labs/go-lib-cryptography/encoding"

// Signature is R ∥ S. gnark-crypto exposes no parser for it beyond the
// verification path, so this type holds the bytes and the checking happens
// in Verify.
type Signature struct {
	sig [SignatureLen]byte
}

func SignatureFromBytes(b []byte) (*Signature, error) {
	var s Signature

	if len(b) != SignatureLen {
		return nil, ErrInvalidSignature
	}

	copy(s.sig[:], b)
	return &s, nil
}

func (s *Signature) Bytes() [SignatureLen]byte {
	return s.sig
}

func (s *Signature) Equal(o *Signature) bool {
	if o == nil {
		return false
	}
	return s.sig == o.sig
}

// IsZero catches a `var s Signature`; no constructor returns one.
func (s *Signature) IsZero() bool {
	return s == nil || *s == Signature{}
}

func (s *Signature) String() string {
	return encoding.Hex.Encode(s.sig[:])
}
