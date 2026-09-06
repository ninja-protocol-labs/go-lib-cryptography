package bls12381ecdsa

import "github.com/ninja-protocol-labs/go-lib-cryptography/encoding"

// Signature is r ∥ s. gnark-crypto exposes no parser for it beyond the
// verification path, so this type holds the bytes and the checking happens
// in Verify.
type Signature struct {
	sig [SignatureLen]byte
}

// SignatureFromBytes wraps r ∥ s, checking only the length.
//
// The scalars are not range-checked here. Verify rejects an out-of-range
// one, and doing it twice would only move the same rejection earlier.
func SignatureFromBytes(b []byte) (*Signature, error) {
	var s Signature

	if len(b) != SignatureLen {
		return nil, ErrInvalidSignature
	}

	copy(s.sig[:], b)
	return &s, nil
}

// Bytes returns r ∥ s, as a copy.
func (s *Signature) Bytes() [SignatureLen]byte {
	return s.sig
}

// Equal reports whether o holds the same r and s. It is nil-safe, and not
// constant-time — a signature is public.
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

// String returns r ∥ s as lowercase hex.
func (s *Signature) String() string {
	return encoding.Hex.Encode(s.sig[:])
}
