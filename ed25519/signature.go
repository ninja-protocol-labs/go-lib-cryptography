package ed25519

import "github.com/ninja-protocol-labs/go-lib-cryptography/encoding"

// Signature is R ∥ S. crypto/ed25519 exposes no parser for it beyond the
// verification path, so this type holds the bytes and the checking happens
// in Verify.
type Signature struct {
	sig [SignatureLen]byte
}

// SignatureFromBytes wraps a signature, checking only the length. What
// the bytes encode is checked by Verify.
func SignatureFromBytes(b []byte) (*Signature, error) {
	var s Signature

	if len(b) != SignatureLen {
		return nil, ErrInvalidSignature
	}

	copy(s.sig[:], b)
	return &s, nil
}

// Bytes returns the signature, as a copy.
func (s *Signature) Bytes() [SignatureLen]byte {
	return s.sig
}

// Equal reports whether o holds the same bytes. It is nil-safe, and not
// constant-time — a signature is public.
func (s *Signature) Equal(o *Signature) bool {
	if o == nil {
		return false
	}
	return s.sig == o.sig
}

// IsZero catches a `var s Signature`.
func (s *Signature) IsZero() bool {
	return s == nil || *s == Signature{}
}

// String returns the signature as lowercase hex.
func (s *Signature) String() string {
	return encoding.Hex.Encode(s.sig[:])
}
