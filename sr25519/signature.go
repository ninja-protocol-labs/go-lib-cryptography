package sr25519

import (
	"github.com/ChainSafe/go-schnorrkel"
	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Signature is a schnorrkel signature: the pair (R, s).
//
// Signing draws a fresh nonce per call, so the same key over the same
// message gives different bytes each time — unlike Ed25519.
type Signature struct {
	sig [SignatureLen]byte
}

// SignatureFromBytes checks the encoding decodes: schnorrkel marks its
// signatures by setting the high bit, distinguishing them from a raw
// Ed25519-shaped one.
func SignatureFromBytes(b []byte) (*Signature, error) {
	var (
		enc [SignatureLen]byte
		s   schnorrkel.Signature
	)

	if len(b) != SignatureLen {
		return nil, ErrInvalidSignature
	}

	copy(enc[:], b)
	if err := s.Decode(enc); err != nil {
		return nil, ErrInvalidSignature
	}

	return &Signature{
		sig: enc,
	}, nil
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

// IsZero catches a `var s Signature`; no constructor returns one.
func (s *Signature) IsZero() bool {
	return s == nil || *s == Signature{}
}

// String returns the signature as lowercase hex.
func (s *Signature) String() string {
	return encoding.Hex.Encode(s.sig[:])
}
