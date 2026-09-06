package sr25519

import (
	"github.com/ChainSafe/go-schnorrkel"
	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

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

func (s *Signature) Bytes() [SignatureLen]byte {
	return s.sig
}

func (s *Signature) Equal(o *Signature) bool {
	if o == nil {
		return false
	}
	return s.sig == o.sig
}

func (s *Signature) IsZero() bool {
	return s == nil || *s == Signature{}
}

func (s *Signature) String() string {
	return encoding.Hex.Encode(s.sig[:])
}
