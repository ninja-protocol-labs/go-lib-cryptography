package secp256r1

import (
	"math/big"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type Signature struct {
	r [SignatureScalarLen]byte
	s [SignatureScalarLen]byte
}

// SignatureFromBytes parses r ∥ s, rejecting a zero half. Unlike
// secp256k1 there is no high-s rule: FIPS 186-5 has none.
func SignatureFromBytes(b []byte) (*Signature, error) {
	var sig Signature

	if len(b) != SignatureCompactLen {
		return nil, ErrInvalidSignature
	}

	copy(sig.r[:], b[:SignatureScalarLen])
	copy(sig.s[:], b[SignatureScalarLen:])
	if sig.r == [SignatureScalarLen]byte{} || sig.s == [SignatureScalarLen]byte{} {
		return nil, ErrInvalidSignature
	}

	return &sig, nil
}

// crypto/ecdsa signs and verifies ASN.1 but exposes no parser for (r, s),
// so the SEQUENCE of two INTEGERs is read here with cryptobyte — what
// crypto/ecdsa uses internally, and strict where encoding/asn1 is lenient.
func SignatureFromDER(b []byte) (*Signature, error) {
	var inner cryptobyte.String

	input := cryptobyte.String(b)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) || !input.Empty() {
		return nil, ErrInvalidSignature
	}

	r, s := new(big.Int), new(big.Int)
	if !inner.ReadASN1Integer(r) || !inner.ReadASN1Integer(s) || !inner.Empty() {
		return nil, ErrInvalidSignature
	}

	return signatureFromScalars(r, s)
}

func signatureFromScalars(r, s *big.Int) (*Signature, error) {
	var sig Signature

	if r.Sign() <= 0 || s.Sign() <= 0 ||
		r.BitLen() > 8*SignatureScalarLen || s.BitLen() > 8*SignatureScalarLen {
		return nil, ErrInvalidSignature
	}

	r.FillBytes(sig.r[:])
	s.FillBytes(sig.s[:])
	return &sig, nil
}

func (sig *Signature) Bytes() [SignatureCompactLen]byte {
	var b [SignatureCompactLen]byte

	copy(b[:SignatureScalarLen], sig.r[:])
	copy(b[SignatureScalarLen:], sig.s[:])
	return b
}

func (sig *Signature) DER() []byte {
	var b cryptobyte.Builder

	r, s := sig.scalars()
	b.AddASN1(asn1.SEQUENCE, func(c *cryptobyte.Builder) {
		c.AddASN1BigInt(r)
		c.AddASN1BigInt(s)
	})
	return b.BytesOrPanic()
}

func (sig *Signature) Equal(o *Signature) bool {
	if o == nil {
		return false
	}
	return sig.r == o.r && sig.s == o.s
}

func (sig *Signature) IsZero() bool {
	return sig == nil || *sig == Signature{}
}

func (sig *Signature) String() string {
	b := sig.Bytes()
	return encoding.Hex.Encode(b[:])
}

func (sig *Signature) scalars() (r, s *big.Int) {
	return new(big.Int).SetBytes(sig.r[:]), new(big.Int).SetBytes(sig.s[:])
}
