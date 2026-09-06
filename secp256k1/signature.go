package secp256k1

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Signature is an ECDSA signature as the pair (r, s), each a big-endian
// scalar. Sign always produces low-s; parsing accepts either.
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

// SignatureFromDER parses the ASN.1 DER encoding, rejecting trailing
// bytes and the same out-of-range scalars SignatureFromBytes does.
//
// The parse is strict about DER's own rules — minimal integer encodings,
// no unnecessary leading zeros — because a lax one accepts several
// encodings of the same signature, which is a second source of
// malleability alongside high-s.
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

// Bytes returns the compact encoding, r ∥ s, as a copy. This is what
// Ethereum and Bitcoin's Schnorr-era formats carry; DER is the older form.
func (sig *Signature) Bytes() [SignatureCompactLen]byte {
	var b [SignatureCompactLen]byte

	copy(b[:SignatureScalarLen], sig.r[:])
	copy(b[SignatureScalarLen:], sig.s[:])
	return b
}

// DER returns the ASN.1 DER encoding Bitcoin script signatures carry.
//
// It is a slice because DER is variable-length. DER integers are signed
// and minimally encoded, so a leading zero byte is prepended when the high
// bit is set and leading zero bytes are otherwise stripped. For signatures
// this package produces that gives 70 or 71 bytes almost always, and 68 or
// 69 on the rare value with leading zeros. It never reaches 72: Sign
// normalises s below n/2, so s never needs the pad byte and only r can.
// A high-s signature from elsewhere can be 72, and SignatureFromDER
// parses it.
func (sig *Signature) DER() []byte {
	r, s := sig.scalars()
	return ecdsa.NewSignature(&r, &s).Serialize()
}

// Equal reports whether other holds the same r and s. It is nil-safe, and
// not constant-time — a signature is public.
//
// A signature and its malleated form (r, n-s) are different values here.
// Only one of them verifies: Verify rejects high-s.
func (sig *Signature) Equal(other *Signature) bool {
	if other == nil {
		return false
	}
	return sig.r == other.r && sig.s == other.s
}

// IsZero catches a `var sig Signature`; no constructor returns one, since
// r and s are both rejected at zero.
func (sig *Signature) IsZero() bool {
	return sig == nil || *sig == Signature{}
}

// String returns the compact encoding as lowercase hex.
func (sig *Signature) String() string {
	b := sig.Bytes()
	return encoding.Hex.Encode(b[:])
}

// scalars is sig in the form dcrd takes; both halves were range-checked at
// construction, so the overflow flags cannot fire.
func (sig *Signature) scalars() (secp256k1.ModNScalar, secp256k1.ModNScalar) {
	var r, s secp256k1.ModNScalar
	r.SetBytes(&sig.r)
	s.SetBytes(&sig.s)
	return r, s
}
