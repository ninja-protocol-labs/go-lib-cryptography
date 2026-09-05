package encoding

import stdbase64 "encoding/base64"

// The four RFC 4648 base64 variants, which differ in two independent
// choices: the last two alphabet characters, and whether output is padded.
//
// The choice is not cosmetic — a decoder configured for one variant
// rejects or misreads the others — and it is fixed by whatever is on the
// other side rather than by preference. Naming all four here is meant to
// make that a visible decision at the call site instead of a default
// someone inherited.
//
//	Base64        +/  with = padding    RFC 4648 §4, the usual default.
//	Base64URL     -_  with = padding    RFC 4648 §5. Safe in URLs and
//	                                    filenames.
//	Base64Raw     +/  unpadded
//	Base64RawURL  -_  unpadded          What JWTs use.
var (
	Base64       = base64Codec{stdbase64.StdEncoding}
	Base64URL    = base64Codec{stdbase64.URLEncoding}
	Base64Raw    = base64Codec{stdbase64.RawStdEncoding}
	Base64RawURL = base64Codec{stdbase64.RawURLEncoding}
)

type base64Codec struct {
	enc *stdbase64.Encoding
}

// Encode returns b in this variant's base64.
func (c base64Codec) Encode(b []byte) string {
	return c.enc.EncodeToString(b)
}

// Decode parses s in this variant's base64. Input encoded under a
// different variant is rejected rather than reinterpreted.
//
// Every failure reports ErrMalformed. The standard library returns one
// error type for a character outside the alphabet and for bad padding
// alike, so there is nothing finer to pass on.
func (c base64Codec) Decode(s string) ([]byte, error) {
	b, err := c.enc.DecodeString(s)
	if err != nil {
		return nil, ErrMalformed
	}
	return b, nil
}

// DecodeInto parses s into dst, which must be exactly the decoded length.
func (c base64Codec) DecodeInto(dst []byte, s string) error {
	b, err := c.Decode(s)
	return decodeInto(dst, b, err)
}
