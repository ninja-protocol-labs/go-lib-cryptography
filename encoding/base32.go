package encoding

import "encoding/base32"

// The RFC 4648 §6 base32 alphabet — A-Z and 2-7, which omits 0, 1 and 8 so
// that nothing is confusable with O, I/l or B when read aloud or copied by
// hand. That readability is the whole reason base32 survives alongside
// base64 despite being less compact.
//
// Base32 pads to a multiple of eight characters with "="; Base32Raw does
// not. Unpadded is what TOTP secrets are usually written in (RFC 6238
// authenticator keys) and what Tor v3 onion addresses use.
var (
	Base32    = base32Codec{base32.StdEncoding}
	Base32Raw = base32Codec{base32.StdEncoding.WithPadding(base32.NoPadding)}
)

type base32Codec struct {
	enc *base32.Encoding
}

// Encode returns b in uppercase base32.
func (c base32Codec) Encode(b []byte) string {
	return c.enc.EncodeToString(b)
}

// Decode parses s. The standard library's decoder is case-sensitive and
// wants uppercase, which is what Encode produces.
//
// Every failure reports ErrMalformed, for the reason given on
// base64Codec.Decode.
func (c base32Codec) Decode(s string) ([]byte, error) {
	b, err := c.enc.DecodeString(s)
	if err != nil {
		return nil, ErrMalformed
	}
	return b, nil
}

// DecodeInto parses s into dst, which must be exactly the decoded length.
func (c base32Codec) DecodeInto(dst []byte, s string) error {
	b, err := c.Decode(s)
	return decodeInto(dst, b, err)
}
