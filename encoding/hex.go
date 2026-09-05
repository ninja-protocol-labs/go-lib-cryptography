package encoding

import (
	stdhex "encoding/hex"
	"strings"
)

// Prefix is the "0x" that marks a hexadecimal literal. It predates every
// blockchain that uses it — C wrote integer literals this way first — so
// handling it here is a convenience about text, not knowledge of any
// protocol.
const Prefix = "0x"

type hexCodec struct{}

// Hex encodes and decodes hexadecimal.
//
// Encode produces lowercase without a prefix; EncodePrefixed adds "0x".
// Decode accepts either case, mixed case, and an optional "0x" — the
// normalisation that keeps a caller from having to guess what shape a
// string arrived in.
var Hex hexCodec

// Encode returns b as lowercase hex, with no prefix.
func (hexCodec) Encode(b []byte) string {
	return stdhex.EncodeToString(b)
}

// EncodePrefixed returns b as lowercase hex with a leading "0x".
func (hexCodec) EncodePrefixed(b []byte) string {
	return Prefix + stdhex.EncodeToString(b)
}

// Decode parses s, which may carry a "0x" prefix and may be upper, lower or
// mixed case.
//
// An odd number of digits is malformed: hex encodes whole bytes, and
// guessing whether the caller meant to pad the front or the back would be
// guessing at their data.
func (hexCodec) Decode(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, Prefix)
	s = strings.TrimPrefix(s, "0X")
	if len(s)%2 != 0 {
		return nil, ErrMalformed
	}
	b, err := stdhex.DecodeString(strings.ToLower(s))
	if err != nil {
		return nil, ErrInvalidCharacter
	}
	return b, nil
}

// DecodeInto parses s into dst, which must be exactly the decoded length.
// See the package doc on why this is the fixed-length form.
func (c hexCodec) DecodeInto(dst []byte, s string) error {
	b, err := c.Decode(s)
	return decodeInto(dst, b, err)
}
