// Package encoding is the public API for the text encodings that
// cryptographic bytes get written down in: hex, base32, base64, base58,
// base58check, and bech32.
//
// # What belongs here
//
// One question decides it: would two different systems implement this
// identically? A radix conversion, an alphabet, a checksum over the bytes
// being encoded — yes. A registry of prefixes, a byte whose value means
// something to one network, the layout of a record — no. Those are the
// property of whatever speaks that protocol, and belong wherever it is
// spoken.
//
// So Base58Check computes and verifies the checksum but knows no version
// bytes; Bech32 encodes a prefix and a data part but knows nothing about
// what the data means. Callers prepend and interpret their own bytes. It is
// the same line this module draws elsewhere: no package here composes a
// primitive into somebody's identifier format.
//
// # Structure serialization is a different layer
//
// Everything here answers "how do I write these bytes as text a human can
// transcribe". Formats that answer "how do I serialize this data structure"
// — RLP, protobuf, a chain's transaction layout — are a layer up and are
// not here, however much they look like encodings.
//
// # Shape
//
// Each codec is a package-level value with no state, the way
// encoding/binary exposes BigEndian and LittleEndian, so that
// encoding.Base58.Encode and encoding.Base64.Encode read the same way:
//
//	Encode(b []byte) string
//	Decode(s string) ([]byte, error)
//	DecodeInto(dst []byte, s string) error
//
// DecodeInto is the fixed-length form, and the reason it takes a
// destination rather than returning one: everything in this module returns
// fixed-size arrays, so decoding into [32]byte is the operation that pairs
// with them.
//
//	var k [32]byte
//	err := encoding.Hex.DecodeInto(k[:], s)
//
// It reports an error unless the input decodes to exactly len(dst) bytes,
// which is a check the standard library's decoders leave to the caller.
package encoding

import "errors"

// Sentinel errors shared by every codec here.
var (
	// ErrInvalidLength means a decode produced a different number of bytes
	// than the destination has room for. Only DecodeInto returns it —
	// Decode has no expectation to violate.
	ErrInvalidLength = errors.New("encoding: decoded length does not match the destination")

	// ErrInvalidCharacter means the input contains a byte the encoding's
	// alphabet does not define.
	ErrInvalidCharacter = errors.New("encoding: input contains a character outside the alphabet")

	// ErrInvalidChecksum means a checksummed encoding decoded cleanly but
	// its checksum does not match the payload — a corrupted or mistyped
	// string, or one from a different encoding that happens to parse.
	ErrInvalidChecksum = errors.New("encoding: checksum mismatch")

	// ErrMalformed means the input is not well formed for the encoding:
	// a bad length, a missing separator, or padding where there should be
	// none.
	ErrMalformed = errors.New("encoding: malformed input")
)

// decodeInto is the shared implementation of every codec's DecodeInto: run
// the codec's own Decode, then hold it to the destination's length.
func decodeInto(dst []byte, decoded []byte, err error) error {
	if err != nil {
		return err
	}
	if len(decoded) != len(dst) {
		return ErrInvalidLength
	}
	copy(dst, decoded)
	return nil
}
