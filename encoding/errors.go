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
