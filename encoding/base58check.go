package encoding

import "crypto/sha256"

// Base58Check is base58 with a four-byte checksum, in Base58Alphabet.
//
// # It knows no version bytes
//
// The format in the wild is version ∥ payload ∥ checksum, and the version
// is where the systems using it differ — in value and in length, from one
// byte to four. None of that is here. Encode takes the bytes to be
// checksummed and Decode returns them; prepending and interpreting a
// version prefix is the caller's, which is what keeps this codec from
// needing to know whose identifier it is holding.
//
// It also sidesteps the trap of assuming a version is one byte, which is
// false for several formats in use.
//
// # Not everything called base58 is this
//
// The name is attached to at least one unrelated construction that chunks
// its input and checksums it with a different hash, and to address formats
// that dropped base58 for bech32 while keeping compatibility with older
// base58 ones. A string round-tripping here is evidence about this
// construction and nothing else.
var Base58Check = base58CheckCodec{}

type base58CheckCodec struct{}

// checksum returns the first ChecksumLen bytes of SHA-256(SHA-256(b)).
//
// The hash is applied twice because the original construction applied it
// twice. No property of SHA-256 requires it; it is a fact about the format
// that every interoperating implementation reproduces.
func checksum(b []byte) [ChecksumLen]byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return [ChecksumLen]byte(second[:ChecksumLen])
}

// Encode appends the checksum to payload and base58-encodes the result.
//
// payload is whatever should be covered by the checksum, version bytes
// included — see the note on Base58Check.
func (base58CheckCodec) Encode(payload []byte) string {
	sum := checksum(payload)
	full := make([]byte, 0, len(payload)+ChecksumLen)
	full = append(full, payload...)
	full = append(full, sum[:]...)
	return Base58.Encode(full)
}

// Decode parses s, verifies the checksum, and returns the payload without
// it.
//
// It reports ErrInvalidChecksum when the string decodes but its last four
// bytes do not match, which is what catches a mistyped or truncated
// address — the reason the checksum is there. A string too short to hold
// one reports ErrMalformed.
//
// The comparison is not constant-time, deliberately: the checksum is an
// integrity check over public data, and there is nothing secret in it to
// leak.
func (base58CheckCodec) Decode(s string) ([]byte, error) {
	full, err := Base58.Decode(s)
	if err != nil {
		return nil, err
	}
	if len(full) < ChecksumLen {
		return nil, ErrMalformed
	}

	payload, want := full[:len(full)-ChecksumLen], full[len(full)-ChecksumLen:]
	if got := checksum(payload); string(got[:]) != string(want) {
		return nil, ErrInvalidChecksum
	}
	return payload, nil
}

// DecodeInto parses s into dst, which must be exactly the payload length
// once the checksum is stripped.
func (base58CheckCodec) DecodeInto(dst []byte, s string) error {
	b, err := Base58Check.Decode(s)
	return decodeInto(dst, b, err)
}
