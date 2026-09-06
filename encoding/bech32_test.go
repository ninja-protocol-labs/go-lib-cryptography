package encoding

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The valid-string vectors from BIP-173 (bech32) and BIP-350 (bech32m).
// They come from the specifications, not from this package.
var (
	validBech32 = []string{
		"A12UEL5L",
		"a12uel5l",
		"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
		"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
		"?1ezyfcl",
	}
	validBech32m = []string{
		"A1LQFN3A",
		"a1lqfn3a",
		"abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
		"?1v759aa",
	}
)

func TestBech32DecodesSpecVectors(t *testing.T) {
	for _, s := range validBech32 {
		_, _, err := Bech32.Decode(s)
		assert.NoError(t, err, "Bech32.Decode(%q)", s)
	}
	for _, s := range validBech32m {
		_, _, err := Bech32m.Decode(s)
		assert.NoError(t, err, "Bech32m.Decode(%q)", s)
	}
}

func TestBech32AndBech32mRejectEachOther(t *testing.T) {
	// The two differ by a single checksum constant, and getting it wrong
	// produces a string that looks right and fails at the far end. This is
	// the same shape of hazard as SHA-3 against Keccak, so it is asserted
	// rather than only documented.
	for _, s := range validBech32 {
		_, _, err := Bech32m.Decode(s)
		assert.ErrorIs(t, err, ErrInvalidChecksum, "Bech32m accepted the bech32 string %q", s)
	}
	for _, s := range validBech32m {
		_, _, err := Bech32.Decode(s)
		assert.ErrorIs(t, err, ErrInvalidChecksum, "Bech32 accepted the bech32m string %q", s)
	}
}

func TestBech32RoundTrip(t *testing.T) {
	for _, c := range []struct {
		name string
		enc  bech32Codec
	}{{"bech32", Bech32}, {"bech32m", Bech32m}} {
		t.Run(c.name, func(t *testing.T) {
			for _, payload := range [][]byte{
				{},
				{0x00},
				{0xde, 0xad, 0xbe, 0xef},
				bytes.Repeat([]byte{0xff}, 20),
			} {
				s, err := c.enc.EncodeBytes("abc", payload)
				require.NoError(t, err, "EncodeBytes(%x)", payload)

				hrp, got, err := c.enc.DecodeBytes(s)
				require.NoError(t, err, "DecodeBytes(%q)", s)

				assert.Equal(t, "abc", hrp)
				assert.True(t, bytes.Equal(payload, got), "round trip of %x = %x", payload, got)
			}
		})
	}
}

func TestBech32CaseRules(t *testing.T) {
	// BIP-173 defines the encoding as case-insensitive, so an all-upper or
	// all-lower string is fine and a mixed one has already been mangled.
	_, _, err := Bech32.Decode("A12UEL5L")
	assert.NoError(t, err, "uppercase rejected")

	_, _, err = Bech32.Decode("a12uel5l")
	assert.NoError(t, err, "lowercase rejected")

	_, _, err = Bech32.Decode("A12uel5l")
	assert.ErrorIs(t, err, ErrMalformed, "mixed case")
}

func TestBech32SeparatorIsTheLastOne(t *testing.T) {
	// '1' is excluded from the data alphabet precisely so the last one is
	// unambiguously the separator, even when the prefix contains one.
	s, err := Bech32.EncodeBytes("a1b", []byte{0x01, 0x02})
	require.NoError(t, err)

	hrp, _, err := Bech32.DecodeBytes(s)
	require.NoError(t, err, "DecodeBytes(%q)", s)
	assert.Equal(t, "a1b", hrp)
}

func TestBech32RejectsMalformed(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"no separator", "abcdef", ErrMalformed},
		{"empty hrp", "1qzzfhee", ErrMalformed},
		{"too short for a checksum", "a1qzz", ErrMalformed},
		{"character outside the data alphabet", "a1bqzzzzzz", ErrInvalidCharacter},
		{"corrupted checksum", "a12uel5m", ErrInvalidChecksum},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Bech32.Decode(tt.in)
			assert.ErrorIs(t, err, tt.want, "Decode(%q)", tt.in)
		})
	}
}

func TestBech32HRPRules(t *testing.T) {
	// BIP-173 restricts the prefix to printable ASCII with no uppercase.
	for _, hrp := range []string{"", "AB", "a b", "a\x7f"} {
		_, err := Bech32.Encode(hrp, nil)
		assert.ErrorIs(t, err, ErrMalformed, "Encode with hrp %q", hrp)
	}
	_, err := Bech32.Encode("?", nil)
	assert.NoError(t, err, `Encode with hrp "?"`)
}

func TestBech32LengthLimit(t *testing.T) {
	// BIP-173 caps a string at 90 characters, because that is the range the
	// checksum's error-detection guarantee was computed over. Some formats
	// exceed it deliberately, which is what the Unlimited pair is for.
	long := bytes.Repeat([]byte{0xff}, 60) // well past 90 characters encoded

	_, err := Bech32.EncodeBytes("abc", long)
	assert.ErrorIs(t, err, ErrMalformed, "Encode past the limit")

	converted, err := ConvertBits(long, 8, 5, true)
	require.NoError(t, err)
	s, err := Bech32.EncodeUnlimited("abc", converted)
	require.NoError(t, err)
	require.Greater(t, len(s), MaxBech32Len, "test premise is wrong")

	_, _, err = Bech32.Decode(s)
	assert.ErrorIs(t, err, ErrMalformed, "Decode past the limit")

	_, _, err = Bech32.DecodeUnlimited(s)
	assert.NoError(t, err)
}

func TestBech32DataMustBeFiveBit(t *testing.T) {
	// Encode takes the data part already converted, so a value that does
	// not fit in five bits is a caller error rather than something to
	// silently truncate.
	_, err := Bech32.Encode("a", []byte{32})
	assert.ErrorIs(t, err, ErrMalformed, "Encode with a six-bit value")
}

func TestConvertBits(t *testing.T) {
	// Eight to five must pad, five to eight must not, and the padding is
	// then required to be zero — a non-zero remainder means the string
	// carried bits no byte payload could have produced.
	in := []byte{0xde, 0xad, 0xbe, 0xef}

	five, err := ConvertBits(in, 8, 5, true)
	require.NoError(t, err, "8->5")
	for _, v := range five {
		require.Zero(t, v>>5, "8->5 produced %d, which does not fit in five bits", v)
	}

	back, err := ConvertBits(five, 5, 8, false)
	require.NoError(t, err, "5->8")
	assert.Equal(t, in, back)

	// Non-zero padding is rejected.
	dirty := append([]byte(nil), five...)
	dirty[len(dirty)-1] |= 1
	_, err = ConvertBits(dirty, 5, 8, false)
	assert.ErrorIs(t, err, ErrMalformed, "5->8 with non-zero padding")
}

func TestBech32CharsetExcludesConfusableCharacters(t *testing.T) {
	// 1, b, i and o are absent so that nothing in the data part can be
	// mistaken for something else when read aloud or copied by hand.
	for _, ch := range "1bio" {
		assert.False(t, strings.ContainsRune(Bech32Charset, ch), "the charset contains %q", ch)
	}
	assert.Len(t, Bech32Charset, 32)
}
