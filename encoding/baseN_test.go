package encoding

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// baseNCodec is the surface every fixed-alphabet codec here shares, so the
// round-trip and length checks can be written once.
type baseNCodec interface {
	Encode(b []byte) string
	Decode(s string) ([]byte, error)
	DecodeInto(dst []byte, s string) error
}

func codecs() map[string]baseNCodec {
	return map[string]baseNCodec{
		"Hex":          Hex,
		"Base32":       Base32,
		"Base32Raw":    Base32Raw,
		"Base64":       Base64,
		"Base64URL":    Base64URL,
		"Base64Raw":    Base64Raw,
		"Base64RawURL": Base64RawURL,
		"Base58":       Base58,
		"Base58Check":  Base58Check,
	}
}

func TestRoundTrip(t *testing.T) {
	inputs := [][]byte{
		{},
		{0x00},
		{0xff},
		{0x00, 0x00, 0x00},
		{0xde, 0xad, 0xbe, 0xef},
		bytes.Repeat([]byte{0x00}, 32),
		bytes.Repeat([]byte{0xff}, 32),
		[]byte("the quick brown fox"),
	}
	for name, c := range codecs() {
		t.Run(name, func(t *testing.T) {
			for _, in := range inputs {
				s := c.Encode(in)

				got, err := c.Decode(s)
				require.NoError(t, err, "Decode(%q) of %x", s, in)
				assert.Equal(t, in, got, "round trip via %q", s)
			}
		})
	}
}

func TestDecodeIntoChecksLength(t *testing.T) {
	in := []byte{0xde, 0xad, 0xbe, 0xef}
	for name, c := range codecs() {
		t.Run(name, func(t *testing.T) {
			s := c.Encode(in)

			var exact [4]byte
			require.NoError(t, c.DecodeInto(exact[:], s))
			assert.Equal(t, in, exact[:])

			for _, n := range []int{3, 5} {
				dst := make([]byte, n)
				assert.ErrorIs(t, c.DecodeInto(dst, s), ErrInvalidLength, "into %d bytes", n)
			}
		})
	}
}

// Base58 vectors, computed independently with a plain big-integer
// implementation of the radix conversion rather than taken from this
// package. Leading zero bytes are the case an implementation gets wrong:
// they carry no magnitude, so they have to be emitted explicitly.
var base58Vectors = []struct {
	hexIn string
	want  string
}{
	{"", ""},
	{"00", "1"},
	{"000000", "111"},
	{"61", "2g"},
	{"626262", "a3gV"},
	{"68656c6c6f20776f726c64", "StV1DL6CwTryKyV"},
	{"ffff", "LUv"},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"11111111111111111111111111111111",
	},
}

func TestBase58MatchesKnownAnswers(t *testing.T) {
	for _, v := range base58Vectors {
		in, err := hex.DecodeString(v.hexIn)
		require.NoError(t, err, "bad test vector %q", v.hexIn)

		assert.Equal(t, v.want, Base58.Encode(in))

		got, err := Base58.Decode(v.want)
		require.NoError(t, err, "Decode(%q)", v.want)
		assert.Equal(t, in, got)
	}
}

func TestBase58LeadingZerosSurvive(t *testing.T) {
	// One leading zero byte per leading '1', which is what makes an
	// all-zero 32-byte value encode to 32 characters rather than none.
	for n := range 5 {
		in := make([]byte, n)

		s := Base58.Encode(in)
		assert.Len(t, s, n, "%d zero bytes encoded to %q", n, s)

		got, err := Base58.Decode(s)
		require.NoError(t, err, "Decode(%q)", s)
		assert.Len(t, got, n, "%q decoded to the wrong length", s)
	}
}

func TestBase58RejectsCharactersOutsideTheAlphabet(t *testing.T) {
	// The four excluded characters are the whole point of the alphabet.
	for _, s := range []string{"0", "O", "I", "l", "abc0def"} {
		_, err := Base58.Decode(s)
		assert.ErrorIs(t, err, ErrInvalidCharacter, "Decode(%q)", s)
	}
}

// The alphabet used to be a constructor parameter validated at runtime,
// with a panic for each way of getting it wrong. It is a constant now, so
// this is where those properties are checked instead: 58 distinct ASCII
// bytes, and an index that inverts them.
func TestBase58AlphabetIsWellFormed(t *testing.T) {
	require.Len(t, Base58Alphabet, 58)

	seen := map[byte]bool{}
	for i := range len(Base58Alphabet) {
		ch := Base58Alphabet[i]

		assert.Less(t, ch, byte(0x80), "non-ASCII character at %d", i)
		assert.False(t, seen[ch], "repeated character %q", ch)
		assert.Equal(t, byte(i), base58Index[ch], "index does not invert %q", ch)
		seen[ch] = true
	}

	// Excluding these four is the whole reason the radix is 58 and not 62.
	for _, ch := range []byte{'0', 'O', 'I', 'l'} {
		assert.Equal(t, byte(base58Invalid), base58Index[ch], "%q must not be in the alphabet", ch)
	}
}

func TestBase58CheckDetectsCorruption(t *testing.T) {
	// The reason base58check exists: a mistyped address fails instead of
	// decoding to the wrong bytes.
	payload := []byte{0x00, 0xde, 0xad, 0xbe, 0xef}
	s := Base58Check.Encode(payload)

	got, err := Base58Check.Decode(s)
	require.NoError(t, err)
	assert.Equal(t, payload, got)

	// Flip one character to something else in the alphabet.
	for i := range s {
		mangled := []byte(s)
		if mangled[i] == Base58Alphabet[0] {
			mangled[i] = Base58Alphabet[1]
		} else {
			mangled[i] = Base58Alphabet[0]
		}

		_, err := Base58Check.Decode(string(mangled))
		assert.Error(t, err, "Decode accepted %q, one character off from %q", mangled, s)
	}
}

func TestBase58CheckRejectsShortInput(t *testing.T) {
	// Anything too small to hold a checksum is malformed rather than
	// checksum-mismatched, which are different problems.
	for _, payload := range [][]byte{{}, {0x01}, {0x01, 0x02, 0x03}} {
		s := Base58.Encode(payload) // plain base58: no checksum appended

		_, err := Base58Check.Decode(s)
		assert.Error(t, err, "Decode(%q) accepted a string with no checksum", s)
	}
}

func TestBase58CheckKnowsNoVersionBytes(t *testing.T) {
	// The payload is passed through untouched, whatever its first bytes
	// mean. A one-byte prefix and a four-byte one are the same to this
	// codec, which is what lets formats with different prefix widths share
	// it.
	for _, payload := range [][]byte{
		{0x00, 0x11, 0x22},
		{0x04, 0x88, 0xb2, 0x1e, 0x11, 0x22},
	} {
		got, err := Base58Check.Decode(Base58Check.Encode(payload))
		require.NoError(t, err)
		assert.Equal(t, payload, got)
	}
}

func TestBase64VariantsAreDistinct(t *testing.T) {
	// Values chosen to produce both of the characters the variants differ
	// on, and a length that needs padding.
	in := []byte{0xfb, 0xff, 0xbe}

	assert.NotEqual(t, Base64URL.Encode(in), Base64.Encode(in),
		"standard and URL alphabets agreed on %x", in)

	assert.Less(t, len(Base64Raw.Encode([]byte{0x00})), len(Base64.Encode([]byte{0x00})),
		"the raw variant is not shorter than the padded one")

	// A padded string must not decode under a raw variant.
	_, err := Base64Raw.Decode(Base64.Encode([]byte{0x00}))
	assert.Error(t, err, "the raw variant accepted padded input")
}

func TestBase32RawIsUnpadded(t *testing.T) {
	in := []byte{0xde, 0xad, 0xbe, 0xef}
	padded, raw := Base32.Encode(in), Base32Raw.Encode(in)

	assert.NotEqual(t, padded, raw)
	assert.Less(t, len(raw), len(padded), "raw %q is not shorter than padded %q", raw, padded)

	_, err := Base32Raw.Decode(padded)
	assert.Error(t, err, "the raw variant accepted padded input")
}
