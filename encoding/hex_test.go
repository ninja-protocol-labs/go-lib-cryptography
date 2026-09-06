package encoding

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHexRoundTrip(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x00},
		{0xff},
		{0xde, 0xad, 0xbe, 0xef},
		bytes.Repeat([]byte{0x00}, 32),
	}
	for _, in := range cases {
		s := Hex.Encode(in)

		got, err := Hex.Decode(s)
		require.NoError(t, err, "Decode(%q)", s)
		// bytes.Equal, not assert.Equal: a nil input round-trips to an
		// empty slice, which is the same bytes and a different value.
		assert.True(t, bytes.Equal(in, got), "round trip of %x = %x", in, got)
	}
}

func TestHexEncodeIsLowercaseAndUnprefixed(t *testing.T) {
	in := []byte{0xde, 0xad, 0xbe, 0xef}

	assert.Equal(t, "deadbeef", Hex.Encode(in))
	assert.Equal(t, "0xdeadbeef", Hex.EncodePrefixed(in))
}

func TestHexDecodeNormalises(t *testing.T) {
	// The point of having our own hex: a string arrives prefixed or not,
	// in either case or mixed, and the caller should not have to guess.
	want := []byte{0xde, 0xad, 0xbe, 0xef}
	for _, s := range []string{
		"deadbeef",
		"DEADBEEF",
		"DeAdBeEf",
		"0xdeadbeef",
		"0xDEADBEEF",
		"0XdeadBEEF",
	} {
		got, err := Hex.Decode(s)
		require.NoError(t, err, "Decode(%q)", s)
		assert.Equal(t, want, got, "Decode(%q)", s)
	}
}

func TestHexDecodeRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"odd length", "abc", ErrMalformed},
		{"odd length with prefix", "0xabc", ErrMalformed},
		{"non-hex character", "zz", ErrInvalidCharacter},
		{"prefix only leaves odd", "0x0", ErrMalformed},
		// Odd length is checked before the alphabet, so a five-character
		// string reports the length problem it actually has.
		{"internal space, odd length", "de ad", ErrMalformed},
		{"internal space, even length", "de ad  ", ErrMalformed},
		{"non-hex at even length", "dexxad", ErrInvalidCharacter},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Hex.Decode(tt.in)
			assert.ErrorIs(t, err, tt.want, "Decode(%q)", tt.in)
		})
	}
}

func TestHexDecodeIntoChecksLength(t *testing.T) {
	// The form that pairs with this module's fixed-size arrays.
	var k [4]byte
	require.NoError(t, Hex.DecodeInto(k[:], "0xdeadbeef"))
	assert.Equal(t, [4]byte{0xde, 0xad, 0xbe, 0xef}, k)

	for _, s := range []string{"deadbe", "deadbeef00"} {
		var short [4]byte
		assert.ErrorIs(t, Hex.DecodeInto(short[:], s), ErrInvalidLength, "DecodeInto(%q)", s)
	}
}

func TestHexDecodeIntoLeavesDestinationAloneOnError(t *testing.T) {
	// A rejected decode must not half-fill the destination, or a caller
	// that ignores the error gets a key made of two different strings.
	k := [4]byte{1, 2, 3, 4}

	require.Error(t, Hex.DecodeInto(k[:], "ffffff"), "DecodeInto accepted the wrong length")
	assert.Equal(t, [4]byte{1, 2, 3, 4}, k, "destination was modified")
}
