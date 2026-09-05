package encoding

import (
	"bytes"
	"errors"
	"testing"
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
		if err != nil {
			t.Fatalf("Decode(%q) failed: %v", s, err)
		}
		if !bytes.Equal(got, in) {
			t.Errorf("round trip of %x = %x", in, got)
		}
	}
}

func TestHexEncodeIsLowercaseAndUnprefixed(t *testing.T) {
	in := []byte{0xde, 0xad, 0xbe, 0xef}
	if got, want := Hex.Encode(in), "deadbeef"; got != want {
		t.Errorf("Encode = %q, want %q", got, want)
	}
	if got, want := Hex.EncodePrefixed(in), "0xdeadbeef"; got != want {
		t.Errorf("EncodePrefixed = %q, want %q", got, want)
	}
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
		if err != nil {
			t.Fatalf("Decode(%q) failed: %v", s, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("Decode(%q) = %x, want %x", s, got, want)
		}
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
			if _, err := Hex.Decode(tt.in); !errors.Is(err, tt.want) {
				t.Errorf("Decode(%q) error = %v, want %v", tt.in, err, tt.want)
			}
		})
	}
}

func TestHexDecodeIntoChecksLength(t *testing.T) {
	// The form that pairs with this module's fixed-size arrays.
	var k [4]byte
	if err := Hex.DecodeInto(k[:], "0xdeadbeef"); err != nil {
		t.Fatalf("DecodeInto failed: %v", err)
	}
	if want := [4]byte{0xde, 0xad, 0xbe, 0xef}; k != want {
		t.Errorf("DecodeInto wrote %x, want %x", k, want)
	}

	for _, s := range []string{"deadbe", "deadbeef00"} {
		var short [4]byte
		if err := Hex.DecodeInto(short[:], s); !errors.Is(err, ErrInvalidLength) {
			t.Errorf("DecodeInto(%q) error = %v, want ErrInvalidLength", s, err)
		}
	}
}

func TestHexDecodeIntoLeavesDestinationAloneOnError(t *testing.T) {
	// A rejected decode must not half-fill the destination, or a caller
	// that ignores the error gets a key made of two different strings.
	k := [4]byte{1, 2, 3, 4}
	if err := Hex.DecodeInto(k[:], "ffffff"); err == nil {
		t.Fatal("DecodeInto accepted the wrong length")
	}
	if want := [4]byte{1, 2, 3, 4}; k != want {
		t.Errorf("destination was modified: %x, want %x", k, want)
	}
}
