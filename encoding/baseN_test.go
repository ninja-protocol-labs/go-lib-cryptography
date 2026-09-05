package encoding

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
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
				if err != nil {
					t.Fatalf("Decode(%q) of %x failed: %v", s, in, err)
				}
				if !bytes.Equal(got, in) {
					t.Errorf("round trip of %x = %x (via %q)", in, got, s)
				}
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
			if err := c.DecodeInto(exact[:], s); err != nil {
				t.Fatalf("DecodeInto failed: %v", err)
			}
			if !bytes.Equal(exact[:], in) {
				t.Errorf("DecodeInto wrote %x, want %x", exact, in)
			}

			for _, n := range []int{3, 5} {
				dst := make([]byte, n)
				if err := c.DecodeInto(dst, s); !errors.Is(err, ErrInvalidLength) {
					t.Errorf("DecodeInto into %d bytes: error = %v, want ErrInvalidLength", n, err)
				}
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
		if err != nil {
			t.Fatalf("bad test vector %q: %v", v.hexIn, err)
		}
		if got := Base58.Encode(in); got != v.want {
			t.Errorf("Encode(%s) = %q, want %q", v.hexIn, got, v.want)
		}
		got, err := Base58.Decode(v.want)
		if err != nil {
			t.Fatalf("Decode(%q) failed: %v", v.want, err)
		}
		if !bytes.Equal(got, in) {
			t.Errorf("Decode(%q) = %x, want %s", v.want, got, v.hexIn)
		}
	}
}

func TestBase58LeadingZerosSurvive(t *testing.T) {
	// One leading zero byte per leading '1', which is what makes an
	// all-zero 32-byte value encode to 32 characters rather than none.
	for n := range 5 {
		in := make([]byte, n)
		s := Base58.Encode(in)
		if len(s) != n {
			t.Errorf("%d zero bytes encoded to %q (%d chars), want %d", n, s, len(s), n)
		}
		got, err := Base58.Decode(s)
		if err != nil {
			t.Fatalf("Decode(%q) failed: %v", s, err)
		}
		if len(got) != n {
			t.Errorf("%q decoded to %d bytes, want %d", s, len(got), n)
		}
	}
}

func TestBase58RejectsCharactersOutsideTheAlphabet(t *testing.T) {
	// The four excluded characters are the whole point of the alphabet.
	for _, s := range []string{"0", "O", "I", "l", "abc0def"} {
		if _, err := Base58.Decode(s); !errors.Is(err, ErrInvalidCharacter) {
			t.Errorf("Decode(%q) error = %v, want ErrInvalidCharacter", s, err)
		}
	}
}

func TestBase58AlphabetsAreNotInterchangeable(t *testing.T) {
	// Why the alphabet is a parameter and neither ordering is privileged:
	// a string encoded under one decodes cleanly under the other, into
	// different bytes, with nothing in the string to say which produced it.
	// Only the caller knows which they meant.
	//
	// The second ordering here is a rotation of the default, chosen to make
	// the point without standing for anyone's format.
	other := NewBase58(Base58Alphabet[29:] + Base58Alphabet[:29])
	in := []byte{0xde, 0xad, 0xbe, 0xef}

	a, b := Base58.Encode(in), other.Encode(in)
	if a == b {
		t.Fatal("the two alphabets produced the same string")
	}

	crossed, err := other.Decode(a)
	if err != nil {
		t.Fatalf("the second alphabet rejected a string from the first: %v", err)
	}
	if bytes.Equal(crossed, in) {
		t.Error("decoding under the wrong alphabet returned the original bytes")
	}
}

func TestNewBase58RejectsBadAlphabets(t *testing.T) {
	cases := map[string]string{
		"too short":     Base58Alphabet[:57],
		"too long":      Base58Alphabet + "0",
		"repeated char": Base58Alphabet[:57] + "1",
		"non-ASCII":     Base58Alphabet[:57] + "\xff",
	}
	for name, alphabet := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("NewBase58 accepted a malformed alphabet")
				}
			}()
			NewBase58(alphabet)
		})
	}
}

func TestBase58CheckDetectsCorruption(t *testing.T) {
	// The reason base58check exists: a mistyped address fails instead of
	// decoding to the wrong bytes.
	payload := []byte{0x00, 0xde, 0xad, 0xbe, 0xef}
	s := Base58Check.Encode(payload)

	got, err := Base58Check.Decode(s)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("round trip = %x, want %x", got, payload)
	}

	// Flip one character to something else in the alphabet.
	for i := range s {
		mangled := []byte(s)
		if mangled[i] == Base58Alphabet[0] {
			mangled[i] = Base58Alphabet[1]
		} else {
			mangled[i] = Base58Alphabet[0]
		}
		if _, err := Base58Check.Decode(string(mangled)); err == nil {
			t.Errorf("Decode accepted %q, one character off from %q", mangled, s)
		}
	}
}

func TestBase58CheckRejectsShortInput(t *testing.T) {
	// Anything too small to hold a checksum is malformed rather than
	// checksum-mismatched, which are different problems.
	for _, payload := range [][]byte{{}, {0x01}, {0x01, 0x02, 0x03}} {
		s := Base58.Encode(payload) // plain base58: no checksum appended
		if _, err := Base58Check.Decode(s); !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrInvalidChecksum) {
			t.Errorf("Decode(%q) error = %v, want ErrMalformed or ErrInvalidChecksum", s, err)
		}
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
		if err != nil {
			t.Fatalf("round trip failed: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("round trip = %x, want %x", got, payload)
		}
	}
}

func TestBase64VariantsAreDistinct(t *testing.T) {
	// Values chosen to produce both of the characters the variants differ
	// on, and a length that needs padding.
	in := []byte{0xfb, 0xff, 0xbe}

	std, url := Base64.Encode(in), Base64URL.Encode(in)
	if std == url {
		t.Errorf("standard and URL alphabets agreed on %x: %q", in, std)
	}
	if raw := Base64Raw.Encode([]byte{0x00}); len(raw) >= len(Base64.Encode([]byte{0x00})) {
		t.Error("the raw variant is not shorter than the padded one")
	}

	// A padded string must not decode under a raw variant, and vice versa.
	if _, err := Base64Raw.Decode(Base64.Encode([]byte{0x00})); err == nil {
		t.Error("the raw variant accepted padded input")
	}
}

func TestBase32RawIsUnpadded(t *testing.T) {
	in := []byte{0xde, 0xad, 0xbe, 0xef}
	padded, raw := Base32.Encode(in), Base32Raw.Encode(in)
	if padded == raw {
		t.Error("padded and raw base32 agreed")
	}
	if len(raw) >= len(padded) {
		t.Errorf("raw %q is not shorter than padded %q", raw, padded)
	}
	if _, err := Base32Raw.Decode(padded); err == nil {
		t.Error("the raw variant accepted padded input")
	}
}
