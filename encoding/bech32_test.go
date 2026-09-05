package encoding

import (
	"bytes"
	"errors"
	"strings"
	"testing"
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
		if _, _, err := Bech32.Decode(s); err != nil {
			t.Errorf("Bech32.Decode(%q) failed: %v", s, err)
		}
	}
	for _, s := range validBech32m {
		if _, _, err := Bech32m.Decode(s); err != nil {
			t.Errorf("Bech32m.Decode(%q) failed: %v", s, err)
		}
	}
}

func TestBech32AndBech32mRejectEachOther(t *testing.T) {
	// The two differ by a single checksum constant, and getting it wrong
	// produces a string that looks right and fails at the far end. This is
	// the same shape of hazard as SHA-3 against Keccak, so it is asserted
	// rather than only documented.
	for _, s := range validBech32 {
		if _, _, err := Bech32m.Decode(s); !errors.Is(err, ErrInvalidChecksum) {
			t.Errorf("Bech32m accepted the bech32 string %q: err = %v", s, err)
		}
	}
	for _, s := range validBech32m {
		if _, _, err := Bech32.Decode(s); !errors.Is(err, ErrInvalidChecksum) {
			t.Errorf("Bech32 accepted the bech32m string %q: err = %v", s, err)
		}
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
				if err != nil {
					t.Fatalf("EncodeBytes(%x) failed: %v", payload, err)
				}
				hrp, got, err := c.enc.DecodeBytes(s)
				if err != nil {
					t.Fatalf("DecodeBytes(%q) failed: %v", s, err)
				}
				if hrp != "abc" {
					t.Errorf("hrp = %q, want abc", hrp)
				}
				if !bytes.Equal(got, payload) {
					t.Errorf("round trip of %x = %x", payload, got)
				}
			}
		})
	}
}

func TestBech32CaseRules(t *testing.T) {
	// BIP-173 defines the encoding as case-insensitive, so an all-upper or
	// all-lower string is fine and a mixed one has already been mangled.
	if _, _, err := Bech32.Decode("A12UEL5L"); err != nil {
		t.Errorf("uppercase rejected: %v", err)
	}
	if _, _, err := Bech32.Decode("a12uel5l"); err != nil {
		t.Errorf("lowercase rejected: %v", err)
	}
	if _, _, err := Bech32.Decode("A12uel5l"); !errors.Is(err, ErrMalformed) {
		t.Errorf("mixed case: err = %v, want ErrMalformed", err)
	}
}

func TestBech32SeparatorIsTheLastOne(t *testing.T) {
	// '1' is excluded from the data alphabet precisely so the last one is
	// unambiguously the separator, even when the prefix contains one.
	s, err := Bech32.EncodeBytes("a1b", []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("EncodeBytes failed: %v", err)
	}
	hrp, _, err := Bech32.DecodeBytes(s)
	if err != nil {
		t.Fatalf("DecodeBytes(%q) failed: %v", s, err)
	}
	if hrp != "a1b" {
		t.Errorf("hrp = %q, want a1b", hrp)
	}
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
			if _, _, err := Bech32.Decode(tt.in); !errors.Is(err, tt.want) {
				t.Errorf("Decode(%q) error = %v, want %v", tt.in, err, tt.want)
			}
		})
	}
}

func TestBech32HRPRules(t *testing.T) {
	// BIP-173 restricts the prefix to printable ASCII with no uppercase.
	for _, hrp := range []string{"", "AB", "a b", "a\x7f"} {
		if _, err := Bech32.Encode(hrp, nil); !errors.Is(err, ErrMalformed) {
			t.Errorf("Encode with hrp %q: err = %v, want ErrMalformed", hrp, err)
		}
	}
	if _, err := Bech32.Encode("?", nil); err != nil {
		t.Errorf("Encode with hrp %q failed: %v", "?", err)
	}
}

func TestBech32LengthLimit(t *testing.T) {
	// BIP-173 caps a string at 90 characters, because that is the range the
	// checksum's error-detection guarantee was computed over. Some formats
	// exceed it deliberately, which is what the Unlimited pair is for.
	long := bytes.Repeat([]byte{0xff}, 60) // well past 90 characters encoded

	if _, err := Bech32.EncodeBytes("abc", long); !errors.Is(err, ErrMalformed) {
		t.Errorf("Encode past the limit: err = %v, want ErrMalformed", err)
	}

	converted, err := ConvertBits(long, 8, 5, true)
	if err != nil {
		t.Fatalf("ConvertBits failed: %v", err)
	}
	s, err := Bech32.EncodeUnlimited("abc", converted)
	if err != nil {
		t.Fatalf("EncodeUnlimited failed: %v", err)
	}
	if len(s) <= MaxBech32Len {
		t.Fatalf("test premise is wrong: %d characters", len(s))
	}

	if _, _, err := Bech32.Decode(s); !errors.Is(err, ErrMalformed) {
		t.Errorf("Decode past the limit: err = %v, want ErrMalformed", err)
	}
	if _, _, err := Bech32.DecodeUnlimited(s); err != nil {
		t.Errorf("DecodeUnlimited failed: %v", err)
	}
}

func TestBech32DataMustBeFiveBit(t *testing.T) {
	// Encode takes the data part already converted, so a value that does
	// not fit in five bits is a caller error rather than something to
	// silently truncate.
	if _, err := Bech32.Encode("a", []byte{32}); !errors.Is(err, ErrMalformed) {
		t.Errorf("Encode with a six-bit value: err = %v, want ErrMalformed", err)
	}
}

func TestConvertBits(t *testing.T) {
	// Eight to five must pad, five to eight must not, and the padding is
	// then required to be zero — a non-zero remainder means the string
	// carried bits no byte payload could have produced.
	in := []byte{0xde, 0xad, 0xbe, 0xef}

	five, err := ConvertBits(in, 8, 5, true)
	if err != nil {
		t.Fatalf("8->5 failed: %v", err)
	}
	for _, v := range five {
		if v>>5 != 0 {
			t.Fatalf("8->5 produced %d, which does not fit in five bits", v)
		}
	}

	back, err := ConvertBits(five, 5, 8, false)
	if err != nil {
		t.Fatalf("5->8 failed: %v", err)
	}
	if !bytes.Equal(back, in) {
		t.Errorf("round trip = %x, want %x", back, in)
	}

	// Non-zero padding is rejected.
	dirty := append([]byte(nil), five...)
	dirty[len(dirty)-1] |= 1
	if _, err := ConvertBits(dirty, 5, 8, false); !errors.Is(err, ErrMalformed) {
		t.Errorf("5->8 with non-zero padding: err = %v, want ErrMalformed", err)
	}
}

func TestBech32CharsetExcludesConfusableCharacters(t *testing.T) {
	// 1, b, i and o are absent so that nothing in the data part can be
	// mistaken for something else when read aloud or copied by hand.
	for _, ch := range "1bio" {
		if strings.ContainsRune(Bech32Charset, ch) {
			t.Errorf("the charset contains %q", ch)
		}
	}
	if len(Bech32Charset) != 32 {
		t.Errorf("charset is %d characters, want 32", len(Bech32Charset))
	}
}
