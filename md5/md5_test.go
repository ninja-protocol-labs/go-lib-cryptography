package md5

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The RFC 1321 §A.5 test suite, regenerated with OpenSSL rather than taken
// from the standard library this package wraps — hashing with crypto/md5
// and comparing against crypto/md5 would only show the wrapper is
// self-consistent.
var vectors = []struct {
	in   string
	want string
}{
	{"", "d41d8cd98f00b204e9800998ecf8427e"},
	{"a", "0cc175b9c0f1b6a831c399e269772661"},
	{"abc", "900150983cd24fb0d6963f7d28e17f72"},
	{"message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
	{"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"},
	{
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"d174ab98d277d9f5a5611c2c9f419d9f",
	},
	{
		// 80 bytes: spills past a single 64-byte block once padding and the
		// length field are appended, so this is the multi-block case.
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
		"57edf4a22be3c955ac49da2e2107b67a",
	},
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test vector %q: %v", s, err)
	}
	return b
}

func TestSumMatchesKnownAnswers(t *testing.T) {
	for _, v := range vectors {
		t.Run(v.in, func(t *testing.T) {
			want := mustDecodeHex(t, v.want)
			if len(want) != Size {
				t.Fatalf("vector length = %d, want %d", len(want), Size)
			}
			if got := Sum([]byte(v.in)); !bytes.Equal(got[:], want) {
				t.Errorf("Sum(%q) = %x, want %x", v.in, got, want)
			}
		})
	}
}

func TestSumOfEmptyInput(t *testing.T) {
	want := mustDecodeHex(t, vectors[0].want)
	if got := Sum(nil); !bytes.Equal(got[:], want) {
		t.Errorf("Sum(nil) = %x, want %x", got, want)
	}
	if Sum(nil) != Sum([]byte{}) {
		t.Error("Sum(nil) != Sum(empty slice)")
	}
}

func TestStreamingAgreesWithOneShot(t *testing.T) {
	for _, v := range vectors {
		t.Run(v.in, func(t *testing.T) {
			h := New()
			if h.Size() != Size {
				t.Errorf("Size() = %d, want %d", h.Size(), Size)
			}
			if h.BlockSize() != BlockSize {
				t.Errorf("BlockSize() = %d, want %d", h.BlockSize(), BlockSize)
			}
			// A byte at a time, so the buffering has to reassemble blocks.
			for i := range len(v.in) {
				h.Write([]byte{v.in[i]})
			}
			if got, want := h.Sum(nil), Sum([]byte(v.in)); !bytes.Equal(got, want[:]) {
				t.Errorf("streaming = %x, one-shot = %x", got, want)
			}
		})
	}
}

func TestStreamingResetIsReusable(t *testing.T) {
	h := New()
	h.Write([]byte("something else entirely"))
	h.Reset()
	h.Write([]byte("abc"))
	if got, want := h.Sum(nil), Sum([]byte("abc")); !bytes.Equal(got, want[:]) {
		t.Errorf("after Reset = %x, want %x", got, want)
	}
}

func TestDigestsDifferAcrossInputs(t *testing.T) {
	// Guards against a wiring mistake that returns a constant.
	seen := make(map[[Size]byte]string, len(vectors))
	for _, v := range vectors {
		d := Sum([]byte(v.in))
		if prev, dup := seen[d]; dup {
			t.Errorf("%q and %q hash to the same digest", prev, v.in)
		}
		seen[d] = v.in
	}
}
