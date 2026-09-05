package ripemd160

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The test vectors published with RIPEMD-160 itself (Dobbertin, Bosselaers
// and Preneel), regenerated here with OpenSSL rather than with the library
// this package wraps — hashing with x/crypto and comparing against
// x/crypto would only show the wrapper is self-consistent.
var vectors = []struct {
	in   string
	want string
}{
	{"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
	{"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"},
	{"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
	{"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"},
	{"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"},
	// 56 bytes: one byte over a single 64-byte block once the padding and
	// length field are appended, so this is the case that must spill into
	// a second compression.
	{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b"},
}

// millionAs is the suite's long-input case, at 15625 blocks.
const millionAs = "52783243c1697bdbe16d37f97f68f08325dc1528"

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

func TestSumOfAMillionAs(t *testing.T) {
	// The suite's long case. Also the only one here that exercises the
	// block counter past a handful of iterations.
	in := bytes.Repeat([]byte{'a'}, 1_000_000)
	want := mustDecodeHex(t, millionAs)
	if got := Sum(in); !bytes.Equal(got[:], want) {
		t.Errorf("Sum(a*1e6) = %x, want %x", got, want)
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
	// Sum is this package's own, built on the streaming hash upstream
	// provides, so unlike a re-exported one-shot this is checking code we
	// wrote.
	for _, v := range vectors {
		t.Run(v.in, func(t *testing.T) {
			h := New()
			if h.Size() != Size {
				t.Errorf("Size() = %d, want %d", h.Size(), Size)
			}
			if h.BlockSize() != BlockSize {
				t.Errorf("BlockSize() = %d, want %d", h.BlockSize(), BlockSize)
			}
			// Byte at a time, so the buffering has to reassemble blocks.
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

func TestSumDoesNotAliasOrOverrun(t *testing.T) {
	// Sum writes into out[:0], relying on append not reallocating when the
	// capacity is exactly the digest length. If that stopped holding, the
	// returned array would be all zero rather than the digest.
	got := Sum([]byte("abc"))
	if got == ([Size]byte{}) {
		t.Fatal("Sum returned an all-zero array")
	}
	if Sum([]byte("abc")) != got {
		t.Error("two calls to Sum disagreed")
	}
}

func TestConstants(t *testing.T) {
	if Size != 20 {
		t.Errorf("Size = %d, want 20", Size)
	}
	if BlockSize != 64 {
		t.Errorf("BlockSize = %d, want 64", BlockSize)
	}
}

func TestDigestsDifferAcrossInputs(t *testing.T) {
	// Guards against a wiring mistake that returns a constant: every
	// vector must hash to something distinct.
	seen := make(map[[Size]byte]string, len(vectors))
	for _, v := range vectors {
		d := Sum([]byte(v.in))
		if prev, dup := seen[d]; dup {
			t.Errorf("%q and %q hash to the same digest", prev, v.in)
		}
		seen[d] = v.in
	}
}
