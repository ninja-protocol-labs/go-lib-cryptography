package blake3

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
)

// vectorInput builds the upstream suite's input of length n: the bytes
// 0,1,2,...,250 repeating. Lengths past a single 1024-byte chunk are what
// exercise BLAKE3's tree, which is where an implementation is most likely
// to be wrong.
func vectorInput(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// vectorKeyArray is vectorKey as the fixed-size array the keyed functions
// take. The upstream key is exactly KeyLen bytes, which this asserts.
func vectorKeyArray(t *testing.T) [KeyLen]byte {
	t.Helper()
	if len(vectorKey) != KeyLen {
		t.Fatalf("upstream key is %d bytes, want %d", len(vectorKey), KeyLen)
	}
	return [KeyLen]byte([]byte(vectorKey))
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test vector %q: %v", s, err)
	}
	return b
}

func TestSumMatchesOfficialVectors(t *testing.T) {
	for _, c := range vectorCases {
		t.Run(name(c.inputLen), func(t *testing.T) {
			in := vectorInput(c.inputLen)
			want := mustDecodeHex(t, c.hash)

			if got := Sum256(in); !bytes.Equal(got[:], want[:Size256]) {
				t.Errorf("Sum256 = %x, want %x", got, want[:Size256])
			}
			if got := Sum512(in); !bytes.Equal(got[:], want[:Size512]) {
				t.Errorf("Sum512 = %x, want %x", got, want[:Size512])
			}
		})
	}
}

func TestSumKeyedMatchesOfficialVectors(t *testing.T) {
	key := vectorKeyArray(t)
	for _, c := range vectorCases {
		t.Run(name(c.inputLen), func(t *testing.T) {
			in := vectorInput(c.inputLen)
			want := mustDecodeHex(t, c.keyedHash)

			if got := SumKeyed256(key, in); !bytes.Equal(got[:], want[:Size256]) {
				t.Errorf("SumKeyed256 = %x, want %x", got, want[:Size256])
			}
			if got := SumKeyed512(key, in); !bytes.Equal(got[:], want[:Size512]) {
				t.Errorf("SumKeyed512 = %x, want %x", got, want[:Size512])
			}
		})
	}
}

func TestEveryLengthIsAPrefixOfTheSameStream(t *testing.T) {
	// BLAKE3's distinguishing property against BLAKE2b, where the output
	// length is mixed into the initial state and shorter digests are
	// different functions.
	in := vectorInput(2049)

	s256, s512 := Sum256(in), Sum512(in)
	if !bytes.Equal(s256[:], s512[:Size256]) {
		t.Error("Sum256 is not the first 32 bytes of Sum512")
	}

	h, err := New(200)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	h.Write(in)
	long := h.Sum(nil)
	if !bytes.Equal(s512[:], long[:Size512]) {
		t.Error("Sum512 is not the first 64 bytes of a 200-byte digest")
	}
}

func TestStreamingAgreesWithOneShot(t *testing.T) {
	// Written across the 1024-byte chunk boundary in awkward pieces, so
	// the buffering has to reassemble chunks itself.
	in := vectorInput(3072)

	h := New256()
	if h.Size() != Size256 {
		t.Errorf("Size() = %d, want %d", h.Size(), Size256)
	}
	if h.BlockSize() != BlockSize {
		t.Errorf("BlockSize() = %d, want %d", h.BlockSize(), BlockSize)
	}
	for _, n := range []int{1, 1022, 3, 1000, 46, 1000} {
		h.Write(in[:n])
		in = in[n:]
	}
	if len(in) != 0 {
		t.Fatalf("test bug: %d bytes left unwritten", len(in))
	}
	if got, want := h.Sum(nil), Sum256(vectorInput(3072)); !bytes.Equal(got, want[:]) {
		t.Errorf("streaming = %x, one-shot = %x", got, want)
	}
}

func TestStreamingResetKeepsTheKey(t *testing.T) {
	key := vectorKeyArray(t)
	in := vectorInput(1025)

	h := NewKeyed256(key)
	h.Write([]byte("something else entirely"))
	h.Reset()
	h.Write(in)

	if got, want := h.Sum(nil), SumKeyed256(key, in); !bytes.Equal(got, want[:]) {
		t.Errorf("after Reset = %x, want %x", got, want)
	}
	// And specifically did not fall back to unkeyed.
	if unkeyed := Sum256(in); bytes.Equal(h.Sum(nil)[:Size256], unkeyed[:]) {
		t.Error("Reset dropped the key")
	}
}

func TestKeyedIsDomainSeparatedFromUnkeyed(t *testing.T) {
	key := vectorKeyArray(t)
	in := vectorInput(64)
	if a, b := SumKeyed256(key, in), Sum256(in); a == b {
		t.Error("keyed and unkeyed modes produced the same digest")
	}

	other := key
	other[0] ^= 0x01
	if a, b := SumKeyed256(key, in), SumKeyed256(other, in); a == b {
		t.Error("two different keys produced the same MAC")
	}
}

func TestNewRejectsSizeBelowOne(t *testing.T) {
	key := vectorKeyArray(t)
	for _, size := range []int{0, -1} {
		if _, err := New(size); !errors.Is(err, ErrInvalidSize) {
			t.Errorf("New(%d) error = %v, want ErrInvalidSize", size, err)
		}
		if _, err := NewKeyed(size, key); !errors.Is(err, ErrInvalidSize) {
			t.Errorf("NewKeyed(%d) error = %v, want ErrInvalidSize", size, err)
		}
	}
	// There is no upper bound — the output is a stream.
	if _, err := New(1 << 20); err != nil {
		t.Errorf("New(1<<20) failed: %v", err)
	}
}

// name labels a subtest by input length, calling out the ones that sit on
// BLAKE3's chunk boundary — where the tree gains a level and an
// implementation is most likely to go wrong.
func name(n int) string {
	if n > 0 && n%ChunkSize == 0 {
		return "len" + strconv.Itoa(n) + "_chunkBoundary"
	}
	return "len" + strconv.Itoa(n)
}
