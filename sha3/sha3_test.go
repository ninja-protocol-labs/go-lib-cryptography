package sha3

import (
	"bytes"
	"hash"
	"testing"
)

// digest describes one fixed-output member of the family, so that the
// known-answer, streaming-agreement and size checks can be written once.
type digest struct {
	name  string
	size  int
	block int
	sum   func([]byte) []byte
	new   func() hash.Hash
	want  string
}

func digests() []digest {
	return []digest{
		{"SHA3-224", Size224, BlockSize224, func(b []byte) []byte { d := Sum224(b); return d[:] }, New224, abcSHA3_224},
		{"SHA3-256", Size256, BlockSize256, func(b []byte) []byte { d := Sum256(b); return d[:] }, New256, abcSHA3_256},
		{"SHA3-384", Size384, BlockSize384, func(b []byte) []byte { d := Sum384(b); return d[:] }, New384, abcSHA3_384},
		{"SHA3-512", Size512, BlockSize512, func(b []byte) []byte { d := Sum512(b); return d[:] }, New512, abcSHA3_512},
	}
}

func TestSumMatchesKnownAnswer(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			want := mustDecodeHex(t, d.want)
			if got := d.sum(testMsg); !bytes.Equal(got, want) {
				t.Errorf("Sum(%q) = %x, want %x", testMsg, got, want)
			}
			if len(want) != d.size {
				t.Errorf("vector length = %d, want %d", len(want), d.size)
			}
		})
	}
}

func TestStreamingAgreesWithOneShot(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			h := d.new()
			if h.Size() != d.size {
				t.Errorf("New().Size() = %d, want %d", h.Size(), d.size)
			}
			if h.BlockSize() != d.block {
				t.Errorf("New().BlockSize() = %d, want %d", h.BlockSize(), d.block)
			}
			h.Write(testMsg[:1])
			h.Write(testMsg[1:])
			if got, want := h.Sum(nil), d.sum(testMsg); !bytes.Equal(got, want) {
				t.Errorf("streaming = %x, one-shot = %x", got, want)
			}
		})
	}
}

func TestStreamingResetIsReusable(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			h := d.new()
			h.Write([]byte("something else entirely"))
			h.Reset()
			h.Write(testMsg)
			if got, want := h.Sum(nil), d.sum(testMsg); !bytes.Equal(got, want) {
				t.Errorf("after Reset = %x, want %x", got, want)
			}
		})
	}
}

func TestSHA3IsNotSHA2(t *testing.T) {
	// Same name, same digest length, unrelated function. A caller that
	// swapped sha2 for sha3 (or the reverse) would get no type error and
	// no length error — only this.
	sha2 := mustDecodeHex(t, abcSHA2_256)
	got := Sum256(testMsg)
	if bytes.Equal(got[:], sha2) {
		t.Error("SHA3-256 produced SHA-256's digest")
	}
}

func TestRateAndCapacitySumToTheState(t *testing.T) {
	// The sponge splits its 200-byte state into a rate it exposes and a
	// capacity it never does, with the capacity fixed at twice the digest
	// length. That is why a longer SHA-3 digest means a smaller block and
	// a slower hash — the opposite of SHA-2, where the block is constant.
	for _, d := range digests() {
		if d.block+2*d.size != stateSize {
			t.Errorf("%s: rate %d + capacity %d != %d", d.name, d.block, 2*d.size, stateSize)
		}
	}
}
