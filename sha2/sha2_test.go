package sha2

import (
	"bytes"
	"hash"
	"testing"
)

// digest describes one member of the family, so that the known-answer,
// streaming-agreement and length checks can be written once instead of
// six times. sum boxes each SumN's differently-sized array into a slice.
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
		{"SHA-224", Size224, BlockSize256, func(b []byte) []byte { d := Sum224(b); return d[:] }, New224, abcSHA224},
		{"SHA-256", Size256, BlockSize256, func(b []byte) []byte { d := Sum256(b); return d[:] }, New256, abcSHA256},
		{"SHA-384", Size384, BlockSize512, func(b []byte) []byte { d := Sum384(b); return d[:] }, New384, abcSHA384},
		{"SHA-512", Size512, BlockSize512, func(b []byte) []byte { d := Sum512(b); return d[:] }, New512, abcSHA512},
		{"SHA-512/224", Size512_224, BlockSize512, func(b []byte) []byte { d := Sum512_224(b); return d[:] }, New512_224, abcSHA512_224},
		{"SHA-512/256", Size512_256, BlockSize512, func(b []byte) []byte { d := Sum512_256(b); return d[:] }, New512_256, abcSHA512_256},
	}
}

func TestSumMatchesKnownAnswer(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			want := mustDecodeHex(t, d.want)
			if got := d.sum(testMsg); !bytes.Equal(got, want) {
				t.Errorf("Sum(%q) = %x, want %x", testMsg, got, want)
			}
		})
	}
}

func TestSumLengthMatchesItsSizeConstant(t *testing.T) {
	// Guards the wiring: a SumN returning the wrong function's digest
	// would usually show up as the wrong length before anything else.
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			if got := len(d.sum(testMsg)); got != d.size {
				t.Errorf("digest length = %d, want %d", got, d.size)
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
			// Written in two pieces, to exercise the buffering rather
			// than just the one-block path.
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

func TestSumOfEmptyInput(t *testing.T) {
	// Nothing but padding — the path a table of non-empty vectors misses.
	want := mustDecodeHex(t, emptySHA256)
	if got := Sum256(nil); !bytes.Equal(got[:], want) {
		t.Errorf("Sum256(nil) = %x, want %x", got, want)
	}
	if Sum256(nil) != Sum256([]byte{}) {
		t.Error("Sum256(nil) != Sum256(empty slice)")
	}
}

func TestDigestsAreDistinct(t *testing.T) {
	// SHA-224 and SHA-512/224 share a length, as do SHA-256 and
	// SHA-512/256 — they are still different functions, and swapping the
	// two in the wiring would not change any length.
	if a, b := Sum224(testMsg), Sum512_224(testMsg); a == b {
		t.Error("SHA-224 and SHA-512/224 produced the same digest")
	}
	if a, b := Sum256(testMsg), Sum512_256(testMsg); a == b {
		t.Error("SHA-256 and SHA-512/256 produced the same digest")
	}
}

func TestBlockSizes(t *testing.T) {
	for _, d := range digests() {
		if got := d.new().BlockSize(); got != d.block {
			t.Errorf("%s BlockSize() = %d, want %d", d.name, got, d.block)
		}
	}
}
