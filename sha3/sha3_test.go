package sha3

import (
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		{"SHA3-224", Size224, BlockSize224, func(b []byte) []byte { d := Hash224(b).Bytes(); return d[:] }, New224, abcSHA3_224},
		{"SHA3-256", Size256, BlockSize256, func(b []byte) []byte { d := Hash256(b).Bytes(); return d[:] }, New256, abcSHA3_256},
		{"SHA3-384", Size384, BlockSize384, func(b []byte) []byte { d := Hash384(b).Bytes(); return d[:] }, New384, abcSHA3_384},
		{"SHA3-512", Size512, BlockSize512, func(b []byte) []byte { d := Hash512(b).Bytes(); return d[:] }, New512, abcSHA3_512},
	}
}

func TestHashMatchesKnownAnswer(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			want := mustDecodeHex(t, d.want)
			require.Len(t, want, d.size, "bad vector")

			assert.Equal(t, want, d.sum(testMsg))
		})
	}
}

func TestStreamingAgreesWithOneShot(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			h := d.new()
			assert.Equal(t, d.size, h.Size())
			assert.Equal(t, d.block, h.BlockSize())

			_, err := h.Write(testMsg[:1])
			require.NoError(t, err)
			_, err = h.Write(testMsg[1:])
			require.NoError(t, err)

			assert.Equal(t, d.sum(testMsg), h.Sum(nil))
		})
	}
}

func TestStreamingResetIsReusable(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			h := d.new()
			_, err := h.Write([]byte("something else entirely"))
			require.NoError(t, err)
			h.Reset()
			_, err = h.Write(testMsg)
			require.NoError(t, err)

			assert.Equal(t, d.sum(testMsg), h.Sum(nil))
		})
	}
}

func TestSHA3IsNotSHA2(t *testing.T) {
	// Same name, same digest length, unrelated function. A caller that
	// swapped sha2 for sha3 (or the reverse) would get no type error and
	// no length error — only this.
	got := Hash256(testMsg).Bytes()
	assert.NotEqual(t, mustDecodeHex(t, abcSHA2_256), got[:])
}

func TestRateAndCapacitySumToTheState(t *testing.T) {
	// The sponge splits its 200-byte state into a rate it exposes and a
	// capacity it never does, with the capacity fixed at twice the digest
	// length. That is why a longer SHA-3 digest means a smaller block and
	// a slower hash — the opposite of SHA-2, where the block is constant.
	for _, d := range digests() {
		assert.Equal(t, stateSize, d.block+2*d.size, d.name)
	}
}
