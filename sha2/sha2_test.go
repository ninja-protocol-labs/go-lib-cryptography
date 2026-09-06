package sha2

import (
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// digest describes one member of the family, so that the known-answer,
// streaming-agreement and length checks can be written once instead of
// six times. sum boxes each HashN's own Digest type into a slice, which is
// the only thing they have in common now that each has its own type.
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
		{"SHA-224", Size224, BlockSize256, func(b []byte) []byte { d := Hash224(b).Bytes(); return d[:] }, New224, abcSHA224},
		{"SHA-256", Size256, BlockSize256, func(b []byte) []byte { d := Hash256(b).Bytes(); return d[:] }, New256, abcSHA256},
		{"SHA-384", Size384, BlockSize512, func(b []byte) []byte { d := Hash384(b).Bytes(); return d[:] }, New384, abcSHA384},
		{"SHA-512", Size512, BlockSize512, func(b []byte) []byte { d := Hash512(b).Bytes(); return d[:] }, New512, abcSHA512},
		{"SHA-512/224", Size512_224, BlockSize512, func(b []byte) []byte { d := Hash512_224(b).Bytes(); return d[:] }, New512_224, abcSHA512_224},
		{"SHA-512/256", Size512_256, BlockSize512, func(b []byte) []byte { d := Hash512_256(b).Bytes(); return d[:] }, New512_256, abcSHA512_256},
	}
}

func TestHashMatchesKnownAnswer(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			assert.Equal(t, mustDecodeHex(t, d.want), d.sum(testMsg))
		})
	}
}

// Guards the wiring: a HashN returning the wrong function's digest would
// usually show up as the wrong length before anything else.
func TestDigestLengthMatchesItsSizeConstant(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			assert.Len(t, d.sum(testMsg), d.size)
		})
	}
}

func TestStreamingAgreesWithOneShot(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			h := d.new()
			assert.Equal(t, d.size, h.Size())

			for _, b := range testMsg {
				_, err := h.Write([]byte{b})
				require.NoError(t, err)
			}
			assert.Equal(t, d.sum(testMsg), h.Sum(nil))
		})
	}
}

func TestBlockSizes(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			assert.Equal(t, d.block, d.new().BlockSize())
		})
	}
}

// Nothing but padding — the path a table of non-empty vectors misses.
func TestHashOfEmptyInput(t *testing.T) {
	got := Hash256(nil).Bytes()
	assert.Equal(t, mustDecodeHex(t, emptySHA256), got[:])
	assert.True(t, Hash256(nil).Equal(Hash256([]byte{})))
}

// SHA-224 and SHA-512/224 share a length, as do SHA-256 and SHA-512/256.
// They are still different functions, and swapping the two in the wiring
// would not change any length. Each having its own type means the mix-up
// now fails to compile as well, which is why this compares bytes.
func TestDigestsAreDistinct(t *testing.T) {
	a, b := Hash224(testMsg).Bytes(), Hash512_224(testMsg).Bytes()
	assert.NotEqual(t, a[:], b[:])

	c, d := Hash256(testMsg).Bytes(), Hash512_256(testMsg).Bytes()
	assert.NotEqual(t, c[:], d[:])
}
