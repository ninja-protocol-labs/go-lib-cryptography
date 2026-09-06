package keccak

import (
	"encoding/hex"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ninja-protocol-labs/go-lib-cryptography/sha3"
)

// testMsg is "abc", the input the sha2 and sha3 packages hash too, so the
// vectors here line up with theirs for comparison.
var testMsg = []byte("abc")

// Expected digests, produced with OpenSSL's KECCAK-256/KECCAK-512 rather
// than with the library being wrapped. emptyKeccak256 is the value
// Ethereum uses as the hash of empty code, so it is a vector anyone
// working on that side will recognize on sight.
const (
	abcKeccak256   = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
	abcKeccak512   = "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96"
	emptyKeccak256 = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	emptyKeccak512 = "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test vector %q: %v", s, err)
	}
	return b
}

type digest struct {
	name  string
	size  int
	block int
	sum   func([]byte) []byte
	new   func() hash.Hash
	abc   string
	empty string
}

func digests() []digest {
	return []digest{
		{"Keccak-256", Size256, BlockSize256, func(b []byte) []byte { d := Hash256(b).Bytes(); return d[:] }, New256, abcKeccak256, emptyKeccak256},
		{"Keccak-512", Size512, BlockSize512, func(b []byte) []byte { d := Hash512(b).Bytes(); return d[:] }, New512, abcKeccak512, emptyKeccak512},
	}
}

func TestHashMatchesKnownAnswer(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			want := mustDecodeHex(t, d.abc)
			require.Len(t, want, d.size, "bad vector")

			assert.Equal(t, want, d.sum(testMsg))
		})
	}
}

// Nothing but padding — and for Keccak-256 the single most recognized
// vector there is, since Ethereum stores it as the code hash of every
// account without code.
func TestHashOfEmptyInput(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			want := mustDecodeHex(t, d.empty)

			assert.Equal(t, want, d.sum(nil))
			assert.Equal(t, want, d.sum([]byte{}))
		})
	}
}

// Hash256 and Hash512 are this package's own, built on top of the
// streaming hash upstream provides — so unlike the other hash packages
// here, this is checking code we wrote, not just a re-export.
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

// Hash256 sums into b[:0], relying on append not reallocating when the
// capacity is exactly the digest length. If that ever stopped holding, the
// digest would come back all zero.
func TestHashDoesNotAliasOrOverrun(t *testing.T) {
	got := Hash256(testMsg)

	assert.False(t, got.IsZero())
	assert.True(t, got.Equal(Hash256(testMsg)))
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

// The whole reason this package exists. Same permutation, same rate, same
// digest length, one different padding byte — and so completely different
// output. Each package having its own Digest type now makes the mix-up a
// compile error too, which is why this compares bytes.
func TestKeccakIsNotSHA3(t *testing.T) {
	k, s := Hash256(testMsg).Bytes(), sha3.Hash256(testMsg).Bytes()
	assert.NotEqual(t, k[:], s[:])

	k512, s512 := Hash512(testMsg).Bytes(), sha3.Hash512(testMsg).Bytes()
	assert.NotEqual(t, k512[:], s512[:])
}

func TestRatesMatchSHA3(t *testing.T) {
	// The padding byte is the only difference between the two packages,
	// so the sponge parameters must be identical at matching lengths.
	assert.Equal(t, sha3.BlockSize256, BlockSize256)
	assert.Equal(t, sha3.BlockSize512, BlockSize512)
}
