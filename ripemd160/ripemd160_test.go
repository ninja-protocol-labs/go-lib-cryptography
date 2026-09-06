package ripemd160

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestHashMatchesKnownAnswers(t *testing.T) {
	for _, v := range vectors {
		t.Run(v.in, func(t *testing.T) {
			want := mustDecodeHex(t, v.want)
			require.Len(t, want, Size, "bad vector")

			got := Hash([]byte(v.in)).Bytes()
			assert.Equal(t, want, got[:])
		})
	}
}

// The suite's long case, and the only one here that exercises the block
// counter past a handful of iterations.
func TestHashOfAMillionAs(t *testing.T) {
	in := bytes.Repeat([]byte{'a'}, 1_000_000)

	got := Hash(in).Bytes()
	assert.Equal(t, mustDecodeHex(t, millionAs), got[:])
}

// Hash writes into b[:0], relying on append not reallocating when the
// capacity is exactly the digest length. If that stopped holding, the
// digest would come back all zero.
func TestHashDoesNotAliasOrOverrun(t *testing.T) {
	d := Hash([]byte("abc"))

	assert.False(t, d.IsZero())
	assert.True(t, d.Equal(Hash([]byte("abc"))))
}

func TestHashOfEmptyInput(t *testing.T) {
	got := Hash(nil).Bytes()
	assert.Equal(t, mustDecodeHex(t, vectors[0].want), got[:])
	assert.True(t, Hash(nil).Equal(Hash([]byte{})))
}

func TestStreamingAgreesWithOneShot(t *testing.T) {
	for _, v := range vectors {
		t.Run(v.in, func(t *testing.T) {
			h := New()
			assert.Equal(t, Size, h.Size())
			assert.Equal(t, BlockSize, h.BlockSize())

			// A byte at a time, so the buffering has to reassemble blocks.
			for i := range len(v.in) {
				_, err := h.Write([]byte{v.in[i]})
				require.NoError(t, err)
			}

			want := Hash([]byte(v.in)).Bytes()
			assert.Equal(t, want[:], h.Sum(nil))
		})
	}
}

func TestStreamingResetIsReusable(t *testing.T) {
	h := New()
	_, err := h.Write([]byte("something else entirely"))
	require.NoError(t, err)
	h.Reset()
	_, err = h.Write([]byte("abc"))
	require.NoError(t, err)

	want := Hash([]byte("abc")).Bytes()
	assert.Equal(t, want[:], h.Sum(nil))
}

// Guards against a wiring mistake that returns a constant: every vector
// must hash to something distinct.
func TestDigestsDifferAcrossInputs(t *testing.T) {
	seen := make(map[[Size]byte]string, len(vectors))
	for _, v := range vectors {
		d := Hash([]byte(v.in)).Bytes()
		prev, dup := seen[d]
		assert.False(t, dup, "%q and %q hash to the same digest", prev, v.in)
		seen[d] = v.in
	}
}
