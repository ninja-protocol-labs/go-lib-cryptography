package md5

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
