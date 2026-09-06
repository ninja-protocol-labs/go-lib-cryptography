package blake3

import (
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestHashMatchesOfficialVectors(t *testing.T) {
	for _, c := range vectorCases {
		t.Run(name(c.inputLen), func(t *testing.T) {
			in := vectorInput(c.inputLen)
			want := mustDecodeHex(t, c.hash)

			got256 := Hash256(in).Bytes()
			assert.Equal(t, want[:Size256], got256[:])

			got512 := Hash512(in).Bytes()
			assert.Equal(t, want[:Size512], got512[:])
		})
	}
}

func TestHashKeyedMatchesOfficialVectors(t *testing.T) {
	key := vectorKeyArray(t)
	for _, c := range vectorCases {
		t.Run(name(c.inputLen), func(t *testing.T) {
			in := vectorInput(c.inputLen)
			want := mustDecodeHex(t, c.keyedHash)

			got256 := HashKeyed256(key, in).Bytes()
			assert.Equal(t, want[:Size256], got256[:])

			got512 := HashKeyed512(key, in).Bytes()
			assert.Equal(t, want[:Size512], got512[:])
		})
	}
}

func TestEveryLengthIsAPrefixOfTheSameStream(t *testing.T) {
	// BLAKE3's distinguishing property against BLAKE2b, where the output
	// length is mixed into the initial state and shorter digests are
	// different functions.
	in := vectorInput(2049)

	s256, s512 := Hash256(in).Bytes(), Hash512(in).Bytes()
	assert.Equal(t, s512[:Size256], s256[:], "Hash256 is not the first 32 bytes of Hash512")

	h, err := New(200)
	require.NoError(t, err)
	_, err = h.Write(in)
	require.NoError(t, err)

	long := h.Sum(nil)
	assert.Equal(t, long[:Size512], s512[:], "Hash512 is not the first 64 bytes of a 200-byte digest")
}

func TestStreamingAgreesWithOneShot(t *testing.T) {
	// Written across the 1024-byte chunk boundary in awkward pieces, so
	// the buffering has to reassemble chunks itself.
	in := vectorInput(3072)

	h := New256()
	assert.Equal(t, Size256, h.Size())
	assert.Equal(t, BlockSize, h.BlockSize())

	for _, n := range []int{1, 1022, 3, 1000, 46, 1000} {
		_, err := h.Write(in[:n])
		require.NoError(t, err)
		in = in[n:]
	}
	require.Empty(t, in, "test bug: bytes left unwritten")

	want := Hash256(vectorInput(3072)).Bytes()
	assert.Equal(t, want[:], h.Sum(nil))
}

func TestStreamingResetKeepsTheKey(t *testing.T) {
	key := vectorKeyArray(t)
	in := vectorInput(1025)

	h := NewKeyed256(key)
	_, err := h.Write([]byte("something else entirely"))
	require.NoError(t, err)
	h.Reset()
	_, err = h.Write(in)
	require.NoError(t, err)

	want := HashKeyed256(key, in).Bytes()
	assert.Equal(t, want[:], h.Sum(nil))

	// And specifically did not fall back to unkeyed.
	unkeyed := Hash256(in).Bytes()
	assert.NotEqual(t, unkeyed[:], h.Sum(nil)[:Size256], "Reset dropped the key")
}

func TestKeyedIsDomainSeparatedFromUnkeyed(t *testing.T) {
	key := vectorKeyArray(t)
	in := vectorInput(64)
	assert.False(t, HashKeyed256(key, in).Equal(Hash256(in)),
		"keyed and unkeyed modes produced the same digest")

	other := key
	other[0] ^= 0x01
	assert.False(t, HashKeyed256(key, in).Equal(HashKeyed256(other, in)),
		"two different keys produced the same MAC")
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
	if _, err := NewKeyed(1<<20, key); err != nil {
		t.Errorf("NewKeyed(1<<20) failed: %v", err)
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

// The 512-bit streaming constructors, which the one-shot vectors above do
// not reach. Every length is a prefix of the same stream, so each must
// agree with its one-shot counterpart.
func TestStreaming512AgreesWithOneShot(t *testing.T) {
	key := vectorKeyArray(t)
	in := vectorInput(1025)

	h := New512()
	_, err := h.Write(in)
	require.NoError(t, err)
	want := Hash512(in).Bytes()
	assert.Equal(t, want[:], h.Sum(nil))

	hk := NewKeyed512(key)
	_, err = hk.Write(in)
	require.NoError(t, err)
	wantK := HashKeyed512(key, in).Bytes()
	assert.Equal(t, wantK[:], hk.Sum(nil))
}
