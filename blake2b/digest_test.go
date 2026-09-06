package blake2b

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every digest length is its own type, so these run the same checks
// against each of them rather than only the 256-bit one.
func TestDigest(t *testing.T) {
	t.Run("BLAKE2b-256", func(t *testing.T) { checkDigest256(t, testMsg, abcBlake2b256) })
	t.Run("BLAKE2b-384", func(t *testing.T) { checkDigest384(t, testMsg, abcBlake2b384) })
	t.Run("BLAKE2b-512", func(t *testing.T) { checkDigest512(t, testMsg, abcBlake2b512) })
}

// badLengths is the set of inputs a DigestNNNFromBytes must reject at the
// given length. Every string of the right length is a valid digest, so
// length is the only thing there is to check.
func badLengths(size int) []struct {
	name string
	in   []byte
} {
	return []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", make([]byte, size-1)},
		{"long", make([]byte, size+1)},
	}
}

func checkDigest256(t *testing.T, data []byte, want string) {
	t.Helper()

	d := Hash256(data)
	b := d.Bytes()

	assert.Equal(t, want, d.String())
	assert.Equal(t, hex.EncodeToString(b[:]), d.String())
	assert.False(t, d.IsZero())

	same, err := Digest256FromBytes(b[:])
	require.NoError(t, err)
	assert.True(t, d.Equal(same))
	assert.False(t, d.Equal(nil))
	assert.False(t, d.Equal(Hash256(nil)))

	for _, tt := range badLengths(Size256) {
		_, err := Digest256FromBytes(tt.in)
		assert.ErrorIs(t, err, ErrInvalidDigest, tt.name)
	}

	// All zeroes is a valid digest, so it must parse; only IsZero flags it.
	zero, err := Digest256FromBytes(make([]byte, Size256))
	require.NoError(t, err)
	assert.True(t, zero.IsZero())

	var uninit Digest256
	var nilDigest *Digest256
	assert.True(t, uninit.IsZero())
	assert.True(t, nilDigest.IsZero())

	// Bytes returns a copy; mutating it must not reach the digest.
	b[0] ^= 0xff
	assert.Equal(t, want, d.String())
}

func checkDigest384(t *testing.T, data []byte, want string) {
	t.Helper()

	d := Hash384(data)
	b := d.Bytes()

	assert.Equal(t, want, d.String())
	assert.Equal(t, hex.EncodeToString(b[:]), d.String())
	assert.False(t, d.IsZero())

	same, err := Digest384FromBytes(b[:])
	require.NoError(t, err)
	assert.True(t, d.Equal(same))
	assert.False(t, d.Equal(nil))
	assert.False(t, d.Equal(Hash384(nil)))

	for _, tt := range badLengths(Size384) {
		_, err := Digest384FromBytes(tt.in)
		assert.ErrorIs(t, err, ErrInvalidDigest, tt.name)
	}

	// All zeroes is a valid digest, so it must parse; only IsZero flags it.
	zero, err := Digest384FromBytes(make([]byte, Size384))
	require.NoError(t, err)
	assert.True(t, zero.IsZero())

	var uninit Digest384
	var nilDigest *Digest384
	assert.True(t, uninit.IsZero())
	assert.True(t, nilDigest.IsZero())

	// Bytes returns a copy; mutating it must not reach the digest.
	b[0] ^= 0xff
	assert.Equal(t, want, d.String())
}

func checkDigest512(t *testing.T, data []byte, want string) {
	t.Helper()

	d := Hash512(data)
	b := d.Bytes()

	assert.Equal(t, want, d.String())
	assert.Equal(t, hex.EncodeToString(b[:]), d.String())
	assert.False(t, d.IsZero())

	same, err := Digest512FromBytes(b[:])
	require.NoError(t, err)
	assert.True(t, d.Equal(same))
	assert.False(t, d.Equal(nil))
	assert.False(t, d.Equal(Hash512(nil)))

	for _, tt := range badLengths(Size512) {
		_, err := Digest512FromBytes(tt.in)
		assert.ErrorIs(t, err, ErrInvalidDigest, tt.name)
	}

	// All zeroes is a valid digest, so it must parse; only IsZero flags it.
	zero, err := Digest512FromBytes(make([]byte, Size512))
	require.NoError(t, err)
	assert.True(t, zero.IsZero())

	var uninit Digest512
	var nilDigest *Digest512
	assert.True(t, uninit.IsZero())
	assert.True(t, nilDigest.IsZero())

	// Bytes returns a copy; mutating it must not reach the digest.
	b[0] ^= 0xff
	assert.Equal(t, want, d.String())
}
