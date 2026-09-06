package keccak

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every digest length is its own type, so these run the same checks
// against each of them rather than only the 256-bit one.
func TestDigest(t *testing.T) {
	t.Run("Keccak-256", func(t *testing.T) { checkDigest256(t, testMsg, abcKeccak256) })
	t.Run("Keccak-512", func(t *testing.T) { checkDigest512(t, testMsg, abcKeccak512) })
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
