package bls12377edwards

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePrivateKey(t *testing.T) {
	a, err := GeneratePrivateKey()
	require.NoError(t, err)
	b, err := GeneratePrivateKey()
	require.NoError(t, err)

	assert.False(t, a.Equal(b), "two generated keys are identical")
	assert.False(t, a.IsZero())
}

// The same seed must always give the same key; that is what PrivateKeyFromSeed
// is for, since Bytes does not round-trip through the seed.
func TestPrivateKeyFromSeedIsDeterministic(t *testing.T) {
	for range 20 {
		seed := randSeed(t)

		a, err := PrivateKeyFromSeed(seed)
		require.NoError(t, err)
		b, err := PrivateKeyFromSeed(seed)
		require.NoError(t, err)

		assert.True(t, a.Equal(b))
		assert.True(t, a.PublicKey().Equal(b.PublicKey()))
	}
}

// Bytes is the expanded form, not the seed, so a round trip goes through
// PrivateKeyFromBytes and not PrivateKeyFromSeed.
func TestPrivateKeyBytesRoundTrip(t *testing.T) {
	for range 20 {
		k := randKey(t)

		b := k.Bytes()
		same, err := PrivateKeyFromBytes(b[:])
		require.NoError(t, err)

		assert.True(t, k.Equal(same))
		assert.True(t, k.PublicKey().Equal(same.PublicKey()))
	}
}

func TestPrivateKeyFromSeedRejectsBadLength(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", make([]byte, SeedLen-1)},
		{"long", make([]byte, SeedLen+1)},
		{"the expanded length", make([]byte, SeckeyLen)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PrivateKeyFromSeed(tt.in)
			assert.ErrorIs(t, err, ErrInvalidPrivateKey)
		})
	}
}

func TestPrivateKeyFromBytesRejectsInvalid(t *testing.T) {
	k := randKey(t)
	valid := k.Bytes()

	// The serialization carries the public key alongside the scalar, so a
	// mismatched pair must be rejected rather than trusted.
	mismatched := valid
	mismatched[0] ^= 0xff

	for _, tt := range []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", valid[:SeckeyLen-1]},
		{"long", append(valid[:], 0)},
		{"the seed length", make([]byte, SeedLen)},
		{"all zero", make([]byte, SeckeyLen)},
		{"all 0xff", bytes.Repeat([]byte{0xff}, SeckeyLen)},
		{"public key does not match the scalar", mismatched[:]},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PrivateKeyFromBytes(tt.in)
			assert.ErrorIs(t, err, ErrInvalidPrivateKey)
		})
	}
}

func TestPrivateKeyEqualAndIsZero(t *testing.T) {
	var uninit PrivateKey
	var nilKey *PrivateKey

	a := randKey(t)
	b := randKey(t)

	assert.True(t, a.Equal(a))
	assert.False(t, a.Equal(b))
	assert.False(t, a.Equal(nil))

	assert.True(t, uninit.IsZero())
	assert.True(t, nilKey.IsZero())
	assert.False(t, a.IsZero())
}
