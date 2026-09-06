package ed448

import (
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

func TestPrivateKeyRoundTrip(t *testing.T) {
	for range 50 {
		k := randKey(t)

		b := k.Bytes()
		same, err := PrivateKeyFromBytes(b[:])
		require.NoError(t, err)

		assert.True(t, k.Equal(same))
		assert.True(t, k.PublicKey().Equal(same.PublicKey()))
	}
}

// Every 32 bytes is a valid seed, so only the length can be wrong.
func TestPrivateKeyFromBytesRejectsBadLength(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", make([]byte, SeckeyLen-1)},
		{"long", make([]byte, SeckeyLen+1)},
		{"the expanded length", make([]byte, 2*SeckeyLen)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PrivateKeyFromBytes(tt.in)
			assert.ErrorIs(t, err, ErrInvalidPrivateKey)
		})
	}
}

// The all-zero seed is a valid key here, unlike the curve packages where
// zero is out of range.
func TestZeroSeedIsAValidKey(t *testing.T) {
	k, err := PrivateKeyFromBytes(make([]byte, SeckeyLen))
	require.NoError(t, err)

	assert.False(t, k.PublicKey().IsZero())
	assert.True(t, Verify(k.PublicKey(), testMsg, nil, signOK(t, k, testMsg)))
}

func TestPrivateKeyEqualAndIsZero(t *testing.T) {
	var uninit PrivateKey
	var nilKey *PrivateKey

	a := keyN(t, 1)
	b := keyN(t, 2)

	assert.True(t, a.Equal(keyN(t, 1)))
	assert.False(t, a.Equal(b))
	assert.False(t, a.Equal(nil))

	assert.True(t, uninit.IsZero())
	assert.True(t, nilKey.IsZero())
	assert.False(t, a.IsZero())
}

// Bytes returns a copy; mutating it must not reach the key.
func TestPrivateKeyBytesIsACopy(t *testing.T) {
	k := keyN(t, 3)
	want := k.Bytes()

	got := k.Bytes()
	got[0] ^= 0xff

	assert.Equal(t, want, k.Bytes())
}

// GeneratePrivateKey caches the public key the generator handed back
// rather than expanding the seed again, so the two paths must agree.
func TestGenerateAgreesWithSeedExpansion(t *testing.T) {
	for range 50 {
		k, err := GeneratePrivateKey()
		require.NoError(t, err)

		seed := k.Bytes()
		fromSeed, err := PrivateKeyFromBytes(seed[:])
		require.NoError(t, err)

		assert.True(t, k.PublicKey().Equal(fromSeed.PublicKey()))
	}
}
