package secp256k1

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

func TestPrivateKeyFromBytesRoundTrip(t *testing.T) {
	for range 100 {
		k, b := randKeyPair(t)

		got := k.Bytes()
		assert.Equal(t, b, got[:])

		same, err := PrivateKeyFromBytes(got[:])
		require.NoError(t, err)
		assert.True(t, k.Equal(same))
		assert.True(t, k.PublicKey().Equal(same.PublicKey()))
	}
}

func TestPrivateKeyFromBytesRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", make([]byte, SeckeyLen-1)},
		{"long", make([]byte, SeckeyLen+1)},
		{"zero", make([]byte, SeckeyLen)},
		{"curve order", mustHex(t, curveOrder)},
		{"all 0xff", bytes.Repeat([]byte{0xff}, SeckeyLen)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PrivateKeyFromBytes(tt.in)
			assert.ErrorIs(t, err, ErrInvalidPrivateKey)
		})
	}
}

// n-1 is the largest valid scalar; the check must be >= n, not > n.
func TestPrivateKeyAcceptsOrderMinusOne(t *testing.T) {
	b := mustHex(t, curveOrder)
	b[SeckeyLen-1]--

	k, err := PrivateKeyFromBytes(b)
	require.NoError(t, err)
	assert.False(t, k.IsZero())
}

func TestPrivateKeyEqual(t *testing.T) {
	a, _ := randKeyPair(t)
	b, _ := randKeyPair(t)

	ab := a.Bytes()
	same, err := PrivateKeyFromBytes(ab[:])
	require.NoError(t, err)

	assert.True(t, a.Equal(same))
	assert.False(t, a.Equal(b))
	assert.False(t, a.Equal(nil))
}

func TestPrivateKeyIsZero(t *testing.T) {
	var uninit PrivateKey
	var nilKey *PrivateKey

	k, _ := randKeyPair(t)

	assert.True(t, uninit.IsZero())
	assert.True(t, nilKey.IsZero())
	assert.False(t, k.IsZero())
}

// Bytes returns a copy; mutating it must not reach the key.
func TestPrivateKeyBytesIsACopy(t *testing.T) {
	k, b := randKeyPair(t)

	got := k.Bytes()
	got[0] ^= 0xff

	after := k.Bytes()
	assert.Equal(t, b, after[:])
}
