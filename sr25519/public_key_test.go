package sr25519

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicKeyRoundTrip(t *testing.T) {
	for range 50 {
		pub := randKey(t).PublicKey()

		b := pub.Bytes()
		same, err := PublicKeyFromBytes(b[:])
		require.NoError(t, err)
		assert.True(t, pub.Equal(same))
	}
}

func TestPublicKeyFromBytesRejectsInvalid(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", make([]byte, PubkeyLen-1)},
		{"long", make([]byte, PubkeyLen+1)},
		// Unlike ed25519 this really is decoded: a Ristretto point has a
		// canonical encoding and these are not one.
		{"all 0xff", bytes.Repeat([]byte{0xff}, PubkeyLen)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PublicKeyFromBytes(tt.in)
			assert.ErrorIs(t, err, ErrInvalidPublicKey)
		})
	}
}

func TestPublicKeyEqualAndIsZero(t *testing.T) {
	var uninit PublicKey
	var nilKey *PublicKey

	a := aliceKey(t).PublicKey()
	b := randKey(t).PublicKey()

	assert.True(t, a.Equal(a))
	assert.False(t, a.Equal(b))
	assert.False(t, a.Equal(nil))

	assert.True(t, uninit.IsZero())
	assert.True(t, nilKey.IsZero())
	assert.False(t, a.IsZero())
}

func TestPublicKeyString(t *testing.T) {
	pub := aliceKey(t).PublicKey()

	b := pub.Bytes()
	assert.Equal(t, hex.EncodeToString(b[:]), pub.String())
	assert.Equal(t, alicePubkey, pub.String())
}
