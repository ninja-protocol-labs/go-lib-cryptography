package x25519

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

func TestPublicKeyFromBytesRejectsBadLength(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", make([]byte, PubkeyLen-1)},
		{"long", make([]byte, PubkeyLen+1)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PublicKeyFromBytes(tt.in)
			assert.ErrorIs(t, err, ErrInvalidPublicKey)
		})
	}
}

// Any 32 bytes parse: there is no on-curve test to fail. Small-order
// points are caught by ECDH instead, not here.
func TestPublicKeyAcceptsAnyLengthCorrectInput(t *testing.T) {
	for _, in := range [][]byte{
		make([]byte, PubkeyLen),
		bytes.Repeat([]byte{0xff}, PubkeyLen),
	} {
		_, err := PublicKeyFromBytes(in)
		assert.NoError(t, err)
	}
}

func TestPublicKeyEqualAndIsZero(t *testing.T) {
	var uninit PublicKey
	var nilKey *PublicKey

	a := keyFromHex(t, aliceSeckey).PublicKey()
	b := keyFromHex(t, bobSeckey).PublicKey()

	assert.True(t, a.Equal(a))
	assert.False(t, a.Equal(b))
	assert.False(t, a.Equal(nil))

	assert.True(t, uninit.IsZero())
	assert.True(t, nilKey.IsZero())
	assert.False(t, a.IsZero())
}

func TestPublicKeyString(t *testing.T) {
	pub := keyFromHex(t, aliceSeckey).PublicKey()

	b := pub.Bytes()
	assert.Equal(t, hex.EncodeToString(b[:]), pub.String())
	assert.Equal(t, alicePubkey, pub.String())
}
