package ed25519

import (
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

// This is a length check only — see the package doc.
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

// Bytes that are not a point on the curve still parse, because stdlib
// does not decompress a public key until a signature is checked against
// it. They simply verify nothing.
func TestPublicKeyAcceptsGarbageAndVerifiesNothing(t *testing.T) {
	garbage := make([]byte, PubkeyLen)
	for i := range garbage {
		garbage[i] = 0xff
	}

	pub, err := PublicKeyFromBytes(garbage)
	require.NoError(t, err)

	sig := Sign(keyN(t, 1), testMsg)
	assert.False(t, Verify(pub, testMsg, sig))
}

func TestPublicKeyEqualAndIsZero(t *testing.T) {
	var uninit PublicKey
	var nilKey *PublicKey

	a := keyN(t, 1).PublicKey()
	b := keyN(t, 2).PublicKey()

	assert.True(t, a.Equal(a))
	assert.False(t, a.Equal(b))
	assert.False(t, a.Equal(nil))

	assert.True(t, uninit.IsZero())
	assert.True(t, nilKey.IsZero())
	assert.False(t, a.IsZero())
}

func TestPublicKeyString(t *testing.T) {
	pub := keyN(t, 1).PublicKey()

	b := pub.Bytes()
	assert.Equal(t, hex.EncodeToString(b[:]), pub.String())
}
