package secp256r1

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

		c := pub.Bytes()
		fromC, err := PublicKeyFromBytes(c[:])
		require.NoError(t, err)
		assert.True(t, pub.Equal(fromC))

		u := pub.BytesUncompressed()
		fromU, err := PublicKeyFromBytes(u[:])
		require.NoError(t, err)
		assert.True(t, pub.Equal(fromU))
	}
}

func TestPublicKeyFromBytesRejectsInvalid(t *testing.T) {
	valid := randKey(t).PublicKey().Bytes()

	// x = 1 has no matching y on P-256, so this is a well-formed encoding
	// of a point that does not exist.
	notOnCurve := mustHex(t,
		"02"+"0000000000000000000000000000000000000000000000000000000000000001")

	badPrefix := valid
	badPrefix[0] = 0x01

	for _, tt := range []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", valid[:PubkeyCompressedLen-1]},
		{"between the two lengths", make([]byte, PubkeyCompressedLen+1)},
		{"long", make([]byte, PubkeyUncompressedLen+1)},
		{"all zero", make([]byte, PubkeyCompressedLen)},
		{"all 0xff", bytes.Repeat([]byte{0xff}, PubkeyCompressedLen)},
		{"invalid prefix", badPrefix[:]},
		{"not on the curve", notOnCurve},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PublicKeyFromBytes(tt.in)
			assert.ErrorIs(t, err, ErrInvalidPublicKey)
		})
	}
}

// The two encodings must describe the same point in both directions.
func TestCompressedAndUncompressedAgree(t *testing.T) {
	for range 20 {
		pub := randKey(t).PublicKey()

		u := pub.BytesUncompressed()
		assert.Equal(t, byte(0x04), u[0])

		back, err := PublicKeyFromBytes(u[:])
		require.NoError(t, err)
		assert.Equal(t, pub.Bytes(), back.Bytes())
	}
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
