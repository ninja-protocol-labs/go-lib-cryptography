package secp256k1

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicKeyFromBytesRoundTrip(t *testing.T) {
	for range 100 {
		k, _ := randKeyPair(t)
		pub := k.PublicKey()

		c := pub.Bytes()
		fromC, err := PublicKeyFromBytes(c[:])
		require.NoError(t, err)
		assert.True(t, pub.Equal(fromC))

		// The uncompressed form must parse back to the same stored point.
		u := pub.BytesUncompressed()
		fromU, err := PublicKeyFromBytes(u[:])
		require.NoError(t, err)
		assert.True(t, pub.Equal(fromU))
	}
}

func TestPublicKeyFromBytesRejectsInvalid(t *testing.T) {
	k, _ := randKeyPair(t)
	valid := k.PublicKey().Bytes()

	badPrefix := valid
	badPrefix[0] = 0x01

	// x = 5 has no matching y: 5³+7 = 132 is a quadratic non-residue mod p,
	// and it is the smallest x for which that holds.
	notOnCurve := mustHex(t,
		"02"+"0000000000000000000000000000000000000000000000000000000000000005")

	tests := []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", make([]byte, PubkeyCompressedLen-1)},
		{"between the two lengths", make([]byte, PubkeyCompressedLen+1)},
		{"long", make([]byte, PubkeyUncompressedLen+1)},
		{"all zero", make([]byte, PubkeyCompressedLen)},
		{"all 0xff", bytes.Repeat([]byte{0xff}, PubkeyCompressedLen)},
		{"invalid prefix", badPrefix[:]},
		{"not on the curve", notOnCurve},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PublicKeyFromBytes(tt.in)
			assert.ErrorIs(t, err, ErrInvalidPublicKey)
		})
	}
}

// Hybrid (0x06/0x07) carries Y and its parity; a mismatch must be rejected.
func TestPublicKeyHybridEncoding(t *testing.T) {
	k, _ := randKeyPair(t)
	u := k.PublicKey().BytesUncompressed()

	odd := u[PubkeyUncompressedLen-1]&1 == 1
	good, bad := byte(0x06), byte(0x07)
	if odd {
		good, bad = 0x07, 0x06
	}

	h := u
	h[0] = good
	got, err := PublicKeyFromBytes(h[:])
	require.NoError(t, err, "matching hybrid prefix rejected")
	assert.True(t, got.Equal(k.PublicKey()))

	h[0] = bad
	_, err = PublicKeyFromBytes(h[:])
	assert.ErrorIs(t, err, ErrInvalidPublicKey, "mismatched hybrid parity accepted")
}

func TestPublicKeyEqual(t *testing.T) {
	a, _ := randKeyPair(t)
	b, _ := randKeyPair(t)

	assert.True(t, a.PublicKey().Equal(a.PublicKey()))
	assert.False(t, a.PublicKey().Equal(b.PublicKey()))
	assert.False(t, a.PublicKey().Equal(nil))
}

func TestPublicKeyIsZero(t *testing.T) {
	var uninit PublicKey
	var nilKey *PublicKey

	k, _ := randKeyPair(t)

	assert.True(t, uninit.IsZero())
	assert.True(t, nilKey.IsZero())
	assert.False(t, k.PublicKey().IsZero())
}

func TestPublicKeyString(t *testing.T) {
	k, err := PrivateKeyFromBytes(scalarN(t, 1))
	require.NoError(t, err)

	b := k.PublicKey().Bytes()
	assert.Equal(t, hex.EncodeToString(b[:]), k.PublicKey().String())
}
