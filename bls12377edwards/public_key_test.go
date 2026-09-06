package bls12377edwards

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicKeyRoundTrip(t *testing.T) {
	for range 20 {
		pub := randKey(t).PublicKey()

		b := pub.Bytes()
		same, err := PublicKeyFromBytes(b[:])
		require.NoError(t, err)
		assert.True(t, pub.Equal(same))
	}
}

func TestPublicKeyFromBytesRejectsInvalid(t *testing.T) {
	valid := randKey(t).PublicKey().Bytes()

	// The identity is a point on the curve and in the subgroup, so only an
	// explicit check excludes it — and it must be excluded: it is the
	// public key of the zero scalar.
	identity := make([]byte, PubkeyLen)
	identity[PubkeyLen-1] = 0x01

	for _, tt := range []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", valid[:PubkeyLen-1]},
		{"long", append(valid[:], 0)},
		{"all 0xff", bytes.Repeat([]byte{0xff}, PubkeyLen)},
		{"identity", identity},
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

	a := randKey(t).PublicKey()
	b := randKey(t).PublicKey()

	assert.True(t, a.Equal(a))
	assert.False(t, a.Equal(b))
	assert.False(t, a.Equal(nil))

	assert.True(t, uninit.IsZero())
	assert.True(t, nilKey.IsZero())
	assert.False(t, a.IsZero())
}

func TestPublicKeyString(t *testing.T) {
	pub := randKey(t).PublicKey()

	b := pub.Bytes()
	assert.Equal(t, hex.EncodeToString(b[:]), pub.String())
}

// SetBytes reduces an out-of-range y rather than rejecting it, so without
// the re-encoding check two different byte strings would name one key.
func TestPublicKeyRejectsNonCanonicalEncoding(t *testing.T) {
	all := bytes.Repeat([]byte{0xff}, PubkeyLen)

	_, err := PublicKeyFromBytes(all)
	assert.ErrorIs(t, err, ErrInvalidPublicKey)

	// Whatever a caller hands in, a parsed key must re-encode to exactly
	// those bytes.
	for range 100 {
		in := randKey(t).PublicKey().Bytes()

		k, err := PublicKeyFromBytes(in[:])
		require.NoError(t, err)
		assert.Equal(t, in, k.Bytes())
	}
}
