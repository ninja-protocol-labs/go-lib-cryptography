package bls12381edwards

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSignature(t *testing.T) *Signature {
	t.Helper()

	sig, err := Sign(randKey(t), []byte("signature under test"), testHash())
	require.NoError(t, err)
	return sig
}

func TestSignatureRoundTrip(t *testing.T) {
	for range 20 {
		sig := testSignature(t)

		b := sig.Bytes()
		same, err := SignatureFromBytes(b[:])
		require.NoError(t, err)
		assert.True(t, sig.Equal(same))
	}
}

func TestSignatureFromBytesRejectsInvalid(t *testing.T) {
	b := testSignature(t).Bytes()

	for _, tt := range []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", b[:SignatureLen-1]},
		{"long", append(b[:], 0)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SignatureFromBytes(tt.in)
			assert.ErrorIs(t, err, ErrInvalidSignature)
		})
	}
}

func TestSignatureEqualAndIsZero(t *testing.T) {
	var uninit Signature
	var nilSig *Signature

	a := testSignature(t)
	b := testSignature(t)

	assert.True(t, a.Equal(a))
	assert.False(t, a.Equal(b))
	assert.False(t, a.Equal(nil))

	assert.True(t, uninit.IsZero())
	assert.True(t, nilSig.IsZero())
	assert.False(t, a.IsZero())
}

func TestSignatureString(t *testing.T) {
	sig := testSignature(t)

	b := sig.Bytes()
	assert.Equal(t, hex.EncodeToString(b[:]), sig.String())
}
