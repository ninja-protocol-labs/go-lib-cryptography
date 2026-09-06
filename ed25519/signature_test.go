package ed25519

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignatureRoundTrip(t *testing.T) {
	for range 20 {
		sig := Sign(randKey(t), testMsg)

		b := sig.Bytes()
		same, err := SignatureFromBytes(b[:])
		require.NoError(t, err)
		assert.True(t, sig.Equal(same))
	}
}

func TestSignatureFromBytesRejectsBadLength(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", make([]byte, SignatureLen-1)},
		{"long", make([]byte, SignatureLen+1)},
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

	a := Sign(keyN(t, 1), testMsg)
	b := Sign(keyN(t, 2), testMsg)

	assert.True(t, a.Equal(a))
	assert.False(t, a.Equal(b))
	assert.False(t, a.Equal(nil))

	assert.True(t, uninit.IsZero())
	assert.True(t, nilSig.IsZero())
	assert.False(t, a.IsZero())
}

func TestSignatureString(t *testing.T) {
	sig := Sign(keyN(t, 1), testMsg)

	b := sig.Bytes()
	assert.Equal(t, hex.EncodeToString(b[:]), sig.String())
}
