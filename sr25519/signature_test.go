package sr25519

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignatureRoundTrip(t *testing.T) {
	for range 20 {
		sig := signOK(t, randKey(t))

		b := sig.Bytes()
		same, err := SignatureFromBytes(b[:])
		require.NoError(t, err)
		assert.True(t, sig.Equal(same))
	}
}

func TestSignatureFromBytesRejectsInvalid(t *testing.T) {
	b := signOK(t, aliceKey(t)).Bytes()

	// schnorrkel marks its signatures with the high bit; clearing it
	// leaves an Ed25519-shaped signature this package must not accept.
	unmarked := b
	unmarked[SignatureLen-1] &= 0x7f

	for _, tt := range []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", b[:SignatureLen-1]},
		{"long", append(b[:], 0)},
		{"all zero", make([]byte, SignatureLen)},
		{"all 0xff", bytes.Repeat([]byte{0xff}, SignatureLen)},
		{"schnorrkel marker cleared", unmarked[:]},
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

	a := signOK(t, aliceKey(t))
	b := signOK(t, randKey(t))

	assert.True(t, a.Equal(a))
	assert.False(t, a.Equal(b))
	assert.False(t, a.Equal(nil))

	assert.True(t, uninit.IsZero())
	assert.True(t, nilSig.IsZero())
	assert.False(t, a.IsZero())
}

func TestSignatureString(t *testing.T) {
	sig := signOK(t, aliceKey(t))

	b := sig.Bytes()
	assert.Equal(t, hex.EncodeToString(b[:]), sig.String())
}
