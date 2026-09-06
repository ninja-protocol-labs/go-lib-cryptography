package secp256r1

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignatureRoundTrip(t *testing.T) {
	for range 50 {
		sig := signOK(t, randKey(t), randDigest(t))

		b := sig.Bytes()
		fromCompact, err := SignatureFromBytes(b[:])
		require.NoError(t, err)
		assert.True(t, sig.Equal(fromCompact))

		fromDER, err := SignatureFromDER(sig.DER())
		require.NoError(t, err)
		assert.True(t, sig.Equal(fromDER))
	}
}

func TestSignatureFromBytesRejectsInvalid(t *testing.T) {
	b := signOK(t, keyN(t, 1), randDigest(t)).Bytes()

	zeroR := make([]byte, SignatureCompactLen)
	copy(zeroR[SignatureScalarLen:], scalarN(t, 1))

	zeroS := make([]byte, SignatureCompactLen)
	copy(zeroS, scalarN(t, 1))

	for _, tt := range []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", b[:SignatureCompactLen-1]},
		{"long", append(b[:], 0)},
		{"all zero", make([]byte, SignatureCompactLen)},
		{"r is zero", zeroR},
		{"s is zero", zeroS},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SignatureFromBytes(tt.in)
			assert.ErrorIs(t, err, ErrInvalidSignature)
		})
	}
}

func TestSignatureFromDERRejectsInvalid(t *testing.T) {
	sig := signOK(t, keyN(t, 1), randDigest(t))
	der := sig.DER()
	compact := sig.Bytes()

	for _, tt := range []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"truncated", der[:len(der)-1]},
		{"trailing byte", append(append([]byte{}, der...), 0)},
		{"compact form", compact[:]},
		{"not a sequence", bytes.Repeat([]byte{0xff}, len(der))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SignatureFromDER(tt.in)
			assert.ErrorIs(t, err, ErrInvalidSignature)
		})
	}
}

// DER is what X.509 and TLS carry, so a signature must survive the trip
// through it and still verify.
func TestDERRoundTripVerifies(t *testing.T) {
	k := randKey(t)
	d := randDigest(t)

	sig := signOK(t, k, d)
	back, err := SignatureFromDER(sig.DER())
	require.NoError(t, err)

	assert.True(t, Verify(k.PublicKey(), d, back))
}

func TestSignatureEqualAndIsZero(t *testing.T) {
	var uninit Signature
	var nilSig *Signature

	d := randDigest(t)
	a := signOK(t, keyN(t, 1), d)
	b := signOK(t, keyN(t, 2), d)

	assert.True(t, a.Equal(a))
	assert.False(t, a.Equal(b))
	assert.False(t, a.Equal(nil))

	assert.True(t, uninit.IsZero())
	assert.True(t, nilSig.IsZero())
	assert.False(t, a.IsZero())
}

func TestSignatureString(t *testing.T) {
	sig := signOK(t, keyN(t, 1), randDigest(t))

	b := sig.Bytes()
	assert.Equal(t, hex.EncodeToString(b[:]), sig.String())
}
