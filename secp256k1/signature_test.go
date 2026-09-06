package secp256k1

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignatureFromBytesRoundTrip(t *testing.T) {
	for range 100 {
		sig, _, _ := testSignature(t)

		b := sig.Bytes()
		same, err := SignatureFromBytes(b[:])
		require.NoError(t, err)
		assert.True(t, sig.Equal(same))
	}
}

func TestSignatureFromDERRoundTrip(t *testing.T) {
	for range 100 {
		sig, _, _ := testSignature(t)

		same, err := SignatureFromDER(sig.DER())
		require.NoError(t, err)
		assert.True(t, sig.Equal(same))
	}
}

func TestSignatureFromBytesRejectsInvalid(t *testing.T) {
	order := mustHex(t, curveOrder)

	atOrder := make([]byte, SignatureCompactLen)
	copy(atOrder, order)
	copy(atOrder[SignatureScalarLen:], scalarN(t, 1))

	sAtOrder := make([]byte, SignatureCompactLen)
	copy(sAtOrder, scalarN(t, 1))
	copy(sAtOrder[SignatureScalarLen:], order)

	zeroR := make([]byte, SignatureCompactLen)
	copy(zeroR[SignatureScalarLen:], scalarN(t, 1))

	zeroS := make([]byte, SignatureCompactLen)
	copy(zeroS, scalarN(t, 1))

	tests := []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", make([]byte, SignatureCompactLen-1)},
		{"long", make([]byte, SignatureCompactLen+1)},
		{"all zero", make([]byte, SignatureCompactLen)},
		{"all 0xff", bytes.Repeat([]byte{0xff}, SignatureCompactLen)},
		{"r is zero", zeroR},
		{"s is zero", zeroS},
		{"r equals the order", atOrder},
		{"s equals the order", sAtOrder},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SignatureFromBytes(tt.in)
			assert.ErrorIs(t, err, ErrInvalidSignature)
		})
	}
}

func TestSignatureFromDERRejectsInvalid(t *testing.T) {
	sig, _, _ := testSignature(t)
	der := sig.DER()

	truncated := der[:len(der)-1]

	trailing := append(append([]byte{}, der...), 0x00)

	compact := sig.Bytes()

	tests := []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"truncated", truncated},
		{"trailing byte", trailing},
		{"compact form", compact[:]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SignatureFromDER(tt.in)
			assert.ErrorIs(t, err, ErrInvalidSignature)
		})
	}
}

// Sign is RFC 6979 deterministic: identical inputs, identical bytes.
func TestSignatureIsDeterministic(t *testing.T) {
	k, _ := randKeyPair(t)
	d := randDigest(t)

	first, err := Sign(k, d)
	require.NoError(t, err)
	second, err := Sign(k, d)
	require.NoError(t, err)

	assert.True(t, first.Equal(second))
}

// Sign always normalizes s into the lower half of the order; negating it
// gives the malleated form, which must differ and be high.
func TestSignNeverProducesHighS(t *testing.T) {
	for range 200 {
		sig, _, _ := testSignature(t)

		assert.False(t, isHighS(t, sig))

		mal := negateS(t, sig)
		assert.True(t, isHighS(t, mal))
		assert.False(t, sig.Equal(mal))
	}
}

func TestSignatureEqual(t *testing.T) {
	a, _, _ := testSignature(t)
	b, _, _ := testSignature(t)

	assert.True(t, a.Equal(a))
	assert.False(t, a.Equal(b))
	assert.False(t, a.Equal(nil))
	assert.False(t, a.Equal(negateS(t, a)))
}
