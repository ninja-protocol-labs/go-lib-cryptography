package bn254bls

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSigPair(t *testing.T) (*SignatureMinPk, *SignatureMinSig) {
	t.Helper()

	b := randSeckey(t)
	msg := []byte("signature under test")

	pk, err := PrivateKeyMinPkFromBytes(b)
	require.NoError(t, err)
	sk, err := PrivateKeyMinSigFromBytes(b)
	require.NoError(t, err)

	a, err := SignMinPk(pk, msg)
	require.NoError(t, err)
	c, err := SignMinSig(sk, msg)
	require.NoError(t, err)
	return a, c
}

func TestSignatureFromBytesRoundTrip(t *testing.T) {
	for range 50 {
		a, c := testSigPair(t)

		ab := a.Bytes()
		back, err := SignatureMinPkFromBytes(ab[:])
		require.NoError(t, err)
		assert.True(t, a.Equal(back))

		cb := c.Bytes()
		back2, err := SignatureMinSigFromBytes(cb[:])
		require.NoError(t, err)
		assert.True(t, c.Equal(back2))
	}
}

func TestSignatureFromBytesRejectsInvalid(t *testing.T) {
	a, c := testSigPair(t)
	ab, cb := a.Bytes(), c.Bytes()

	// x = 4 has no matching y on this curve, so this is a
	// well-formed encoding of a point that does not exist. Flipping a
	// byte of a real point would not do: about half of all x values are
	// on the curve, which made this test pass at random.
	notOnCurve := mustHex(t,
		"800000000000000000000000000000000000000000000000"+
			"0000000000000004")

	t.Run("min-pk", func(t *testing.T) {
		for _, tt := range []struct {
			name string
			in   []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
			{"short", ab[:SignatureMinPkLen-1]},
			{"a G1 encoding", cb[:]},
			{"all zero", make([]byte, SignatureMinPkLen)},
			{"all 0xff", bytes.Repeat([]byte{0xff}, SignatureMinPkLen)},
		} {
			t.Run(tt.name, func(t *testing.T) {
				_, err := SignatureMinPkFromBytes(tt.in)
				assert.ErrorIs(t, err, ErrInvalidSignature)
			})
		}
	})

	t.Run("min-sig", func(t *testing.T) {
		for _, tt := range []struct {
			name string
			in   []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
			{"short", cb[:SignatureMinSigLen-1]},
			{"a G2 encoding", ab[:]},
			{"all zero", make([]byte, SignatureMinSigLen)},
			{"all 0xff", bytes.Repeat([]byte{0xff}, SignatureMinSigLen)},
			{"not on the curve", notOnCurve},
		} {
			t.Run(tt.name, func(t *testing.T) {
				_, err := SignatureMinSigFromBytes(tt.in)
				assert.ErrorIs(t, err, ErrInvalidSignature)
			})
		}
	})
}

func TestSignatureEqualAndIsZero(t *testing.T) {
	a, c := testSigPair(t)
	other, _ := testSigPair(t)

	var uninitPk SignatureMinPk
	var nilSig *SignatureMinPk

	assert.True(t, a.Equal(a))
	assert.False(t, a.Equal(other))
	assert.False(t, a.Equal(nil))
	assert.False(t, c.Equal(nil))

	assert.True(t, uninitPk.IsZero())
	assert.True(t, nilSig.IsZero())
	assert.False(t, a.IsZero())
}

// Signing is deterministic: BLS has no nonce.
func TestSignatureIsDeterministic(t *testing.T) {
	b := randSeckey(t)
	msg := []byte("determinism")

	k, err := PrivateKeyMinPkFromBytes(b)
	require.NoError(t, err)

	first, err := SignMinPk(k, msg)
	require.NoError(t, err)
	second, err := SignMinPk(k, msg)
	require.NoError(t, err)

	assert.True(t, first.Equal(second))
}

func TestSignatureStringAndMinSigZero(t *testing.T) {
	a, c := testSigPair(t)

	ab, cb := a.Bytes(), c.Bytes()
	assert.Equal(t, hex.EncodeToString(ab[:]), a.String())
	assert.Equal(t, hex.EncodeToString(cb[:]), c.String())

	var uninit SignatureMinSig
	var nilSig *SignatureMinSig

	assert.True(t, uninit.IsZero())
	assert.True(t, nilSig.IsZero())
	assert.False(t, c.IsZero())
}
