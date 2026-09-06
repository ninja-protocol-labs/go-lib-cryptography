package bn254bls

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePrivateKey(t *testing.T) {
	a, err := GeneratePrivateKeyMinPk()
	require.NoError(t, err)
	b, err := GeneratePrivateKeyMinPk()
	require.NoError(t, err)

	assert.False(t, a.Equal(b), "two generated keys are identical")
	assert.False(t, a.IsZero())

	c, err := GeneratePrivateKeyMinSig()
	require.NoError(t, err)
	assert.False(t, c.IsZero())
}

func TestPrivateKeyFromBytesRoundTrip(t *testing.T) {
	for range 50 {
		b := randSeckey(t)

		pk, err := PrivateKeyMinPkFromBytes(b)
		require.NoError(t, err)
		sk, err := PrivateKeyMinSigFromBytes(b)
		require.NoError(t, err)

		gotPk, gotSk := pk.Bytes(), sk.Bytes()
		assert.Equal(t, b, gotPk[:])
		assert.Equal(t, b, gotSk[:], "both schemes hold the same scalar")

		same, err := PrivateKeyMinPkFromBytes(gotPk[:])
		require.NoError(t, err)
		assert.True(t, pk.Equal(same))
		assert.True(t, pk.PublicKey().Equal(same.PublicKey()))
	}
}

func TestPrivateKeyFromBytesRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", make([]byte, SeckeyLen-1)},
		{"long", make([]byte, SeckeyLen+1)},
		{"zero", make([]byte, SeckeyLen)},
		{"curve order", mustHex(t, curveOrder)},
		{"all 0xff", bytes.Repeat([]byte{0xff}, SeckeyLen)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PrivateKeyMinPkFromBytes(tt.in)
			assert.ErrorIs(t, err, ErrInvalidPrivateKey)

			_, err = PrivateKeyMinSigFromBytes(tt.in)
			assert.ErrorIs(t, err, ErrInvalidPrivateKey)
		})
	}
}

// r-1 is the largest valid scalar; the check must be >= r, not > r.
func TestPrivateKeyAcceptsOrderMinusOne(t *testing.T) {
	b := mustHex(t, curveOrder)
	b[SeckeyLen-1]--

	k, err := PrivateKeyMinPkFromBytes(b)
	require.NoError(t, err)
	assert.False(t, k.IsZero())
}

func TestPrivateKeyEqual(t *testing.T) {
	a, err := PrivateKeyMinPkFromBytes(randSeckey(t))
	require.NoError(t, err)
	b, err := PrivateKeyMinPkFromBytes(randSeckey(t))
	require.NoError(t, err)

	ab := a.Bytes()
	same, err := PrivateKeyMinPkFromBytes(ab[:])
	require.NoError(t, err)

	assert.True(t, a.Equal(same))
	assert.False(t, a.Equal(b))
	assert.False(t, a.Equal(nil))
}

func TestPrivateKeyIsZero(t *testing.T) {
	var uninitPk PrivateKeyMinPk
	var uninitSig PrivateKeyMinSig
	var nilPk *PrivateKeyMinPk

	assert.True(t, uninitPk.IsZero())
	assert.True(t, uninitSig.IsZero())
	assert.True(t, nilPk.IsZero())
}

// Bytes returns a copy; mutating it must not reach the key.
func TestPrivateKeyBytesIsACopy(t *testing.T) {
	b := randSeckey(t)

	k, err := PrivateKeyMinPkFromBytes(b)
	require.NoError(t, err)

	got := k.Bytes()
	got[0] ^= 0xff

	after := k.Bytes()
	assert.Equal(t, b, after[:])
}

func TestPrivateKeyMinSigEqualAndPublicKeyString(t *testing.T) {
	b := randSeckey(t)

	a, err := PrivateKeyMinSigFromBytes(b)
	require.NoError(t, err)
	same, err := PrivateKeyMinSigFromBytes(b)
	require.NoError(t, err)
	other, err := PrivateKeyMinSigFromBytes(randSeckey(t))
	require.NoError(t, err)

	assert.True(t, a.Equal(same))
	assert.False(t, a.Equal(other))
	assert.False(t, a.Equal(nil))

	pub := a.PublicKey().Bytes()
	assert.Equal(t, hex.EncodeToString(pub[:]), a.PublicKey().String())
}
