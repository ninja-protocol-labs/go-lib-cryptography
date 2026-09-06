package sr25519

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePrivateKey(t *testing.T) {
	a, err := GeneratePrivateKey()
	require.NoError(t, err)
	b, err := GeneratePrivateKey()
	require.NoError(t, err)

	assert.False(t, a.Equal(b), "two generated keys are identical")
	assert.False(t, a.IsZero())
}

// The Alice scalar must give the published Alice public key.
func TestAlicePublicKey(t *testing.T) {
	pub := aliceKey(t).PublicKey().Bytes()

	assert.Equal(t, mustHex(t, alicePubkey), pub[:])
}

func TestPrivateKeyRoundTrip(t *testing.T) {
	for range 50 {
		k := randKey(t)

		b := k.Bytes()
		same, err := PrivateKeyFromBytes(b[:])
		require.NoError(t, err)

		assert.True(t, k.Equal(same))
		assert.True(t, k.PublicKey().Equal(same.PublicKey()))
	}
}

func TestPrivateKeyFromBytesRejectsInvalid(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", make([]byte, SeckeyLen-1)},
		{"long", make([]byte, SeckeyLen+1)},
		{"zero", make([]byte, SeckeyLen)},
		{"all 0xff", bytes.Repeat([]byte{0xff}, SeckeyLen)},
		{"the group order", mustHex(t, curveOrder)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PrivateKeyFromBytes(tt.in)
			assert.ErrorIs(t, err, ErrInvalidPrivateKey)
		})
	}
}

func TestPrivateKeyEqualAndIsZero(t *testing.T) {
	var uninit PrivateKey
	var nilKey *PrivateKey

	a := aliceKey(t)
	b := randKey(t)

	assert.True(t, a.Equal(aliceKey(t)))
	assert.False(t, a.Equal(b))
	assert.False(t, a.Equal(nil))

	assert.True(t, uninit.IsZero())
	assert.True(t, nilKey.IsZero())
	assert.False(t, a.IsZero())
}

func TestPrivateKeyBytesIsACopy(t *testing.T) {
	k := aliceKey(t)
	want := k.Bytes()

	got := k.Bytes()
	got[0] ^= 0xff

	assert.Equal(t, want, k.Bytes())
}

// GeneratePrivateKey takes schnorrkel's own keypair rather than deriving
// the public key itself, so the two paths must agree.
func TestGenerateAgreesWithScalarDerivation(t *testing.T) {
	for range 50 {
		k, err := GeneratePrivateKey()
		require.NoError(t, err)

		b := k.Bytes()
		fromScalar, err := PrivateKeyFromBytes(b[:])
		require.NoError(t, err)

		assert.True(t, k.PublicKey().Equal(fromScalar.PublicKey()))
	}
}
