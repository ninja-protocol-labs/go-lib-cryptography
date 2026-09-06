package secp256r1

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

func TestPrivateKeyRoundTrip(t *testing.T) {
	for range 50 {
		b := randSeckey(t)

		k, err := PrivateKeyFromBytes(b)
		require.NoError(t, err)

		got := k.Bytes()
		assert.Equal(t, b, got[:])

		same, err := PrivateKeyFromBytes(got[:])
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
		{"curve order", mustHex(t, curveOrder)},
		{"all 0xff", bytes.Repeat([]byte{0xff}, SeckeyLen)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PrivateKeyFromBytes(tt.in)
			assert.ErrorIs(t, err, ErrInvalidPrivateKey)
		})
	}
}

// n-1 is the largest valid scalar; the check must be >= n, not > n.
func TestPrivateKeyAcceptsOrderMinusOne(t *testing.T) {
	b := mustHex(t, curveOrder)
	b[SeckeyLen-1]--

	k, err := PrivateKeyFromBytes(b)
	require.NoError(t, err)
	assert.False(t, k.IsZero())
}

func TestPrivateKeyEqualAndIsZero(t *testing.T) {
	var uninit PrivateKey
	var nilKey *PrivateKey

	a := keyN(t, 1)
	b := keyN(t, 2)

	assert.True(t, a.Equal(keyN(t, 1)))
	assert.False(t, a.Equal(b))
	assert.False(t, a.Equal(nil))

	assert.True(t, uninit.IsZero())
	assert.True(t, nilKey.IsZero())
	assert.False(t, a.IsZero())
}

func TestPrivateKeyBytesIsACopy(t *testing.T) {
	k := keyN(t, 3)
	want := k.Bytes()

	got := k.Bytes()
	got[0] ^= 0xff

	assert.Equal(t, want, k.Bytes())
}

func TestECDHIsSymmetric(t *testing.T) {
	for range 20 {
		a, b := randKey(t), randKey(t)

		fromA, err := a.ECDH(b.PublicKey())
		require.NoError(t, err)
		fromB, err := b.ECDH(a.PublicKey())
		require.NoError(t, err)

		assert.Equal(t, fromA, fromB)
	}
}

func TestECDHVariesByKey(t *testing.T) {
	a, b, c := randKey(t), randKey(t), randKey(t)

	ab, err := a.ECDH(b.PublicKey())
	require.NoError(t, err)
	ac, err := a.ECDH(c.PublicKey())
	require.NoError(t, err)

	assert.NotEqual(t, ab, ac)
}

func TestECDHRejectsNil(t *testing.T) {
	var nilKey *PrivateKey
	k := randKey(t)

	_, err := k.ECDH(nil)
	assert.ErrorIs(t, err, ErrECDHFailed)

	_, err = nilKey.ECDH(k.PublicKey())
	assert.ErrorIs(t, err, ErrECDHFailed)
}
