package x25519

import (
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
		k := randKey(t)

		b := k.Bytes()
		same, err := PrivateKeyFromBytes(b[:])
		require.NoError(t, err)

		assert.True(t, k.Equal(same))
		assert.True(t, k.PublicKey().Equal(same.PublicKey()))
	}
}

func TestPrivateKeyFromBytesRejectsBadLength(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", make([]byte, SeckeyLen-1)},
		{"long", make([]byte, SeckeyLen+1)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PrivateKeyFromBytes(tt.in)
			assert.ErrorIs(t, err, ErrInvalidPrivateKey)
		})
	}
}

// Clamping means the stored scalar is whatever was handed in, but the
// derived public key ignores the bits clamping fixes: two scalars that
// differ only there give the same public key.
func TestClampedBitsDoNotAffectThePublicKey(t *testing.T) {
	b := mustHex(t, aliceSeckey)

	flipped := append([]byte{}, b...)
	flipped[0] |= 0x07  // low three bits, cleared by clamping
	flipped[31] &= 0x7f // high bit, cleared by clamping
	flipped[31] |= 0x40 // second-highest, set by clamping

	a, err := PrivateKeyFromBytes(b)
	require.NoError(t, err)
	c, err := PrivateKeyFromBytes(flipped)
	require.NoError(t, err)

	assert.False(t, a.Equal(c), "the stored scalars should differ")
	assert.True(t, a.PublicKey().Equal(c.PublicKey()), "clamping should erase the difference")
}

func TestPrivateKeyEqualAndIsZero(t *testing.T) {
	var uninit PrivateKey
	var nilKey *PrivateKey

	a := keyFromHex(t, aliceSeckey)
	b := keyFromHex(t, bobSeckey)

	assert.True(t, a.Equal(keyFromHex(t, aliceSeckey)))
	assert.False(t, a.Equal(b))
	assert.False(t, a.Equal(nil))

	assert.True(t, uninit.IsZero())
	assert.True(t, nilKey.IsZero())
	assert.False(t, a.IsZero())
}

func TestPrivateKeyBytesIsACopy(t *testing.T) {
	k := keyFromHex(t, aliceSeckey)
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

// A small-order public key drives the raw result to zero, which
// crypto/ecdh refuses. PublicKeyFromBytes cannot catch this, so ECDH is
// where it has to be caught.
func TestECDHRejectsSmallOrderPoints(t *testing.T) {
	k := randKey(t)

	for _, tt := range []struct {
		name string
		u    string
	}{
		{"zero", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"one", "0100000000000000000000000000000000000000000000000000000000000000"},
		{"order 8", "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"},
		{"p-1", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := PublicKeyFromBytes(mustHex(t, tt.u))
			require.NoError(t, err, "parsing must accept it")

			_, err = k.ECDH(pub)
			assert.ErrorIs(t, err, ErrECDHFailed, "ECDH must reject it")
		})
	}
}

func TestECDHRejectsNil(t *testing.T) {
	var nilKey *PrivateKey
	k := randKey(t)

	_, err := k.ECDH(nil)
	assert.ErrorIs(t, err, ErrECDHFailed)

	_, err = nilKey.ECDH(k.PublicKey())
	assert.ErrorIs(t, err, ErrECDHFailed)
}
