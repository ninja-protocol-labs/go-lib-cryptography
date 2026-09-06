package bn254bls

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	msgs := [][]byte{nil, {}, []byte("abc"), make([]byte, 4096)}

	for range 10 {
		b := randSeckey(t)

		pk, err := PrivateKeyMinPkFromBytes(b)
		require.NoError(t, err)
		sk, err := PrivateKeyMinSigFromBytes(b)
		require.NoError(t, err)

		for _, msg := range msgs {
			a, err := SignMinPk(pk, msg)
			require.NoError(t, err)
			assert.True(t, VerifyMinPk(pk.PublicKey(), msg, a))

			c, err := SignMinSig(sk, msg)
			require.NoError(t, err)
			assert.True(t, VerifyMinSig(sk.PublicKey(), msg, c))
		}
	}
}

// A signature under one scheme must never verify under the other. The
// types make the mistake uncompilable; this pins the maths behind that.
func TestSchemesDoNotInteroperate(t *testing.T) {
	b := randSeckey(t)
	msg := []byte("scheme separation")

	pk, err := PrivateKeyMinPkFromBytes(b)
	require.NoError(t, err)
	sk, err := PrivateKeyMinSigFromBytes(b)
	require.NoError(t, err)

	minPk, err := SignMinPk(pk, msg)
	require.NoError(t, err)
	minSig, err := SignMinSig(sk, msg)
	require.NoError(t, err)

	// Same group, wrong scheme: reinterpret each signature as the other
	// scheme's public key group and check it fails.
	pkBytes := minPk.Bytes()
	asPub, err := PublicKeyMinSigFromBytes(pkBytes[:])
	require.NoError(t, err, "a G2 signature is a well-formed G2 point")
	assert.False(t, VerifyMinSig(asPub, msg, minSig))
}

func TestSignRejectsNilKey(t *testing.T) {
	_, err := SignMinPk(nil, []byte("x"))
	assert.ErrorIs(t, err, ErrInvalidPrivateKey)

	_, err = SignMinSig(nil, []byte("x"))
	assert.ErrorIs(t, err, ErrInvalidPrivateKey)
}

func TestVerifyRejects(t *testing.T) {
	b := randSeckey(t)
	msg := []byte("the message")

	pk, err := PrivateKeyMinPkFromBytes(b)
	require.NoError(t, err)
	sig, err := SignMinPk(pk, msg)
	require.NoError(t, err)

	other, err := PrivateKeyMinPkFromBytes(randSeckey(t))
	require.NoError(t, err)

	t.Run("wrong key", func(t *testing.T) {
		assert.False(t, VerifyMinPk(other.PublicKey(), msg, sig))
	})

	t.Run("wrong message", func(t *testing.T) {
		assert.False(t, VerifyMinPk(pk.PublicKey(), []byte("другое"), sig))
	})

	t.Run("wrong dst", func(t *testing.T) {
		assert.False(t, VerifyMinPkWithDST(pk.PublicKey(), msg, sig, []byte("other dst")))
	})

	t.Run("nil key", func(t *testing.T) {
		assert.False(t, VerifyMinPk(nil, msg, sig))
	})

	t.Run("nil signature", func(t *testing.T) {
		assert.False(t, VerifyMinPk(pk.PublicKey(), msg, nil))
	})
}

// A DST is a domain separator: the same key and message under two tags
// must give two unrelated signatures, neither verifying under the other.
func TestDSTSeparatesDomains(t *testing.T) {
	b := randSeckey(t)
	msg := []byte("same message")

	pk, err := PrivateKeyMinPkFromBytes(b)
	require.NoError(t, err)

	a, err := SignMinPkWithDST(pk, msg, []byte("dst one"))
	require.NoError(t, err)
	c, err := SignMinPkWithDST(pk, msg, []byte("dst two"))
	require.NoError(t, err)

	assert.False(t, a.Equal(c))
	assert.False(t, VerifyMinPkWithDST(pk.PublicKey(), msg, a, []byte("dst two")))
	assert.True(t, VerifyMinPkWithDST(pk.PublicKey(), msg, a, []byte("dst one")))
}
