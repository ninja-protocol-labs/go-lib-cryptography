package bls12381edwards

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	msgs := [][]byte{nil, {}, []byte("abc"), make([]byte, 1024)}

	for range 10 {
		k := randKey(t)

		for _, msg := range msgs {
			sig, err := Sign(k, msg, testHash())
			require.NoError(t, err)
			assert.True(t, Verify(k.PublicKey(), msg, sig, testHash()))
		}
	}
}

// The hash is not optional and has no default: it must be the one the
// verifier — in a circuit, the gadget — uses.
func TestHashIsRequired(t *testing.T) {
	k := randKey(t)

	_, err := Sign(k, []byte("x"), nil)
	assert.ErrorIs(t, err, ErrHashRequired)

	sig, err := Sign(k, []byte("x"), testHash())
	require.NoError(t, err)
	assert.False(t, Verify(k.PublicKey(), []byte("x"), sig, nil))
}

func TestSignRejectsNilKey(t *testing.T) {
	_, err := Sign(nil, []byte("x"), testHash())
	assert.ErrorIs(t, err, ErrInvalidPrivateKey)
}

func TestVerifyRejects(t *testing.T) {
	k := randKey(t)
	other := randKey(t)
	msg := []byte("the message")

	sig, err := Sign(k, msg, testHash())
	require.NoError(t, err)

	t.Run("wrong key", func(t *testing.T) {
		assert.False(t, Verify(other.PublicKey(), msg, sig, testHash()))
	})

	t.Run("wrong message", func(t *testing.T) {
		assert.False(t, Verify(k.PublicKey(), []byte("another"), sig, testHash()))
	})

	t.Run("tampered signature", func(t *testing.T) {
		bad := *sig
		bad.sig[0] ^= 0x01
		assert.False(t, Verify(k.PublicKey(), msg, &bad, testHash()))
	})

	t.Run("nil key", func(t *testing.T) {
		assert.False(t, Verify(nil, msg, sig, testHash()))
	})

	t.Run("nil signature", func(t *testing.T) {
		assert.False(t, Verify(k.PublicKey(), msg, nil, testHash()))
	})
}
