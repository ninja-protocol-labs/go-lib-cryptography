package sr25519

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	msgs := [][]byte{nil, {}, testMsg, make([]byte, 4096)}

	for range 10 {
		k := randKey(t)

		for _, msg := range msgs {
			sig, err := Sign(k, testCtx, msg)
			require.NoError(t, err)
			assert.True(t, Verify(k.PublicKey(), testCtx, msg, sig))
		}
	}
}

// Signing draws a fresh nonce per call, so the bytes differ every time
// and both signatures still verify.
func TestSignIsRandomized(t *testing.T) {
	k := aliceKey(t)

	a, err := Sign(k, testCtx, testMsg)
	require.NoError(t, err)
	b, err := Sign(k, testCtx, testMsg)
	require.NoError(t, err)

	assert.False(t, a.Equal(b), "two signatures over the same message are identical")
	assert.True(t, Verify(k.PublicKey(), testCtx, testMsg, a))
	assert.True(t, Verify(k.PublicKey(), testCtx, testMsg, b))
}

func TestVerifyRejects(t *testing.T) {
	k := aliceKey(t)
	other := randKey(t)
	sig := signOK(t, k)

	t.Run("wrong key", func(t *testing.T) {
		assert.False(t, Verify(other.PublicKey(), testCtx, testMsg, sig))
	})

	t.Run("wrong message", func(t *testing.T) {
		assert.False(t, Verify(k.PublicKey(), testCtx, []byte("another"), sig))
	})

	t.Run("wrong context", func(t *testing.T) {
		assert.False(t, Verify(k.PublicKey(), []byte("other ctx"), testMsg, sig))
	})

	t.Run("tampered signature", func(t *testing.T) {
		bad := *sig
		bad.sig[0] ^= 0x01
		assert.False(t, Verify(k.PublicKey(), testCtx, testMsg, &bad))
	})

	t.Run("nil key", func(t *testing.T) {
		assert.False(t, Verify(nil, testCtx, testMsg, sig))
	})

	t.Run("nil signature", func(t *testing.T) {
		assert.False(t, Verify(k.PublicKey(), testCtx, testMsg, nil))
	})
}

func TestSignRejectsNilKey(t *testing.T) {
	_, err := Sign(nil, testCtx, testMsg)
	assert.ErrorIs(t, err, ErrInvalidPrivateKey)
}
