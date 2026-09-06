package bls12377ecdsa

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

// A nil hash means msg is already a digest.
func TestSignPreHashed(t *testing.T) {
	k := randKey(t)
	digest := make([]byte, SeckeyLen)
	copy(digest, []byte("a 32-byte digest, near enough..."))

	sig, err := Sign(k, digest, nil)
	require.NoError(t, err)
	assert.True(t, Verify(k.PublicKey(), digest, sig, nil))

	// The hash must match on both sides.
	assert.False(t, Verify(k.PublicKey(), digest, sig, testHash()))
}

// Signing is hedged, not deterministic: the same input signs differently
// every time, and both signatures verify.
func TestSignIsHedged(t *testing.T) {
	k := randKey(t)
	msg := []byte("hedged nonce")

	a, err := Sign(k, msg, testHash())
	require.NoError(t, err)
	b, err := Sign(k, msg, testHash())
	require.NoError(t, err)

	assert.False(t, a.Equal(b), "two signatures over the same message are identical")
	assert.True(t, Verify(k.PublicKey(), msg, a, testHash()))
	assert.True(t, Verify(k.PublicKey(), msg, b, testHash()))
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
