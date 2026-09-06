package ed448

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	msgs := [][]byte{nil, {}, testMsg, make([]byte, 4096)}
	ctxs := [][]byte{nil, {}, []byte("ctx")}

	for range 5 {
		k := randKey(t)

		for _, msg := range msgs {
			for _, ctx := range ctxs {
				sig, err := Sign(k, msg, ctx)
				require.NoError(t, err)
				assert.True(t, Verify(k.PublicKey(), msg, ctx, sig))

				ph, err := SignPh(k, msg, ctx)
				require.NoError(t, err)
				assert.True(t, VerifyPh(k.PublicKey(), msg, ctx, ph))
			}
		}
	}
}

// Ed448 has no nonce: the same inputs always sign the same.
func TestSignIsDeterministic(t *testing.T) {
	k := randKey(t)

	a, err := Sign(k, testMsg, nil)
	require.NoError(t, err)
	b, err := Sign(k, testMsg, nil)
	require.NoError(t, err)

	assert.True(t, a.Equal(b))
}

func TestVerifyRejects(t *testing.T) {
	k := keyN(t, 1)
	other := keyN(t, 2)

	sig, err := Sign(k, testMsg, nil)
	require.NoError(t, err)

	t.Run("wrong key", func(t *testing.T) {
		assert.False(t, Verify(other.PublicKey(), testMsg, nil, sig))
	})

	t.Run("wrong message", func(t *testing.T) {
		assert.False(t, Verify(k.PublicKey(), []byte("another"), nil, sig))
	})

	t.Run("wrong context", func(t *testing.T) {
		assert.False(t, Verify(k.PublicKey(), testMsg, []byte("ctx"), sig))
	})

	t.Run("tampered signature", func(t *testing.T) {
		bad := *sig
		bad.sig[0] ^= 0x01
		assert.False(t, Verify(k.PublicKey(), testMsg, nil, &bad))
	})

	t.Run("nil key", func(t *testing.T) {
		assert.False(t, Verify(nil, testMsg, nil, sig))
	})

	t.Run("nil signature", func(t *testing.T) {
		assert.False(t, Verify(k.PublicKey(), testMsg, nil, nil))
	})
}

// Unlike ed25519, an empty context is an ordinary valid input rather than
// a different scheme — Ed448 always folds it into the domain hash.
func TestEmptyContextIsValid(t *testing.T) {
	k := keyN(t, 1)

	withNil, err := Sign(k, testMsg, nil)
	require.NoError(t, err)
	withEmpty, err := Sign(k, testMsg, []byte{})
	require.NoError(t, err)

	assert.True(t, withNil.Equal(withEmpty))
	assert.True(t, Verify(k.PublicKey(), testMsg, []byte{}, withNil))
}

// The two variants are separate schemes.
func TestPhIsDomainSeparated(t *testing.T) {
	k := keyN(t, 1)

	plain, err := Sign(k, testMsg, nil)
	require.NoError(t, err)
	ph, err := SignPh(k, testMsg, nil)
	require.NoError(t, err)

	assert.False(t, plain.Equal(ph))
	assert.False(t, VerifyPh(k.PublicKey(), testMsg, nil, plain))
	assert.False(t, Verify(k.PublicKey(), testMsg, nil, ph))
}

func TestContextSeparatesContexts(t *testing.T) {
	k := keyN(t, 1)

	a, err := Sign(k, testMsg, []byte("one"))
	require.NoError(t, err)
	b, err := Sign(k, testMsg, []byte("two"))
	require.NoError(t, err)

	assert.False(t, a.Equal(b))
	assert.False(t, Verify(k.PublicKey(), testMsg, []byte("two"), a))
}

// CIRCL panics on an oversize context, so the length is checked first.
func TestContextTooLong(t *testing.T) {
	k := keyN(t, 1)
	ctx := make([]byte, ContextMaxLen+1)

	_, err := Sign(k, testMsg, ctx)
	assert.ErrorIs(t, err, ErrContextTooLong)
	_, err = SignPh(k, testMsg, ctx)
	assert.ErrorIs(t, err, ErrContextTooLong)

	sig, err := Sign(k, testMsg, nil)
	require.NoError(t, err)
	assert.False(t, Verify(k.PublicKey(), testMsg, ctx, sig))
	assert.False(t, VerifyPh(k.PublicKey(), testMsg, ctx, sig))
}

// The longest allowed context must still work.
func TestContextAtMaxLength(t *testing.T) {
	k := keyN(t, 1)
	ctx := make([]byte, ContextMaxLen)

	sig, err := Sign(k, testMsg, ctx)
	require.NoError(t, err)
	assert.True(t, Verify(k.PublicKey(), testMsg, ctx, sig))
}

func TestSignRejectsNilKey(t *testing.T) {
	_, err := Sign(nil, testMsg, nil)
	assert.ErrorIs(t, err, ErrInvalidPrivateKey)
	_, err = SignPh(nil, testMsg, nil)
	assert.ErrorIs(t, err, ErrInvalidPrivateKey)
}
