package ed25519

import (
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	msgs := [][]byte{nil, {}, testMsg, make([]byte, 4096)}

	for range 10 {
		k := randKey(t)

		for _, msg := range msgs {
			sig := Sign(k, msg)
			assert.True(t, Verify(k.PublicKey(), msg, sig))
		}
	}
}

// Ed25519 has no nonce: the same key and message always sign the same.
func TestSignIsDeterministic(t *testing.T) {
	k := randKey(t)

	assert.True(t, Sign(k, testMsg).Equal(Sign(k, testMsg)))
}

func TestVerifyRejects(t *testing.T) {
	k := keyN(t, 1)
	other := keyN(t, 2)
	sig := Sign(k, testMsg)

	t.Run("wrong key", func(t *testing.T) {
		assert.False(t, Verify(other.PublicKey(), testMsg, sig))
	})

	t.Run("wrong message", func(t *testing.T) {
		assert.False(t, Verify(k.PublicKey(), []byte("another"), sig))
	})

	t.Run("tampered signature", func(t *testing.T) {
		bad := *sig
		bad.sig[0] ^= 0x01
		assert.False(t, Verify(k.PublicKey(), testMsg, &bad))
	})

	t.Run("nil key", func(t *testing.T) {
		assert.False(t, Verify(nil, testMsg, sig))
	})

	t.Run("nil signature", func(t *testing.T) {
		assert.False(t, Verify(k.PublicKey(), testMsg, nil))
	})
}

// An empty context would silently select plain Ed25519 rather than
// Ed25519ctx, so it is refused instead.
func TestCtxRequiresANonEmptyContext(t *testing.T) {
	k := keyN(t, 1)

	_, err := SignCtx(k, testMsg, nil)
	assert.ErrorIs(t, err, ErrContextRequired)
	_, err = SignCtx(k, testMsg, []byte{})
	assert.ErrorIs(t, err, ErrContextRequired)

	sig, err := SignCtx(k, testMsg, []byte("ctx"))
	require.NoError(t, err)
	assert.False(t, VerifyCtx(k.PublicKey(), testMsg, nil, sig))
}

// The three variants are separate schemes: a signature from one must not
// verify under another, even with the same key and message.
func TestVariantsAreDomainSeparated(t *testing.T) {
	k := keyN(t, 1)
	ctx := []byte("ctx")
	d := sha512.Sum512(testMsg)

	pure := Sign(k, testMsg)
	withCtx, err := SignCtx(k, testMsg, ctx)
	require.NoError(t, err)
	ph, err := SignPh(k, d, nil)
	require.NoError(t, err)

	assert.False(t, pure.Equal(withCtx))
	assert.False(t, pure.Equal(ph))
	assert.False(t, withCtx.Equal(ph))

	assert.False(t, VerifyCtx(k.PublicKey(), testMsg, ctx, pure))
	assert.False(t, Verify(k.PublicKey(), testMsg, withCtx))
	assert.False(t, VerifyPh(k.PublicKey(), d, nil, pure))
}

// A different context gives a different signature and does not verify.
func TestCtxSeparatesContexts(t *testing.T) {
	k := keyN(t, 1)

	a, err := SignCtx(k, testMsg, []byte("one"))
	require.NoError(t, err)
	b, err := SignCtx(k, testMsg, []byte("two"))
	require.NoError(t, err)

	assert.False(t, a.Equal(b))
	assert.False(t, VerifyCtx(k.PublicKey(), testMsg, []byte("two"), a))
}

func TestContextTooLong(t *testing.T) {
	k := keyN(t, 1)
	ctx := make([]byte, ContextMaxLen+1)

	_, err := SignCtx(k, testMsg, ctx)
	assert.ErrorIs(t, err, ErrSigningFailed)

	d := sha512.Sum512(testMsg)
	_, err = SignPh(k, d, ctx)
	assert.ErrorIs(t, err, ErrSigningFailed)
}

func TestPhRoundTripWithAndWithoutContext(t *testing.T) {
	k := randKey(t)
	d := sha512.Sum512(testMsg)

	for _, ctx := range [][]byte{nil, {}, []byte("ctx")} {
		sig, err := SignPh(k, d, ctx)
		require.NoError(t, err)
		assert.True(t, VerifyPh(k.PublicKey(), d, ctx, sig))

		other := sha512.Sum512([]byte("another"))
		assert.False(t, VerifyPh(k.PublicKey(), other, ctx, sig))
	}
}

func TestSignCtxAndPhRejectNilKey(t *testing.T) {
	d := sha512.Sum512(testMsg)

	_, err := SignCtx(nil, testMsg, []byte("ctx"))
	assert.ErrorIs(t, err, ErrInvalidPrivateKey)
	_, err = SignPh(nil, d, nil)
	assert.ErrorIs(t, err, ErrInvalidPrivateKey)

	assert.False(t, VerifyCtx(nil, testMsg, []byte("ctx"), &Signature{}))
	assert.False(t, VerifyPh(nil, d, nil, &Signature{}))
}
