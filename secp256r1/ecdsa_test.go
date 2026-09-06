package secp256r1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	for range 50 {
		k := randKey(t)
		d := randDigest(t)

		sig := signOK(t, k, d)
		assert.True(t, Verify(k.PublicKey(), d, sig))
	}
}

// crypto/ecdsa mixes fresh entropy into every signature, so the same
// input signs differently each time and both signatures verify.
func TestSignIsRandomized(t *testing.T) {
	k := randKey(t)
	d := randDigest(t)

	a, b := signOK(t, k, d), signOK(t, k, d)

	assert.False(t, a.Equal(b), "two signatures over the same digest are identical")
	assert.True(t, Verify(k.PublicKey(), d, a))
	assert.True(t, Verify(k.PublicKey(), d, b))
}

func TestSignRejectsBadInput(t *testing.T) {
	k := randKey(t)
	d := randDigest(t)

	t.Run("nil key", func(t *testing.T) {
		_, err := Sign(nil, d)
		assert.ErrorIs(t, err, ErrInvalidPrivateKey)
	})

	for _, tt := range []struct {
		name string
		in   []byte
	}{
		{"nil digest", nil},
		{"short", d[:DigestLen-1]},
		{"long", append(d, 0)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Sign(k, tt.in)
			assert.ErrorIs(t, err, ErrInvalidDigest)
		})
	}
}

func TestVerifyRejects(t *testing.T) {
	k := randKey(t)
	other := randKey(t)
	d := randDigest(t)
	sig := signOK(t, k, d)

	t.Run("wrong key", func(t *testing.T) {
		assert.False(t, Verify(other.PublicKey(), d, sig))
	})

	t.Run("wrong digest", func(t *testing.T) {
		assert.False(t, Verify(k.PublicKey(), randDigest(t), sig))
	})

	t.Run("tampered signature", func(t *testing.T) {
		bad := *sig
		bad.r[0] ^= 0x01
		assert.False(t, Verify(k.PublicKey(), d, &bad))
	})

	t.Run("nil key", func(t *testing.T) {
		assert.False(t, Verify(nil, d, sig))
	})

	t.Run("nil signature", func(t *testing.T) {
		assert.False(t, Verify(k.PublicKey(), d, nil))
	})

	t.Run("short digest", func(t *testing.T) {
		assert.False(t, Verify(k.PublicKey(), d[:DigestLen-1], sig))
	})
}
