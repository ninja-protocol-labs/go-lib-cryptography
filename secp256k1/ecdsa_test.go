package secp256k1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	for range 200 {
		sig, k, d := testSignature(t)
		assert.True(t, Verify(k.PublicKey(), d, sig))
	}
}

func TestSignRejectsBadInput(t *testing.T) {
	k, _ := randKeyPair(t)
	d := randDigest(t)

	t.Run("nil key", func(t *testing.T) {
		_, err := Sign(nil, d)
		assert.ErrorIs(t, err, ErrInvalidPrivateKey)
	})

	t.Run("short digest", func(t *testing.T) {
		_, err := Sign(k, d[:DigestLen-1])
		assert.ErrorIs(t, err, ErrInvalidDigest)
	})

	t.Run("long digest", func(t *testing.T) {
		_, err := Sign(k, append(d, 0x00))
		assert.ErrorIs(t, err, ErrInvalidDigest)
	})

	t.Run("nil digest", func(t *testing.T) {
		_, err := Sign(k, nil)
		assert.ErrorIs(t, err, ErrInvalidDigest)
	})
}

func TestVerifyRejects(t *testing.T) {
	sig, k, d := testSignature(t)
	other, _ := randKeyPair(t)

	t.Run("wrong key", func(t *testing.T) {
		assert.False(t, Verify(other.PublicKey(), d, sig))
	})

	t.Run("wrong digest", func(t *testing.T) {
		wrong := append([]byte{}, d...)
		wrong[0] ^= 0x01
		assert.False(t, Verify(k.PublicKey(), wrong, sig))
	})

	t.Run("tampered r", func(t *testing.T) {
		bad := *sig
		bad.r[0] ^= 0x01
		assert.False(t, Verify(k.PublicKey(), d, &bad))
	})

	t.Run("malleated s", func(t *testing.T) {
		assert.False(t, Verify(k.PublicKey(), d, negateS(t, sig)))
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

func TestRecoverRoundTrip(t *testing.T) {
	for range 200 {
		k, _ := randKeyPair(t)
		d := randDigest(t)

		sig, id, err := SignRecoverable(k, d)
		require.NoError(t, err)
		require.LessOrEqual(t, id, byte(RecoveryIDMax))

		got, err := Recover(d, sig, id)
		require.NoError(t, err)
		assert.True(t, got.Equal(k.PublicKey()))
	}
}

// SignRecoverable must agree with Sign: same scalars, only the id is extra.
func TestSignRecoverableMatchesSign(t *testing.T) {
	for range 100 {
		k, _ := randKeyPair(t)
		d := randDigest(t)

		plain, err := Sign(k, d)
		require.NoError(t, err)

		rec, _, err := SignRecoverable(k, d)
		require.NoError(t, err)

		assert.True(t, plain.Equal(rec))
	}
}

func TestSignRecoverableRejectsBadInput(t *testing.T) {
	k, _ := randKeyPair(t)

	t.Run("nil key", func(t *testing.T) {
		_, _, err := SignRecoverable(nil, randDigest(t))
		assert.ErrorIs(t, err, ErrInvalidPrivateKey)
	})

	t.Run("short digest", func(t *testing.T) {
		_, _, err := SignRecoverable(k, randDigest(t)[:DigestLen-1])
		assert.ErrorIs(t, err, ErrInvalidDigest)
	})
}

func TestRecoverRejectsBadInput(t *testing.T) {
	k, _ := randKeyPair(t)
	d := randDigest(t)

	sig, id, err := SignRecoverable(k, d)
	require.NoError(t, err)

	tests := []struct {
		name string
		d    []byte
		sig  *Signature
		id   byte
	}{
		{"nil signature", d, nil, id},
		{"short digest", d[:DigestLen-1], sig, id},
		{"id out of range", d, sig, RecoveryIDMax + 1},
		{"malleated s", d, negateS(t, sig), id},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Recover(tt.d, tt.sig, tt.id)
			assert.ErrorIs(t, err, ErrInvalidSignature)
		})
	}
}

// A wrong-but-in-range id recovers some other key, never the right one.
// This is why the id has to be carried alongside the signature.
func TestRecoverWithWrongIDGivesAnotherKey(t *testing.T) {
	for range 100 {
		k, _ := randKeyPair(t)
		d := randDigest(t)

		sig, id, err := SignRecoverable(k, d)
		require.NoError(t, err)

		for try := byte(0); try <= RecoveryIDMax; try++ {
			if try == id {
				continue
			}
			got, err := Recover(d, sig, try)
			if err != nil {
				continue
			}
			assert.False(t, got.Equal(k.PublicKey()),
				"id %d recovered the same key as %d", try, id)
		}
	}
}

// Why Recover rejects high-s: negating s flips the recovery id's low bit,
// so a malleated signature recovers a *different* key with the original id
// instead of failing. Rejecting is the only silent-safe answer.
func TestMalleatedSignatureFlipsRecoveryID(t *testing.T) {
	var sameID, flippedID int

	for range 200 {
		k, _ := randKeyPair(t)
		d := randDigest(t)

		sig, id, err := SignRecoverable(k, d)
		require.NoError(t, err)

		mal := negateS(t, sig)

		for _, try := range []byte{id, id ^ 1} {
			got, err := recoverAllowingHighS(t, d, mal, try)
			if err != nil {
				continue
			}
			if got.Equal(k.PublicKey()) {
				if try == id {
					sameID++
				} else {
					flippedID++
				}
			}
		}
	}

	t.Logf("malleated signature recovered the original key with: same id %d, flipped id %d",
		sameID, flippedID)

	assert.Zero(t, sameID, "the original id still recovered the key")
	assert.NotZero(t, flippedID, "the flipped id never recovered the key")
}
