package bn254bls

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicKeyFromBytesRoundTrip(t *testing.T) {
	for range 50 {
		b := randSeckey(t)

		pk, err := PrivateKeyMinPkFromBytes(b)
		require.NoError(t, err)
		sk, err := PrivateKeyMinSigFromBytes(b)
		require.NoError(t, err)

		g1 := pk.PublicKey().Bytes()
		back1, err := PublicKeyMinPkFromBytes(g1[:])
		require.NoError(t, err)
		assert.True(t, pk.PublicKey().Equal(back1))

		g2 := sk.PublicKey().Bytes()
		back2, err := PublicKeyMinSigFromBytes(g2[:])
		require.NoError(t, err)
		assert.True(t, sk.PublicKey().Equal(back2))
	}
}

func TestPublicKeyFromBytesRejectsInvalid(t *testing.T) {
	k, err := PrivateKeyMinPkFromBytes(scalarN(t, 1))
	require.NoError(t, err)
	g1 := k.PublicKey().Bytes()

	s, err := PrivateKeyMinSigFromBytes(scalarN(t, 1))
	require.NoError(t, err)
	g2 := s.PublicKey().Bytes()

	// The identity verifies against every message, so it must not parse.
	infG1 := make([]byte, PubkeyMinPkLen)
	infG1[0] = 0xc0
	infG2 := make([]byte, PubkeyMinSigLen)
	infG2[0] = 0xc0

	// x = 4 has no matching y on this curve, so this is a
	// well-formed encoding of a point that does not exist. Flipping a
	// byte of a real point would not do: about half of all x values are
	// on the curve, which made this test pass at random.
	notOnCurve := mustHex(t,
		"800000000000000000000000000000000000000000000000"+
			"0000000000000004")

	t.Run("min-pk", func(t *testing.T) {
		tests := []struct {
			name string
			in   []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
			{"short", g1[:PubkeyMinPkLen-1]},
			{"a G2 encoding", g2[:]},
			{"all zero", make([]byte, PubkeyMinPkLen)},
			{"all 0xff", bytes.Repeat([]byte{0xff}, PubkeyMinPkLen)},
			{"identity", infG1},
			{"not on the curve", notOnCurve},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := PublicKeyMinPkFromBytes(tt.in)
				assert.ErrorIs(t, err, ErrInvalidPublicKey)
			})
		}
	})

	t.Run("min-sig", func(t *testing.T) {
		tests := []struct {
			name string
			in   []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
			{"short", g2[:PubkeyMinSigLen-1]},
			{"a G1 encoding", g1[:]},
			{"all zero", make([]byte, PubkeyMinSigLen)},
			{"all 0xff", bytes.Repeat([]byte{0xff}, PubkeyMinSigLen)},
			{"identity", infG2},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := PublicKeyMinSigFromBytes(tt.in)
				assert.ErrorIs(t, err, ErrInvalidPublicKey)
			})
		}
	})
}

func TestPublicKeyEqual(t *testing.T) {
	a, err := PrivateKeyMinPkFromBytes(scalarN(t, 1))
	require.NoError(t, err)
	b, err := PrivateKeyMinPkFromBytes(scalarN(t, 2))
	require.NoError(t, err)

	assert.True(t, a.PublicKey().Equal(a.PublicKey()))
	assert.False(t, a.PublicKey().Equal(b.PublicKey()))
	assert.False(t, a.PublicKey().Equal(nil))
}

func TestPublicKeyIsZero(t *testing.T) {
	var uninitPk PublicKeyMinPk
	var uninitSig PublicKeyMinSig
	var nilPk *PublicKeyMinPk

	assert.True(t, uninitPk.IsZero())
	assert.True(t, uninitSig.IsZero())
	assert.True(t, nilPk.IsZero())
}

func TestPublicKeyString(t *testing.T) {
	k, err := PrivateKeyMinPkFromBytes(scalarN(t, 1))
	require.NoError(t, err)

	b := k.PublicKey().Bytes()
	assert.Equal(t, hex.EncodeToString(b[:]), k.PublicKey().String())
	assert.Equal(t, generatorG1, k.PublicKey().String())
}

func TestPublicKeyMinSigEqual(t *testing.T) {
	a, err := PrivateKeyMinSigFromBytes(scalarN(t, 1))
	require.NoError(t, err)
	b, err := PrivateKeyMinSigFromBytes(scalarN(t, 2))
	require.NoError(t, err)

	assert.True(t, a.PublicKey().Equal(a.PublicKey()))
	assert.False(t, a.PublicKey().Equal(b.PublicKey()))
	assert.False(t, a.PublicKey().Equal(nil))
}
