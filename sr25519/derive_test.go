package sr25519

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func chainCodeN(n byte) [ChainCodeLen]byte {
	var cc [ChainCodeLen]byte
	cc[ChainCodeLen-1] = n
	return cc
}

// A hard-derived child must be a working key, with its cached public key
// derived rather than left zero.
func TestDeriveHardProducesAUsableKey(t *testing.T) {
	cc := chainCodeN(1)

	child, _, err := aliceKey(t).DeriveHard(cc, []byte("//child"))
	require.NoError(t, err)

	assert.False(t, child.IsZero())
	assert.False(t, child.PublicKey().IsZero())

	sig, err := Sign(child, testCtx, testMsg)
	require.NoError(t, err)
	assert.True(t, Verify(child.PublicKey(), testCtx, testMsg, sig))
}

func TestDeriveHardIsDeterministic(t *testing.T) {
	cc := chainCodeN(1)
	k := aliceKey(t)

	a, ccA, err := k.DeriveHard(cc, []byte("//child"))
	require.NoError(t, err)
	b, ccB, err := k.DeriveHard(cc, []byte("//child"))
	require.NoError(t, err)

	assert.True(t, a.Equal(b))
	assert.Equal(t, ccA, ccB)
}

func TestDeriveHardVariesByIndexAndChainCode(t *testing.T) {
	k := aliceKey(t)

	base, _, err := k.DeriveHard(chainCodeN(1), []byte("//one"))
	require.NoError(t, err)

	byIndex, _, err := k.DeriveHard(chainCodeN(1), []byte("//two"))
	require.NoError(t, err)
	assert.False(t, base.Equal(byIndex))

	byChainCode, _, err := k.DeriveHard(chainCodeN(2), []byte("//one"))
	require.NoError(t, err)
	assert.False(t, base.Equal(byChainCode))

	assert.False(t, base.Equal(k), "the child equals its parent")
}

func TestDeriveSoftIsDeterministicAndVaries(t *testing.T) {
	pub := aliceKey(t).PublicKey()
	cc := chainCodeN(1)

	a, ccA, err := pub.DeriveSoft(cc, []byte("//child"))
	require.NoError(t, err)
	b, ccB, err := pub.DeriveSoft(cc, []byte("//child"))
	require.NoError(t, err)

	assert.True(t, a.Equal(b))
	assert.Equal(t, ccA, ccB)
	assert.False(t, a.Equal(pub), "the child equals its parent")

	other, _, err := pub.DeriveSoft(cc, []byte("//other"))
	require.NoError(t, err)
	assert.False(t, a.Equal(other))
}

func TestDeriveRejectsNil(t *testing.T) {
	var (
		nilPriv *PrivateKey
		nilPub  *PublicKey
	)
	cc := chainCodeN(1)

	_, _, err := nilPriv.DeriveHard(cc, []byte("//x"))
	assert.ErrorIs(t, err, ErrDeriveFailed)

	_, _, err = nilPub.DeriveSoft(cc, []byte("//x"))
	assert.ErrorIs(t, err, ErrDeriveFailed)
}
