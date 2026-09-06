package bls12381bls

import (
	"testing"

	"github.com/ninja-protocol-labs/go-lib-cryptography/bls12381"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func signerSet(t *testing.T, n int) []*PrivateKeyMinPk {
	t.Helper()

	out := make([]*PrivateKeyMinPk, n)
	for i := range out {
		k, err := PrivateKeyMinPkFromBytes(randSeckey(t))
		require.NoError(t, err)
		out[i] = k
	}
	return out
}

func TestFastAggregateVerify(t *testing.T) {
	const n = 16

	keys := signerSet(t, n)
	msg := []byte("one block, many attesters")

	pubs := make([]*PublicKeyMinPk, n)
	sigs := make([]*SignatureMinPk, n)
	for i, k := range keys {
		pubs[i] = k.PublicKey()

		s, err := SignMinPk(k, msg)
		require.NoError(t, err)
		sigs[i] = s
	}

	agg, err := AggregateSignaturesMinPk(sigs)
	require.NoError(t, err)
	assert.True(t, FastAggregateVerifyMinPk(pubs, msg, agg))

	t.Run("a missing signer fails", func(t *testing.T) {
		short, err := AggregateSignaturesMinPk(sigs[:n-1])
		require.NoError(t, err)
		assert.False(t, FastAggregateVerifyMinPk(pubs, msg, short))
	})

	t.Run("an extra key fails", func(t *testing.T) {
		extra := signerSet(t, 1)[0]
		assert.False(t, FastAggregateVerifyMinPk(append(pubs, extra.PublicKey()), msg, agg))
	})

	t.Run("wrong message fails", func(t *testing.T) {
		assert.False(t, FastAggregateVerifyMinPk(pubs, []byte("another block"), agg))
	})
}

// Aggregation is a sum, so the order of the terms must not matter.
func TestAggregateIsOrderIndependent(t *testing.T) {
	keys := signerSet(t, 8)
	msg := []byte("order independence")

	sigs := make([]*SignatureMinPk, len(keys))
	pubs := make([]*PublicKeyMinPk, len(keys))
	for i, k := range keys {
		pubs[i] = k.PublicKey()

		s, err := SignMinPk(k, msg)
		require.NoError(t, err)
		sigs[i] = s
	}

	forward, err := AggregateSignaturesMinPk(sigs)
	require.NoError(t, err)

	reversed := make([]*SignatureMinPk, len(sigs))
	for i := range sigs {
		reversed[i] = sigs[len(sigs)-1-i]
	}
	backward, err := AggregateSignaturesMinPk(reversed)
	require.NoError(t, err)

	assert.True(t, forward.Equal(backward))

	pf, err := AggregatePublicKeysMinPk(pubs)
	require.NoError(t, err)

	revPubs := make([]*PublicKeyMinPk, len(pubs))
	for i := range pubs {
		revPubs[i] = pubs[len(pubs)-1-i]
	}
	pb, err := AggregatePublicKeysMinPk(revPubs)
	require.NoError(t, err)

	assert.True(t, pf.Equal(pb))
}

func TestAggregateVerifyDistinctMessages(t *testing.T) {
	const n = 8

	keys := signerSet(t, n)
	pubs := make([]*PublicKeyMinPk, n)
	msgs := make([][]byte, n)
	sigs := make([]*SignatureMinPk, n)

	for i, k := range keys {
		pubs[i] = k.PublicKey()
		msgs[i] = []byte{byte(i), byte(i * 3)}

		s, err := SignMinPk(k, msgs[i])
		require.NoError(t, err)
		sigs[i] = s
	}

	agg, err := AggregateSignaturesMinPk(sigs)
	require.NoError(t, err)
	assert.True(t, AggregateVerifyMinPk(pubs, msgs, agg))

	t.Run("swapped messages fail", func(t *testing.T) {
		swapped := make([][]byte, n)
		copy(swapped, msgs)
		swapped[0], swapped[1] = swapped[1], swapped[0]
		assert.False(t, AggregateVerifyMinPk(pubs, swapped, agg))
	})

	t.Run("length mismatch fails", func(t *testing.T) {
		assert.False(t, AggregateVerifyMinPk(pubs, msgs[:n-1], agg))
	})

	t.Run("nil signature fails", func(t *testing.T) {
		assert.False(t, AggregateVerifyMinPk(pubs, msgs, nil))
	})
}

func TestAggregateMinSig(t *testing.T) {
	const n = 8

	msg := []byte("min-sig aggregation")
	pubs := make([]*PublicKeyMinSig, n)
	sigs := make([]*SignatureMinSig, n)

	for i := range pubs {
		k, err := PrivateKeyMinSigFromBytes(randSeckey(t))
		require.NoError(t, err)
		pubs[i] = k.PublicKey()

		s, err := SignMinSig(k, msg)
		require.NoError(t, err)
		sigs[i] = s
	}

	agg, err := AggregateSignaturesMinSig(sigs)
	require.NoError(t, err)
	assert.True(t, FastAggregateVerifyMinSig(pubs, msg, agg))
	assert.False(t, FastAggregateVerifyMinSig(pubs, []byte("other"), agg))
}

// The rogue key attack the FastAggregateVerify doc warns about, made
// concrete: a key chosen as x·G - Σ(honest keys) lets its holder forge an
// aggregate over a message the honest signers never saw.
func TestRogueKeyAttackSucceedsUnderTheBasicScheme(t *testing.T) {
	honest := signerSet(t, 3)
	msg := []byte("a message no honest signer ever saw")

	honestPubs := make([]*PublicKeyMinPk, len(honest))
	for i, k := range honest {
		honestPubs[i] = k.PublicKey()
	}

	sumHonest, err := AggregatePublicKeysMinPk(honestPubs)
	require.NoError(t, err)

	// The attacker's registered key is x·G minus the honest sum.
	attacker, err := PrivateKeyMinPkFromBytes(randSeckey(t))
	require.NoError(t, err)

	x := attacker.Bytes()

	sum := sumHonest.Bytes()
	sumPoint, err := bls12381.G1PointFromCompressed(sum[:])
	require.NoError(t, err)

	rogue := bls12381.G1Generator().Mul(x).Add(sumPoint.Neg()).Bytes()
	roguePub, err := PublicKeyMinPkFromBytes(rogue[:])
	require.NoError(t, err)

	// The attacker signs alone; the aggregate of every key verifies.
	forged, err := SignMinPk(attacker, msg)
	require.NoError(t, err)

	all := append(honestPubs, roguePub)
	assert.True(t, FastAggregateVerifyMinPk(all, msg, forged),
		"the rogue key attack is expected to succeed under the basic scheme")
}

func TestAggregateVerifyDistinctMessagesMinSig(t *testing.T) {
	const n = 5

	pubs := make([]*PublicKeyMinSig, n)
	msgs := make([][]byte, n)
	sigs := make([]*SignatureMinSig, n)

	for i := range pubs {
		k, err := PrivateKeyMinSigFromBytes(randSeckey(t))
		require.NoError(t, err)

		pubs[i] = k.PublicKey()
		msgs[i] = []byte{byte(i), byte(i * 5)}

		s, err := SignMinSig(k, msgs[i])
		require.NoError(t, err)
		sigs[i] = s
	}

	agg, err := AggregateSignaturesMinSig(sigs)
	require.NoError(t, err)
	assert.True(t, AggregateVerifyMinSig(pubs, msgs, agg))

	msgs[0], msgs[1] = msgs[1], msgs[0]
	assert.False(t, AggregateVerifyMinSig(pubs, msgs, agg))
	assert.False(t, AggregateVerifyMinSig(pubs, msgs[:n-1], agg))
	assert.False(t, AggregateVerifyMinSig(pubs, msgs, nil))
}

func TestAggregatorLenAndMinSigStream(t *testing.T) {
	var (
		pk  SignatureAggregatorMinPk
		sig SignatureAggregatorMinSig
	)

	assert.Zero(t, pk.Len())
	assert.Zero(t, sig.Len())

	msg := []byte("streamed min-sig")
	sigs := make([]*SignatureMinSig, 4)
	for i := range sigs {
		k, err := PrivateKeyMinSigFromBytes(randSeckey(t))
		require.NoError(t, err)

		s, err := SignMinSig(k, msg)
		require.NoError(t, err)

		sigs[i] = s
		require.NoError(t, sig.Add(s))
	}

	assert.Equal(t, len(sigs), sig.Len())
	assert.ErrorIs(t, sig.Add(nil), ErrAggregateFailed)

	streamed, err := sig.Signature()
	require.NoError(t, err)
	onePass, err := AggregateSignaturesMinSig(sigs)
	require.NoError(t, err)
	assert.True(t, streamed.Equal(onePass))

	_, err = pk.Signature()
	assert.ErrorIs(t, err, ErrAggregateFailed)
	_, err = AggregatePublicKeysMinSig(nil)
	assert.ErrorIs(t, err, ErrAggregateFailed)
	_, err = AggregatePublicKeysMinSig([]*PublicKeyMinSig{nil})
	assert.ErrorIs(t, err, ErrAggregateFailed)
	_, err = AggregateSignaturesMinSig([]*SignatureMinSig{nil})
	assert.ErrorIs(t, err, ErrAggregateFailed)
}

// An empty or nil-bearing key set must fail rather than aggregate to the
// identity, which would verify against a matching identity signature.
func TestFastAggregateVerifyRejectsEmptyKeySet(t *testing.T) {
	k, err := PrivateKeyMinPkFromBytes(randSeckey(t))
	require.NoError(t, err)
	sig, err := SignMinPk(k, testMsg)
	require.NoError(t, err)

	assert.False(t, FastAggregateVerifyMinPk(nil, testMsg, sig))
	assert.False(t, FastAggregateVerifyMinPk([]*PublicKeyMinPk{nil}, testMsg, sig))

	s, err := PrivateKeyMinSigFromBytes(randSeckey(t))
	require.NoError(t, err)
	sigSig, err := SignMinSig(s, testMsg)
	require.NoError(t, err)

	assert.False(t, FastAggregateVerifyMinSig(nil, testMsg, sigSig))
	assert.False(t, FastAggregateVerifyMinSig([]*PublicKeyMinSig{nil}, testMsg, sigSig))
}
