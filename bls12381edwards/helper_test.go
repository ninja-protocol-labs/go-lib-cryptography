package bls12381edwards

import (
	"crypto/rand"
	"hash"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	"github.com/stretchr/testify/require"
)

// testHash is the Fiat-Shamir hash gnark's own circuits use: MiMC over the
// same 𝔽r this curve is defined on. It comes from gnark rather than this
// module's bls12381mimc, whose API is element-based and so not a hash.Hash.
func testHash() hash.Hash {
	return mimc.NewMiMC()
}

func randSeed(t *testing.T) []byte {
	t.Helper()

	b := make([]byte, SeedLen)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func randKey(t *testing.T) *PrivateKey {
	t.Helper()

	k, err := PrivateKeyFromSeed(randSeed(t))
	require.NoError(t, err)
	return k
}
