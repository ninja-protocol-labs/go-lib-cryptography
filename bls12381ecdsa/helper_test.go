package bls12381ecdsa

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
)

// curveOrder is r, the order of the group. Every scalar must be below it.
const curveOrder = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"

func testHash() hash.Hash {
	return sha256.New()
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func randSeckey(t *testing.T) []byte {
	t.Helper()

	for {
		b := make([]byte, SeckeyLen)
		_, err := rand.Read(b)
		require.NoError(t, err)

		if _, err := PrivateKeyFromBytes(b); err == nil {
			return b
		}
	}
}

func randKey(t *testing.T) *PrivateKey {
	t.Helper()

	k, err := PrivateKeyFromBytes(randSeckey(t))
	require.NoError(t, err)
	return k
}
