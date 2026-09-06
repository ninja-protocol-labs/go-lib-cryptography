package bls12381bls

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// curveOrder is r, the order of G1, G2 and 𝔾ₜ.
const curveOrder = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// scalarN is the big-endian encoding of the small scalar n.
func scalarN(t *testing.T, n byte) []byte {
	t.Helper()

	b := make([]byte, SeckeyLen)
	b[SeckeyLen-1] = n
	return b
}

func randSeckey(t *testing.T) []byte {
	t.Helper()

	for {
		b := make([]byte, SeckeyLen)
		_, err := rand.Read(b)
		require.NoError(t, err)

		if _, err := PrivateKeyMinPkFromBytes(b); err == nil {
			return b
		}
	}
}

// testMsg is the fixed message the signing tests share.
var testMsg = []byte("the quick brown fox jumps over the lazy dog")
