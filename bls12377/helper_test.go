package bls12377

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// scalarArrN is the big-endian encoding of the small scalar n, the form
// Mul and MSM take.
func scalarArrN(t *testing.T, n byte) [ScalarLen]byte {
	t.Helper()

	var b [ScalarLen]byte
	b[ScalarLen-1] = n
	return b
}

func randScalar(t *testing.T) [ScalarLen]byte {
	t.Helper()

	var b [ScalarLen]byte
	_, err := rand.Read(b[:])
	require.NoError(t, err)
	return b
}

// testMsg is the fixed message the pairing and MSM tests share; only that
// it is non-empty and stable matters.
var testMsg = []byte("the quick brown fox jumps over the lazy dog")

// testDST is a domain separation tag for the hash-to-curve tests. Which tag
// does not matter here; that a wrong one gives a different point does.
var testDST = []byte("XMD:SHA-256_RO_TESTING_")

// g1PointN and g2PointN are n*G, a cheap way to get a point that is not the
// generator.
func g1PointN(t *testing.T, n byte) G1Point {
	t.Helper()

	return G1Generator().Mul(scalarArrN(t, n))
}

func g2PointN(t *testing.T, n byte) G2Point {
	t.Helper()

	return G2Generator().Mul(scalarArrN(t, n))
}
