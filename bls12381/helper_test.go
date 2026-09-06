package bls12381

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// curveOrder is r, the order of G1, G2 and GT.
const curveOrder = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// scalarArrN is scalarN in the fixed-array form Mul and MSM take.
func scalarArrN(t *testing.T, n byte) [SeckeyLen]byte {
	t.Helper()

	var b [SeckeyLen]byte
	b[SeckeyLen-1] = n
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

// testMsg is the fixed message the pairing and MSM tests share; only that
// it is non-empty and stable matters.
var testMsg = []byte("the quick brown fox jumps over the lazy dog")

func privKeyMinPkN(t *testing.T, n byte) *PrivateKeyMinPk {
	t.Helper()

	k, err := PrivateKeyMinPkFromBytes(scalarN(t, n))
	require.NoError(t, err)
	return k
}

func privKeyMinSigN(t *testing.T, n byte) *PrivateKeyMinSig {
	t.Helper()

	k, err := PrivateKeyMinSigFromBytes(scalarN(t, n))
	require.NoError(t, err)
	return k
}

func signMinPk(t *testing.T, k *PrivateKeyMinPk, msg []byte) [SignatureMinPkLen]byte {
	t.Helper()

	sig, err := SignMinPk(k, msg)
	require.NoError(t, err)
	return sig.Bytes()
}
