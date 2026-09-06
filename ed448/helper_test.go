package ed448

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

// scalarN is a seed with the small value n, the simplest stable key.
func scalarN(t *testing.T, n byte) []byte {
	t.Helper()

	b := make([]byte, SeckeyLen)
	b[SeckeyLen-1] = n
	return b
}

func randKey(t *testing.T) *PrivateKey {
	t.Helper()

	b := make([]byte, SeckeyLen)
	_, err := rand.Read(b)
	require.NoError(t, err)

	k, err := PrivateKeyFromBytes(b)
	require.NoError(t, err)
	return k
}

func keyN(t *testing.T, n byte) *PrivateKey {
	t.Helper()

	k, err := PrivateKeyFromBytes(scalarN(t, n))
	require.NoError(t, err)
	return k
}

// testMsg is the fixed message the signing tests share.
var testMsg = []byte("the quick brown fox jumps over the lazy dog")

// signOK is Sign with the context omitted and the error folded into a
// fatal, for tests that are not about either.
func signOK(t *testing.T, k *PrivateKey, msg []byte) *Signature {
	t.Helper()

	sig, err := Sign(k, msg, nil)
	require.NoError(t, err)
	return sig
}
