package secp256r1

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// curveOrder is n, the order of P-256's group.
const curveOrder = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

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

func keyN(t *testing.T, n byte) *PrivateKey {
	t.Helper()

	k, err := PrivateKeyFromBytes(scalarN(t, n))
	require.NoError(t, err)
	return k
}

func randDigest(t *testing.T) []byte {
	t.Helper()

	d := make([]byte, DigestLen)
	_, err := rand.Read(d)
	require.NoError(t, err)
	return d
}

func signOK(t *testing.T, k *PrivateKey, d []byte) *Signature {
	t.Helper()

	sig, err := Sign(k, d)
	require.NoError(t, err)
	return sig
}
