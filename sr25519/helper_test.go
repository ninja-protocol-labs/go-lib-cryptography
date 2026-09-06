package sr25519

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// The Substrate "Alice" development account: the seed from `subkey
// inspect //Alice` expanded to the scalar this package stores, and its
// published public key.
const (
	aliceScalar = "33a6f3093f158a7109f679410bef1a0c54168145e0cecb4df006c1c2fffb1f09"
	alicePubkey = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"

	// curveOrder is Ristretto255's group order.
	curveOrder = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"
)

var (
	testMsg = []byte("the quick brown fox jumps over the lazy dog")
	testCtx = []byte("example context")
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func aliceKey(t *testing.T) *PrivateKey {
	t.Helper()

	k, err := PrivateKeyFromBytes(mustHex(t, aliceScalar))
	require.NoError(t, err)
	return k
}

func randKey(t *testing.T) *PrivateKey {
	t.Helper()

	for {
		b := make([]byte, SeckeyLen)
		_, err := rand.Read(b)
		require.NoError(t, err)

		if k, err := PrivateKeyFromBytes(b); err == nil {
			return k
		}
	}
}

func signOK(t *testing.T, k *PrivateKey) *Signature {
	t.Helper()

	sig, err := Sign(k, testCtx, testMsg)
	require.NoError(t, err)
	return sig
}
