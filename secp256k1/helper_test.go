package secp256k1

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/stretchr/testify/require"
)

// curveOrder is n, the order of the group. Every scalar must be below it.
const curveOrder = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"

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

		if _, err := PrivateKeyFromBytes(b); err == nil {
			return b
		}
	}
}

func randDigest(t *testing.T) []byte {
	t.Helper()

	d := make([]byte, DigestLen)
	_, err := rand.Read(d)
	require.NoError(t, err)
	return d
}

func randKeyPair(t *testing.T) (*PrivateKey, []byte) {
	t.Helper()

	b := randSeckey(t)
	k, err := PrivateKeyFromBytes(b)
	require.NoError(t, err)
	return k, b
}

func testSignature(t *testing.T) (*Signature, *PrivateKey, []byte) {
	t.Helper()

	k, _ := randKeyPair(t)
	d := randDigest(t)

	sig, err := Sign(k, d)
	require.NoError(t, err)
	return sig, k, d
}

// isHighS reports whether s is in the upper half of the order.
func isHighS(t *testing.T, sig *Signature) bool {
	t.Helper()

	_, s := sig.scalars()
	return s.IsOverHalfOrder()
}

// negateS returns sig with s replaced by n-s: the malleated form Sign never
// produces and Verify must reject.
func negateS(t *testing.T, sig *Signature) *Signature {
	t.Helper()

	var s secp256k1.ModNScalar

	out := *sig
	s.SetBytes(&sig.s)
	s.Negate()
	s.PutBytes(&out.s)
	return &out
}

// recoverAllowingHighS is Recover without the high-s rejection, so a test
// can observe what a malleated signature actually recovers to.
func recoverAllowingHighS(t *testing.T, d []byte, sig *Signature, id byte) (*PublicKey, error) {
	t.Helper()

	var k [PubkeyCompressedLen]byte

	b := make([]byte, 1+SignatureCompactLen)
	b[0] = compactRecoveryBase + id
	copy(b[1:], sig.r[:])
	copy(b[1+SignatureScalarLen:], sig.s[:])

	p, _, err := ecdsa.RecoverCompact(b, d)
	if err != nil {
		return nil, err
	}

	copy(k[:], p.SerializeCompressed())
	return &PublicKey{
		key: k,
	}, nil
}
