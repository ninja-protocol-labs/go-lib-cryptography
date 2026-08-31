package bls12381

import "testing"

// testMsg is the fixed message used across sign/verify/aggregate tests —
// the actual bytes don't matter, only that it's non-empty and stable.
var testMsg = []byte("the quick brown fox jumps over the lazy dog")

// privKeyN returns the PrivateKey for the small scalar n, the simplest
// non-zero test value available — used the way seckeyOne/seckeyN is used
// throughout secp256k1's own tests.
func privKeyN(t *testing.T, n byte) *PrivateKey {
	t.Helper()
	b := make([]byte, 32)
	b[31] = n
	priv, err := PrivateKeyFromBytes(b)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed for a valid key: %v", err)
	}
	return priv
}

// privKeyOne is privKeyN(t, 1) — its public key is the G1/G2 generator
// itself, since 1*G = G.
func privKeyOne(t *testing.T) *PrivateKey {
	t.Helper()
	return privKeyN(t, 1)
}
