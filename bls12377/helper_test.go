package bls12377

import "testing"

// testMsg is the fixed message used across sign/verify/aggregate tests —
// the actual bytes don't matter, only that it's non-empty and stable.
var testMsg = []byte("the quick brown fox jumps over the lazy dog")

// privKeyN returns the PrivateKey for the small scalar n, the simplest
// non-zero test value available — the same helper shape bls12381's and
// secp256k1's tests use.
func privKeyN(t *testing.T, n byte) *PrivateKey {
	t.Helper()
	b := scalarN(n)
	priv, err := PrivateKeyFromBytes(b[:])
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

// scalarN is the big-endian encoding of the small scalar n, the form
// G1Point.Mul and MultiScalarMultG1 take.
func scalarN(n byte) [SeckeyLen]byte {
	var b [SeckeyLen]byte
	b[SeckeyLen-1] = n
	return b
}

// signMinPk is SignMinPk with the error folded into a t.Fatal, so the
// tests that only care about the signature bytes stay readable.
func signMinPk(t *testing.T, priv *PrivateKey, msg []byte) [SignatureMinPkLen]byte {
	t.Helper()
	sig, err := SignMinPk(priv, msg)
	if err != nil {
		t.Fatalf("SignMinPk failed: %v", err)
	}
	return sig
}

// signMinSig is signMinPk's mirror for the min-sig scheme.
func signMinSig(t *testing.T, priv *PrivateKey, msg []byte) [SignatureMinSigLen]byte {
	t.Helper()
	sig, err := SignMinSig(priv, msg)
	if err != nil {
		t.Fatalf("SignMinSig failed: %v", err)
	}
	return sig
}
