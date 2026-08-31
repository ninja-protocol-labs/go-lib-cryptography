package internal

import "testing"

// scalarOne returns the big-endian encoding of the scalar 1, the simplest
// non-zero test value available — used the way seckeyOne(1) is used
// throughout secp256k1's own tests.
func scalarOne(t *testing.T) [ScalarLen]byte {
	t.Helper()
	return scalarN(t, 1)
}

func scalarN(t *testing.T, n byte) [ScalarLen]byte {
	t.Helper()
	var s [ScalarLen]byte
	s[ScalarLen-1] = n
	return s
}

// testMsg and testDst are the fixed message/DST pair shared across
// hash-to-curve tests — the actual bytes don't matter, only that they're
// non-empty and stable across calls within a test.
var (
	testMsg = []byte("the quick brown fox jumps over the lazy dog")
	testDst = []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_TEST")
)

// newPairingCtx allocates a pairing context buffer sized for dst and
// initializes it — the setup every pairing test starts from.
func newPairingCtx(t *testing.T, hashOrEncode bool, dst []byte) []byte {
	t.Helper()
	ctx := make([]byte, PairingSizeof()+len(dst))
	PairingInit(ctx, hashOrEncode, dst)
	return ctx
}
