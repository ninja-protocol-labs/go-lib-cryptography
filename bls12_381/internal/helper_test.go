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
