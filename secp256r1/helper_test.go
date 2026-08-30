package secp256r1

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// The order of the secp256r1 group. Keys are valid in [1, n-1], so n itself
// and everything above it must be rejected.
var curveOrder, _ = new(big.Int).SetString(
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16,
)

// The expected public key for seckeyOne (private key 1) — a fixed constant
// of the curve (it happens to equal the generator point G itself, since
// 1*G = G, but these exist as a test vector for seckeyOne, not as a
// reference to G), shared across this package's test files. Byte literals
// rather than a hex string so there is no decode step standing between this
// and the actual bytes under test.
var (
	seckeyOnePubkeyCompressed = []byte{
		0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42,
		0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
		0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33,
		0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
		0x96,
	}
	seckeyOnePubkeyUncompressed = []byte{
		0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42,
		0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
		0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33,
		0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
		0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f,
		0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
		0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
		0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51,
		0xf5,
	}
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in test case: %v", err)
	}
	return b
}

// seckeyOne returns the PrivateKey for scalar 1, whose public key is the
// generator point — the simplest non-zero test vector available.
func seckeyOne(t *testing.T) *PrivateKey {
	t.Helper()
	b := make([]byte, SeckeyLen)
	b[SeckeyLen-1] = 1
	priv, err := PrivateKeyFromBytes(b)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed for a valid key: %v", err)
	}
	return priv
}

// seckeyN returns the PrivateKey for the small scalar n, for tests that just
// need a second, distinct key.
func seckeyN(t *testing.T, n byte) *PrivateKey {
	t.Helper()
	b := make([]byte, SeckeyLen)
	b[SeckeyLen-1] = n
	priv, err := PrivateKeyFromBytes(b)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed for a valid key: %v", err)
	}
	return priv
}

var testMsg = []byte("the quick brown fox jumps over the lazy dog")
