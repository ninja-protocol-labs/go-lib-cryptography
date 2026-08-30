package secp256k1

import (
	"encoding/hex"
	"math/big"
	"testing"
)

var (
	// The order of the secp256k1 group. S values live in [1, n-1]; flipping one
	// (n - s) turns a low-S signature into its high-S counterpart and back,
	// which is how flipHighS below manufactures a high-S test signature without
	// a from-scratch test vector.
	curveOrder, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	testMsg       = []byte("the quick brown fox jumps over the lazy dog")
)

// flipHighS takes a 64-byte compact (r||s) signature — SignCompact always
// produces the low-S form — and returns the same signature with s replaced
// by n-s, its high-S counterpart. Applying it twice reproduces the
// original.
func flipHighS(t *testing.T, sig []byte) []byte {
	t.Helper()
	if len(sig) != 64 {
		t.Fatalf("flipHighS: sig is %d bytes, want 64", len(sig))
	}

	s := new(big.Int).SetBytes(sig[32:64])
	flipped := new(big.Int).Sub(curveOrder, s)
	flippedBytes := flipped.FillBytes(make([]byte, 32))

	out := make([]byte, 64)
	copy(out[:32], sig[:32])
	copy(out[32:], flippedBytes)
	return out
}

// The expected public key for seckeyOne (private key 1) — a fixed constant
// of the curve (it happens to equal the generator point G itself, since
// 1*G = G, but these exist as a test vector for seckeyOne, not as a
// reference to G), shared across this package's test files. Byte literals
// rather than a hex string so there is no decode step (and, for the 65-byte
// uncompressed form, no string concatenation) standing between this and the
// actual bytes under test.
var (
	seckeyOnePubkeyCompressed = []byte{
		0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb,
		0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
		0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
		0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
		0x98,
	}
	seckeyOnePubkeyUncompressed = []byte{
		0x04, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb,
		0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
		0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
		0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
		0x98, 0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4,
		0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08,
		0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54,
		0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4,
		0xb8,
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
	b := make([]byte, 32)
	b[31] = 1
	priv, err := PrivateKeyFromBytes(b)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed for a valid key: %v", err)
	}
	return priv
}
