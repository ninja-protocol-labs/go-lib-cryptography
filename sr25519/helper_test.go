package sr25519

import (
	"testing"
)

// The well-known Substrate "Alice" development seed (as produced by
// `subkey inspect //Alice`), expanded to the scalar this package's
// PrivateKey actually stores (MiniSecretKey.ExpandEd25519().Encode() in
// go-schnorrkel terms — see key.go's package doc for why PrivateKey is
// scalar-shaped, not seed-shaped), and its derived public key. Both were
// computed via go-schnorrkel directly rather than hand-transcribed.
var (
	aliceScalar = []byte{
		0x33, 0xa6, 0xf3, 0x09, 0x3f, 0x15, 0x8a, 0x71,
		0x09, 0xf6, 0x79, 0x41, 0x0b, 0xef, 0x1a, 0x0c,
		0x54, 0x16, 0x81, 0x45, 0xe0, 0xce, 0xcb, 0x4d,
		0xf0, 0x06, 0xc1, 0xc2, 0xff, 0xfb, 0x1f, 0x09,
	}
	alicePubkey = []byte{
		0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c,
		0x61, 0x14, 0x1a, 0xbd, 0x04, 0xa9, 0x9f, 0xd6,
		0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3,
		0x9a, 0x56, 0x84, 0xe7, 0xa5, 0x6d, 0xa2, 0x7d,
	}
)

var testMsg = []byte("the quick brown fox jumps over the lazy dog")
var testCtx = []byte("example context")

func aliceKey(t *testing.T) *PrivateKey {
	t.Helper()
	priv, err := PrivateKeyFromBytes(aliceScalar)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed for a valid scalar: %v", err)
	}
	return priv
}

func seckeyN(t *testing.T, n byte) *PrivateKey {
	t.Helper()
	b := make([]byte, SeckeyLen)
	b[SeckeyLen-1] = n
	priv, err := PrivateKeyFromBytes(b)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed for a valid scalar: %v", err)
	}
	return priv
}
