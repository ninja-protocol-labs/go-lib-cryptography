package sha2

import (
	"encoding/hex"
	"testing"
)

// testMsg is "abc", the input every FIPS 180-4 example vector uses.
var testMsg = []byte("abc")

// The expected digests of testMsg. These were produced with OpenSSL, not
// with the standard library this package wraps — hashing with crypto/sha256
// and comparing against crypto/sha256 would only prove the wrapper is
// self-consistent, not that Sum224 is wired to SHA-224 rather than to
// SHA-256.
const (
	abcSHA224     = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
	abcSHA256     = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	abcSHA384     = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
	abcSHA512     = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
	abcSHA512_224 = "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
	abcSHA512_256 = "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"

	// The empty string under SHA-256, to cover the padding-only path.
	emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// mustDecodeHex turns a test vector into bytes.
func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test vector %q: %v", s, err)
	}
	return b
}
