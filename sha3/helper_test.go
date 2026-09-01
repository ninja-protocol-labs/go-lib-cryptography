package sha3

import (
	"encoding/hex"
	"testing"
)

// testMsg is "abc", the input FIPS 202's example vectors use.
var testMsg = []byte("abc")

// The expected outputs for testMsg. Produced with OpenSSL, not with the
// standard library this package wraps: hashing with crypto/sha3 and
// comparing against crypto/sha3 would only prove the wrapper is
// self-consistent, not that Sum256 is wired to SHA3-256.
const (
	abcSHA3_224 = "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
	abcSHA3_256 = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
	abcSHA3_384 = "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
	abcSHA3_512 = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"

	abcSHAKE128_32 = "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
	abcSHAKE256_64 = "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"

	// SHA-256("abc") — not SHA3-256's. Used to assert the two are not
	// silently the same function.
	abcSHA2_256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
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
