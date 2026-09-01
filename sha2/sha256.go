package sha2

import (
	"crypto/sha256"
	"hash"
)

// Size256 is the byte length of a SHA-256 digest.
const Size256 = sha256.Size

// Sum256 returns the SHA-256 digest of data.
//
// This is the family's default, and the one with dedicated instructions
// on most current hardware. Note that it is length-extendable: see the
// package doc before using it over anything secret.
func Sum256(data []byte) [Size256]byte {
	return sha256.Sum256(data)
}

// New256 returns a streaming SHA-256 hash, for data that does not arrive
// in one piece. Its Sum appends to the slice it is given, unlike Sum256's
// array return.
func New256() hash.Hash {
	return sha256.New()
}
