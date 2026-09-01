package sha2

import (
	"crypto/sha256"
	"hash"
)

// Size224 is the byte length of a SHA-224 digest.
const Size224 = sha256.Size224

// Sum224 returns the SHA-224 digest of data.
//
// SHA-224 is SHA-256 truncated to 224 bits from a different initial
// state, so it is no faster than SHA-256 — it exists for protocols that
// specify it. If a shorter digest is wanted for its own sake, Sum512_256
// is usually the better choice.
func Sum224(data []byte) [Size224]byte {
	return sha256.Sum224(data)
}

// New224 returns a streaming SHA-224 hash, for data that does not arrive
// in one piece. Its Sum appends to the slice it is given, unlike Sum224's
// array return.
func New224() hash.Hash {
	return sha256.New224()
}
