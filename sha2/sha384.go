package sha2

import (
	"crypto/sha512"
	"hash"
)

// Size384 is the byte length of a SHA-384 digest.
const Size384 = sha512.Size384

// Sum384 returns the SHA-384 digest of data.
//
// SHA-384 is SHA-512 truncated to 384 bits from a different initial
// state. Unlike SHA-512/224 and SHA-512/256 it withholds only a quarter
// of the state, which is not enough to stop a length-extension attack —
// treat it as extendable, like SHA-512 itself.
func Sum384(data []byte) [Size384]byte {
	return sha512.Sum384(data)
}

// New384 returns a streaming SHA-384 hash, for data that does not arrive
// in one piece. Its Sum appends to the slice it is given, unlike Sum384's
// array return.
func New384() hash.Hash {
	return sha512.New384()
}
