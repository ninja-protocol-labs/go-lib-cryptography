package sha2

import (
	"crypto/sha512"
	"hash"
)

// Size512 is the byte length of a SHA-512 digest.
const Size512 = sha512.Size

// Sum512 returns the SHA-512 digest of data.
//
// On 64-bit hardware without SHA-256 instructions this is the fastest
// member of the family per byte. It is length-extendable: see the package
// doc before using it over anything secret.
func Sum512(data []byte) [Size512]byte {
	return sha512.Sum512(data)
}

// New512 returns a streaming SHA-512 hash, for data that does not arrive
// in one piece. Its Sum appends to the slice it is given, unlike Sum512's
// array return.
func New512() hash.Hash {
	return sha512.New()
}
