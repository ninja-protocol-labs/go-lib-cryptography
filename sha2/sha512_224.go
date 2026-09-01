package sha2

import (
	"crypto/sha512"
	"hash"
)

// Size512_224 is the byte length of a SHA-512/224 digest.
const Size512_224 = sha512.Size224

// Sum512_224 returns the SHA-512/224 digest of data — the same length as
// SHA-224, from the 64-bit compression function, and not vulnerable to
// length extension.
func Sum512_224(data []byte) [Size512_224]byte {
	return sha512.Sum512_224(data)
}

// New512_224 returns a streaming SHA-512/224 hash, for data that does not
// arrive in one piece. Its Sum appends to the slice it is given, unlike
// Sum512_224's array return.
func New512_224() hash.Hash {
	return sha512.New512_224()
}
