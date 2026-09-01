package sha2

import (
	"crypto/sha512"
	"hash"
)

// Size512_256 is the byte length of a SHA-512/256 digest.
const Size512_256 = sha512.Size256

// Sum512_256 returns the SHA-512/256 digest of data — the same length as
// SHA-256, from the 64-bit compression function, and not vulnerable to
// length extension because most of the state is withheld.
//
// Prefer it over Sum256 where nothing external fixes the choice and the
// hardware has no SHA-256 instructions.
func Sum512_256(data []byte) [Size512_256]byte {
	return sha512.Sum512_256(data)
}

// New512_256 returns a streaming SHA-512/256 hash, for data that does not
// arrive in one piece. Its Sum appends to the slice it is given, unlike
// Sum512_256's array return.
func New512_256() hash.Hash {
	return sha512.New512_256()
}
