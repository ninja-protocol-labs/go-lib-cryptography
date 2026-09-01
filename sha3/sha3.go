package sha3

import (
	"crypto/sha3"
	"hash"
)

// The fixed-output half of FIPS 202. Every digest here is the same Keccak
// permutation over a 200-byte state, differing only in how much of that
// state is exposed as the rate — which is why, unlike SHA-2, a longer
// digest means a smaller block and a slower hash.

const (
	// Size224, Size256, Size384 and Size512 are the byte lengths of the
	// corresponding SHA-3 digests.
	Size224 = 28
	Size256 = 32
	Size384 = 48
	Size512 = 64

	// BlockSize224, BlockSize256, BlockSize384 and BlockSize512 are the
	// sponge's rate for each digest length: the 200-byte state minus twice
	// the digest length, the remainder being the capacity an attacker
	// never sees.
	BlockSize224 = stateSize - 2*Size224
	BlockSize256 = stateSize - 2*Size256
	BlockSize384 = stateSize - 2*Size384
	BlockSize512 = stateSize - 2*Size512
)

// stateSize is the Keccak-f[1600] permutation's state, in bytes. Rate plus
// capacity always adds up to this.
const stateSize = 200

// Sum224 returns the SHA3-224 digest of data.
func Sum224(data []byte) [Size224]byte {
	return sha3.Sum224(data)
}

// Sum256 returns the SHA3-256 digest of data. This is FIPS 202's SHA-3,
// not Ethereum's Keccak-256 — see the package doc.
func Sum256(data []byte) [Size256]byte {
	return sha3.Sum256(data)
}

// Sum384 returns the SHA3-384 digest of data.
func Sum384(data []byte) [Size384]byte {
	return sha3.Sum384(data)
}

// Sum512 returns the SHA3-512 digest of data.
func Sum512(data []byte) [Size512]byte {
	return sha3.Sum512(data)
}

// New224 returns a streaming SHA3-224 hash, for data that does not arrive
// in one piece. Its Sum appends to the slice it is given, unlike Sum224's
// array return.
func New224() hash.Hash {
	return sha3.New224()
}

// New256 returns a streaming SHA3-256 hash.
func New256() hash.Hash {
	return sha3.New256()
}

// New384 returns a streaming SHA3-384 hash.
func New384() hash.Hash {
	return sha3.New384()
}

// New512 returns a streaming SHA3-512 hash.
func New512() hash.Hash {
	return sha3.New512()
}
