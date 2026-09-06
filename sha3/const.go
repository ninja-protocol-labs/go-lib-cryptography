// Package sha3 is the public API for FIPS 202: the SHA-3 hash functions,
// one per file with a Digest type each, and the SHAKE and cSHAKE
// extendable-output functions in shake.go.
//
// Like sha2, this is a thin wrapper over the standard library
// (crypto/sha3) that deliberately adds nothing to it — see sha2's doc for
// why the wrapper exists at all. Its HashN and NewN mirror sha2's, so that
// sha2.Hash256 and sha3.Hash256 are the two functions a caller is actually
// choosing between — and, because each returns its own package's Digest256,
// one cannot be passed where the other belongs.
//
// # SHA-3 is not SHA-2's successor
//
// SHA-3 was standardized as an alternative to SHA-2, not a replacement:
// SHA-2 is not broken, and on hardware with SHA-256 instructions — most
// current x86-64 and arm64 — SHA-256 is considerably faster than
// SHA3-256, which has no such support. Reach for SHA-3 when a protocol
// specifies it, when a sponge's resistance to length extension matters,
// or when SHAKE's caller-chosen output length is what the construction
// needs. Not on the assumption that a higher number is a stronger hash.
//
// # SHA-3 is not Keccak-256
//
// SHA3-256 and Ethereum's Keccak-256 run the same permutation and differ
// in a single padding byte, which makes their digests entirely unrelated
// for the same input. Anything targeting Ethereum wants the keccak
// package, not this one — and a mix-up will not look like a bug until
// something on the other side rejects a hash.
//
// # Length extension
//
// The sponge absorbs into, and squeezes from, a state larger than its
// output, so none of the functions here are length-extendable the way
// SHA-256 is. A raw SHA-3 or SHAKE over secret ∥ message is therefore not
// trivially forgeable. HMAC still works and is still fine; KMAC (SP
// 800-185, not implemented here) is FIPS 202's own answer.
package sha3

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

	// BlockSizeSHAKE128 and BlockSizeSHAKE256 are the two SHAKE rates:
	// the 200-byte state minus twice the security level.
	BlockSizeSHAKE128 = stateSize - 2*16
	BlockSizeSHAKE256 = stateSize - 2*32
)

// stateSize is the Keccak-f[1600] permutation's state, in bytes. Rate plus
// capacity always adds up to this.
const stateSize = 200
