// Package sha3 is the public API for FIPS 202: the SHA-3 hash functions
// in sha3.go, and the SHAKE and cSHAKE extendable-output functions in
// shake.go.
//
// Like sha2, this is a thin wrapper over the standard library
// (crypto/sha3) that deliberately adds nothing to it — see sha2's doc for
// why the wrapper exists at all. Its SumN and NewN mirror sha2's, so that
// sha2.Sum256 and sha3.Sum256 are the two functions a caller is actually
// choosing between.
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
