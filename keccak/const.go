// Package keccak is the public API for the original Keccak hash
// functions — the ones Ethereum uses, not FIPS 202's SHA-3.
//
// # Why this is a separate package from sha3
//
// Keccak won the SHA-3 competition in 2012. Before publishing FIPS 202 in
// 2015, NIST changed the domain-separation byte appended to the message:
// Keccak pads with 0x01, SHA-3 pads with 0x06. That is the entire
// difference — same permutation, same rate, same capacity, same
// everything else. It is also enough to make the two produce completely
// unrelated digests for the same input.
//
// Ethereum had already shipped against the pre-standardization version
// and did not follow the change, so what its yellow paper, its EVM's
// KECCAK256 opcode, its address derivation, and every ABI selector call
// "keccak256" is this package, not sha3. A mix-up will not fail to
// compile and will not fail on length: it will simply produce a hash the
// other side rejects, or an address that belongs to nobody.
//
// # What is here
//
// Only Keccak-256 and Keccak-512. FIPS 202 defines four digest lengths,
// but only these two survived as legacy Keccak in the Go ecosystem —
// there is no Keccak-224 or Keccak-384 to wrap, and no demand for one.
// If you find yourself wanting the other lengths, you almost certainly
// want sha3.
//
// # Implementation
//
// Built on golang.org/x/crypto/sha3's NewLegacyKeccak256 and
// NewLegacyKeccak512. Since Go 1.24 put SHA-3 in the standard library,
// legacy Keccak is the only reason that package still exists — the rest
// of it forwards to crypto/sha3.
//
// Upstream offers a streaming hash.Hash and no one-shot function, so
// Hash256 and Hash512 here are this package's own, written to match the
// shape every other hash in this module has: a Digest type per length, so
// that a Keccak-256 digest cannot be passed where a SHA3-256 one belongs.
//
// # Length extension
//
// Keccak is a sponge, like SHA-3, so it is not length-extendable the way
// SHA-256 is. Use HMAC for a MAC regardless.
package keccak

const (
	// Size256 is the byte length of a Keccak-256 digest.
	Size256 = 32

	// Size512 is the byte length of a Keccak-512 digest.
	Size512 = 64

	// BlockSize256 and BlockSize512 are the sponge's rate for each digest
	// length: the 200-byte state minus twice the digest length. Identical
	// to sha3's rates at the same lengths — the padding byte is the only
	// thing that differs between the two packages.
	BlockSize256 = stateSize - 2*Size256
	BlockSize512 = stateSize - 2*Size512
)

// stateSize is the Keccak-f[1600] permutation's state, in bytes.
const stateSize = 200
