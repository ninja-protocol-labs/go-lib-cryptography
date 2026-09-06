// Package bn254poseidon2 is the public API for Poseidon2 over BN254's
// scalar field.
//
// # This is Poseidon2, not Poseidon
//
// They are different functions. Poseidon2 (Grassi, Khovratovich, Schofnegger,
// 2023) rebuilds Poseidon's linear layer to cut the number of constraints,
// and uses different round constants; it shares no digests with the original.
//
// That matters more here than the SHA-3/Keccak distinction does, because
// "Poseidon" in the wild is not one function either: circomlib, Polygon and
// StarkNet each ship their own parameter choices, and none of them agree
// with each other or with this. A hash produced by a circom circuit will
// not verify here. The package is named poseidon2 so that nobody has to
// discover that at integration time.
//
// # This is not a byte hash
//
// Like bn254mimc and unlike every other hash in this module, Poseidon2 is
// an arithmetic hash: it is defined over a prime field and its input is a
// sequence of field elements. That is what makes it cheap to prove — its
// round function is field multiplications a circuit can express directly,
// where SHA-256's bit operations are not. Outside a circuit there is no
// reason to prefer it.
//
// Input is one field element per argument, 32 canonical big-endian bytes
// each. Anything not below r is rejected with ErrNotCanonical rather than
// reduced, since reducing would map two distinct inputs to one digest.
// That applies to the bytes handed to DigestFromBytes too, since a digest
// is a field element itself.
//
// Taking elements rather than bytes also closes a hazard gnark-crypto
// documents in the construction underneath: its Merkle-Damgard wrapper
// zero-pads a short final block instead of applying real padding, so for
// arbitrary byte input the digest of x and of x followed by zeros can be
// the same. With input measured in whole field elements there is no partial
// block and no such ambiguity.
//
// # Compress and Sum are different functions
//
// Unlike bn254mimc, where compressing two elements is just hashing two
// elements, Poseidon2 has a genuine 2-to-1 compression function, and the
// arbitrary-length hash is Merkle-Damgard built on top of it starting from
// an all-zero initial state. So:
//
//	Compress(a, b) != Hash(a, b)         // Hash is Compress(Compress(IV, a), b)
//
// Use Compress for the internal nodes of a Merkle tree — that is what it is
// for, and it is one permutation call rather than two. Use Hash for a digest
// over a sequence.
//
// # Which parameters
//
// The permutation is width 2, with 6 full rounds and 50 partial rounds:
// gnark-crypto's defaults for this curve, and what its circuits verify
// against. There is deliberately no way to change them. Choosing parameters
// is how this family ended up mutually incompatible; a library offering the
// choice mostly offers a new way to be incompatible.
//
// # Security
//
// Poseidon2 rests on a far smaller body of cryptanalysis than SHA-2, and
// low-degree arithmetic hashes as a class are under active attack work —
// Gröbner-basis attacks on this shape improve periodically. That is the
// price of being cheap to prove. Do not use it as a general-purpose hash
// outside the circuit that needs it.
package bn254poseidon2

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

const (
	// ElementLen is the byte length of one field element, and so of every
	// input and output of this package.
	ElementLen = fr.Bytes

	// Size is the byte length of a digest: one field element.
	Size = ElementLen

	// BlockSize is the byte length of one absorbed block, again one field
	// element.
	BlockSize = ElementLen

	// Width is the permutation's state width in field elements. It is 2,
	// which is what makes Compress a 2-to-1 function.
	Width = 2

	// FullRounds and PartialRounds are the permutation's round counts for
	// this curve. They are here to be read, not chosen — see the package
	// doc on why the parameters are fixed.
	FullRounds    = 6
	PartialRounds = 50
)
