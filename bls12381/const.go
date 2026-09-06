// Package bls12381 is the BLS12-381 curve: the two source groups G1 and
// G2, the target group 𝔾ₜ, the pairing between them, hash-to-curve and
// multi-scalar multiplication.
//
// It is arithmetic only. BLS signatures over this curve are in
// bls12381bls, EdDSA over its companion twisted Edwards curve (Jubjub) in
// bls12381edwards, and the algebraic hashes over its scalar field in
// bls12381mimc and bls12381poseidon2.
//
// gnark-crypto's types never appear in this package's API — points and
// field elements go in and out as fixed-size arrays — so that changing
// the backend is not a breaking change for callers.
package bls12381

const (
	// ScalarLen is the byte length of a scalar modulo r, the order of G1,
	// G2 and 𝔾ₜ. Every scalar this package's multiplication takes is this
	// wide.
	ScalarLen = 32

	// G1CompressedLen and G2CompressedLen are the byte lengths of a
	// compressed point in each source group.
	G1CompressedLen = 48
	G2CompressedLen = 96

	// GTLen is a 𝔾ₜ element: 12 𝔽p coordinates of 48 bytes.
	GTLen = 12 * 48
)
