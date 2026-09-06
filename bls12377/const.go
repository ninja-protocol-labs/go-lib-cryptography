// Package bls12377 is the BLS12-377 curve: the two source groups G1 and G2,
// the target group 𝔾ₜ, the pairing between them, hash-to-curve and
// multi-scalar multiplication.
//
// It is arithmetic only. BLS signatures over this curve are in bls12377bls,
// ECDSA in bls12377ecdsa, EdDSA over its companion twisted Edwards curve in
// bls12377edwards, and the algebraic hashes over its scalar field in
// bls12377mimc and bls12377poseidon2.
//
// gnark-crypto's types never appear in this package's API — points and
// field elements go in and out as fixed-size arrays — so that changing the
// backend is not a breaking change for callers.
package bls12377

const (
	// ScalarLen is the byte length of a scalar modulo r, the order of G1,
	// G2 and 𝔾ₜ. Every scalar this package's multiplication takes is this
	// wide.
	ScalarLen = 32

	// G1CompressedLen and G2CompressedLen are the byte lengths of a
	// compressed point in each source group.
	G1CompressedLen = 48
	G2CompressedLen = 96

	// GTLen is a 𝔾ₜ element: 12 𝔽p coordinates.
	GTLen = 12 * 48
)
