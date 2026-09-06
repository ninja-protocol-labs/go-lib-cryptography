// Package bn254 is the BN254 curve: the two source groups G1 and G2,
// the target group 𝔾ₜ, the pairing between them, hash-to-curve and
// multi-scalar multiplication.
//
// It is arithmetic only. BLS signatures over this curve are in bn254bls,
// ECDSA in bn254ecdsa, EdDSA over Baby Jubjub in
// bn254edwards, and the algebraic hashes over its scalar field in
// bn254mimc and bn254poseidon2.
//
// gnark-crypto's types never appear in this package's API — points and
// field elements go in and out as fixed-size arrays — so that changing the
// backend is not a breaking change for callers.
package bn254

const (
	// ScalarLen is the byte length of a scalar modulo r, the order of G1,
	// G2 and 𝔾ₜ. Every scalar this package's multiplication takes is this
	// wide.
	ScalarLen = 32

	// G1CompressedLen and G2CompressedLen are the byte lengths of a
	// compressed point in each source group.
	G1CompressedLen = 32
	G2CompressedLen = 64

	// GTLen is a 𝔾ₜ element: 12 𝔽p coordinates.
	GTLen = 12 * 32
)
