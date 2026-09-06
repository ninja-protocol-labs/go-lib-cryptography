// Package bls12377edwards implements EdDSA over the twisted Edwards curve
// embedded in BLS12-377's scalar field 𝔽r — BLS12-377's companion curve,
// the same construction Zcash's Jubjub is for BLS12-381 and Baby Jubjub
// (EIP-2494) is for BLS12-377. Unlike those two it has no widely established
// name of its own; arkworks calls it ed_on_bls12_377 and Aleo calls it
// Edwards BLS12.
//
// It is not BLS12-377. This is a separate curve that takes BLS12-377's
// scalar field as its own base field, which is exactly why it exists: a
// zk-SNARK circuit over BLS12-377 computes natively in 𝔽r, so this
// curve's arithmetic is cheap to prove there while BLS12-377's own 𝔽p
// arithmetic is not. Verifying a signature inside a circuit is the whole
// point; outside one, use ed25519 instead, which is standardised,
// interoperable and faster.
//
// Two things differ from RFC 8032's Ed25519, and both are visible here:
//
//   - There is no built-in message hash. gnark's EdDSA signs a sequence of
//     field elements and computes the Fiat-Shamir challenge H(R, A, M)
//     with a caller-supplied hash — MiMC over 𝔽r in gnark's own circuits,
//     because that is the cheap one to prove. Sign and Verify both take a
//     hash.Hash, and both fail without one. See bls12377mimc.
//   - A private key does not round-trip through its seed. The scalar and
//     the nonce source are derived from the seed and the seed is then
//     discarded, so Bytes returns public key ∥ scalar ∥ nonce source, not
//     the 32 bytes that produced it. Use PrivateKeyFromSeed to regenerate
//     a key deterministically from stored entropy.
//
// These signatures interoperate with gnark's std/signature/eddsa gadget
// and with nothing else.
package bls12377edwards

const (
	// ScalarLen is the byte length of an element of 𝔽r, the field this
	// curve is defined over.
	ScalarLen = 32

	// SeedLen is the byte length of the seed PrivateKeyFromSeed expands
	// into a key pair.
	SeedLen = ScalarLen

	// SeckeyLen is the byte length of a serialized private key:
	// public key ∥ scalar ∥ nonce source.
	SeckeyLen = 3 * ScalarLen

	// PubkeyLen is the byte length of a compressed curve point.
	PubkeyLen = ScalarLen

	// SignatureLen is the byte length of a signature: R ∥ S.
	SignatureLen = 2 * ScalarLen
)
