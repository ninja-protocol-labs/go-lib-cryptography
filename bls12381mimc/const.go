// Package bn254mimc is the public API for MiMC over BLS12-381's scalar field.
//
// # This is not a byte hash
//
// Every other hash in this module takes bytes and returns bytes. MiMC does
// not: it is an arithmetic hash, defined over a prime field, and its input
// is a sequence of field elements. That is the whole reason it exists —
// its round function is a handful of field multiplications, which a
// zero-knowledge circuit can prove for a fraction of what proving SHA-256
// would cost. Outside a circuit it is slower than SHA-256 and has had far
// less cryptanalysis; there is no reason to reach for it unless a proof
// system is involved.
//
// Input is one field element per argument, 32 canonical big-endian bytes
// each. The canonicality is not decoration: 32 bytes has more values than
// the field has elements, and quietly reducing an out-of-range one would
// map two distinct inputs to the same hash. Anything out of range is
// rejected with ErrNotCanonical rather than reduced — including the bytes
// handed to DigestFromBytes, since a digest is a field element too.
//
// To hash arbitrary bytes, map them into the field first — with a
// hash-to-field construction, not by chopping them into 32-byte pieces and
// hoping each lands in range.
//
// # The curve is part of the function
//
// MiMC over BLS12-381's 𝔽r and MiMC over BN254's 𝔽r are different
// functions over different fields, with different round constants. They
// share no digests and cannot be substituted for one another, which is why
// the curve is in this package's name rather than in a parameter.
//
// # Which parameterisation
//
// MiMC is a family, not a single function. This one is gnark-crypto's: the
// Miyaguchi-Preneel mode over the x⁵ S-box, 110 rounds, with constants
// derived from the seed string "seed". It is what gnark's circuits verify
// against, and it interoperates with those and with nothing else in
// particular — MiMC as used by circomlib and by various rollups is a
// different parameterisation and produces different digests.
//
// There is deliberately no way to change the parameters here. Choosing
// them is how the ecosystem ended up with a dozen mutually incompatible
// MiMCs; a library that offers the choice mostly offers a new way to be
// incompatible.
//
// # Two modes
//
// Hash takes any number of elements. Compress takes exactly two, which is
// what a Merkle tree needs at every node — it is Hash of two elements,
// named for the thing it is used for. Hasher is the streaming form, for
// input that does not arrive at once.
//
// # Security
//
// MiMC's security rests on a much smaller body of analysis than SHA-2's,
// and low-degree arithmetic hashes as a class have been the subject of
// active attack work — Gröbner-basis attacks on this shape of construction
// improve periodically. It is the price of being cheap to prove. Do not use
// it as a general-purpose hash outside the circuit that needs it.
package bls12381mimc

import "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

const (
	// ElementLen is the byte length of one field element, and so of every
	// input and output of this package.
	ElementLen = fr.Bytes

	// Size is the byte length of a digest. MiMC's output is a single field
	// element, so it is ElementLen.
	Size = ElementLen

	// BlockSize is the byte length of one absorbed block, again one field
	// element.
	BlockSize = ElementLen
)
