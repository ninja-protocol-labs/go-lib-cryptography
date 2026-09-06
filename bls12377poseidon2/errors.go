package bls12377poseidon2

import "errors"

// Sentinel errors.
var (
	// ErrNotCanonical means an Element's bytes do not encode a value below
	// r, BLS12-377's scalar field order. Every Element is 32 bytes, but not
	// every 32 bytes is a field element: the top values are unrepresentable,
	// and silently reducing them would map two different inputs to the same
	// element and so to the same hash.
	ErrNotCanonical = errors.New("bls12377poseidon2: element is not a canonical field element")

	// ErrNoInput means a digest was taken over nothing.
	//
	// The construction underneath returns its initial state in that case —
	// 32 zero bytes — which is a valid-looking digest indistinguishable from
	// an uninitialised value. Hashing nothing is a bug at the call site far
	// more often than it is intent, so this reports it.
	ErrNoInput = errors.New("bls12377poseidon2: no elements to hash")
)
