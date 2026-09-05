package mimcbls12381

import "errors"

// Sentinel errors.
var (
	// ErrNotCanonical means an Element's bytes do not encode a value below
	// r, BLS12-381's scalar field order. Every Element is 32 bytes, but not
	// every 32 bytes is a field element: the top values are unrepresentable,
	// and silently reducing them would map two different inputs to the same
	// element and so to the same hash.
	ErrNotCanonical = errors.New("mimcbls12381: element is not a canonical field element")

	// ErrNoInput means a digest was taken over nothing.
	//
	// The library underneath returns the zero element in that case — its
	// initial state, unchanged — which is a valid-looking digest
	// indistinguishable from an uninitialised value, and gnark's own source
	// carries a TODO questioning it. Hashing nothing is a bug at the call
	// site far more often than it is intent, so this reports it.
	ErrNoInput = errors.New("mimcbls12381: no elements to hash")
)
