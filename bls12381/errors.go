package bls12381

import "errors"

// Sentinel errors. Verify functions return bool, not error, so they need
// no sentinel of their own — the same convention used throughout this
// module (see secp256k1/errors.go).
var (
	// ErrInvalidPrivateKey means the given bytes do not decode to a valid
	// scalar.
	ErrInvalidPrivateKey = errors.New("bls12381: invalid private key")

	// ErrInvalidPublicKey means the given bytes do not decode to a valid,
	// in-subgroup point — wrong length, bad encoding, not on the curve, or
	// not in the correct prime-order subgroup.
	ErrInvalidPublicKey = errors.New("bls12381: invalid public key")

	// ErrInvalidSignature means the given bytes do not decode to a valid,
	// in-subgroup point.
	ErrInvalidSignature = errors.New("bls12381: invalid signature")

	// ErrAggregateFailed means aggregating public keys or signatures
	// failed: an empty input, or one of the inputs failed to parse.
	ErrAggregateFailed = errors.New("bls12381: aggregation failed")

	// ErrPairingFailed means a Pairing method failed: a malformed point,
	// or (Merge) sessions that were not initialized compatibly.
	ErrPairingFailed = errors.New("bls12381: pairing operation failed")

	// ErrLengthMismatch means two slices that are required to describe the
	// same set of items (points and scalars, public keys and messages) had
	// different lengths.
	ErrLengthMismatch = errors.New("bls12381: mismatched input lengths")
)
