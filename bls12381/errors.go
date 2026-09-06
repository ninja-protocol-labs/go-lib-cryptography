package bls12381

import "errors"

var (
	// ErrInvalidPoint means bytes handed to a *FromCompressed function are
	// not a valid encoding of a point in the prime-order subgroup.
	ErrInvalidPoint = errors.New("bls12381: invalid point")

	// ErrHashToCurveFailed is only reachable with a domain separation tag
	// longer than 255 bytes, which RFC 9380's expand_message_xmd cannot
	// encode.
	ErrHashToCurveFailed = errors.New("bls12381: hash to curve failed")

	ErrPairingFailed  = errors.New("bls12381: pairing failed")
	ErrLengthMismatch = errors.New("bls12381: length mismatch")
)
