package bn254

import "errors"

var (
	// ErrInvalidPoint means bytes handed to a *FromCompressed function are
	// not a valid encoding of a point in the prime-order subgroup.
	ErrInvalidPoint = errors.New("bn254: invalid point")

	// ErrHashToCurveFailed is only reachable with a domain separation tag
	// longer than 255 bytes, which RFC 9380's expand_message_xmd cannot
	// encode.
	ErrHashToCurveFailed = errors.New("bn254: hash to curve failed")

	ErrPairingFailed  = errors.New("bn254: pairing failed")
	ErrLengthMismatch = errors.New("bn254: length mismatch")
)
