package pbkdf2

import "errors"

// Sentinel errors for the parameters this package checks itself. A key
// length beyond what the construction can produce is reported by the
// standard library instead, with its own message — computing that bound
// needs the hash's output size, and duplicating the check here would only
// add a second place to keep correct.
var (
	// ErrInvalidIterations means the iteration count is below 1. RFC 8018
	// defines c as a positive integer, and the standard library does not
	// enforce it: with a count of zero or less its loop simply never runs,
	// so the result is silently identical to a single iteration. A count
	// that arrived as zero from a config file would then produce the
	// weakest possible derivation without anything failing.
	ErrInvalidIterations = errors.New("pbkdf2: iteration count below 1")

	// ErrInvalidKeyLen means the requested key length is below 1.
	ErrInvalidKeyLen = errors.New("pbkdf2: key length below 1")
)
