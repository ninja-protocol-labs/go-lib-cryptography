package scrypt

import "errors"

// Sentinel errors for the parameters this package checks itself. N, r and p
// are validated by the underlying library, which returns descriptive errors
// for them; duplicating those checks here would only add a second place to
// keep correct.
var (
	// ErrInvalidKeyLen means the requested key length is below 1.
	//
	// This check is this package's addition, and it exists because the
	// alternative is a panic rather than an error: the underlying library
	// does not validate the key length, and the PBKDF2 call it finishes
	// with panics on the error the standard library returns for a
	// non-positive one. A key length that arrived as zero from
	// configuration would take down the process, from a function whose
	// signature promises an error.
	ErrInvalidKeyLen = errors.New("scrypt: key length below 1")
)
