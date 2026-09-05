package argon2

import "errors"

// Sentinel errors for the parameters this package checks.
//
// Every one of them exists because the alternative is a panic. The
// underlying library's functions return no error at all, so an invalid
// parameter takes down the process rather than being reported — from a
// derivation whose inputs typically come from a stored parameter set or a
// config file, which is exactly where a bad value shows up.
var (
	// ErrInvalidTime means the pass count is below 1. The library panics
	// with "argon2: number of rounds too small".
	ErrInvalidTime = errors.New("argon2: time below 1")

	// ErrInvalidThreads means the parallelism is below 1. The library
	// panics with "argon2: parallelism degree too low".
	ErrInvalidThreads = errors.New("argon2: threads below 1")

	// ErrInvalidKeyLen means the requested key length is below 1. This one
	// is not even a deliberate panic: the library asks BLAKE2b for a
	// zero-length digest, discards the error that comes back, and then
	// writes to the nil hash — a nil dereference several frames down from
	// anything the caller wrote.
	ErrInvalidKeyLen = errors.New("argon2: key length below 1")
)
