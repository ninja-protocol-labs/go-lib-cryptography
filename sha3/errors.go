package sha3

import "errors"

// Sentinel errors. The digest and one-shot XOF functions cannot fail; only
// a misuse of the streaming XOF can.
var (
	// ErrWriteAfterRead means Write was called on a SHAKE that has already
	// produced output. The sponge switched from absorbing to squeezing at
	// the first Read, and absorbing into a squeezing sponge would produce
	// a stream no other implementation agrees with.
	ErrWriteAfterRead = errors.New("sha3: write to a SHAKE that has already been read")
)
