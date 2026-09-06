package sha3

import "errors"

// Sentinel errors. Hashing itself cannot fail; only parsing a digest back
// in, or misusing the streaming XOF, can.
var (
	// ErrInvalidDigest means bytes handed to a DigestNNNFromBytes were not
	// that digest's length. There is nothing else to check: every string of
	// the right length is a possible SHA-3 digest.
	ErrInvalidDigest = errors.New("sha3: invalid digest")

	// ErrWriteAfterRead means Write was called on a SHAKE that has already
	// produced output. The sponge switched from absorbing to squeezing at
	// the first Read, and absorbing into a squeezing sponge would produce
	// a stream no other implementation agrees with.
	ErrWriteAfterRead = errors.New("sha3: write to a SHAKE that has already been read")
)
