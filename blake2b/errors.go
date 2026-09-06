package blake2b

import "errors"

// Sentinel errors. Only the keyed and variable-size constructors can
// fail; the fixed-size unkeyed Hash functions cannot, and return no error.
var (
	// ErrInvalidDigest means bytes handed to a DigestNNNFromBytes were not
	// that digest's length. There is nothing else to check: every string of
	// the right length is a possible BLAKE2b digest.
	ErrInvalidDigest = errors.New("blake2b: invalid digest")

	// ErrKeyTooLong means the key is longer than MaxKeyLen. BLAKE2b takes
	// the key as a prefix block rather than through HMAC's outer/inner
	// padding, so it cannot absorb a key longer than one block half.
	ErrKeyTooLong = errors.New("blake2b: key longer than 64 bytes")

	// ErrInvalidSize means a requested digest size is outside [1,
	// MaxSize]. BLAKE2b's output length is bound into its initial state,
	// so it is a parameter of the function, not a truncation of a longer
	// digest — a 32-byte New is not Sum512 cut short.
	ErrInvalidSize = errors.New("blake2b: digest size outside [1, 64]")

	// ErrXOFSizeTooLarge means a BLAKE2Xb output length exceeds
	// MaxXOFSize. Use OutputLengthUnknown for a stream with no length
	// fixed in advance.
	ErrXOFSizeTooLarge = errors.New("blake2b: XOF output length too large")

	// ErrWriteAfterRead means Write was called on an XOF that has already
	// produced output. Absorbing into a squeezing state would produce a
	// stream no other implementation agrees with.
	ErrWriteAfterRead = errors.New("blake2b: write to an XOF that has already been read")
)
