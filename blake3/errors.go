package blake3

import "errors"

// Sentinel errors. Only the variable-size constructors can fail: keys are
// fixed-size arrays, so a wrong-sized key is a compile error rather than
// a runtime one, and the fixed-size Sum functions cannot fail at all.
var (
	// ErrInvalidSize means a requested output length is below 1. BLAKE3
	// has no upper bound — its output is a stream — so this is the only
	// size that can be wrong.
	ErrInvalidSize = errors.New("blake3: output size below 1")

	// ErrWriteAfterRead means Write was called on an XOF that has already
	// produced output. The stream is committed at the first Read,
	// and absorbing into it afterwards would produce bytes no other
	// implementation agrees with.
	ErrWriteAfterRead = errors.New("blake3: write to an XOF that has already been read")
)
