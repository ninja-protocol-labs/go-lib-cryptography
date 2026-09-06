package ripemd160

import "errors"

// ErrInvalidDigest means bytes handed to DigestFromBytes were not Size
// long. There is nothing else to check: every string of the right length
// is a possible RIPEMD-160 digest.
var ErrInvalidDigest = errors.New("ripemd160: invalid digest")
