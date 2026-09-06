package sha2

import "errors"

// ErrInvalidDigest means bytes handed to a DigestNNNFromBytes were not that
// digest's length. There is nothing else to check: every string of the
// right length is a possible SHA-2 digest.
var ErrInvalidDigest = errors.New("sha2: invalid digest")
