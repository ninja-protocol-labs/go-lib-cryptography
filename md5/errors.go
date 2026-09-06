package md5

import "errors"

// ErrInvalidDigest means bytes handed to DigestFromBytes were not Size
// long. There is nothing else to check: every string of the right length
// is a possible MD5 digest.
var ErrInvalidDigest = errors.New("md5: invalid digest")
