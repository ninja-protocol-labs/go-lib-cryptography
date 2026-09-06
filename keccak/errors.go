package keccak

import "errors"

// ErrInvalidDigest means bytes handed to a DigestNNNFromBytes were not that
// digest's length. There is nothing else to check: every string of the
// right length is a possible Keccak digest.
var ErrInvalidDigest = errors.New("keccak: invalid digest")
