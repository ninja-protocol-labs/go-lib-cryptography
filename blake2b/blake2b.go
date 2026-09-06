package blake2b

import (
	"hash"

	"golang.org/x/crypto/blake2b"
)

// New returns a streaming BLAKE2b hash producing size bytes, keyed by key.
// size must be in [1, MaxSize]; pass nil for key to go unkeyed.
//
// Every size is a distinct function, not a truncation of a longer one, so
// New(32, nil) agrees with Hash256 and not with Hash512's first 32 bytes.
// It returns a hash.Hash rather than a Digest because the length is the
// caller's, which is what this module's fixed-size convention reserves a
// slice for.
func New(size int, key []byte) (hash.Hash, error) {
	return newSized(size, key)
}

// newSized validates before handing off, so that the two ways to get this
// wrong are told apart by this package's own sentinels rather than
// collapsed into whatever upstream returns.
func newSized(size int, key []byte) (hash.Hash, error) {
	if size < 1 || size > MaxSize {
		return nil, ErrInvalidSize
	}
	if len(key) > MaxKeyLen {
		return nil, ErrKeyTooLong
	}
	h, err := blake2b.New(size, key)
	if err != nil {
		return nil, err
	}
	return h, nil
}
