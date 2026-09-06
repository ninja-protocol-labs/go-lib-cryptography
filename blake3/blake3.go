package blake3

import (
	"hash"

	"lukechampine.com/blake3"
)

// New returns a streaming BLAKE3 hash producing size bytes. size must be
// at least 1; there is no upper bound, since every length is a prefix of
// the same stream.
//
// It returns a hash.Hash rather than a Digest because the length is the
// caller's, which is what this module's fixed-size convention reserves a
// slice for. For an output length not known in advance, or one large
// enough that buffering it is wasteful, use NewXOF instead.
func New(size int) (hash.Hash, error) {
	if size < 1 {
		return nil, ErrInvalidSize
	}
	return blake3.New(size, nil), nil
}

// NewKeyed returns a streaming keyed BLAKE3 hash producing size bytes.
func NewKeyed(size int, key [KeyLen]byte) (hash.Hash, error) {
	if size < 1 {
		return nil, ErrInvalidSize
	}
	return blake3.New(size, key[:]), nil
}
