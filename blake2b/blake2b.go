// Package blake2b is the public API for BLAKE2b (RFC 7693) and its
// extendable-output variant BLAKE2Xb, which lives in xof.go.
//
// BLAKE2b is a SHA-3 finalist's successor, built on the BLAKE stream
// cipher core rather than a sponge. It is typically faster than SHA-256
// on 64-bit hardware without SHA extensions, and faster than SHA-3
// everywhere. Its two distinguishing features over the SHA family are
// below.
//
// # A digest size is a parameter, not a truncation
//
// BLAKE2b's output length is bound into its initial state, so a 32-byte
// digest is a different function from the first 32 bytes of a 64-byte
// one. Sum256(m) and Sum512(m)[:32] are unrelated values. This is the
// same relationship SHA-512/256 has to SHA-512, and the opposite of what
// truncating a hash yourself would give you.
//
// # Keying replaces HMAC
//
// BLAKE2b takes an optional key directly, absorbed as a prefix block, and
// the result is a PRF suitable as a MAC. There is no length-extension
// weakness to work around, so HMAC's nested construction buys nothing
// here: SumKeyed256(key, m) is the MAC, not HMAC(BLAKE2b, key, m).
//
// A key is at most MaxKeyLen bytes. Unlike HMAC, longer keys are rejected
// rather than silently hashed down, which is why the keyed functions
// return an error where the unkeyed ones do not.
//
// # Implementation
//
// Built on golang.org/x/crypto/blake2b, which carries AVX2 and NEON
// assembly. Upstream provides unkeyed one-shot sums and keyed streaming
// constructors, but no keyed one-shot; SumKeyed256 and friends below are
// this package's, so that the MAC path has the same shape as everything
// else here — a fixed-size array out.
package blake2b

import (
	"hash"

	"golang.org/x/crypto/blake2b"
)

const (
	// Size256, Size384 and Size512 are the byte lengths of the three
	// standard BLAKE2b digests. Any length in [1, MaxSize] is valid — see
	// New — these are simply the ones with named constructors.
	Size256 = blake2b.Size256
	Size384 = blake2b.Size384
	Size512 = blake2b.Size

	// BlockSize is the byte length of the compression function's input
	// block, the same for every digest size.
	BlockSize = blake2b.BlockSize

	// MaxSize is the largest digest BLAKE2b produces. Longer output needs
	// BLAKE2Xb — see NewXOF.
	MaxSize = blake2b.Size

	// MaxKeyLen is the longest key the keyed functions accept.
	MaxKeyLen = blake2b.Size
)

// Sum256 returns the unkeyed 32-byte BLAKE2b digest of data.
//
// Not the first 32 bytes of Sum512 — see the package doc.
func Sum256(data []byte) [Size256]byte {
	return blake2b.Sum256(data)
}

// Sum384 returns the unkeyed 48-byte BLAKE2b digest of data.
func Sum384(data []byte) [Size384]byte {
	return blake2b.Sum384(data)
}

// Sum512 returns the unkeyed 64-byte BLAKE2b digest of data. This is
// BLAKE2b's full output and the one to use when nothing forces a shorter
// digest.
func Sum512(data []byte) [Size512]byte {
	return blake2b.Sum512(data)
}

// SumKeyed256 returns the 32-byte BLAKE2b digest of data under key — a
// MAC, with no HMAC wrapper needed. key must be at most MaxKeyLen bytes;
// a nil key gives the same result as Sum256.
func SumKeyed256(key, data []byte) ([Size256]byte, error) {
	var out [Size256]byte
	h, err := New256(key)
	if err != nil {
		return out, err
	}
	h.Write(data)
	h.Sum(out[:0])
	return out, nil
}

// SumKeyed384 returns the 48-byte keyed BLAKE2b digest of data.
func SumKeyed384(key, data []byte) ([Size384]byte, error) {
	var out [Size384]byte
	h, err := New384(key)
	if err != nil {
		return out, err
	}
	h.Write(data)
	h.Sum(out[:0])
	return out, nil
}

// SumKeyed512 returns the 64-byte keyed BLAKE2b digest of data. This is
// the MAC to reach for unless something fixes a shorter tag length.
func SumKeyed512(key, data []byte) ([Size512]byte, error) {
	var out [Size512]byte
	h, err := New512(key)
	if err != nil {
		return out, err
	}
	h.Write(data)
	h.Sum(out[:0])
	return out, nil
}

// New256 returns a streaming 32-byte BLAKE2b hash, keyed by key. Pass nil
// for the unkeyed hash.
func New256(key []byte) (hash.Hash, error) {
	return newSized(Size256, key)
}

// New384 returns a streaming 48-byte BLAKE2b hash, keyed by key.
func New384(key []byte) (hash.Hash, error) {
	return newSized(Size384, key)
}

// New512 returns a streaming 64-byte BLAKE2b hash, keyed by key.
func New512(key []byte) (hash.Hash, error) {
	return newSized(Size512, key)
}

// New returns a streaming BLAKE2b hash producing size bytes, keyed by key.
// size must be in [1, MaxSize]; pass nil for key to go unkeyed.
//
// Every size is a distinct function, not a truncation of a longer one, so
// New(32, nil) agrees with Sum256 and not with Sum512's first 32 bytes.
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
