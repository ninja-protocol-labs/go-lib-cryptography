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

import "golang.org/x/crypto/blake2b"

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
