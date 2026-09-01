// Package blake3 is the public API for BLAKE3, in all three of the modes
// its specification defines: plain hashing here, keyed hashing here, and
// key derivation in derive.go. The extendable output every mode shares
// lives in xof.go.
//
// BLAKE3 is BLAKE2's successor, built on a reduced-round core arranged as
// a binary tree over 1024-byte chunks. The tree is what makes it fast —
// chunks hash independently, so the work parallelizes and vectorizes —
// and it is also why its output is unbounded: the root of the tree is a
// stream, and a "digest" is just its first N bytes.
//
// # One function, three modes
//
// The mode is bound into the compression function's flags, so the three
// are domain-separated by construction and never produce related output:
//
//   - hash: Sum256, Sum512, New256, New512, NewXOF.
//   - keyed_hash: SumKeyed256, SumKeyed512, NewKeyed*, NewKeyedXOF. A PRF
//     over a 32-byte key, usable directly as a MAC — no HMAC wrapper, and
//     no length-extension weakness to work around.
//   - derive_key: DeriveKey and DeriveKeyN, for turning one key into
//     independent subkeys under a context string.
//
// # Every output length is a prefix of the same stream
//
// Unlike BLAKE2b, where the digest length is mixed into the initial state,
// BLAKE3's output length changes nothing about the computation. Sum256(m)
// really is the first 32 bytes of Sum512(m), and of the XOF's stream. Ask
// for whatever length you need without wondering whether the shorter one
// is a different function.
//
// # A 32-byte key, always
//
// Keyed mode takes exactly KeyLen bytes — not "up to", as BLAKE2b does,
// and not "anything, hashed down", as HMAC does. The keyed functions here
// take a [KeyLen]byte array rather than a slice so that a wrong-sized key
// cannot be passed at all; the underlying library panics on one.
//
// To key from a password or from material that is not already 32 uniform
// bytes, run it through a KDF first — or through DeriveKey, if the input
// is itself a strong key.
//
// # Implementation
//
// Built on lukechampine.com/blake3. Chosen over github.com/zeebo/blake3
// after measuring both: on arm64, where neither ships assembly, this one
// hashes bulk input several times faster, and it is past 1.0 where the
// other is not. The two agree on output, as they must.
package blake3

import (
	"hash"

	"lukechampine.com/blake3"
)

const (
	// Size256 and Size512 are the byte lengths of the two conventional
	// digests. BLAKE3's output is unbounded, so these are conventions
	// rather than limits — see New for any other length.
	Size256 = 32
	Size512 = 64

	// BlockSize is the byte length of the compression function's input
	// block.
	BlockSize = 64

	// KeyLen is the byte length of a keyed-mode key, and of a derived key
	// from DeriveKey. Exactly this, never less or more.
	KeyLen = 32

	// ChunkSize is the input each leaf of BLAKE3's tree covers. It is not
	// something a caller passes anywhere; it is here because it explains
	// the shape of everything above — hashing parallelizes at this
	// granularity, and the tree's structure changes at its multiples.
	ChunkSize = 1024
)

// Sum256 returns the first 32 bytes of BLAKE3's output over data.
func Sum256(data []byte) [Size256]byte {
	return blake3.Sum256(data)
}

// Sum512 returns the first 64 bytes of BLAKE3's output over data. Its
// first 32 bytes are exactly Sum256(data).
func Sum512(data []byte) [Size512]byte {
	return blake3.Sum512(data)
}

// SumKeyed256 returns the first 32 bytes of keyed BLAKE3 over data — a
// MAC, with no HMAC wrapper needed.
func SumKeyed256(key [KeyLen]byte, data []byte) [Size256]byte {
	var out [Size256]byte
	h := blake3.New(Size256, key[:])
	h.Write(data)
	h.Sum(out[:0])
	return out
}

// SumKeyed512 returns the first 64 bytes of keyed BLAKE3 over data.
func SumKeyed512(key [KeyLen]byte, data []byte) [Size512]byte {
	var out [Size512]byte
	h := blake3.New(Size512, key[:])
	h.Write(data)
	h.Sum(out[:0])
	return out
}

// New256 returns a streaming BLAKE3 hash producing 32 bytes, for data
// that does not arrive in one piece.
func New256() hash.Hash {
	return blake3.New(Size256, nil)
}

// New512 returns a streaming BLAKE3 hash producing 64 bytes.
func New512() hash.Hash {
	return blake3.New(Size512, nil)
}

// NewKeyed256 returns a streaming keyed BLAKE3 hash producing 32 bytes.
func NewKeyed256(key [KeyLen]byte) hash.Hash {
	return blake3.New(Size256, key[:])
}

// NewKeyed512 returns a streaming keyed BLAKE3 hash producing 64 bytes.
func NewKeyed512(key [KeyLen]byte) hash.Hash {
	return blake3.New(Size512, key[:])
}

// New returns a streaming BLAKE3 hash producing size bytes. size must be
// at least 1; there is no upper bound, since every length is a prefix of
// the same stream.
//
// For an output length not known in advance, or one large enough that
// buffering it is wasteful, use NewXOF instead.
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
