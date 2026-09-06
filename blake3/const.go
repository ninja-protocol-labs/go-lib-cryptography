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

const (
	// Size256 and Size512 are the two digest lengths with named
	// constructors. BLAKE3's output is a stream of any length, so these are
	// conveniences rather than limits — see New for any other length.
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
