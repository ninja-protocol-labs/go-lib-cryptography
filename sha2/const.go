// Package sha2 is the public API for the SHA-2 family (FIPS 180-4). Each
// digest gets its own file and its own Digest type: sha224.go, sha256.go,
// sha384.go, sha512.go, sha512_224.go and sha512_256.go.
//
// This is a thin wrapper over crypto/sha256 and crypto/sha512, and
// deliberately adds nothing to them: the standard library's shape — a
// one-shot function per digest and a NewN returning a streaming
// hash.Hash — is already close to what this module's own conventions
// produce. The one-shot returns a DigestN rather than a bare array, so
// that two digests of the same length cannot be swapped for each other. It exists so that every hash in this module is reached
// through one import root, including the ones the standard library does
// not provide (keccak, blake2b, ripemd160, poseidon), and so that
// swapping an implementation later is not a breaking change for callers.
//
// The one place this departs from the standard library is the package
// split. crypto puts SHA-256 and SHA-512 in separate packages; here they
// are one package named for the family, so that it sits alongside sha3 as
// its counterpart and HashN reads the same way in both — sha2.Hash256 and
// sha3.Hash256 are the two functions a caller is actually choosing
// between. Merging any further is not possible: SHA-256 and SHA3-256
// cannot both be Hash256 in one package.
//
// # Two compression functions, six digests
//
// The family is really two constructions. SHA-224 and SHA-256 work on
// 32-bit words in 64-byte blocks; SHA-384, SHA-512 and the two truncated
// SHA-512 variants work on 64-bit words in 128-byte blocks. Within each
// group the members differ only in initial state and output length, which
// is why the two block sizes below are the only family-level constants —
// everything else belongs to one digest and lives in its own file.
//
// On 64-bit hardware the 512 group is faster per byte, absorbing twice as
// much per compression. That makes SHA-512/256 a strictly better SHA-256
// wherever interoperability does not force the choice: same digest
// length, faster, and not vulnerable to length extension. The exception
// is hardware with SHA-256 instructions (most current x86-64 and arm64),
// where SHA-256 wins decisively — measure rather than assume.
//
// # Length extension
//
// SHA-224, SHA-256, SHA-384 and SHA-512 are Merkle-Damgård constructions
// whose digest is their entire final state, so an attacker who knows
// Hash256(secret ∥ m) and len(secret) can compute
// Hash256(secret ∥ m ∥ padding ∥ suffix) without knowing secret. Never use
// a raw hash as a message authentication code: use HMAC (crypto/hmac).
//
// SHA-512/224 and SHA-512/256 withhold most of their state and so are not
// extendable, as sha3's sponge functions are not — but HMAC is still the
// right answer for a MAC.
package sha2

import (
	"crypto/sha256"
	"crypto/sha512"
)

const (
	// BlockSize256 is the input block length shared by SHA-224 and
	// SHA-256. It is what HMAC pads its key to, and the granularity a
	// streaming hash absorbs at.
	BlockSize256 = sha256.BlockSize

	// BlockSize512 is the input block length shared by SHA-384, SHA-512,
	// SHA-512/224 and SHA-512/256 — twice BlockSize256, which is where
	// their throughput advantage on 64-bit hardware comes from.
	BlockSize512 = sha512.BlockSize
)

// Digest lengths. Each is also the length of the matching Digest type.
const (
	Size224     = sha256.Size224
	Size256     = sha256.Size
	Size384     = sha512.Size384
	Size512     = sha512.Size
	Size512_224 = sha512.Size224
	Size512_256 = sha512.Size256
)
