// Package ripemd160 is the public API for the RIPEMD-160 hash function.
//
// # This is a legacy hash
//
// RIPEMD-160 is here because protocols designed before about 2010 specify
// it and cannot change, not because it is a good choice today. Do not
// reach for it in a new design: sha2's SHA-256 or blake3 is what you
// want.
//
// The concrete reason it survives is Bitcoin, whose addresses are built
// on RIPEMD160(SHA256(x)) — chosen for a 160-bit identifier shorter than
// SHA-256's, and one that does not rest on a single hash's design. Every
// chain and wallet format descended from it inherits the choice.
//
// # Security
//
// No practical collision on full RIPEMD-160 has been published, but a
// 160-bit digest caps collision resistance at 80 bits by the birthday
// bound alone — below what any current design should target, and the same
// arithmetic that retired SHA-1. It remains acceptable where it serves as
// a second-preimage-resistant identifier over an input that is already a
// hash, as in the Bitcoin construction above, and unacceptable as a
// general-purpose collision-resistant hash.
//
// # Implementation
//
// Built on golang.org/x/crypto/ripemd160, which is itself marked
// deprecated and states it will not receive an optimized implementation.
// Go has no other maintained RIPEMD-160, and hand-writing one here would
// be worse than importing that. Expect it to be slow relative to every
// other hash in this module.
//
// Importing this package also registers crypto.RIPEMD160 in the standard
// library's hash registry, a side effect of the underlying package's init.
//
// Upstream provides only a streaming hash.Hash, so Sum below is this
// package's, written to match the shape every other hash here has.
//
// # No Hash160
//
// The RIPEMD160(SHA256(x)) construction is Bitcoin protocol policy, not a
// property of this hash, so it belongs in a library that knows about
// Bitcoin rather than here — the same reason secp256k1 in this module
// does not carry BIP-340's tagged hashes. Compose it from sha2.Sum256 and
// Sum at the call site.
//
// # Length extension
//
// RIPEMD-160 is a Merkle-Damgård construction whose digest is its whole
// final state, so it is length-extendable: never use it as a raw MAC, use
// HMAC (crypto/hmac).
package ripemd160

import "golang.org/x/crypto/ripemd160"

const (
	// Size is the byte length of a RIPEMD-160 digest.
	Size = ripemd160.Size

	// BlockSize is the byte length of the compression function's input
	// block. It is what HMAC pads its key to, and the granularity a
	// streaming hash absorbs at.
	BlockSize = ripemd160.BlockSize
)
