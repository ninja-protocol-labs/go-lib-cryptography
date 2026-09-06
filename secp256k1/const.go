// Package secp256k1 is the public API for the secp256k1 curve — Bitcoin's
// and Ethereum's — wrapping github.com/decred/dcrd/dcrec/secp256k1/v4.
//
// # Not secp256r1
//
// The names differ by one character and the curves share nothing. secp256k1
// is a Koblitz curve with parameters chosen so they can be derived from
// nothing, which is why it is what the chains use; secp256r1 is NIST P-256,
// whose parameters come from an unexplained seed. Keys, signatures and
// digests are all 32 or 64 bytes on both, so a mix-up produces no length
// error — only a signature the other side rejects. Each is its own package
// here, so the two cannot be passed for one another.
//
// # Signatures are always low-s
//
// For every valid signature (r, s) the pair (r, n-s) verifies just as well,
// so a signature can be altered by anyone without the key. Where the
// signature is part of what identifies a transaction, that is a way to
// change its hash — Bitcoin's transaction malleability. Sign normalises s
// into the lower half of the order, as BIP-62 and BIP-146 require and as
// EIP-2 requires of Ethereum.
//
// Parsing does not: SignatureFromBytes and SignatureFromDER accept high-s,
// because whether it is allowed is a policy of the protocol rather than a
// property of the encoding. Verify and Recover both reject it.
//
// # Recovery
//
// SignRecoverable returns the recovery id alongside the signature, and
// Recover reconstructs the public key from a digest, a signature and that
// id. This is what lets Ethereum transactions carry no public key. Note
// that the id belongs to the exact signature it came from: negating s
// flips it, so a malleated signature needs the other id.
//
// # Implementation
//
// Pure Go. This package once bound libsecp256k1 through cgo; the pure-Go
// backend was verified to produce byte-identical RFC 6979 signatures
// before the cgo one was removed, and the vectors in vectors_test.go are
// what was captured then.
package secp256k1

const (
	// SeckeyLen is the byte length of a private key, and of each half of a
	// signature: every scalar on this curve is 32 bytes.
	SeckeyLen = 32

	// PubkeyCompressedLen and PubkeyUncompressedLen are the two SEC 1 point
	// encodings: a parity byte and x, or 0x04 and both coordinates.
	PubkeyCompressedLen   = 33
	PubkeyUncompressedLen = 65

	// DigestLen is the length of the message digest Sign and Verify take.
	// They take a digest, not a message — hashing is the caller's, since
	// which hash is part of the protocol rather than of the signature.
	DigestLen = 32

	// SignatureCompactLen is r ∥ s, and SignatureScalarLen is one of them.
	SignatureCompactLen = 64
	SignatureScalarLen  = 32

	// RecoveryIDMax is the largest recovery id. Two bits: which of the two
	// x candidates, and whether r had to be reduced.
	RecoveryIDMax = 3
)

// dcrd packs a recoverable signature as <27+id+4><R><S>, where the +4
// marks a compressed key.
const compactRecoveryBase = 27 + 4
