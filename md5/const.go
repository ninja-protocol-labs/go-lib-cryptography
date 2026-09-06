// Package md5 is the public API for MD5 (RFC 1321).
//
// # MD5 is broken, and this is what that means
//
// Its collision resistance is gone entirely. Producing two distinct inputs
// with the same digest takes seconds on a laptop, and chosen-prefix
// collisions — where an attacker picks meaningful content on both sides and
// appends colliding blocks — are practical too. That is not a theoretical
// margin: the Flame malware used a chosen-prefix MD5 collision in 2012 to
// forge a code-signing certificate that Windows accepted.
//
// Its preimage resistance is, so far, intact. The best published attack is
// around 2¹²³ work against 2¹²⁸ for brute force — an academic result, not a
// usable one. That distinction is why HMAC-MD5 is not trivially forgeable,
// since HMAC does not rest on collision resistance. It is not a reason to
// choose either.
//
// So: never use MD5 where an adversary can influence what is hashed.
// Not for signatures, certificates, tokens, deduplication of untrusted
// input, or integrity checks that are meant to survive tampering. Not for
// passwords, where being fast is a second disqualification on top of the
// first. sha2 is the default; blake3 if speed matters.
//
// # What it is still for
//
// Reading data that already exists. Legacy protocols and formats specify
// MD5 and cannot be changed — S3 ETags, older package manifests, a long
// tail of file-integrity manifests — and interoperating with them means
// computing it. That is the whole reason this package exists, and the
// reason it is not simply absent.
//
// It is also fine as a non-cryptographic checksum where nobody chooses the
// input: detecting accidental corruption, bucketing, cache keys over
// trusted data. A non-cryptographic hash would be faster and would not
// invite the misreading, but MD5 is not wrong there.
//
// # Length extension
//
// MD5 is a Merkle-Damgård construction whose digest is its whole final
// state, so it is length-extendable: knowing Sum(secret ∥ m) and
// len(secret) is enough to compute Sum(secret ∥ m ∥ padding ∥ suffix). Do
// not use a raw hash as a MAC — though for MD5 that advice is redundant,
// since it should not be carrying anything security-relevant at all.
//
// # Implementation
//
// A thin wrapper over crypto/md5. Sum is a re-export: the standard library
// already returns a fixed-size array, so unlike keccak or ripemd160 in this
// module there was nothing to add.
package md5

import "crypto/md5"

const (
	// Size is the byte length of an MD5 digest.
	Size = md5.Size

	// BlockSize is the byte length of the compression function's input
	// block.
	BlockSize = md5.BlockSize
)
