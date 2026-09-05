// Package pbkdf2 is the public API for PBKDF2, the password-based key
// derivation function of RFC 8018 (PKCS #5 v2.1).
//
// PBKDF2 stretches a password into key material by iterating HMAC over a
// salt. Its only cost knob is the iteration count, and that is the whole
// story of both what it is for and where it falls short.
//
// # What the iteration count buys, and what it does not
//
// Iterations make a guess cost more CPU time. They do not make a guess
// cost memory or parallelism, so an attacker with a GPU or an ASIC gains
// against a defender with a CPU at essentially the full ratio of their
// throughputs — thousands to one. scrypt and argon2 exist precisely to
// close that gap by making each guess also cost memory.
//
// Use this package when a specification, an interoperating implementation
// or a compliance regime names PBKDF2 — it is the one password KDF that
// is in FIPS 140's approved list, and it appears in WPA2, in PKCS #12, in
// most disk-encryption headers, and in a large number of file formats. For
// a new design with a free choice, argon2 is the better one.
//
// # Choosing parameters
//
// NIST SP 800-132 sets the floor at 1,000 iterations and calls for salts
// of at least 128 bits drawn from a CSPRNG. That floor is two decades old
// and far too low today: pick the iteration count by measuring, targeting
// whatever delay the application can afford per login — a few hundred
// milliseconds is a common budget — and revisit it as hardware moves.
// This package deliberately ships no default constant, because a number
// baked into a library ages into a liability.
//
// The salt must be unique per password and stored alongside the derived
// key; it is not a secret. Reusing one salt across users lets a single
// precomputed table attack all of them at once, which is the whole reason
// salts exist.
//
// # The hash argument
//
// PBKDF2 is defined over any PRF; in practice that means HMAC with some
// hash, which is what Key takes. SHA-256 is the usual choice. Note that
// the hash's block size interacts with cost in a way that surprises
// people: SHA-512 processes 128-byte blocks, so on 64-bit hardware it
// costs an attacker more per guess than SHA-256 does, which is an argument
// for it rather than against.
//
// # Implementation
//
// A thin wrapper over the standard library's crypto/pbkdf2, added in Go
// 1.24. Key's output is a slice rather than a fixed-size array because the
// length is the caller's choice — the same exception this module's array
// convention makes for XOF output and DER.
package pbkdf2

import (
	"crypto/pbkdf2"
	"hash"
)

// Key derives keyLen bytes from password and salt by iterating
// HMAC-h iter times, per RFC 8018.
//
// h is the hash to build the PRF from — sha2.New256 and friends. password
// is a string rather than a byte slice because that is the shape it
// almost always arrives in, and copying it into a slice to call this
// would only spread the secret across more memory.
//
// It returns ErrInvalidIterations or ErrInvalidKeyLen for a non-positive
// count or length, and the standard library's own error for a key length
// beyond what the construction can produce ((2³²-1) × the hash's size).
//
// The iteration check is this package's addition. The standard library
// accepts a count of zero and below, where its loop never runs and the
// result is silently the same as a single iteration — so a count that
// arrived as zero from configuration would produce the weakest possible
// derivation with nothing failing. Beyond rejecting that, this does not
// police whether iter is large enough to be useful; see the package doc
// on choosing it.
//
// The result is key material, not a password hash to be stored: it is the
// caller's job to keep the salt and parameters beside it, and to compare
// with a constant-time comparison rather than ==.
func Key(h func() hash.Hash, password string, salt []byte, iter, keyLen int) ([]byte, error) {
	if iter < 1 {
		return nil, ErrInvalidIterations
	}
	if keyLen < 1 {
		return nil, ErrInvalidKeyLen
	}
	return pbkdf2.Key(h, password, salt, iter, keyLen)
}
