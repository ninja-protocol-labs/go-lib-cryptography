// Package ed25519 is the public API for the Ed25519 signature scheme
// (Curve25519 in Edwards form), in the three variants RFC 8032 defines:
// pure Ed25519, Ed25519ctx and Ed25519ph.
//
// Go's standard library already implements this curve (crypto/ed25519)
// in constant time, so this is a thin wrapper over it, keeping the same
// shape and conventions as the other key packages here.
//
// Two things are structurally different, both because Ed25519 works
// differently from the Weierstrass curves the other packages wrap, not by
// choice of this package:
//
//   - PrivateKey stores the 32-byte seed (RFC 8032's private key), not
//     stdlib's 64-byte expanded form (seed ∥ public key). The expanded
//     form is purely a signing cache that NewKeyFromSeed recomputes
//     deterministically, so storing the seed loses nothing and keeps this
//     PrivateKey the same one-scalar shape as secp256k1's.
//   - PublicKeyFromBytes checks length only, not that the bytes decode to
//     a point on the curve. Unlike secp256k1 and secp256r1, stdlib does
//     not decompress an Ed25519 public key until a signature is actually
//     checked against it, so there is no earlier validation to plug into.
package ed25519

import ed "crypto/ed25519"

const (
	// SeckeyLen is the byte length of a private key: RFC 8032's seed.
	SeckeyLen = ed.SeedSize

	// PubkeyLen is the byte length of a public key.
	PubkeyLen = ed.PublicKeySize

	// ExpandedLen is the byte length of the seed ∥ public key form the
	// backend's signing functions take.
	ExpandedLen = SeckeyLen + PubkeyLen

	// SignatureLen is the byte length of a signature from any Sign
	// variant here.
	SignatureLen = ed.SignatureSize

	// DigestLen is the byte length of the SHA-512 digest SignPh takes.
	DigestLen = 64

	// ContextMaxLen is the longest domain separation string Ed25519ctx
	// and Ed25519ph accept.
	ContextMaxLen = 255
)
