// Package ed25519 is the public API for the Ed25519 signature scheme
// (Curve25519 in Edwards form).
//
// Go's standard library already implements this curve (crypto/ed25519)
// with a constant-time implementation — so, like secp256r1, there is no
// cgo boundary here, no vendored C library, and no internal package. This
// is a thin wrapper over the standard library, keeping the same
// PrivateKey/PublicKey shape and conventions as the other curve packages
// where the underlying math allows it.
//
// Two things are structurally different here, both because Ed25519 itself
// works differently from the Weierstrass curves the other packages wrap,
// not by choice of this package:
//
//   - PrivateKey stores the 32-byte seed (RFC 8032's private key), not
//     stdlib's 64-byte expanded form (seed || public key). The expanded
//     form exists purely as a signing-performance cache: NewKeyFromSeed
//     recomputes it deterministically from the seed alone, so storing
//     just the seed loses nothing and keeps this package's PrivateKey the
//     same "one scalar" shape as secp256k1/secp256r1's.
//   - PublicKeyFromBytes only checks length, not that the bytes decode to
//     a valid curve point: unlike secp256k1/secp256r1, Ed25519 public
//     keys are Edwards-point encodings that stdlib does not decompress
//     (and thus does not validate) until a signature is actually checked
//     against them. There is no earlier validation to plug into.
package ed25519

import (
	ed "crypto/ed25519"
	"crypto/rand"
)

const (
	// SeckeyLen is the byte length of a PrivateKey's seed (RFC 8032's
	// private key; stdlib's SeedSize).
	SeckeyLen = ed.SeedSize

	// PubkeyLen is the byte length of a PublicKey.
	PubkeyLen = ed.PublicKeySize

	// SignatureLen is the byte length of a signature produced by any
	// Sign variant in this package.
	SignatureLen = ed.SignatureSize
)

// PrivateKey is an Ed25519 seed.
type PrivateKey struct {
	seed [SeckeyLen]byte
}

// GeneratePrivateKey draws a random private key.
func GeneratePrivateKey() (*PrivateKey, error) {
	_, priv, err := ed.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var seed [SeckeyLen]byte
	copy(seed[:], priv.Seed())
	return &PrivateKey{
		seed: seed,
	}, nil
}

// PrivateKeyFromBytes wraps a 32-byte seed. Any 32 bytes are a valid
// Ed25519 seed — there is no [1, n-1]-style range to reject, unlike
// secp256k1/secp256r1 scalars — so this only checks length.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != SeckeyLen {
		return nil, ErrInvalidPrivateKey
	}
	var seed [SeckeyLen]byte
	copy(seed[:], b)
	return &PrivateKey{
		seed: seed,
	}, nil
}

// Bytes returns the 32-byte seed. The returned slice is a copy; mutating
// it does not affect k.
func (k *PrivateKey) Bytes() []byte {
	out := make([]byte, SeckeyLen)
	copy(out, k.seed[:])
	return out
}

// expand recomputes stdlib's 64-byte (seed || public key) form from k's
// seed, for handing to crypto/ed25519's signing functions.
func (k *PrivateKey) expand() ed.PrivateKey {
	return ed.NewKeyFromSeed(k.seed[:])
}

// PublicKey derives the public key corresponding to k. Unlike
// secp256k1/secp256r1's PublicKey methods, this cannot fail: every
// 32-byte seed deterministically expands (via SHA-512) to a valid public
// key, with no validity check in between to fail.
func (k *PrivateKey) PublicKey() *PublicKey {
	pub := k.expand().Public().(ed.PublicKey)
	var pk [PubkeyLen]byte
	copy(pk[:], pub)
	return &PublicKey{
		key: pk,
	}
}

// Equal reports whether k and other are the same key.
func (k *PrivateKey) Equal(other *PrivateKey) bool {
	if other == nil {
		return false
	}
	return k.seed == other.seed
}

// PublicKey is an Ed25519 public key.
type PublicKey struct {
	key [PubkeyLen]byte
}

// PublicKeyFromBytes wraps a 32-byte public key. See the package doc for
// why this is a length check only, not on-curve validation.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != PubkeyLen {
		return nil, ErrInvalidPublicKey
	}
	var pk [PubkeyLen]byte
	copy(pk[:], b)
	return &PublicKey{
		key: pk,
	}, nil
}

// Bytes returns the 32-byte public key. The returned slice is a copy;
// mutating it does not affect k.
func (k *PublicKey) Bytes() []byte {
	out := make([]byte, PubkeyLen)
	copy(out, k.key[:])
	return out
}

// Equal reports whether k and other are the same key.
func (k *PublicKey) Equal(other *PublicKey) bool {
	if other == nil {
		return false
	}
	return k.key == other.key
}
