// Package ed448 is the public API for the Ed448 (Ed448-Goldilocks)
// signature scheme.
//
// Go's standard library has no Ed448 support at all (crypto/ed25519 covers
// only Ed25519) — this package wraps Cloudflare's CIRCL
// (github.com/cloudflare/ed/sign/ed448) instead, this library's first
// dependency beyond the standard library. Unlike the sr25519-donna
// evaluation, CIRCL's Ed448 is pure Go (no cgo, no C toolchain to trust),
// actively maintained, carries Wycheproof test vectors alongside RFC 8032's
// own, and isn't listed among the packages CIRCL's own README flags as
// known non-constant-time.
//
// Key shape mirrors ed25519: PrivateKey stores only the 57-byte seed, not
// CIRCL's 114-byte expanded (seed || public key) form — that form is a
// signing-performance cache CIRCL's own NewKeyFromSeed recomputes
// deterministically from the seed alone. PublicKey() takes no error for
// the same reason it doesn't in ed25519: every 57-byte seed deterministically
// expands to a valid key, with no validity check in between to fail.
// PublicKeyFromBytes is a length check only, not point validation — Ed448
// public keys aren't decoded until a signature is actually verified against
// them.
package ed448

import (
	"crypto/rand"

	ed "github.com/cloudflare/circl/sign/ed448"
)

const (
	// SeckeyLen is the byte length of a PrivateKey's seed.
	SeckeyLen = ed.SeedSize

	// PubkeyLen is the byte length of a PublicKey.
	PubkeyLen = ed.PublicKeySize

	// SignatureLen is the byte length of a signature produced by any Sign
	// variant in this package.
	SignatureLen = ed.SignatureSize

	// ContextMaxLen is the maximum byte length of a context string
	// accepted by Sign/SignPh.
	ContextMaxLen = ed.ContextMaxSize
)

// PrivateKey is an Ed448 seed.
type PrivateKey struct {
	key [SeckeyLen]byte
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
		key: seed,
	}, nil
}

// PrivateKeyFromBytes wraps a 57-byte seed. Any 57 bytes are a valid Ed448
// seed — there is no [1, n-1]-style range to reject — so this only checks
// length.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != SeckeyLen {
		return nil, ErrInvalidPrivateKey
	}
	var seed [SeckeyLen]byte
	copy(seed[:], b)
	return &PrivateKey{
		key: seed,
	}, nil
}

// Bytes returns the 57-byte seed. The returned slice is a copy; mutating
// it does not affect k.
func (k *PrivateKey) Bytes() []byte {
	out := make([]byte, SeckeyLen)
	copy(out, k.key[:])
	return out
}

// expand recomputes ed's 114-byte (seed || public key) form from k's
// seed, for handing to ed's signing functions.
func (k *PrivateKey) expand() ed.PrivateKey {
	return ed.NewKeyFromSeed(k.key[:])
}

// PublicKey derives the public key corresponding to k. This cannot fail:
// every 57-byte seed deterministically expands to a valid public key, with
// no validity check in between to fail.
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
	return k.key == other.key
}

// PublicKey is an Ed448 public key.
type PublicKey struct {
	key [PubkeyLen]byte
}

// PublicKeyFromBytes wraps a 57-byte public key. See the package doc for
// why this is a length check only, not point validation.
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

// Bytes returns the 57-byte public key. The returned slice is a copy;
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
