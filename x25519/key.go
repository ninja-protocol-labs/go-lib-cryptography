// Package x25519 is the public API for X25519 (RFC 7748) key exchange
// over Curve25519.
//
// Go's standard library already implements this via crypto/ecdh — like
// secp256r1, there is no cgo boundary here, no vendored C library, and no
// internal package. This is a thin wrapper over the standard library,
// keeping the same PrivateKey/PublicKey shape and conventions as the
// other curve packages.
//
// X25519 is a Diffie-Hellman function only — there is no signing scheme
// here the way there is for ed25519/ed448, despite Curve25519 being the
// same underlying curve Ed25519 uses in a different (Edwards) form. This
// package treats the two as unrelated: an X25519 key is not an Ed25519 key
// (RFC 7748 and RFC 8032 use different encodings and different scalar
// clamping), and this package makes no attempt to convert between them.
//
// PrivateKey.PublicKey() takes no error, like ed25519/ed448's: X25519
// derivation is scalar clamping followed by a fixed scalar multiplication,
// which cannot fail for any 32-byte input. PublicKeyFromBytes is a length
// check only — X25519's Montgomery-ladder design has no on-curve check to
// perform; any 32-byte u-coordinate is accepted, adversarial or not (see
// ECDH in dh.go for where that's actually handled).
package x25519

import (
	"crypto/ecdh"
	"crypto/rand"
)

const (
	// SeckeyLen is the byte length of a PrivateKey's scalar.
	SeckeyLen = 32

	// PubkeyLen is the byte length of a PublicKey.
	PubkeyLen = 32
)

func curve() ecdh.Curve { return ecdh.X25519() }

// PrivateKey is an X25519 scalar.
type PrivateKey struct {
	key [SeckeyLen]byte
}

// GeneratePrivateKey draws a random private key.
func GeneratePrivateKey() (*PrivateKey, error) {
	priv, err := curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var key [SeckeyLen]byte
	copy(key[:], priv.Bytes())
	return &PrivateKey{
		key: key,
	}, nil
}

// PrivateKeyFromBytes wraps a 32-byte scalar. See the package doc for why
// this is a length check only.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if _, err := curve().NewPrivateKey(b); err != nil {
		return nil, ErrInvalidPrivateKey
	}
	var key [SeckeyLen]byte
	copy(key[:], b)
	return &PrivateKey{
		key: key,
	}, nil
}

// Bytes returns the 32-byte scalar. The returned slice is a copy; mutating
// it does not affect k.
func (k *PrivateKey) Bytes() []byte {
	out := make([]byte, SeckeyLen)
	copy(out, k.key[:])
	return out
}

// PublicKey derives the public key corresponding to k. See the package doc
// for why this cannot fail.
func (k *PrivateKey) PublicKey() *PublicKey {
	priv, _ := curve().NewPrivateKey(k.key[:])
	var pk [PubkeyLen]byte
	copy(pk[:], priv.PublicKey().Bytes())
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

// PublicKey is an X25519 u-coordinate.
type PublicKey struct {
	key [PubkeyLen]byte
}

// PublicKeyFromBytes wraps a 32-byte u-coordinate. See the package doc for
// why this is a length check only.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if _, err := curve().NewPublicKey(b); err != nil {
		return nil, ErrInvalidPublicKey
	}
	var pk [PubkeyLen]byte
	copy(pk[:], b)
	return &PublicKey{
		key: pk,
	}, nil
}

// Bytes returns the 32-byte u-coordinate. The returned slice is a copy;
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
