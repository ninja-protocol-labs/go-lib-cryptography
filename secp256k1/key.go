// Package secp256k1 is the public API for the secp256k1 curve: key types
// and the signing/verification schemes built on internal's cgo bindings.
//
// The internal package never crosses its cgo boundary into this package as
// anything but plain byte arrays and bool/error results — this file and its
// siblings are what turn that into PrivateKey/PublicKey and named,
// per-scheme functions.
package secp256k1

import (
	"crypto/rand"

	"github.com/ninja-protocol-labs/go-lib-cryptography/secp256k1/internal"
)

// Encoding lengths. Everything this package returns is a fixed-size array
// of one of these lengths rather than a slice — the length is part of the
// type, so it cannot be got wrong, and the value carries no aliasing back
// to the key it came from. Parsing runs the other way: the *FromBytes
// functions and the sig parameters take slices, because checking an
// untrusted length is exactly their job.
//
// The one exception is DER, which is genuinely variable-length (see
// SignDER); SignatureDERMaxLen bounds it. A slice return in this package
// means "the length really does vary".
const (
	// SeckeyLen is the byte length of a PrivateKey.
	SeckeyLen = internal.SeckeyLen

	// PubkeyCompressedLen is the byte length of a compressed PublicKey.
	PubkeyCompressedLen = internal.PubkeyCompressedLen

	// PubkeyUncompressedLen is the byte length of an uncompressed
	// PublicKey.
	PubkeyUncompressedLen = internal.PubkeyUncompressedLen

	// SignatureCompactLen is the byte length of a compact (r ∥ s) ECDSA
	// signature, and of a recoverable one.
	SignatureCompactLen = internal.SignatureCompactLen

	// SignatureDERMaxLen bounds the DER encoding of an ECDSA signature.
	// The encoding itself is variable-length, so SignDER and friends
	// return a slice.
	SignatureDERMaxLen = internal.SignatureDERMaxLen

	// SignatureSchnorrLen is the byte length of a BIP-340 Schnorr
	// signature, including the one MuSig aggregates to.
	SignatureSchnorrLen = internal.SignatureCompactLen

	// MusigPubNonceLen, MusigAggNonceLen and MusigPartialSigLen are the
	// serialized (wire) lengths of the MuSig2 types, not their in-memory
	// sizes.
	MusigPubNonceLen   = internal.MusigPubnonceSerializedLen
	MusigAggNonceLen   = internal.MusigAggnonceSerializedLen
	MusigPartialSigLen = internal.MusigPartialSigSerializedLen
)

// PrivateKey is a secp256k1 scalar in [1, n-1].
type PrivateKey struct {
	key [internal.SeckeyLen]byte
}

// GeneratePrivateKey draws a random private key. The odds of drawing a
// value that fails the curve's own validity check (out of [1, n-1]) are
// astronomically small — around 1 in 2^128 — but the loop exists so this
// function's contract does not depend on getting lucky.
func GeneratePrivateKey() (*PrivateKey, error) {
	for {
		var key [internal.SeckeyLen]byte
		if _, err := rand.Read(key[:]); err != nil {
			return nil, err
		}
		if internal.SeckeyVerify(&key) {
			return &PrivateKey{
				key: key,
			}, nil
		}
	}
}

// PrivateKeyFromBytes parses a 32-byte scalar, verifying it decodes to a
// value in [1, n-1].
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != internal.SeckeyLen {
		return nil, ErrInvalidPrivateKey
	}
	var key [internal.SeckeyLen]byte
	copy(key[:], b)
	if !internal.SeckeyVerify(&key) {
		return nil, ErrInvalidPrivateKey
	}
	return &PrivateKey{
		key: key,
	}, nil
}

// Bytes returns the 32-byte scalar.
func (k *PrivateKey) Bytes() [SeckeyLen]byte {
	return k.key
}

// PublicKey derives the public key corresponding to k. An error here would
// mean k's scalar, despite having passed SeckeyVerify at construction, has
// no corresponding point — not something normal operation can produce, but
// reported rather than assumed impossible.
func (k *PrivateKey) PublicKey() (*PublicKey, error) {
	compressed, ok := internal.PubkeyCreateCompressed(&k.key)
	if !ok {
		return nil, ErrPublicKeyDerivationFailed
	}
	return &PublicKey{
		key: compressed,
	}, nil
}

// Equal reports whether k and other are the same key.
func (k *PrivateKey) Equal(other *PrivateKey) bool {
	if other == nil {
		return false
	}
	return k.key == other.key
}

// PublicKey is a point on the secp256k1 curve.
type PublicKey struct {
	key [internal.PubkeyCompressedLen]byte
}

// PublicKeyFromBytes parses a compressed (33-byte) or uncompressed (65-byte)
// public key, verifying it is a valid point on the curve. The internal
// representation is always compressed; the original form does not affect
// equality or later serialization.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	compressed, ok := internal.PubkeyParseCompressed(b)
	if !ok {
		return nil, ErrInvalidPublicKey
	}
	return &PublicKey{
		key: compressed,
	}, nil
}

// Bytes returns the 33-byte compressed encoding.
func (k *PublicKey) Bytes() [PubkeyCompressedLen]byte {
	return k.key
}

// BytesUncompressed returns the 65-byte uncompressed encoding. An error here
// would mean k's compressed point, despite being validated at construction,
// cannot be re-serialized in the other format — not something normal
// operation can produce, but reported rather than assumed impossible.
func (k *PublicKey) BytesUncompressed() ([PubkeyUncompressedLen]byte, error) {
	uncompressed, ok := internal.PubkeyParseUncompressed(k.key[:])
	if !ok {
		return [PubkeyUncompressedLen]byte{}, ErrPublicKeySerializationFailed
	}
	return uncompressed, nil
}

// Equal reports whether k and other are the same point.
func (k *PublicKey) Equal(other *PublicKey) bool {
	if other == nil {
		return false
	}
	return k.key == other.key
}
