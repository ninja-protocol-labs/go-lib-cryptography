// Package bls12381 is the public API for BLS signatures over the
// BLS12-381 curve: key types and the signing/verification schemes built on
// internal's cgo bindings.
//
// The internal package never crosses its cgo boundary into this package as
// anything but plain byte arrays and bool/int results — this file and its
// siblings are what turn that into PrivateKey/PublicKey* and named,
// per-scheme functions.
//
// BLS has two point-assignment conventions, and this package supports
// both under one PrivateKey rather than splitting into subpackages:
//   - min-pk ("minimal public key size"): public keys in G1 (48 bytes
//     compressed), signatures in G2 (96 bytes). PrivateKey.PublicKeyMinPk,
//     SignMinPk, VerifyMinPk and friends.
//   - min-sig ("minimal signature size"): the mirror image — public keys
//     in G2, signatures in G1. PrivateKey.PublicKeyMinSig, SignMinSig,
//     VerifyMinSig and friends.
//
// A signature produced under one convention never verifies under the
// other — pick one per application and use it consistently; the two
// halves of this package's naming exist so mixing them up is a type error
// (PublicKeyMinPk vs PublicKeyMinSig), not a silent runtime failure.
package bls12381

import (
	"crypto/rand"

	"github.com/ninja-protocol-labs/go-lib-cryptography/bls12381/internal"
)

// Default domain separation tags, the ciphersuite IDs for the "basic"
// scheme (draft-irtf-cfrg-bls-signature's SC_TAG "_NUL_": no message
// augmentation, no proof-of-possession) at the two point assignments.
// Sign/Verify use these; the WithDST variants take a caller-supplied one
// instead, for applications that need a different ciphersuite (e.g. Ethereum
// consensus's proof-of-possession scheme, which is not implemented by this
// package).
const (
	DefaultDSTMinPk  = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
	DefaultDSTMinSig = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
)

// Encoding lengths. Everything this package returns is a fixed-size array
// of one of these lengths rather than a slice: the length is part of the
// type, so it cannot be got wrong, and the value carries no aliasing back
// to the key it came from. Parsing runs the other way — the *FromBytes
// functions and the sig parameters take slices, because checking an
// untrusted length is exactly their job, and an array parameter would push
// that check to the caller as a panicking conversion.
//
// They are also what makes those array types nameable: the internal
// package's own constants are not reachable from outside this module, so a
// caller could never write down the type of what Bytes returns without
// these.
const (
	// G1CompressedLen is the byte length of a compressed G1 point.
	G1CompressedLen = internal.P1CompressedLen

	// G2CompressedLen is the byte length of a compressed G2 point.
	G2CompressedLen = internal.P2CompressedLen

	// SeckeyLen is the byte length of a PrivateKey: a big-endian scalar
	// modulo r, BLS12-381's group order. It is also the width of every
	// scalar this package's scalar multiplication and MSM take.
	SeckeyLen = internal.ScalarLen

	// PubkeyMinPkLen is the byte length of a compressed min-pk public key
	// (a G1 point).
	PubkeyMinPkLen = G1CompressedLen

	// PubkeyMinSigLen is the byte length of a compressed min-sig public
	// key (a G2 point).
	PubkeyMinSigLen = G2CompressedLen

	// SignatureMinPkLen is the byte length of a compressed min-pk
	// signature (a G2 point).
	SignatureMinPkLen = G2CompressedLen

	// SignatureMinSigLen is the byte length of a compressed min-sig
	// signature (a G1 point).
	SignatureMinSigLen = G1CompressedLen
)

// PrivateKey is a BLS12-381 scalar. The same scalar underlies both the
// min-pk and min-sig public keys derived from it — it is not itself
// scheme-specific.
type PrivateKey struct {
	key [internal.ScalarLen]byte
}

// GeneratePrivateKey draws a random private key via blst's own key
// derivation (IETF's KeyGen, EIP-2333 §2.3), fed 32 bytes of randomness as
// IKM. Unlike a raw uniform scalar, this always succeeds — KeyGen's HKDF
// construction cannot land outside [1, r-1].
func GeneratePrivateKey() (*PrivateKey, error) {
	var ikm [32]byte
	if _, err := rand.Read(ikm[:]); err != nil {
		return nil, err
	}
	key := internal.Keygen(ikm[:], nil)
	return &PrivateKey{key: key}, nil
}

// PrivateKeyFromBytes parses a 32-byte big-endian scalar, verifying it
// decodes to a value in [1, r-1].
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != internal.ScalarLen {
		return nil, ErrInvalidPrivateKey
	}
	var key [internal.ScalarLen]byte
	copy(key[:], b)
	if !internal.SkCheck(&key) {
		return nil, ErrInvalidPrivateKey
	}
	return &PrivateKey{key: key}, nil
}

// Bytes returns the 32-byte big-endian scalar.
func (k *PrivateKey) Bytes() [SeckeyLen]byte {
	return k.key
}

// Equal reports whether k and other are the same key.
func (k *PrivateKey) Equal(other *PrivateKey) bool {
	if other == nil {
		return false
	}
	return k.key == other.key
}

// PublicKeyMinPk derives k's min-pk public key (a G1 point). Always
// succeeds: k's scalar is already validated at construction, and every
// valid scalar has a corresponding point.
func (k *PrivateKey) PublicKeyMinPk() *PublicKeyMinPk {
	compressed := internal.SkToPkInG1Compressed(&k.key)
	point, _ := internal.P1Uncompress(&compressed)
	return &PublicKeyMinPk{point: point}
}

// PublicKeyMinSig derives k's min-sig public key (a G2 point).
func (k *PrivateKey) PublicKeyMinSig() *PublicKeyMinSig {
	compressed := internal.SkToPkInG2Compressed(&k.key)
	point, _ := internal.P2Uncompress(&compressed)
	return &PublicKeyMinSig{point: point}
}

// PublicKeyMinPk is a min-pk scheme public key: a G1 point, 48 bytes
// compressed.
type PublicKeyMinPk struct {
	point [internal.P1AffineLen]byte
}

// PublicKeyMinPkFromBytes parses a 48-byte compressed G1 point, checking
// both its curve and subgroup membership.
func PublicKeyMinPkFromBytes(b []byte) (*PublicKeyMinPk, error) {
	if len(b) != internal.P1CompressedLen {
		return nil, ErrInvalidPublicKey
	}
	var compressed [internal.P1CompressedLen]byte
	copy(compressed[:], b)
	point, code := internal.P1Uncompress(&compressed)
	if code != internal.ErrSuccess {
		return nil, ErrInvalidPublicKey
	}
	if !internal.P1AffineInG1(&point) {
		return nil, ErrInvalidPublicKey
	}
	return &PublicKeyMinPk{point: point}, nil
}

// Bytes returns the 48-byte compressed encoding.
func (k *PublicKeyMinPk) Bytes() [PubkeyMinPkLen]byte {
	return internal.P1AffineCompress(&k.point)
}

// Equal reports whether k and other are the same key.
func (k *PublicKeyMinPk) Equal(other *PublicKeyMinPk) bool {
	if other == nil {
		return false
	}
	return internal.P1AffineIsEqual(&k.point, &other.point)
}

// PublicKeyMinSig is a min-sig scheme public key: a G2 point, 96 bytes
// compressed.
type PublicKeyMinSig struct {
	point [internal.P2AffineLen]byte
}

// PublicKeyMinSigFromBytes parses a 96-byte compressed G2 point, checking
// both its curve and subgroup membership.
func PublicKeyMinSigFromBytes(b []byte) (*PublicKeyMinSig, error) {
	if len(b) != internal.P2CompressedLen {
		return nil, ErrInvalidPublicKey
	}
	var compressed [internal.P2CompressedLen]byte
	copy(compressed[:], b)
	point, code := internal.P2Uncompress(&compressed)
	if code != internal.ErrSuccess {
		return nil, ErrInvalidPublicKey
	}
	if !internal.P2AffineInG2(&point) {
		return nil, ErrInvalidPublicKey
	}
	return &PublicKeyMinSig{point: point}, nil
}

// Bytes returns the 96-byte compressed encoding.
func (k *PublicKeyMinSig) Bytes() [PubkeyMinSigLen]byte {
	return internal.P2AffineCompress(&k.point)
}

// Equal reports whether k and other are the same key.
func (k *PublicKeyMinSig) Equal(other *PublicKeyMinSig) bool {
	if other == nil {
		return false
	}
	return internal.P2AffineIsEqual(&k.point, &other.point)
}
