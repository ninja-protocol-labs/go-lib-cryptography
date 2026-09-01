// Package bls12377 is the public API for the BLS12-377 curve — the
// Barreto-Lynn-Scott curve introduced by Zexe and used by Celo, chosen so
// that its scalar field is the base field of BW6-761, which makes proofs
// about BLS12-377 pairings cheap to verify in an outer proof.
//
// Like bn254 and unlike secp256k1/bls12381, there is no cgo boundary here
// and no vendored C library: the arithmetic comes from gnark-crypto
// (github.com/consensys/gnark-crypto/ecc/bls12-377), which is pure Go.
// gnark-crypto's own types stay out of this package's API surface,
// wrapped in unexported fields, so swapping the backend later is not a
// breaking change for callers.
//
// # BLS12-377 is not BLS12-381
//
// The two are different curves that happen to share their compressed
// encoding sizes — a public key is 48 bytes in G1 and 96 in G2 in both
// packages. Nothing about those encodings interoperates: a key or
// signature from one curve parsed by the other is either rejected or,
// worse, accepted as a different point. Keep them apart at the type
// level, which having two packages does for you, and do not shuttle raw
// bytes between them.
//
// BLS12-377 targets roughly 126-bit security, comparable to BLS12-381's
// 128. Its reason to exist is the BW6-761 pairing above it, not a
// security advantage; for ordinary signing with a free choice of curve,
// bls12381 is the one with the standardized ciphersuites.
//
// # Schemes in this package
//
// BLS signatures, in both point-assignment conventions, exactly as in the
// bls12381 and bn254 packages:
//
//   - min-pk ("minimal public key size"): public keys in G1 (48 bytes
//     compressed), signatures in G2 (96 bytes). PrivateKey.PublicKeyMinPk,
//     SignMinPk, VerifyMinPk and friends.
//   - min-sig ("minimal signature size"): the mirror image — public keys
//     in G2, signatures in G1. PrivateKey.PublicKeyMinSig, SignMinSig,
//     VerifyMinSig and friends.
//
// A signature produced under one convention never verifies under the
// other — pick one per application and use it consistently.
//
// Plus the two signature schemes gnark-crypto ships for this curve, each
// with its own key types since neither shares BLS's key shape: ECDSA over
// BLS12-377's own group (see ecdsa.go) and EdDSA over the twisted Edwards
// curve embedded in its scalar field (see eddsa.go). Both exist to be
// verified *inside* a gnark circuit, where native arithmetic is free and
// secp256k1/Ed25519 arithmetic is not; neither is an on-chain or
// interoperability standard the way secp256k1 ECDSA or RFC 8032 Ed25519
// is.
package bls12377

import (
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
)

// Encoding lengths. Everything this package returns is a fixed-size array
// of one of these lengths rather than a slice: the length is part of the
// type, so it cannot be got wrong, and the value carries no aliasing back
// to the key it came from. Parsing runs the other way — the *FromBytes
// functions and the sig parameters take slices, because checking an
// untrusted length is exactly their job, and an array parameter would push
// that check to the caller as a panicking conversion.
const (
	// G1CompressedLen is the byte length of a compressed G1 point.
	G1CompressedLen = bls12377.SizeOfG1AffineCompressed

	// G2CompressedLen is the byte length of a compressed G2 point.
	G2CompressedLen = bls12377.SizeOfG2AffineCompressed

	// GTLen is the byte length of a 𝔾ₜ element: 12 𝔽p coordinates.
	GTLen = bls12377.SizeOfGT

	// SeckeyLen is the byte length of a PrivateKey: a big-endian scalar
	// modulo r, BLS12-377's group order. It is also the width of every
	// scalar this package's scalar multiplication and MSM take.
	SeckeyLen = fr.Bytes

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

// Default domain separation tags for the BLS signature schemes.
//
// Unlike bls12381's, these are not standardized by anyone:
// draft-irtf-cfrg-bls-signature registers ciphersuites over BLS12-381
// only, and RFC 9380 registers no hash-to-curve suite for BLS12-377 at
// all. What these are is the IETF BLS draft's naming pattern
// ("BLS_SIG_" ∥ hash-to-curve suite ID ∥ scheme tag) applied to a suite
// ID written in RFC 9380's own style for what gnark-crypto's
// HashToG1/HashToG2 actually implement here: SSWU (not BN254's SVDW),
// with expand_message_xmd over SHA-256, and the "basic" scheme's SC_TAG
// (_NUL_: no message augmentation, no proof-of-possession).
//
// They are this package's convention, chosen so that two users of this
// package interoperate by default. Anything that has to interoperate with
// an external BN254 BLS implementation should pass that implementation's
// tag to the WithDST variants instead — there is no ecosystem-wide
// default here to fall back on.
const (
	DefaultDSTMinPk  = "BLS_SIG_BLS12377G2_XMD:SHA-256_SSWU_RO_NUL_"
	DefaultDSTMinSig = "BLS_SIG_BLS12377G1_XMD:SHA-256_SSWU_RO_NUL_"
)

// order is r, the order of G1, G2 and GT — the modulus of the scalar
// field a PrivateKey lives in, and the base field of BW6-761.
var order = fr.Modulus()

// PrivateKey is a BLS12-377 scalar in [1, r-1], stored big-endian. The same
// scalar underlies both the min-pk and min-sig public keys derived from
// it — it is not itself scheme-specific.
type PrivateKey struct {
	key [SeckeyLen]byte
}

// GeneratePrivateKey draws a uniformly random private key.
func GeneratePrivateKey() (*PrivateKey, error) {
	for {
		var e fr.Element
		if _, err := e.SetRandom(); err != nil {
			return nil, err
		}
		// Zero is the one scalar in range that is not a valid key: it
		// maps every public key to the identity. Redrawing costs nothing
		// — it happens with probability 2⁻²⁵⁴.
		if e.IsZero() {
			continue
		}
		return &PrivateKey{key: e.Bytes()}, nil
	}
}

// PrivateKeyFromBytes parses a big-endian scalar, rejecting anything
// outside [1, r-1].
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != SeckeyLen {
		return nil, ErrInvalidPrivateKey
	}
	s := new(big.Int).SetBytes(b)
	if s.Sign() == 0 || s.Cmp(order) >= 0 {
		return nil, ErrInvalidPrivateKey
	}
	var key [SeckeyLen]byte
	copy(key[:], b)
	return &PrivateKey{key: key}, nil
}

// Bytes returns the big-endian scalar.
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

// scalar returns k as a big.Int, the form gnark-crypto's scalar
// multiplication takes.
func (k *PrivateKey) scalar() *big.Int {
	return new(big.Int).SetBytes(k.key[:])
}

// PublicKeyMinPk derives k's min-pk public key: k*G1. This cannot fail —
// k is already known to be a valid scalar.
func (k *PrivateKey) PublicKeyMinPk() *PublicKeyMinPk {
	var p bls12377.G1Affine
	p.ScalarMultiplicationBase(k.scalar())
	return &PublicKeyMinPk{point: p}
}

// PublicKeyMinSig derives k's min-sig public key: k*G2.
func (k *PrivateKey) PublicKeyMinSig() *PublicKeyMinSig {
	var p bls12377.G2Affine
	p.ScalarMultiplicationBase(k.scalar())
	return &PublicKeyMinSig{point: p}
}

// PublicKeyMinPk is a min-pk public key: a point in G1.
type PublicKeyMinPk struct {
	point bls12377.G1Affine
}

// PublicKeyMinPkFromBytes parses a compressed G1 point, checking the
// encoding, that it is on the curve, and that it is in the prime-order
// subgroup.
func PublicKeyMinPkFromBytes(b []byte) (*PublicKeyMinPk, error) {
	if len(b) != PubkeyMinPkLen {
		return nil, ErrInvalidPublicKey
	}
	var p bls12377.G1Affine
	if _, err := p.SetBytes(b); err != nil {
		return nil, ErrInvalidPublicKey
	}
	return &PublicKeyMinPk{point: p}, nil
}

// Bytes returns the compressed public key.
func (k *PublicKeyMinPk) Bytes() [PubkeyMinPkLen]byte {
	return k.point.Bytes()
}

// Equal reports whether k and other are the same key.
func (k *PublicKeyMinPk) Equal(other *PublicKeyMinPk) bool {
	if other == nil {
		return false
	}
	return k.point.Equal(&other.point)
}

// PublicKeyMinSig is a min-sig public key: a point in G2.
type PublicKeyMinSig struct {
	point bls12377.G2Affine
}

// PublicKeyMinSigFromBytes parses a compressed G2 point, checking the
// encoding, that it is on the curve, and that it is in the prime-order
// subgroup.
func PublicKeyMinSigFromBytes(b []byte) (*PublicKeyMinSig, error) {
	if len(b) != PubkeyMinSigLen {
		return nil, ErrInvalidPublicKey
	}
	var p bls12377.G2Affine
	if _, err := p.SetBytes(b); err != nil {
		return nil, ErrInvalidPublicKey
	}
	return &PublicKeyMinSig{point: p}, nil
}

// Bytes returns the compressed public key.
func (k *PublicKeyMinSig) Bytes() [PubkeyMinSigLen]byte {
	return k.point.Bytes()
}

// Equal reports whether k and other are the same key.
func (k *PublicKeyMinSig) Equal(other *PublicKeyMinSig) bool {
	if other == nil {
		return false
	}
	return k.point.Equal(&other.point)
}
