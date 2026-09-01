// Package bn254 is the public API for the BN254 curve — the
// Barreto-Naehrig curve that appears in Ethereum's precompiles as
// altbn128, and the curve gnark's proving system is built on.
//
// Unlike secp256k1 and bls12381, there is no cgo boundary here and no
// vendored C library: the arithmetic comes from gnark-crypto
// (github.com/consensys/gnark-crypto/ecc/bn254), which is pure Go. This
// package is the same kind of wrapper the other curve packages are — it
// keeps gnark-crypto's types out of its own API surface, exposing only
// key types, plain bytes, and this package's own point types, so that
// swapping the backend later is not a breaking change for callers.
//
// # A note on security level
//
// BN254 is not BLS12-381. Advances in the tower number field sieve have
// dropped its effective security to roughly 100 bits, below the 128-bit
// level BLS12-381 targets. It remains in wide use because Ethereum's
// pairing precompiles fix it in place and because gnark's circuits target
// it — not because it is the stronger choice. For new work with a free
// choice of curve, prefer bls12381.
//
// # Schemes in this package
//
// BLS signatures, in both point-assignment conventions, exactly as in the
// bls12381 package:
//
//   - min-pk ("minimal public key size"): public keys in G1 (32 bytes
//     compressed), signatures in G2 (64 bytes). PrivateKey.PublicKeyMinPk,
//     SignMinPk, VerifyMinPk and friends.
//   - min-sig ("minimal signature size"): the mirror image — public keys
//     in G2, signatures in G1. PrivateKey.PublicKeyMinSig, SignMinSig,
//     VerifyMinSig and friends.
//
// A signature produced under one convention never verifies under the
// other — pick one per application and use it consistently.
//
// Plus the two signature schemes gnark-crypto ships for this curve,
// each with its own key types since neither shares BLS's key shape:
// ECDSA over BN254's own group (see ecdsa.go) and EdDSA over the twisted
// Edwards curve embedded in BN254's scalar field (see eddsa.go). Both
// exist to be verified *inside* a gnark circuit, where BN254-native
// arithmetic is free and secp256k1/Ed25519 arithmetic is not; neither is
// an on-chain or interoperability standard the way secp256k1 ECDSA or
// RFC 8032 Ed25519 is.
package bn254

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
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
	G1CompressedLen = bn254.SizeOfG1AffineCompressed

	// G2CompressedLen is the byte length of a compressed G2 point.
	G2CompressedLen = bn254.SizeOfG2AffineCompressed

	// GTLen is the byte length of a 𝔾ₜ element: 12 𝔽p coordinates.
	GTLen = bn254.SizeOfGT

	// SeckeyLen is the byte length of a PrivateKey: a big-endian scalar
	// modulo r, BN254's group order. It is also the width of every scalar
	// this package's scalar multiplication and MSM take.
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
// draft-irtf-cfrg-bls-signature only registers ciphersuites over
// BLS12-381, and RFC 9380 registers hash-to-curve suites for BN254 but no
// signature scheme on top of them. What these are is the IETF BLS draft's
// naming pattern ("BLS_SIG_" ∥ hash-to-curve suite ID ∥ scheme tag)
// applied to RFC 9380 §8.8's BN254 suite IDs, with the "basic" scheme's
// SC_TAG (_NUL_: no message augmentation, no proof-of-possession) — the
// same construction bls12381 uses, over the suites gnark-crypto's
// HashToG1/HashToG2 actually implement (SVDW, expand_message_xmd with
// SHA-256).
//
// They are this package's convention, chosen so that two users of this
// package interoperate by default. Anything that has to interoperate with
// an external BN254 BLS implementation should pass that implementation's
// tag to the WithDST variants instead — there is no ecosystem-wide
// default here to fall back on.
const (
	DefaultDSTMinPk  = "BLS_SIG_BN254G2_XMD:SHA-256_SVDW_RO_NUL_"
	DefaultDSTMinSig = "BLS_SIG_BN254G1_XMD:SHA-256_SVDW_RO_NUL_"
)

// order is r, the order of G1, G2 and GT — the modulus of the scalar
// field a PrivateKey lives in.
var order = fr.Modulus()

// PrivateKey is a BN254 scalar in [1, r-1], stored big-endian. The same
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
	var p bn254.G1Affine
	p.ScalarMultiplicationBase(k.scalar())
	return &PublicKeyMinPk{point: p}
}

// PublicKeyMinSig derives k's min-sig public key: k*G2.
func (k *PrivateKey) PublicKeyMinSig() *PublicKeyMinSig {
	var p bn254.G2Affine
	p.ScalarMultiplicationBase(k.scalar())
	return &PublicKeyMinSig{point: p}
}

// PublicKeyMinPk is a min-pk public key: a point in G1.
type PublicKeyMinPk struct {
	point bn254.G1Affine
}

// PublicKeyMinPkFromBytes parses a compressed G1 point, checking the
// encoding, that it is on the curve, and that it is in the prime-order
// subgroup.
func PublicKeyMinPkFromBytes(b []byte) (*PublicKeyMinPk, error) {
	if len(b) != PubkeyMinPkLen {
		return nil, ErrInvalidPublicKey
	}
	var p bn254.G1Affine
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
	point bn254.G2Affine
}

// PublicKeyMinSigFromBytes parses a compressed G2 point, checking the
// encoding, that it is on the curve, and that it is in the prime-order
// subgroup.
func PublicKeyMinSigFromBytes(b []byte) (*PublicKeyMinSig, error) {
	if len(b) != PubkeyMinSigLen {
		return nil, ErrInvalidPublicKey
	}
	var p bn254.G2Affine
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
