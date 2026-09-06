// Package bls12381ecdsa implements ECDSA over BLS12-381's own group: SEC 1 ECDSA
// with BLS12-381's G1 in place of a NIST or Koblitz curve, a hedged nonce, and
// BIP-62 low-s normalization.
//
// This exists to be verified inside a gnark circuit, where BLS12-381
// arithmetic is native and secp256k1 arithmetic is not. It is not an
// interoperability standard: nothing outside the gnark ecosystem produces
// or checks these signatures, and for ordinary on-chain or wire-compatible
// ECDSA the secp256k1 package is the right one.
//
// Unlike bls12381edwards, these keys really do live on BLS12-381 — the scalar and
// the point are in the same groups the bls12381 package's BLS keys use. They
// are separate types all the same, because a key established for one
// scheme must not sign under the other.
package bls12381ecdsa

import "github.com/consensys/gnark-crypto/ecc/bls12-381"

const (
	// SeckeyLen is the byte length of a private key: a big-endian scalar
	// modulo r, BLS12-381's group order.
	SeckeyLen = 32

	// PubkeyLen is the byte length of a compressed public key (a G1
	// point), the same encoding a min-pk BLS public key uses.
	PubkeyLen = bls12381.SizeOfG1AffineCompressed

	// SignatureLen is the byte length of a signature: r ∥ s, each a
	// 32-byte big-endian scalar.
	SignatureLen = 2 * SeckeyLen
)
