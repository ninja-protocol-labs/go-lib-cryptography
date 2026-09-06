// Package bn254ecdsa implements ECDSA over BN254's own group: SEC 1 ECDSA
// with BN254's G1 in place of a NIST or Koblitz curve, a hedged nonce, and
// BIP-62 low-s normalization.
//
// This exists to be verified inside a gnark circuit, where BN254
// arithmetic is native and secp256k1 arithmetic is not. It is not an
// interoperability standard: nothing outside the gnark ecosystem produces
// or checks these signatures, and for ordinary on-chain or wire-compatible
// ECDSA the secp256k1 package is the right one.
//
// Unlike bn254edwards, these keys really do live on BN254 — the scalar and
// the point are in the same groups the bn254 package's BLS keys use. They
// are separate types all the same, because a key established for one
// scheme must not sign under the other.
package bn254ecdsa

import "github.com/consensys/gnark-crypto/ecc/bn254"

const (
	// SeckeyLen is the byte length of a private key: a big-endian scalar
	// modulo r, BN254's group order.
	SeckeyLen = 32

	// PubkeyLen is the byte length of a compressed public key (a G1
	// point), the same encoding a min-pk BLS public key uses.
	PubkeyLen = bn254.SizeOfG1AffineCompressed

	// SignatureLen is the byte length of a signature: r ∥ s, each a
	// 32-byte big-endian scalar.
	SignatureLen = 2 * SeckeyLen
)
