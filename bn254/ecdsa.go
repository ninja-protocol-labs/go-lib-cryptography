package bn254

import (
	"crypto/rand"
	"hash"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	gnarkecdsa "github.com/consensys/gnark-crypto/ecc/bn254/ecdsa"
)

// ECDSA over BN254's own group, as gnark-crypto implements it: SEC 1
// ECDSA with BN254's G1 in place of a NIST or Koblitz curve, a hedged
// (key- and entropy-derived) nonce, and BIP-62 low-s normalization.
//
// This exists to be *verified inside a gnark circuit*, where BN254
// arithmetic is native and secp256k1 arithmetic is not. It is not an
// interoperability standard: nothing outside the gnark ecosystem produces
// or checks these signatures, and for ordinary on-chain or
// wire-compatible ECDSA the secp256k1 package is the right one.
//
// The key types are separate from PrivateKey/PublicKeyMinPk even though
// the scalar and the point live in the same groups, because gnark-crypto's
// signer carries its own cached key material and its own serialization,
// and conflating the two would invite signing under one scheme with a key
// established for the other.

const (
	// ECDSASignatureLen is the byte length of an ECDSA signature: r ∥ s,
	// each a 32-byte big-endian scalar.
	ECDSASignatureLen = 2 * SeckeyLen

	// ECDSAPubkeyLen is the byte length of a compressed ECDSA public key
	// (a G1 point), the same encoding as a min-pk BLS public key.
	ECDSAPubkeyLen = bn254.SizeOfG1AffineCompressed
)

// ECDSAPrivateKey is a BN254 scalar used for ECDSA.
type ECDSAPrivateKey struct {
	key gnarkecdsa.PrivateKey
}

// GenerateECDSAPrivateKey draws a random ECDSA private key.
func GenerateECDSAPrivateKey() (*ECDSAPrivateKey, error) {
	k, err := gnarkecdsa.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ECDSAPrivateKey{key: *k}, nil
}

// ECDSAPrivateKeyFromBytes parses a big-endian scalar in [1, r-1].
//
// gnark-crypto's own PrivateKey serialization is public key ∥ scalar, and
// its parser trusts the public key half rather than checking it against
// the scalar. This takes just the scalar — the same 32-byte shape as this
// package's other private keys — and derives the public half itself, so a
// mismatched pair cannot be constructed.
func ECDSAPrivateKeyFromBytes(b []byte) (*ECDSAPrivateKey, error) {
	if len(b) != SeckeyLen {
		return nil, ErrInvalidPrivateKey
	}
	s := new(big.Int).SetBytes(b)
	if s.Sign() == 0 || s.Cmp(order) >= 0 {
		return nil, ErrInvalidPrivateKey
	}

	var pub bn254.G1Affine
	pub.ScalarMultiplicationBase(s)
	pubBytes := pub.Bytes()

	buf := make([]byte, 0, ECDSAPubkeyLen+SeckeyLen)
	buf = append(buf, pubBytes[:]...)
	buf = append(buf, b...)

	var k gnarkecdsa.PrivateKey
	if _, err := k.SetBytes(buf); err != nil {
		return nil, ErrInvalidPrivateKey
	}
	return &ECDSAPrivateKey{key: k}, nil
}

// Bytes returns the big-endian scalar, without the cached public key
// gnark-crypto's own serialization prepends.
func (k *ECDSAPrivateKey) Bytes() [SeckeyLen]byte {
	var out [SeckeyLen]byte
	full := k.key.Bytes()
	copy(out[:], full[ECDSAPubkeyLen:])
	return out
}

// PublicKey derives the public key corresponding to k.
func (k *ECDSAPrivateKey) PublicKey() *ECDSAPublicKey {
	return &ECDSAPublicKey{key: k.key.PublicKey}
}

// Equal reports whether k and other are the same key.
func (k *ECDSAPrivateKey) Equal(other *ECDSAPrivateKey) bool {
	if other == nil {
		return false
	}
	a, b := k.Bytes(), other.Bytes()
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// ECDSAPublicKey is a point in G1 used to verify ECDSA signatures.
type ECDSAPublicKey struct {
	key gnarkecdsa.PublicKey
}

// ECDSAPublicKeyFromBytes parses a compressed G1 point.
func ECDSAPublicKeyFromBytes(b []byte) (*ECDSAPublicKey, error) {
	if len(b) != ECDSAPubkeyLen {
		return nil, ErrInvalidPublicKey
	}
	var k gnarkecdsa.PublicKey
	if _, err := k.SetBytes(b); err != nil {
		return nil, ErrInvalidPublicKey
	}
	return &ECDSAPublicKey{key: k}, nil
}

// Bytes returns the compressed public key.
func (k *ECDSAPublicKey) Bytes() [ECDSAPubkeyLen]byte {
	var out [ECDSAPubkeyLen]byte
	copy(out[:], k.key.Bytes())
	return out
}

// Equal reports whether k and other are the same key.
func (k *ECDSAPublicKey) Equal(other *ECDSAPublicKey) bool {
	if other == nil {
		return false
	}
	return k.key.Equal(&other.key)
}

// SignECDSA signs msg with priv, returning r ∥ s.
//
// hFunc is the hash applied to msg before signing; pass nil to treat msg
// as an already-computed digest. Either way, an input longer than the
// bit-length of r is truncated to that length by SEC 1's conversion rule,
// which makes anything past those bits malleable — so a digest handed in
// with hFunc == nil should be at most 32 bytes.
//
// The signature is *not* deterministic. gnark-crypto derives the nonce
// from SHA-512(scalar ∥ 32 fresh random bytes ∥ message) — a hedged
// nonce, which keeps a broken RNG from leaking the key the way a purely
// random nonce would, while still producing different bytes on every call.
// Do not treat two signatures over the same message as comparable; note
// also that signing therefore fails if the system entropy source does.
//
// s is normalized to the lower half of the order (BIP-62), so a valid
// signature has exactly one accepted encoding.
func SignECDSA(priv *ECDSAPrivateKey, msg []byte, hFunc hash.Hash) ([ECDSASignatureLen]byte, error) {
	var out [ECDSASignatureLen]byte
	if priv == nil {
		return out, ErrInvalidPrivateKey
	}
	sig, err := priv.key.Sign(msg, hFunc)
	if err != nil {
		return out, ErrSigningFailed
	}
	copy(out[:], sig)
	return out, nil
}

// VerifyECDSA checks an r ∥ s signature against pub and msg. hFunc must be
// the same hash SignECDSA was given (or nil for a pre-hashed message).
// A signature with a high s is rejected, not silently normalized.
func VerifyECDSA(pub *ECDSAPublicKey, msg, sig []byte, hFunc hash.Hash) bool {
	if pub == nil || len(sig) != ECDSASignatureLen {
		return false
	}
	ok, err := pub.key.Verify(sig, msg, hFunc)
	return err == nil && ok
}
