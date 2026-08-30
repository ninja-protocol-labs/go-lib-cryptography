// Package sr25519 is the public API for sr25519 — a Schnorr signature
// scheme over Ristretto255 (a prime-order group built on Curve25519),
// specified by Web3 Foundation's schnorrkel and used as Polkadot/
// Substrate's default account scheme.
//
// Go's standard library has no support for this at all, and unlike
// secp256k1 there is no single dominant, widely-audited C reference
// implementation to vendor. This package wraps
// github.com/ChainSafe/go-schnorrkel — a pure Go implementation that was
// professionally audited by Trail of Bits in August 2021 (see
// audit_report.pdf in that repository), which found and (mostly) fixed
// five issues, including a high-severity one letting a point-at-infinity
// public key defeat both signature and VRF verification. One
// informational finding (a spec deviation shared with the upstream Rust
// implementation, kept for wire compatibility) was left unfixed by
// design, not oversight. Code added to go-schnorrkel after that audit —
// notably the Keypair type and NewSecretKeyFromEd25519Bytes — was not
// covered by it; this package doesn't use either.
//
// This is a smaller surface than secp256k1's: sr25519's own reference
// implementation (and this Go port of it) simply doesn't expose as much
// as libsecp256k1 does. What's covered: key management, Schnorr sign/
// verify, Substrate-style hierarchical key derivation, and the VRF. Not
// covered: batch verification (a performance optimization over looping
// Verify, not a distinct correctness guarantee — see sign.go) and BIP39
// mnemonic support (go-schnorrkel has it, but it's mnemonic-phrase
// protocol logic, not sr25519 curve math — the same reasoning that
// excluded Silent Payments from secp256k1).
//
// Key shape: PrivateKey stores the raw 32-byte scalar schnorrkel actually
// signs with — schnorrkel.SecretKey.key — not schnorrkel's 32-byte
// MiniSecretKey "seed" form, unlike this package's earlier design and
// unlike ed25519/ed448's PrivateKey. This is a deliberate departure from
// this library's usual "store the smallest re-derivable form" rule,
// because callers of this package store this library's own PrivateKey
// bytes directly (e.g. encrypted at rest) rather than treating them as
// interchangeable with Substrate-ecosystem seed material — so the bytes
// in and out of this package must be the same bytes actually used to
// sign, not a seed one more expansion step away from it.
//
// This trades away one thing: a real Substrate seed (e.g. from `subkey
// inspect //Alice`) is a MiniSecretKey, not this scalar, so it can't be
// passed to PrivateKeyFromBytes directly — it must be expanded first
// (MiniSecretKey.ExpandEd25519().Encode() in go-schnorrkel terms).
// PrivateKeyFromBytes has no way to detect this and will not error: it
// will simply produce a different, unrelated key if handed seed bytes by
// mistake, the same way secp256k1.PrivateKeyFromBytes would for any other
// wrong-but-well-formed scalar. In exchange, this package's own
// GeneratePrivateKey/PrivateKeyFromBytes/Bytes round-trip is exactly the
// scalar used for every operation in this package, with no separate seed
// ever alive to also protect.
//
// schnorrkel.SecretKey's other 32 bytes — its nonce field — are dropped
// entirely: grepping go-schnorrkel confirms nonce is written when a
// SecretKey is expanded from a seed, but never read by Sign, Public,
// derivation, or VRF signing in this Go port (the Rust reference uses it
// for synthetic/deterministic nonce derivation; this port's own comments
// note the merlin dependency doesn't yet support that, and it draws a
// fresh nonce from crypto/rand per signature instead — see Sign in
// sign.go). Carrying it here would only be 32 dead bytes.
package sr25519

import (
	"github.com/ChainSafe/go-schnorrkel"
)

const (
	// SeckeyLen is the byte length of a PrivateKey's scalar.
	SeckeyLen = schnorrkel.SecretKeySize

	// PubkeyLen is the byte length of a PublicKey.
	PubkeyLen = schnorrkel.PublicKeySize

	// SignatureLen is the byte length of a Signature.
	SignatureLen = schnorrkel.SignatureSize

	// ChainCodeLen is the byte length of a chain code used in
	// hierarchical key derivation.
	ChainCodeLen = schnorrkel.ChainCodeLength
)

// PrivateKey is an sr25519 scalar — the actual value used to sign, not a
// seed. See the package doc for why.
type PrivateKey struct {
	key [SeckeyLen]byte
}

// GeneratePrivateKey draws a random private key: a fresh seed, expanded
// and immediately discarded, keeping only the scalar it expands to (see
// the package doc).
func GeneratePrivateKey() (*PrivateKey, error) {
	msk, err := schnorrkel.GenerateMiniSecretKey()
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		key: msk.ExpandEd25519().Encode(),
	}, nil
}

// PrivateKeyFromBytes wraps a 32-byte scalar, verifying it decodes to a
// value in [1, n-1] where n is Ristretto255's group order — the zero
// scalar is rejected because it maps to the point-at-infinity public key,
// which this package's own Verify/VerifyVRF already refuse to accept (see
// ErrPublicKeyAtInfinity in sign.go and vrf.go). This is a length-and-seed
// check schnorrkel.NewSecretKey itself doesn't do — it accepts any 32
// bytes uninspected, deferring the failure to first use — so it's done
// here instead, at construction, consistent with this library's other
// PrivateKeyFromBytes functions.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != SeckeyLen {
		return nil, ErrInvalidPrivateKey
	}
	var key [SeckeyLen]byte
	copy(key[:], b)

	sc, err := schnorrkel.ScalarFromBytes(key)
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}
	zero, err := schnorrkel.ScalarFromBytes([SeckeyLen]byte{})
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}
	if sc.Equal(zero) == 1 {
		return nil, ErrInvalidPrivateKey
	}

	return &PrivateKey{
		key: key,
	}, nil
}

// Bytes returns the 32-byte scalar. The returned slice is a copy;
// mutating it does not affect k.
func (k *PrivateKey) Bytes() []byte {
	out := make([]byte, SeckeyLen)
	copy(out, k.key[:])
	return out
}

// secretKey wraps k's scalar as schnorrkel's SecretKey, with a zeroed,
// unused nonce (see the package doc).
func (k *PrivateKey) secretKey() *schnorrkel.SecretKey {
	return schnorrkel.NewSecretKey(k.key, [32]byte{})
}

// PublicKey derives the public key corresponding to k. An error here
// would mean k's scalar, despite having passed validation at
// construction, no longer validates — not something normal operation can
// produce, but reported rather than assumed impossible.
func (k *PrivateKey) PublicKey() (*PublicKey, error) {
	pub, err := k.secretKey().Public()
	if err != nil {
		return nil, ErrPublicKeyDerivationFailed
	}
	return &PublicKey{
		key: pub.Encode(),
	}, nil
}

// Equal reports whether k and other are the same key.
func (k *PrivateKey) Equal(other *PrivateKey) bool {
	if other == nil {
		return false
	}
	return k.key == other.key
}

// PublicKey is an sr25519 public key (a compressed Ristretto255 point).
type PublicKey struct {
	key [PubkeyLen]byte
}

// PublicKeyFromBytes parses a 32-byte public key, verifying it decodes to
// a canonically-encoded Ristretto point. Real validation, unlike
// ed25519/ed448's length-only checks — see the package doc there for why
// those schemes can't do the same.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != PubkeyLen {
		return nil, ErrInvalidPublicKey
	}
	var enc [PubkeyLen]byte
	copy(enc[:], b)
	if _, err := schnorrkel.NewPublicKey(enc); err != nil {
		return nil, ErrInvalidPublicKey
	}
	return &PublicKey{
		key: enc,
	}, nil
}

// schnorrkelKey reconstructs schnorrkel's PublicKey from k's bytes. k.key
// is already known to decode successfully (checked at construction in
// PublicKeyFromBytes, or produced directly by this package's own
// derivation), so the error is dropped.
func (k *PublicKey) schnorrkelKey() *schnorrkel.PublicKey {
	pub, _ := schnorrkel.NewPublicKey(k.key)
	return pub
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
