// Package sr25519 is the public API for sr25519 — a Schnorr signature
// scheme over Ristretto255, specified by Web3 Foundation's schnorrkel and
// used as Polkadot/Substrate's default account scheme.
//
// It wraps github.com/ChainSafe/go-schnorrkel, a pure Go implementation
// audited by Trail of Bits in August 2021. Code added there after that
// audit — the Keypair type and NewSecretKeyFromEd25519Bytes — is not used
// here. Batch verification and BIP39 mnemonics are out of scope; key
// management, sign/verify, Substrate hierarchical derivation and the VRF
// are in it.
//
// PrivateKey stores the 32-byte scalar schnorrkel signs with, not the
// MiniSecretKey seed it expands from. That departs from this library's
// usual "store the smallest re-derivable form", so that the bytes in and
// out of this package are the bytes actually used to sign. The cost is
// that a Substrate seed (`subkey inspect //Alice`) cannot be handed to
// PrivateKeyFromBytes directly — expand it first, with
// MiniSecretKey.ExpandEd25519().Encode(). There is no way to detect the
// mistake: a seed is a well-formed scalar and simply yields a different
// key.
//
// schnorrkel.SecretKey's other 32 bytes, its nonce field, are dropped:
// this Go port writes it when expanding a seed but never reads it, drawing
// a fresh nonce from crypto/rand per signature instead.
package sr25519

import "github.com/ChainSafe/go-schnorrkel"

const (
	SeckeyLen    = schnorrkel.SecretKeySize
	PubkeyLen    = schnorrkel.PublicKeySize
	SignatureLen = schnorrkel.SignatureSize

	// ChainCodeLen is the byte length of a hierarchical derivation chain
	// code.
	ChainCodeLen = schnorrkel.ChainCodeLength

	VRFOutputLen = 32
	VRFProofLen  = 64
)
