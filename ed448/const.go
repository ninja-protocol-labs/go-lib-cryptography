// Package ed448 is the public API for the Ed448 (Ed448-Goldilocks)
// signature scheme, in the two variants RFC 8032 defines for it: Ed448 and
// Ed448ph.
//
// Go's standard library has no Ed448, so this wraps Cloudflare's CIRCL
// (github.com/cloudflare/circl/sign/ed448). CIRCL's Ed448 is pure Go,
// actively maintained, carries RFC 8032's own vectors alongside
// Wycheproof's, and is not among the packages CIRCL's README flags as
// known non-constant-time.
//
// The key shape mirrors ed25519: PrivateKey stores the 57-byte seed, not
// CIRCL's 114-byte expanded form, which is a signing cache recomputed
// deterministically from the seed. PublicKeyFromBytes checks length only —
// an Ed448 public key is not decoded until a signature is checked against
// it, so there is no earlier validation to plug into.
//
// Ed448 folds context into both signing paths rather than reserving it for
// a separate scheme the way Ed25519 does, so there is no Ctx variant here
// and no equivalent of ed25519's "an empty context silently changes the
// scheme" footgun: an empty context is an ordinary, valid input.
package ed448

import ed "github.com/cloudflare/circl/sign/ed448"

const (
	// SeckeyLen is the byte length of a private key: RFC 8032's seed.
	SeckeyLen = ed.SeedSize

	// PubkeyLen is the byte length of a public key.
	PubkeyLen = ed.PublicKeySize

	// ExpandedLen is the byte length of the seed ∥ public key form the
	// backend's signing functions take.
	ExpandedLen = SeckeyLen + PubkeyLen

	// SignatureLen is the byte length of a signature from either Sign
	// variant here.
	SignatureLen = ed.SignatureSize

	// ContextMaxLen is the longest domain separation string Ed448 and
	// Ed448ph accept.
	ContextMaxLen = ed.ContextMaxSize
)
