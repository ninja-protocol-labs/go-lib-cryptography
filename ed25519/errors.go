package ed25519

import "errors"

// Sentinel errors for the functions that return one — parsing and the
// context/prehash signing variants. Verify functions return bool, not
// error, so they need no sentinel of their own; plain Sign is infallible
// (see eddsa.go) and returns no error either.
var (
	// ErrInvalidPrivateKey means the given bytes are not a 32-byte seed.
	ErrInvalidPrivateKey = errors.New("ed25519: invalid private key")

	// ErrInvalidPublicKey means the given bytes are not a 32-byte public
	// key. This is a length check only: unlike secp256k1/secp256r1,
	// Ed25519 public keys are not validated as on-curve points until a
	// signature is actually verified against them.
	ErrInvalidPublicKey = errors.New("ed25519: invalid public key")

	// ErrSigningFailed means the Ed25519ctx/Ed25519ph signing variants
	// failed — e.g. a context string longer than 255 bytes.
	ErrSigningFailed = errors.New("ed25519: signing failed")

	// ErrContextRequired means SignCtx was called with an empty
	// context. crypto/ed25519 treats Hash==0 with an empty Context as
	// plain Ed25519, not Ed25519ctx (RFC 8032's ctx variant is only
	// selected by a non-empty context) — so an empty context here would
	// silently produce a different, non-context-separated scheme instead
	// of failing, which this rejects explicitly.
	ErrContextRequired = errors.New("ed25519: SignCtx requires a non-empty context")
)
