package ed25519

import "errors"

var (
	// ErrInvalidPrivateKey means the given bytes are not a seed of the
	// right length. There is no range check to fail: any 32 bytes are a
	// valid Ed25519 seed.
	ErrInvalidPrivateKey = errors.New("ed25519: invalid private key")

	// ErrInvalidPublicKey is a length check only — see the package doc.
	ErrInvalidPublicKey = errors.New("ed25519: invalid public key")

	// ErrInvalidSignature means the bytes are not SignatureLen long.
	// What they encode is checked by Verify, not here.
	ErrInvalidSignature = errors.New("ed25519: invalid signature")

	// ErrSigningFailed means an Ed25519ctx or Ed25519ph signature could
	// not be produced, e.g. a context string longer than ContextMaxLen.
	ErrSigningFailed = errors.New("ed25519: signing failed")

	// ErrContextRequired means SignCtx was called with an empty context.
	// crypto/ed25519 selects Ed25519ctx only when the context is
	// non-empty and silently falls back to plain Ed25519 when it is not,
	// so an empty context would quietly produce a different scheme rather
	// than fail.
	ErrContextRequired = errors.New("ed25519: SignCtx requires a non-empty context")
)
