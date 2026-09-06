package ed448

import "errors"

var (
	// ErrInvalidPrivateKey means the given bytes are not a seed of the
	// right length. There is no range check to fail: any 57 bytes are a
	// valid Ed448 seed.
	ErrInvalidPrivateKey = errors.New("ed448: invalid private key")

	// ErrInvalidPublicKey is a length check only — see the package doc.
	ErrInvalidPublicKey = errors.New("ed448: invalid public key")

	// ErrInvalidSignature means the bytes are not SignatureLen long.
	// What they encode is checked by Verify, not here.
	ErrInvalidSignature = errors.New("ed448: invalid signature")

	// ErrContextTooLong means a context string longer than ContextMaxLen
	// was given. CIRCL panics on one rather than returning an error, so
	// the length is checked before reaching it.
	ErrContextTooLong = errors.New("ed448: context is too long")
)
