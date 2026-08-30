package ed448

import "errors"

// Sentinel errors for the functions that return one — parsing and signing.
// Verify functions return bool, not error, so they need no sentinel of
// their own.
var (
	// ErrInvalidPrivateKey means the given bytes are not a 57-byte seed.
	ErrInvalidPrivateKey = errors.New("ed448: invalid private key")

	// ErrInvalidPublicKey means the given bytes are not a 57-byte public
	// key. This is a length check only: as with ed25519, Ed448 public
	// keys are point encodings that aren't decoded (and thus validated)
	// until a signature is actually verified against them.
	ErrInvalidPublicKey = errors.New("ed448: invalid public key")

	// ErrContextTooLong means the given context string is longer than
	// ContextMaxSize (255 bytes). circl's Sign/SignPh panic on this
	// instead of returning an error, so it's checked here first.
	ErrContextTooLong = errors.New("ed448: context exceeds 255 bytes")
)
