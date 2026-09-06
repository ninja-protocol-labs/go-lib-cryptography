package bn254edwards

import "errors"

// Sentinel errors.
var (
	// ErrInvalidPrivateKey means the seed is not SeedLen long, or the
	// expansion of it could not be turned into a key.
	ErrInvalidPrivateKey = errors.New("bn254edwards: invalid private key")

	// ErrInvalidPublicKey means the bytes are not a compressed point on
	// Baby Jubjub in the prime-order subgroup, or are a non-canonical
	// encoding of one — see PublicKeyFromBytes.
	ErrInvalidPublicKey = errors.New("bn254edwards: invalid public key")

	// ErrInvalidSignature means the bytes are not SignatureLen long. What
	// they encode is checked when the signature is used, not when it is
	// parsed; see SignatureFromBytes.
	ErrInvalidSignature = errors.New("bn254edwards: invalid signature")

	// ErrHashRequired means Sign or Verify was called with a nil hash.
	// There is no default: EdDSA over an embedded curve is used inside a
	// circuit, where which hash is used is the expensive part of the
	// choice, so this package will not make it silently.
	ErrHashRequired = errors.New("bn254edwards: hash function required")

	// ErrSigningFailed means no signature could be produced.
	ErrSigningFailed = errors.New("bn254edwards: signing failed")
)
