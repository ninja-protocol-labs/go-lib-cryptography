package secp256r1

import "errors"

// Sentinel errors for the functions that return one — parsing and
// construction. Verify functions return bool, not error, so they need no
// sentinel of their own.
var (
	// ErrInvalidPrivateKey means the given bytes do not decode to a scalar
	// in [1, n-1]: wrong length, zero, or at or above the curve order.
	ErrInvalidPrivateKey = errors.New("secp256r1: invalid private key")

	// ErrInvalidPublicKey means the given bytes do not decode to a valid
	// point on the curve in either compressed or uncompressed form.
	ErrInvalidPublicKey = errors.New("secp256r1: invalid public key")

	// ErrPublicKeyDerivationFailed means deriving a public key from an
	// already-validated private key failed — not something normal
	// operation can produce.
	ErrPublicKeyDerivationFailed = errors.New("secp256r1: public key derivation failed")

	// ErrPublicKeySerializationFailed means re-encoding an
	// already-validated public key into a different wire format failed —
	// not something normal operation can produce.
	ErrPublicKeySerializationFailed = errors.New("secp256r1: public key serialization failed")

	// ErrSigningFailed means signing failed despite valid inputs — not
	// something normal operation can produce, since a PrivateKey's scalar
	// is already validated at construction.
	ErrSigningFailed = errors.New("secp256r1: signing failed")

	// ErrECDHFailed means computing a shared secret failed despite valid
	// inputs — not something normal operation can produce, since both
	// PrivateKey and PublicKey are already validated at construction.
	ErrECDHFailed = errors.New("secp256r1: ECDH failed")
)
