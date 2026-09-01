package bn254

import "errors"

// Sentinel errors. Verify functions return bool, not error, so they need
// no sentinel of their own — the same convention used throughout this
// module (see secp256k1/errors.go, bls12381/errors.go).
var (
	// ErrInvalidPrivateKey means the given bytes do not decode to a valid
	// scalar — wrong length, zero, or not below the group order r.
	ErrInvalidPrivateKey = errors.New("bn254: invalid private key")

	// ErrInvalidPublicKey means the given bytes do not decode to a valid,
	// in-subgroup point — wrong length, bad encoding, not on the curve, or
	// not in the correct prime-order subgroup.
	ErrInvalidPublicKey = errors.New("bn254: invalid public key")

	// ErrInvalidSignature means the given bytes do not decode to a valid
	// signature — a malformed point, or malformed (r, s) scalars.
	ErrInvalidSignature = errors.New("bn254: invalid signature")

	// ErrAggregateFailed means aggregating public keys or signatures
	// failed: an empty input, or one of the inputs failed to parse.
	ErrAggregateFailed = errors.New("bn254: aggregation failed")

	// ErrPairingFailed means a pairing computation failed — gnark-crypto's
	// Miller loop and pairing check reject mismatched input lengths.
	ErrPairingFailed = errors.New("bn254: pairing operation failed")

	// ErrLengthMismatch means two slices that are required to describe the
	// same set of items (points and scalars, public keys and messages) had
	// different lengths.
	ErrLengthMismatch = errors.New("bn254: mismatched input lengths")

	// ErrHashToCurveFailed means hashing a message to a curve point failed.
	// The only way gnark-crypto's hash-to-curve fails is a domain
	// separation tag longer than 255 bytes, which RFC 9380's
	// expand_message_xmd cannot encode.
	ErrHashToCurveFailed = errors.New("bn254: hash to curve failed")

	// ErrSigningFailed means a signature could not be produced — reading
	// entropy for the ECDSA nonce failed, or a required hash function was
	// not supplied.
	ErrSigningFailed = errors.New("bn254: signing failed")

	// ErrHashRequired means a scheme that needs a hash function for its
	// Fiat-Shamir challenge was called without one. EdDSA here signs a
	// sequence of field elements and has no built-in message hash, so
	// SignEdDSA/VerifyEdDSA require the caller to name one (MiMC, in
	// gnark's own circuits).
	ErrHashRequired = errors.New("bn254: a hash function is required")
)
