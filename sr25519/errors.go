package sr25519

import "errors"

// Sentinel errors for the functions that return one. Verify/VerifyBatch's
// bool-returning success case collapses every failure reason (bad
// encoding, wrong signature, at-infinity key) into false, matching the
// Verify* convention used elsewhere in this library — the sentinels below
// are for the parsing and derivation functions that do return an error.
var (
	// ErrInvalidPrivateKey means the given bytes are not a 32-byte seed.
	// Any 32 bytes are a valid sr25519 seed — there is no further range
	// to reject — so this is a length check only.
	ErrInvalidPrivateKey = errors.New("sr25519: invalid private key")

	// ErrInvalidPublicKey means the given bytes are not a valid,
	// canonically-encoded Ristretto point. Unlike ed25519/ed448 (Edwards
	// points, not validated until verify time), Ristretto decoding does
	// perform real validation at parse time, so this can genuinely
	// reject malformed input here, not just wrong-length input.
	ErrInvalidPublicKey = errors.New("sr25519: invalid public key")

	// ErrPublicKeyDerivationFailed means deriving a public key from an
	// already-validated private key failed — not something normal
	// operation can produce.
	ErrPublicKeyDerivationFailed = errors.New("sr25519: public key derivation failed")

	// ErrInvalidSignature means the given bytes are not a validly
	// encoded 64-byte schnorrkel signature (wrong length, or missing
	// the high bit that marks it as schnorrkel rather than raw Ed25519).
	ErrInvalidSignature = errors.New("sr25519: invalid signature encoding")

	// ErrSigningFailed means signing failed despite valid inputs — not
	// something normal operation can produce.
	ErrSigningFailed = errors.New("sr25519: signing failed")

	// ErrDeriveFailed means hierarchical key derivation failed despite
	// valid inputs — not something normal operation can produce.
	ErrDeriveFailed = errors.New("sr25519: key derivation failed")

	// ErrInvalidVRFOutput means the given bytes are not a validly
	// encoded 32-byte VRF output (a Ristretto point).
	ErrInvalidVRFOutput = errors.New("sr25519: invalid VRF output encoding")

	// ErrInvalidVRFProof means the given bytes are not a validly
	// encoded 64-byte VRF proof.
	ErrInvalidVRFProof = errors.New("sr25519: invalid VRF proof encoding")

	// ErrVRFSignFailed means VRF signing failed despite valid inputs —
	// not something normal operation can produce.
	ErrVRFSignFailed = errors.New("sr25519: VRF signing failed")
)
