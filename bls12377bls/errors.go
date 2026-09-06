package bls12377bls

import "errors"

// Sentinel errors.
var (
	// ErrInvalidPrivateKey means the bytes are not SeckeyLen long, or the
	// scalar they encode is not in [1, r-1].
	ErrInvalidPrivateKey = errors.New("bls12377bls: invalid private key")

	// ErrInvalidPublicKey means the bytes are not a compressed point in
	// the scheme's public-key group, are not in the prime-order subgroup,
	// or are the identity. The identity is rejected because it verifies
	// against every message.
	ErrInvalidPublicKey = errors.New("bls12377bls: invalid public key")

	// ErrInvalidSignature means the bytes are not a compressed point in
	// the scheme's signature group, or are not in the prime-order
	// subgroup.
	ErrInvalidSignature = errors.New("bls12377bls: invalid signature")

	// ErrHashToCurveFailed means a message could not be mapped to a curve
	// point. Hash-to-curve is defined for every input, so this is a fault
	// in the library underneath rather than something a caller caused.
	ErrHashToCurveFailed = errors.New("bls12377bls: hash to curve failed")

	// ErrAggregateFailed means an aggregation was given no inputs. The sum
	// of nothing is the point at infinity, which verifies for nothing, so
	// it is reported rather than returned.
	ErrAggregateFailed = errors.New("bls12377bls: aggregation failed")
)
