package bls12381

import "errors"

var (
	ErrInvalidPrivateKey = errors.New("bls12381: invalid private key")
	ErrInvalidPublicKey  = errors.New("bls12381: invalid public key")
	ErrInvalidSignature  = errors.New("bls12381: invalid signature")
	ErrHashToCurveFailed = errors.New("bls12381: hash to curve failed")
	ErrAggregateFailed   = errors.New("bls12381: aggregation failed")
	ErrPairingFailed     = errors.New("bls12381: pairing failed")
	ErrLengthMismatch    = errors.New("bls12381: length mismatch")
)
