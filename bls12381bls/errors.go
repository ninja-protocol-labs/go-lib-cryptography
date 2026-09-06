package bls12381bls

import "errors"

var (
	ErrInvalidPrivateKey = errors.New("bls12381bls: invalid private key")
	ErrInvalidPublicKey  = errors.New("bls12381bls: invalid public key")
	ErrInvalidSignature  = errors.New("bls12381bls: invalid signature")
	ErrHashToCurveFailed = errors.New("bls12381bls: hash to curve failed")
	ErrAggregateFailed   = errors.New("bls12381bls: aggregation failed")
)
