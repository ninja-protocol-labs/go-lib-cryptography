package bls12377bls

import "errors"

var (
	ErrInvalidPrivateKey = errors.New("bls12377bls: invalid private key")
	ErrInvalidPublicKey  = errors.New("bls12377bls: invalid public key")
	ErrInvalidSignature  = errors.New("bls12377bls: invalid signature")
	ErrHashToCurveFailed = errors.New("bls12377bls: hash to curve failed")
	ErrAggregateFailed   = errors.New("bls12377bls: aggregation failed")
)
