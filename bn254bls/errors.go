package bn254bls

import "errors"

var (
	ErrInvalidPrivateKey = errors.New("bn254bls: invalid private key")
	ErrInvalidPublicKey  = errors.New("bn254bls: invalid public key")
	ErrInvalidSignature  = errors.New("bn254bls: invalid signature")
	ErrHashToCurveFailed = errors.New("bn254bls: hash to curve failed")
	ErrAggregateFailed   = errors.New("bn254bls: aggregation failed")
)
