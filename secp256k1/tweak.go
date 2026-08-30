package secp256k1

import "github.com/ninja-protocol-labs/go-lib-cryptography/secp256k1/internal"

// Key tweaking: additive/multiplicative derivation (the arithmetic behind
// schemes like BIP32-style child keys) and point negation.
//
// Every function here returns a new key rather than mutating the receiver —
// PrivateKey and PublicKey are treated as immutable everywhere else in this
// package, and tweaking is no exception.

// TweakAdd returns k's scalar plus tweak, mod the curve order. This is
// the secret-key half of additive key derivation schemes.
//
// A uniformly random tweak fails only with negligible probability (around 1
// in 2^128) — but it is a real failure mode, unlike the "can't happen"
// panics-turned-errors elsewhere in this package, since a tweak equal to
// -k's scalar (mod n) is a legitimate value a caller could construct.
func (k *PrivateKey) TweakAdd(tweak [32]byte) (*PrivateKey, error) {
	key := k.key
	if !internal.SeckeyTweakAdd(&key, &tweak) {
		return nil, ErrTweakFailed
	}
	return &PrivateKey{
		key: key,
	}, nil
}

// TweakMul returns k's scalar times tweak, mod the curve order.
func (k *PrivateKey) TweakMul(tweak [32]byte) (*PrivateKey, error) {
	key := k.key
	if !internal.SeckeyTweakMul(&key, &tweak) {
		return nil, ErrTweakFailed
	}
	return &PrivateKey{
		key: key,
	}, nil
}

// Negate returns n - k's scalar, where n is the curve order: the private
// key for the point with the same x coordinate and the opposite y.
func (k *PrivateKey) Negate() (*PrivateKey, error) {
	key := k.key
	if !internal.SeckeyNegate(&key) {
		return nil, ErrNegateFailed
	}
	return &PrivateKey{
		key: key,
	}, nil
}

// TweakAdd is the public-key half of PrivateKey.TweakAdd: k's point plus
// tweak*G.
func (k *PublicKey) TweakAdd(tweak [32]byte) (*PublicKey, error) {
	compressed, ok := internal.PubkeyTweakAddCompressed(k.key[:], &tweak)
	if !ok {
		return nil, ErrTweakFailed
	}
	return &PublicKey{
		key: compressed,
	}, nil
}

// TweakMul is the public-key half of PrivateKey.TweakMul: tweak*k's point.
func (k *PublicKey) TweakMul(tweak [32]byte) (*PublicKey, error) {
	compressed, ok := internal.PubkeyTweakMulCompressed(k.key[:], &tweak)
	if !ok {
		return nil, ErrTweakFailed
	}
	return &PublicKey{
		key: compressed,
	}, nil
}

// Negate returns the point with the same x coordinate as k and the
// opposite y.
func (k *PublicKey) Negate() (*PublicKey, error) {
	compressed, ok := internal.PubkeyNegateCompressed(k.key[:])
	if !ok {
		return nil, ErrNegateFailed
	}
	return &PublicKey{
		key: compressed,
	}, nil
}
