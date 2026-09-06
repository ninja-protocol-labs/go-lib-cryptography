package bls12381ecdsa

import "hash"

// Sign signs msg with k, returning r ∥ s.
//
// h is the hash applied to msg before signing; pass nil to treat msg
// as an already-computed digest. Either way, an input longer than the
// bit-length of r is truncated to that length by SEC 1's conversion rule,
// which makes anything past those bits malleable — so a digest handed in
// with h == nil should be at most SeckeyLen bytes.
//
// The signature is *not* deterministic. gnark-crypto derives the nonce
// from SHA-512(scalar ∥ 32 fresh random bytes ∥ message) — a hedged nonce,
// which keeps a broken RNG from leaking the key the way a purely random
// nonce would, while still producing different bytes on every call. Do not
// treat two signatures over the same message as comparable; note also that
// signing fails if the system entropy source does.
//
// s is normalized to the lower half of the order (BIP-62), so a valid
// signature has exactly one accepted encoding.
func Sign(k *PrivateKey, msg []byte, h hash.Hash) (*Signature, error) {
	var s Signature

	if k == nil {
		return nil, ErrInvalidPrivateKey
	}

	sig, err := k.key.Sign(msg, h)
	if err != nil {
		return nil, ErrSigningFailed
	}

	copy(s.sig[:], sig)
	return &s, nil
}

// Verify checks sig against k and msg. h must be the same hash Sign
// was given, or nil for a pre-hashed message. A high-s signature is
// rejected rather than silently normalized.
func Verify(k *PublicKey, msg []byte, sig *Signature, h hash.Hash) bool {
	if k == nil || sig == nil {
		return false
	}

	ok, err := k.key.Verify(sig.sig[:], msg, h)
	return err == nil && ok
}
