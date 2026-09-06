package bls12377edwards

import "hash"

// Sign signs msg with k, returning R ∥ S.
//
// h computes the Fiat-Shamir challenge and is required — there is no
// default, and no sensible one: it has to be the same hash the verifier
// uses, which is a choice about the proving system rather than about this
// signature. gnark's own circuits use MiMC over 𝔽r; see bls12377mimc.
func Sign(k *PrivateKey, msg []byte, h hash.Hash) (*Signature, error) {
	var s Signature

	if k == nil {
		return nil, ErrInvalidPrivateKey
	}
	if h == nil {
		return nil, ErrHashRequired
	}

	sig, err := k.key.Sign(msg, h)
	if err != nil {
		return nil, ErrSigningFailed
	}

	copy(s.sig[:], sig)
	return &s, nil
}

// Verify checks sig against k and msg. h must be the same hash Sign
// was given.
func Verify(k *PublicKey, msg []byte, sig *Signature, h hash.Hash) bool {
	if k == nil || sig == nil || h == nil {
		return false
	}

	ok, err := k.key.Verify(sig.sig[:], msg, h)
	return err == nil && ok
}
