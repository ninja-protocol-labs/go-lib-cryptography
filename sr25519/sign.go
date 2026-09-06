package sr25519

import "github.com/ChainSafe/go-schnorrkel"

// Signing draws a fresh nonce per call, so a signature over the same
// message differs every time. Batch verification is not exposed: it is a
// performance optimisation over looping Verify, not a distinct guarantee.

// Sign signs msg with k, domain-separated by ctx.
func Sign(k *PrivateKey, ctx, msg []byte) (*Signature, error) {
	var s Signature

	if k == nil {
		return nil, ErrInvalidPrivateKey
	}

	sig, err := k.secretKey().Sign(schnorrkel.NewSigningContext(ctx, msg))
	if err != nil {
		return nil, ErrSigningFailed
	}

	s.sig = sig.Encode()
	return &s, nil
}

// Verify reports whether sig is k's signature over msg under ctx.
func Verify(k *PublicKey, ctx, msg []byte, sig *Signature) bool {
	var s schnorrkel.Signature

	if k == nil || sig == nil {
		return false
	}
	if err := s.Decode(sig.sig); err != nil {
		return false
	}

	ok, err := k.schnorrkelKey().Verify(&s, schnorrkel.NewSigningContext(ctx, msg))
	return err == nil && ok
}
