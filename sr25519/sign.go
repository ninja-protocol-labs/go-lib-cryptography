package sr25519

import (
	"github.com/ChainSafe/go-schnorrkel"
)

// Schnorr signing and verification. Unlike the other packages in this
// library, signing here isn't over a plain message: schnorrkel signs over
// a Merlin transcript (a domain-separated hash construction), so both
// functions below take a context (for domain separation between
// unrelated uses of the same key — schnorrkel's own convention, see
// NewSigningContext) and a message, and build that transcript internally
// rather than exposing schnorrkel's own transcript type in this package's
// API.
//
// Sign is not deterministic (unlike secp256k1/ed25519/ed448's plain Sign):
// schnorrkel draws a fresh random nonce per signature rather than
// deriving one from the key and message, so there is no Hedged variant to
// add here — every signature already mixes fresh entropy.
//
// schnorrkel also supports batch verification (multiple signatures
// checked faster together than one at a time), which this package
// deliberately doesn't expose: it's a performance optimization over
// looping Verify, not a distinct correctness guarantee, and out of scope
// alongside this package's other deliberate omissions (see the package
// doc in key.go).

// Signature is an sr25519 (schnorrkel) signature.
type Signature struct {
	sig [SignatureLen]byte
}

// SignatureFromBytes parses a 64-byte signature, verifying it decodes as
// a schnorrkel signature (its high bit must be set — schnorrkel's own
// marker distinguishing it from a raw Ed25519-shaped signature).
func SignatureFromBytes(b []byte) (*Signature, error) {
	if len(b) != SignatureLen {
		return nil, ErrInvalidSignature
	}
	var enc [SignatureLen]byte
	copy(enc[:], b)
	var s schnorrkel.Signature
	if err := s.Decode(enc); err != nil {
		return nil, ErrInvalidSignature
	}
	return &Signature{
		sig: enc,
	}, nil
}

// Bytes returns the 64-byte encoding of the signature.
func (s *Signature) Bytes() [SignatureLen]byte {
	return s.sig
}

// Sign signs message with priv, domain-separated by context.
func Sign(priv *PrivateKey, context, message []byte) (*Signature, error) {
	sig, err := priv.secretKey().Sign(schnorrkel.NewSigningContext(context, message))
	if err != nil {
		return nil, ErrSigningFailed
	}
	return &Signature{
		sig: sig.Encode(),
	}, nil
}

// Verify reports whether sig is a valid signature of message by pub under
// context.
func Verify(pub *PublicKey, context, message []byte, sig *Signature) bool {
	var s schnorrkel.Signature
	if err := s.Decode(sig.sig); err != nil {
		return false
	}
	ok, err := pub.schnorrkelKey().Verify(&s, schnorrkel.NewSigningContext(context, message))
	if err != nil {
		return false
	}
	return ok
}
