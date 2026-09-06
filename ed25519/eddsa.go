package ed25519

import (
	"crypto"
	ed "crypto/ed25519"
)

// The three RFC 8032 variants:
//
//   - Sign/Verify: pure Ed25519, over the raw message. Ed25519 already
//     makes two passes over it internally, so there is no pre-hashed form
//     to offer — hashing it yourself would only hash it a third time.
//     Signing cannot fail, which is why Sign alone among this library's
//     Sign functions returns no error.
//   - SignCtx/VerifyCtx: Ed25519ctx, domain-separated by a context string
//     so one key cannot be confused across two protocols.
//   - SignPh/VerifyPh: Ed25519ph, where the caller has already hashed the
//     message with SHA-512 and passes the digest.
//
// context is optional for the Ph variants — Ed25519ph stays separated from
// plain Ed25519 by its own flag byte regardless — but required for the Ctx
// ones. See ErrContextRequired.

// Sign signs msg with k using pure Ed25519.
func Sign(k *PrivateKey, msg []byte) *Signature {
	var s Signature

	copy(s.sig[:], ed.Sign(k.expand(), msg))
	return &s
}

// Verify reports whether sig is k's pure-Ed25519 signature over msg.
func Verify(k *PublicKey, msg []byte, sig *Signature) bool {
	if k == nil || sig == nil {
		return false
	}
	return ed.Verify(k.key[:], msg, sig.sig[:])
}

// SignCtx signs msg with k using Ed25519ctx, domain-separated by ctx. ctx
// must be non-empty and at most ContextMaxLen bytes.
func SignCtx(k *PrivateKey, msg, ctx []byte) (*Signature, error) {
	var s Signature

	if k == nil {
		return nil, ErrInvalidPrivateKey
	}
	if len(ctx) == 0 {
		return nil, ErrContextRequired
	}

	sig, err := k.expand().Sign(nil, msg, &ed.Options{
		Hash:    crypto.Hash(0),
		Context: string(ctx),
	})
	if err != nil {
		return nil, ErrSigningFailed
	}

	copy(s.sig[:], sig)
	return &s, nil
}

// VerifyCtx reports whether sig is k's Ed25519ctx signature over msg under
// ctx. An empty ctx is always false rather than falling back to verifying
// sig as a plain Ed25519 signature.
func VerifyCtx(k *PublicKey, msg, ctx []byte, sig *Signature) bool {
	if k == nil || sig == nil || len(ctx) == 0 {
		return false
	}

	err := ed.VerifyWithOptions(k.key[:], msg, sig.sig[:], &ed.Options{
		Hash:    crypto.Hash(0),
		Context: string(ctx),
	})
	return err == nil
}

// SignPh signs a SHA-512 digest with k using Ed25519ph, optionally
// domain-separated by ctx. d must be the digest of the actual message,
// computed by the caller.
func SignPh(k *PrivateKey, d [DigestLen]byte, ctx []byte) (*Signature, error) {
	var s Signature

	if k == nil {
		return nil, ErrInvalidPrivateKey
	}

	sig, err := k.expand().Sign(nil, d[:], &ed.Options{
		Hash:    crypto.SHA512,
		Context: string(ctx),
	})
	if err != nil {
		return nil, ErrSigningFailed
	}

	copy(s.sig[:], sig)
	return &s, nil
}

// VerifyPh reports whether sig is k's Ed25519ph signature over d under ctx.
func VerifyPh(k *PublicKey, d [DigestLen]byte, ctx []byte, sig *Signature) bool {
	if k == nil || sig == nil {
		return false
	}

	err := ed.VerifyWithOptions(k.key[:], d[:], sig.sig[:], &ed.Options{
		Hash:    crypto.SHA512,
		Context: string(ctx),
	})
	return err == nil
}
