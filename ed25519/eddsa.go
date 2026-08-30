package ed25519

import (
	"crypto"
	ed "crypto/ed25519"
)

// EdDSA signing and verification, in the three variants RFC 8032 defines:
//
//   - Sign/Verify: pure Ed25519. Takes the raw, arbitrary-length message
//     directly — Ed25519 already makes two passes over it internally, so
//     (unlike the other packages' SignDigest* functions) there is no
//     pre-hashed-digest form to offer here; pre-hashing it yourself would
//     just be hashing it a third time. Pure signing cannot fail (every
//     32-byte seed and every message produce a signature), so, uniquely
//     among every Sign* function in this library, Sign returns no error.
//   - SignCtx/VerifyCtx: Ed25519ctx, RFC 8032's context-string variant —
//     the same double-pass-over-the-raw-message signing, domain-separated
//     by a context string of up to 255 bytes so the same key can't be
//     confused across two different protocols' messages.
//   - SignPh/VerifyPh: Ed25519ph, the prehashed variant. Here the message
//     really has been hashed once already (SHA-512, by the caller) before
//     it reaches this package, so the parameter is the 64-byte digest —
//     matching the DigestXxx naming convention used elsewhere in this
//     library, even though Ed25519ph is spelled without "Digest" in its
//     own name.
//
// context is optional in SignPh/VerifyPh — pass nil or an empty slice for
// no context string; Ed25519ph stays domain-separated from plain Ed25519
// regardless, via its own internal flag byte. It is NOT optional in
// SignCtx/VerifyCtx: crypto/ed25519 only selects the Ed25519ctx
// scheme when opts.Context is non-empty, and silently falls back to plain
// Ed25519 when it's empty — so an empty context is rejected explicitly
// here rather than being allowed to silently produce a different scheme.

// Sign signs message with priv using pure Ed25519.
func Sign(priv *PrivateKey, message []byte) []byte {
	return ed.Sign(priv.expand(), message)
}

// Verify reports whether sig is a valid pure-Ed25519 signature of message
// by pub.
func Verify(pub *PublicKey, message, sig []byte) bool {
	return ed.Verify(pub.key[:], message, sig)
}

// SignCtx signs message with priv using Ed25519ctx, domain-separated by
// context. context must be non-empty (see the package doc above) and at
// most 255 bytes.
func SignCtx(priv *PrivateKey, message, context []byte) ([]byte, error) {
	if len(context) == 0 {
		return nil, ErrContextRequired
	}
	sig, err := priv.expand().Sign(nil, message, &ed.Options{
		Hash:    crypto.Hash(0),
		Context: string(context),
	})
	if err != nil {
		return nil, ErrSigningFailed
	}
	return sig, nil
}

// VerifyCtx reports whether sig is a valid Ed25519ctx signature of
// message by pub under context. An empty context always returns false
// (see the package doc above) rather than falling back to verifying sig
// as a plain-Ed25519 signature.
func VerifyCtx(pub *PublicKey, message, context, sig []byte) bool {
	if len(context) == 0 {
		return false
	}
	err := ed.VerifyWithOptions(pub.key[:], message, sig, &ed.Options{
		Hash:    crypto.Hash(0),
		Context: string(context),
	})
	return err == nil
}

// SignPh signs a SHA-512 digest with priv using Ed25519ph, optionally
// domain-separated by context. digest must be the SHA-512 hash of the
// actual message, computed by the caller.
func SignPh(priv *PrivateKey, digest [64]byte, context []byte) ([]byte, error) {
	sig, err := priv.expand().Sign(nil, digest[:], &ed.Options{
		Hash:    crypto.SHA512,
		Context: string(context),
	})
	if err != nil {
		return nil, ErrSigningFailed
	}
	return sig, nil
}

// VerifyPh reports whether sig is a valid Ed25519ph signature of digest by
// pub under context.
func VerifyPh(pub *PublicKey, digest [64]byte, context []byte, sig []byte) bool {
	err := ed.VerifyWithOptions(pub.key[:], digest[:], sig, &ed.Options{
		Hash:    crypto.SHA512,
		Context: string(context),
	})
	return err == nil
}
