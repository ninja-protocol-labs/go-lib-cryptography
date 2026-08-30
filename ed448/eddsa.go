package ed448

import (
	ed "github.com/cloudflare/circl/sign/ed448"
)

// EdDSA signing and verification, in the two variants RFC 8032 defines for
// Ed448 — a simpler split than ed25519's three (Sign/SignCtx/SignPh),
// because Ed448 folds context into both signing paths rather than
// reserving it for a separate ctx-only scheme: context is always part of
// the domain-separation hash, and can simply be empty — there's no
// "ctx-flavored" third scheme, and no equivalent of ed25519's "empty
// context silently downgrades to a different scheme" footgun, since an
// empty context here is just an ordinary, valid Ed448/Ed448ph input.
//
//   - Sign/Verify: Ed448, over the raw message.
//   - SignPh/VerifyPh: Ed448ph, the prehashed variant. Unlike ed25519's
//     SignPh, circl hashes the message internally (with SHAKE-256) rather
//     than taking a caller-supplied digest — so, unlike every DigestXxx
//     function elsewhere in this library, message here is the actual raw
//     message, not a digest.
//
// context may be nil or empty in both Sign/Verify and SignPh/VerifyPh.
// circl panics if context exceeds ContextMaxLen (255 bytes) instead of
// returning an error, so Sign/SignPh check that length themselves first —
// unlike ed25519's plain Sign, which takes no error at all, Ed448's Sign
// can fail on this one input.

// Sign signs message with priv using Ed448, domain-separated by context.
func Sign(priv *PrivateKey, message, context []byte) ([]byte, error) {
	if len(context) > ContextMaxLen {
		return nil, ErrContextTooLong
	}
	return ed.Sign(priv.expand(), message, string(context)), nil
}

// Verify reports whether sig is a valid Ed448 signature of message by pub
// under context.
func Verify(pub *PublicKey, message, sig, context []byte) bool {
	return ed.Verify(pub.key[:], message, sig, string(context))
}

// SignPh signs message with priv using Ed448ph, domain-separated by
// context. Unlike ed25519's SignPh, message is the raw message — circl
// hashes it internally rather than taking a caller-supplied digest.
func SignPh(priv *PrivateKey, message, context []byte) ([]byte, error) {
	if len(context) > ContextMaxLen {
		return nil, ErrContextTooLong
	}
	return ed.SignPh(priv.expand(), message, string(context)), nil
}

// VerifyPh reports whether sig is a valid Ed448ph signature of message by
// pub under context.
func VerifyPh(pub *PublicKey, message, sig, context []byte) bool {
	return ed.VerifyPh(pub.key[:], message, sig, string(context))
}
