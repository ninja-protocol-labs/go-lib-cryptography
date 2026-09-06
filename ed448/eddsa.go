package ed448

import ed "github.com/cloudflare/circl/sign/ed448"

// The two RFC 8032 variants for this curve:
//
//   - Sign/Verify: Ed448, over the raw message.
//   - SignPh/VerifyPh: Ed448ph, the prehashed variant. Unlike ed25519's
//     SignPh, CIRCL hashes the message itself with SHAKE-256 rather than
//     taking a caller-supplied digest, so msg here is the raw message.
//
// ctx may be nil or empty in either. CIRCL panics on a context longer than
// ContextMaxLen instead of returning an error, so the length is checked
// first — which is why Sign returns an error here and ed25519's does not.

// Sign signs msg with k using Ed448, domain-separated by ctx.
func Sign(k *PrivateKey, msg, ctx []byte) (*Signature, error) {
	var s Signature

	if k == nil {
		return nil, ErrInvalidPrivateKey
	}
	if len(ctx) > ContextMaxLen {
		return nil, ErrContextTooLong
	}

	copy(s.sig[:], ed.Sign(k.expand(), msg, string(ctx)))
	return &s, nil
}

// Verify reports whether sig is k's Ed448 signature over msg under ctx.
func Verify(k *PublicKey, msg, ctx []byte, sig *Signature) bool {
	if k == nil || sig == nil || len(ctx) > ContextMaxLen {
		return false
	}
	return ed.Verify(k.key[:], msg, sig.sig[:], string(ctx))
}

// SignPh signs msg with k using Ed448ph. msg is the raw message, not a
// digest — see the note above.
func SignPh(k *PrivateKey, msg, ctx []byte) (*Signature, error) {
	var s Signature

	if k == nil {
		return nil, ErrInvalidPrivateKey
	}
	if len(ctx) > ContextMaxLen {
		return nil, ErrContextTooLong
	}

	copy(s.sig[:], ed.SignPh(k.expand(), msg, string(ctx)))
	return &s, nil
}

// VerifyPh reports whether sig is k's Ed448ph signature over msg under ctx.
func VerifyPh(k *PublicKey, msg, ctx []byte, sig *Signature) bool {
	if k == nil || sig == nil || len(ctx) > ContextMaxLen {
		return false
	}
	return ed.VerifyPh(k.key[:], msg, sig.sig[:], string(ctx))
}
