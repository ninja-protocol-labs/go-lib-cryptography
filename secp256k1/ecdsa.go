package secp256k1

import "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

// Sign returns a deterministic (RFC 6979) signature over the 32-byte
// digest d, with s normalized to the lower half of the order.
//
// d is a digest, not a message: hashing is the caller's, since which hash
// to use is part of the protocol rather than of the signature.
//
// The nonce comes from the key and the digest, so signing the same digest
// with the same key twice gives identical bytes and consumes no entropy.
func Sign(k *PrivateKey, d []byte) (*Signature, error) {
	var sig Signature

	if k == nil {
		return nil, ErrInvalidPrivateKey
	}
	if len(d) != DigestLen {
		return nil, ErrInvalidDigest
	}

	out := ecdsa.Sign(k.scalar(), d)
	r, s := out.R(), out.S()
	r.PutBytes(&sig.r)
	s.PutBytes(&sig.s)
	return &sig, nil
}

// Verify reports whether sig is k's signature over d. High-s signatures
// are rejected: they are malleable, and both Bitcoin and Ethereum forbid
// them.
//
// A nil key or signature, a digest of the wrong length, and a failed
// verification are all false. There is nothing a caller can do differently
// about any of them.
func Verify(k *PublicKey, d []byte, sig *Signature) bool {
	if k == nil || sig == nil || len(d) != DigestLen {
		return false
	}

	r, s := sig.scalars()
	if s.IsOverHalfOrder() {
		return false
	}
	return ecdsa.NewSignature(&r, &s).Verify(d, k.point())
}

// SignRecoverable is Sign plus the recovery code (0-3) that lets Recover
// rebuild the public key from the signature alone.
//
// This is what lets an Ethereum transaction carry a signature and no
// public key: the sender's address is derived from the key recovered from
// it. The code belongs to this exact signature — see Recover.
func SignRecoverable(k *PrivateKey, d []byte) (*Signature, byte, error) {
	var sig Signature

	if k == nil {
		return nil, 0, ErrInvalidPrivateKey
	}
	if len(d) != DigestLen {
		return nil, 0, ErrInvalidDigest
	}

	b := ecdsa.SignCompact(k.scalar(), d, true)
	copy(sig.r[:], b[1:1+SignatureScalarLen])
	copy(sig.s[:], b[1+SignatureScalarLen:])
	return &sig, (b[0] - 27) & RecoveryIDMax, nil
}

// Recover returns the public key that signed d, given sig and the recovery
// code SignRecoverable produced.
//
// High-s is rejected, as in Verify, and here it matters more: negating s
// flips the recovery code's low bit, so a malleated signature recovers a
// different key rather than failing.
//
// Recovery is not verification. It returns whichever key satisfies the
// equation, so a caller holding an expected key must compare against it;
// a caller that does not is letting the signature choose the signer.
func Recover(d []byte, sig *Signature, id byte) (*PublicKey, error) {
	var k [PubkeyCompressedLen]byte

	if sig == nil || len(d) != DigestLen || id > RecoveryIDMax {
		return nil, ErrInvalidSignature
	}

	_, s := sig.scalars()
	if s.IsOverHalfOrder() {
		return nil, ErrInvalidSignature
	}

	b := make([]byte, 1+SignatureCompactLen)
	b[0] = compactRecoveryBase + id
	copy(b[1:], sig.r[:])
	copy(b[1+SignatureScalarLen:], sig.s[:])

	p, _, err := ecdsa.RecoverCompact(b, d)
	if err != nil {
		return nil, ErrRecoveryFailed
	}

	copy(k[:], p.SerializeCompressed())
	return &PublicKey{
		key: k,
	}, nil
}
