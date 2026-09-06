package secp256r1

import "errors"

// Sentinel errors. Every failure reports one of these rather than what
// crypto/ecdsa returned, so a caller can tell what was rejected without
// matching on message text.
var (
	// ErrInvalidPrivateKey means the bytes are not SeckeyLen long, or the
	// scalar they encode is not in [1, n-1].
	ErrInvalidPrivateKey = errors.New("secp256r1: invalid private key")

	// ErrInvalidPublicKey means the bytes are not a point on the curve in
	// either SEC 1 encoding this package accepts, compressed or
	// uncompressed.
	ErrInvalidPublicKey = errors.New("secp256r1: invalid public key")

	// ErrInvalidSignature means the compact form is not
	// SignatureCompactLen long, r or s is zero, or the DER form is
	// malformed.
	//
	// Unlike secp256k1's, this does not reject a scalar at or above the
	// curve order: crypto/ecdsa's Verify rejects those itself, so checking
	// here would only move the same rejection earlier.
	ErrInvalidSignature = errors.New("secp256r1: invalid signature")

	// ErrInvalidDigest means the digest is not DigestLen long. Sign and
	// Verify take a digest, not a message.
	ErrInvalidDigest = errors.New("secp256r1: invalid digest")

	// ErrSigningFailed means crypto/ecdsa could not produce a signature.
	// Signing here is randomised, so in practice this is the entropy
	// source failing — secp256k1's RFC 6979 signing has no such error.
	ErrSigningFailed = errors.New("secp256r1: signing failed")

	// ErrECDHFailed means the exchange produced no usable secret.
	ErrECDHFailed = errors.New("secp256r1: key exchange failed")
)
