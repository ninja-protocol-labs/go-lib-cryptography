package secp256k1

import "errors"

// Sentinel errors. Every parsing failure reports one of these rather than
// what the library underneath returned, so a caller can tell what was
// rejected without matching on message text.
var (
	// ErrInvalidPrivateKey means the bytes are not SeckeyLen long, or the
	// scalar they encode is zero or at least the curve order. Both are
	// checked here because dcrd's PrivKeyFromBytes reduces an out-of-range
	// scalar instead of rejecting it, which would silently accept two
	// different inputs as the same key.
	ErrInvalidPrivateKey = errors.New("secp256k1: invalid private key")

	// ErrInvalidPublicKey means the bytes are not a point on the curve in
	// any SEC 1 encoding this package accepts: compressed, uncompressed, or
	// hybrid with a parity byte that matches Y.
	ErrInvalidPublicKey = errors.New("secp256k1: invalid public key")

	// ErrInvalidDigest means the digest is not DigestLen long. Sign and
	// Verify take a digest, not a message.
	ErrInvalidDigest = errors.New("secp256k1: invalid digest")

	// ErrInvalidSignature means r or s is zero or at least the curve order,
	// the compact form is not SignatureCompactLen long, or the DER form is
	// malformed. High-s is not an encoding error and is not reported here —
	// see the package doc.
	ErrInvalidSignature = errors.New("secp256k1: invalid signature")

	// ErrRecoveryFailed means no public key could be recovered from the
	// digest, signature and recovery id given. Usually the id belongs to a
	// different signature: negating s flips it.
	ErrRecoveryFailed = errors.New("secp256k1: public key recovery failed")
)
