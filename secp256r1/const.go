// Package secp256r1 is the public API for the secp256r1 (NIST P-256)
// curve, wrapping crypto/ecdsa and crypto/ecdh.
//
// The one piece of crypto/elliptic used is MarshalCompressed and
// UnmarshalCompressed, for the compressed public key encoding: point
// encoding, not arithmetic, and the only pair there without a deprecation
// notice. Converting between that and the uncompressed SEC 1 form the
// stdlib deals in is done by hand rather than through the deprecated
// elliptic.Marshal and Unmarshal.
//
// Three things secp256k1 offers that this does not, all because
// crypto/ecdsa exposes no primitive for them and hand-rolling would mean
// reimplementing curve arithmetic: no hedged signing (crypto/ecdsa already
// mixes fresh entropy into every signature), no high-s rejection (a
// Bitcoin policy, not part of FIPS 186-5), and no public key recovery.
package secp256r1

const (
	// SeckeyLen is the byte length of a private key: a scalar in [1, n-1].
	SeckeyLen = 32

	// PubkeyCompressedLen and PubkeyUncompressedLen are the two SEC 1
	// public key encodings; the compressed one is canonical here.
	PubkeyCompressedLen   = 33
	PubkeyUncompressedLen = 65

	// DigestLen is the byte length of the digest Sign takes.
	DigestLen = 32

	// SignatureCompactLen is r ∥ s; SignatureScalarLen is each half.
	SignatureCompactLen = 64
	SignatureScalarLen  = SignatureCompactLen / 2

	// SharedSecretLen is the byte length of what ECDH returns.
	SharedSecretLen = 32
)
