package secp256r1

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// ECDSA signing and verification, in both of the format axes ECDSA actually
// has:
//
//   - message shape: Sign* hashes a raw message (SHA-256, once); SignDigest*
//     takes an already-hashed 32-byte value for callers who already have a
//     digest and must not hash it twice.
//   - wire format: Compact is the fixed 64-byte r||s encoding; DER is the
//     variable-length ASN.1 encoding used by X.509/TLS. Neither is "the
//     default" here — both are first-class, named functions rather than one
//     function with a format flag.
//
// Two things secp256k1's ECDSA surface has that this one does not, both for
// the same underlying reason — crypto/ecdsa doesn't expose the primitives a
// safe implementation would need, and hand-rolling them would mean
// reimplementing curve arithmetic ourselves rather than calling an audited
// one:
//
//   - No Hedged sign variant or aux_rand parameter: crypto/ecdsa's Sign
//     already always mixes fresh entropy with the private key and message
//     for every signature (see the package doc) — there is no pure-
//     deterministic mode to add entropy on top of.
//   - No allowHighS on Verify: low-S malleability rejection is a
//     libsecp256k1/Bitcoin-specific policy, not part of FIPS 186-5 ECDSA
//     itself, so crypto/ecdsa's Verify has nothing to opt out of.
//   - No SignRecoverable/Recover: crypto/ecdsa has no recovery-id concept,
//     and reconstructing a public key from (r, s) would require computing a
//     modular square root ourselves to recover y from x — real curve
//     arithmetic this package otherwise avoids entirely.

// SignCompact signs msg (hashed internally) and returns the 64-byte compact
// (r||s) encoding.
func SignCompact(priv *PrivateKey, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	return SignDigestCompact(priv, digest)
}

// SignDigestCompact signs an already-hashed 32-byte digest and returns the
// 64-byte compact (r||s) encoding.
func SignDigestCompact(priv *PrivateKey, digest [32]byte) ([]byte, error) {
	key, err := ecdsa.ParseRawPrivateKey(curve(), priv.key[:])
	if err != nil {
		return nil, ErrSigningFailed
	}

	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, ErrSigningFailed
	}

	sig := make([]byte, 2*SeckeyLen)
	r.FillBytes(sig[:SeckeyLen])
	s.FillBytes(sig[SeckeyLen:])
	return sig, nil
}

// SignDER signs msg (hashed internally) and returns the DER encoding.
func SignDER(priv *PrivateKey, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	return SignDigestDER(priv, digest)
}

// SignDigestDER signs an already-hashed 32-byte digest and returns the DER
// encoding.
func SignDigestDER(priv *PrivateKey, digest [32]byte) ([]byte, error) {
	key, err := ecdsa.ParseRawPrivateKey(curve(), priv.key[:])
	if err != nil {
		return nil, ErrSigningFailed
	}

	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return nil, ErrSigningFailed
	}
	return sig, nil
}

// VerifyCompact reports whether sig (64-byte compact encoding) is a valid
// signature over msg (hashed internally) by pub.
func VerifyCompact(pub *PublicKey, msg, sig []byte) bool {
	digest := sha256.Sum256(msg)
	return VerifyDigestCompact(pub, digest, sig)
}

// VerifyDigestCompact is VerifyCompact for an already-hashed 32-byte digest.
func VerifyDigestCompact(pub *PublicKey, digest [32]byte, sig []byte) bool {
	if len(sig) != 2*SeckeyLen {
		return false
	}
	uncompressed, err := pub.BytesUncompressed()
	if err != nil {
		return false
	}
	key, err := ecdsa.ParseUncompressedPublicKey(curve(), uncompressed)
	if err != nil {
		return false
	}

	r := new(big.Int).SetBytes(sig[:SeckeyLen])
	s := new(big.Int).SetBytes(sig[SeckeyLen:])
	return ecdsa.Verify(key, digest[:], r, s)
}

// VerifyDER reports whether sig (DER encoding) is a valid signature over msg
// (hashed internally) by pub.
func VerifyDER(pub *PublicKey, msg, sig []byte) bool {
	digest := sha256.Sum256(msg)
	return VerifyDigestDER(pub, digest, sig)
}

// VerifyDigestDER is VerifyDER for an already-hashed 32-byte digest.
func VerifyDigestDER(pub *PublicKey, digest [32]byte, sig []byte) bool {
	uncompressed, err := pub.BytesUncompressed()
	if err != nil {
		return false
	}
	key, err := ecdsa.ParseUncompressedPublicKey(curve(), uncompressed)
	if err != nil {
		return false
	}
	return ecdsa.VerifyASN1(key, digest[:], sig)
}
