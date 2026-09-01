package secp256k1

import (
	"crypto/sha256"

	"github.com/ninja-protocol-labs/go-lib-cryptography/secp256k1/internal"
)

// ECDSA signing and verification, in both of the format axes ECDSA actually
// has:
//
//   - message shape: Sign* hashes a raw message (SHA-256, once — not the
//     double-SHA256 some chains use, which is their own convention, not
//     part of ECDSA itself); SignDigest* takes an already-hashed 32-byte
//     value for callers who must not hash it twice.
//   - wire format: Compact is the fixed 64-byte r||s encoding; DER is the
//     variable-length ASN.1 encoding used by X.509/TLS and most general
//     ECDSA implementations. Neither is "the default" here — both are
//     first-class, named functions rather than one function with a format
//     flag.
//
// Every Sign* function has a Hedged sibling that folds auxRand into the
// nonce derivation as extra entropy, so repeated signatures over the same
// input are unlinkable, without giving up the deterministic-nonce
// protection against a failing RNG. auxRand need not be secret.

// SignCompact signs msg (hashed internally) and returns the 64-byte compact
// (r||s) encoding.
func SignCompact(priv *PrivateKey, msg []byte) ([SignatureCompactLen]byte, error) {
	digest := sha256.Sum256(msg)
	return SignDigestCompact(priv, digest)
}

// SignCompactHedged is SignCompact with auxRand folded into the nonce.
func SignCompactHedged(priv *PrivateKey, msg []byte, auxRand *[32]byte) ([SignatureCompactLen]byte, error) {
	digest := sha256.Sum256(msg)
	return SignDigestCompactHedged(priv, digest, auxRand)
}

// SignDigestCompact signs an already-hashed 32-byte digest and returns the
// 64-byte compact (r||s) encoding.
func SignDigestCompact(priv *PrivateKey, digest [32]byte) ([SignatureCompactLen]byte, error) {
	sig, ok := internal.ECDSASignCompact(&digest, &priv.key)
	if !ok {
		return [SignatureCompactLen]byte{}, ErrSigningFailed
	}
	return sig, nil
}

// SignDigestCompactHedged is SignDigestCompact with auxRand folded into the
// nonce.
func SignDigestCompactHedged(priv *PrivateKey, digest [32]byte, auxRand *[32]byte) ([SignatureCompactLen]byte, error) {
	sig, ok := internal.ECDSASignCompactHedged(&digest, &priv.key, auxRand)
	if !ok {
		return [SignatureCompactLen]byte{}, ErrSigningFailed
	}
	return sig, nil
}

// SignDER signs msg (hashed internally) and returns the DER encoding.
//
// This is the one signer in this package that returns a slice rather
// than a fixed-size array: DER is variable-length (bounded by
// SignatureDERMaxLen), so the length genuinely is not known from the
// type.
func SignDER(priv *PrivateKey, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	return SignDigestDER(priv, digest)
}

// SignDERHedged is SignDER with auxRand folded into the nonce.
func SignDERHedged(priv *PrivateKey, msg []byte, auxRand *[32]byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	return SignDigestDERHedged(priv, digest, auxRand)
}

// SignDigestDER signs an already-hashed 32-byte digest and returns the DER
// encoding.
func SignDigestDER(priv *PrivateKey, digest [32]byte) ([]byte, error) {
	sig, n, ok := internal.ECDSASignDER(&digest, &priv.key)
	if !ok {
		return nil, ErrSigningFailed
	}
	return sig[:n], nil
}

// SignDigestDERHedged is SignDigestDER with auxRand folded into the nonce.
func SignDigestDERHedged(priv *PrivateKey, digest [32]byte, auxRand *[32]byte) ([]byte, error) {
	sig, n, ok := internal.ECDSASignDERHedged(&digest, &priv.key, auxRand)
	if !ok {
		return nil, ErrSigningFailed
	}
	return sig[:n], nil
}

// VerifyCompact reports whether sig (64-byte compact encoding) is a valid
// signature over msg (hashed internally) by pub.
//
// A high-S signature is rejected unless allowHighS is set, in which case it
// is folded into low-S form before verifying — needed only for signatures
// from implementations that do not enforce low-S themselves.
func VerifyCompact(pub *PublicKey, msg, sig []byte, allowHighS bool) bool {
	digest := sha256.Sum256(msg)
	return VerifyDigestCompact(pub, digest, sig, allowHighS)
}

// VerifyDigestCompact is VerifyCompact for an already-hashed 32-byte digest.
func VerifyDigestCompact(pub *PublicKey, digest [32]byte, sig []byte, allowHighS bool) bool {
	if len(sig) != SignatureCompactLen {
		return false
	}
	var fixed [SignatureCompactLen]byte
	copy(fixed[:], sig)
	return internal.ECDSAVerifyCompact(&digest, pub.key[:], &fixed, allowHighS)
}

// VerifyDER reports whether sig (DER encoding) is a valid signature over msg
// (hashed internally) by pub. allowHighS is as in VerifyCompact.
func VerifyDER(pub *PublicKey, msg, sig []byte, allowHighS bool) bool {
	digest := sha256.Sum256(msg)
	return VerifyDigestDER(pub, digest, sig, allowHighS)
}

// VerifyDigestDER is VerifyDER for an already-hashed 32-byte digest.
func VerifyDigestDER(pub *PublicKey, digest [32]byte, sig []byte, allowHighS bool) bool {
	return internal.ECDSAVerifyDER(&digest, pub.key[:], sig, allowHighS)
}

// SignRecoverable signs msg (hashed internally) and returns the 64-byte
// compact signature plus the recovery id Recover needs to reconstruct pub
// from the signature and message alone, without pub being supplied
// separately.
func SignRecoverable(priv *PrivateKey, msg []byte) (sig [SignatureCompactLen]byte, recoveryID int, err error) {
	digest := sha256.Sum256(msg)
	return SignDigestRecoverable(priv, digest)
}

// SignRecoverableHedged is SignRecoverable with auxRand folded into the
// nonce.
func SignRecoverableHedged(priv *PrivateKey, msg []byte, auxRand *[32]byte) (sig [SignatureCompactLen]byte, recoveryID int, err error) {
	digest := sha256.Sum256(msg)
	return SignDigestRecoverableHedged(priv, digest, auxRand)
}

// SignDigestRecoverable is SignRecoverable for an already-hashed 32-byte
// digest.
func SignDigestRecoverable(priv *PrivateKey, digest [32]byte) ([SignatureCompactLen]byte, int, error) {
	sig, recID, ok := internal.ECDSASignRecoverable(&digest, &priv.key)
	if !ok {
		return [SignatureCompactLen]byte{}, 0, ErrSigningFailed
	}
	return sig, recID, nil
}

// SignDigestRecoverableHedged is SignDigestRecoverable with auxRand folded
// into the nonce.
func SignDigestRecoverableHedged(priv *PrivateKey, digest [32]byte, auxRand *[32]byte) ([SignatureCompactLen]byte, int, error) {
	sig, recID, ok := internal.ECDSASignRecoverableHedged(&digest, &priv.key, auxRand)
	if !ok {
		return [SignatureCompactLen]byte{}, 0, ErrSigningFailed
	}
	return sig, recID, nil
}

// Recover reconstructs the public key that produced sig (with the recovery
// id from SignRecoverable) over msg (hashed internally).
func Recover(msg []byte, sig []byte, recoveryID int) (*PublicKey, error) {
	digest := sha256.Sum256(msg)
	return RecoverDigest(digest, sig, recoveryID)
}

// RecoverDigest is Recover for an already-hashed 32-byte digest.
func RecoverDigest(digest [32]byte, sig []byte, recoveryID int) (*PublicKey, error) {
	if len(sig) != SignatureCompactLen {
		return nil, ErrInvalidSignature
	}
	var fixed [SignatureCompactLen]byte
	copy(fixed[:], sig)

	compressed, ok := internal.ECDSARecoverCompressed(&digest, &fixed, recoveryID)
	if !ok {
		return nil, ErrInvalidSignature
	}
	return &PublicKey{
		key: compressed,
	}, nil
}
