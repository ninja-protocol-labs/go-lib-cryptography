package secp256k1

import "errors"

// Sentinel errors for the functions that return one — parsing and
// construction. Verify functions return bool, not error, so they need no
// sentinel of their own.
var (
	// ErrInvalidPrivateKey means the given bytes do not decode to a scalar
	// in [1, n-1]: wrong length, zero, or at or above the curve order.
	ErrInvalidPrivateKey = errors.New("secp256k1: invalid private key")

	// ErrInvalidPublicKey means the given bytes do not decode to a valid
	// point on the curve in either compressed or uncompressed form.
	ErrInvalidPublicKey = errors.New("secp256k1: invalid public key")

	// ErrPublicKeyDerivationFailed means deriving a public key from an
	// already-validated private key failed — not something normal
	// operation can produce.
	ErrPublicKeyDerivationFailed = errors.New("secp256k1: public key derivation failed")

	// ErrPublicKeySerializationFailed means re-encoding an
	// already-validated public key into a different wire format failed —
	// not something normal operation can produce.
	ErrPublicKeySerializationFailed = errors.New("secp256k1: public key serialization failed")

	// ErrSigningFailed means signing failed despite valid inputs — not
	// something normal operation can produce, since a PrivateKey's scalar
	// is already validated at construction.
	ErrSigningFailed = errors.New("secp256k1: signing failed")

	// ErrInvalidSignature means the given signature bytes are malformed,
	// or (for Recover/RecoverDigest) do not yield a valid public key for
	// the given recovery id.
	ErrInvalidSignature = errors.New("secp256k1: invalid signature")

	// ErrECDHFailed means computing a shared secret failed despite valid
	// inputs — not something normal operation can produce, since both
	// PrivateKey and PublicKey are already validated at construction.
	ErrECDHFailed = errors.New("secp256k1: ECDH failed")

	// ErrTweakFailed means TweakAdd/TweakMul produced an invalid result —
	// most commonly a tweak that exactly cancels the key it is applied to.
	// A uniformly random tweak triggers this only with negligible
	// probability, but it is a real, reachable failure, not a "can't
	// happen" case.
	ErrTweakFailed = errors.New("secp256k1: key tweak failed")

	// ErrNegateFailed means negating an already-validated key failed — not
	// something normal operation can produce.
	ErrNegateFailed = errors.New("secp256k1: key negation failed")

	// ErrEllswiftFailed means producing an ElligatorSwift encoding failed —
	// not something normal operation can produce, since the key involved
	// is already validated at construction.
	ErrEllswiftFailed = errors.New("secp256k1: ellswift encoding failed")

	// ErrMusigKeyAggFailed means MusigAggregateKeys failed: zero keys, more
	// than MaxCombinePubkeys keys, or a set that sums to the point at
	// infinity.
	ErrMusigKeyAggFailed = errors.New("secp256k1: MuSig2 key aggregation failed")

	// ErrMusigNonceGenFailed means generating a MuSig2 nonce pair failed.
	ErrMusigNonceGenFailed = errors.New("secp256k1: MuSig2 nonce generation failed")

	// ErrInvalidMusigPubNonce means the given bytes are not a valid
	// 66-byte encoded MuSig2 public nonce.
	ErrInvalidMusigPubNonce = errors.New("secp256k1: invalid MuSig2 public nonce")

	// ErrMusigNonceAggFailed means MusigAggregateNonces failed: zero
	// pubnonces, or more than MaxCombinePubkeys of them.
	ErrMusigNonceAggFailed = errors.New("secp256k1: MuSig2 nonce aggregation failed")

	// ErrInvalidMusigAggNonce means the given bytes are not a valid
	// 66-byte encoded MuSig2 aggregate nonce.
	ErrInvalidMusigAggNonce = errors.New("secp256k1: invalid MuSig2 aggregate nonce")

	// ErrMusigSessionFailed means MusigProcessNonce failed.
	ErrMusigSessionFailed = errors.New("secp256k1: MuSig2 session setup failed")

	// ErrMusigSecnonceReused means Sign was called twice on the same
	// *MusigSecnonce. The first call, successful or not, is final —
	// nonce reuse leaks the secret key outright, so this is refused
	// rather than attempted.
	ErrMusigSecnonceReused = errors.New("secp256k1: MuSig2 secnonce already used")

	// ErrMusigPartialSignFailed means producing a MuSig2 partial signature
	// failed — most commonly a MusigSecnonce that was not generated for
	// the given priv and session.
	ErrMusigPartialSignFailed = errors.New("secp256k1: MuSig2 partial signing failed")

	// ErrInvalidMusigPartialSig means the given bytes are not a valid
	// 32-byte encoded MuSig2 partial signature.
	ErrInvalidMusigPartialSig = errors.New("secp256k1: invalid MuSig2 partial signature")

	// ErrMusigSigAggFailed means MusigAggregateSignatures failed: zero
	// partial signatures, or more than MaxCombinePubkeys of them.
	ErrMusigSigAggFailed = errors.New("secp256k1: MuSig2 signature aggregation failed")
)
