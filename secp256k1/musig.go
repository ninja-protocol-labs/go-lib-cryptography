package secp256k1

import (
	"crypto/rand"

	"github.com/ninja-protocol-labs/go-lib-cryptography/secp256k1/internal"
)

// MuSig2: n-of-n signature aggregation. A session runs through five stages,
// each producing the state the next one needs — state that, past the first
// stage, has to travel between participants (over whatever channel they
// use), not just between calls in one process:
//
//  1. MusigAggregateKeys combines every signer's PublicKey into one
//     aggregate key and a MusigKeyaggCache.
//  2. Each signer calls MusigGenerateNonce locally, keeps the returned
//     MusigSecnonce secret, and sends the returned MusigPubNonce to
//     whoever is collecting them.
//  3. Once every pubnonce has arrived, MusigAggregateNonces combines them,
//     and MusigProcessNonce turns that into a MusigSession.
//  4. Each signer calls Sign on their own MusigSecnonce and sends the
//     resulting MusigPartialSig to whoever is aggregating.
//  5. Once every partial signature has arrived, MusigAggregateSignatures
//     combines them into a complete signature — verifiable exactly like any
//     other Schnorr signature, via VerifySchnorr against the aggregate key
//     from step 1.
//
// Every type below wraps a fixed-size internal representation opaquely; use
// Bytes()/Parse* to cross a wire, not a type's fields directly.

// MaxMusigParticipants bounds how many keys MusigAggregateKeys, how many
// pubnonces MusigAggregateNonces, and how many partial signatures
// MusigAggregateSignatures will accept.
const MaxMusigParticipants = internal.MaxCombinePubkeys

// MusigKeyaggCache is the result of aggregating a set of public keys: it
// caches what MusigGenerateNonce, MusigProcessNonce, and Sign need to know
// about the aggregation, and — after a TweakAdd/XOnlyTweakAdd call —
// records the tweak too.
type MusigKeyaggCache struct {
	cache [internal.MusigKeyaggCacheLen]byte
}

// MusigAggregateKeys combines pubkeys into a single aggregate key. Order
// matters: aggregating the same keys in a different order produces a
// different aggregate key. Sort pubkeys first (by their Bytes()) if the
// aggregate must not depend on order.
func MusigAggregateKeys(pubkeys []*PublicKey) (*PublicKey, *MusigKeyaggCache, error) {
	packed := make([][internal.PubkeyCompressedLen]byte, len(pubkeys))
	for i, pub := range pubkeys {
		packed[i] = pub.key
	}

	_, cache, ok := internal.MusigPubkeyAgg(packed)
	if !ok {
		return nil, nil, ErrMusigKeyAggFailed
	}
	full, ok := internal.MusigPubkeyGetCompressed(&cache)
	if !ok {
		return nil, nil, ErrMusigKeyAggFailed
	}

	return &PublicKey{key: full}, &MusigKeyaggCache{cache: cache}, nil
}

// TweakAdd tweaks the aggregate key by adding tweak*G, mutating c in place
// so that a later Sign in this session produces a signature valid for the
// tweaked key — unlike PublicKey.TweakAdd, which only computes a new point.
func (c *MusigKeyaggCache) TweakAdd(tweak [32]byte) (*PublicKey, error) {
	compressed, ok := internal.MusigPubkeyECTweakAddCompressed(&c.cache, &tweak)
	if !ok {
		return nil, ErrTweakFailed
	}
	return &PublicKey{
		key: compressed,
	}, nil
}

// XOnlyTweakAdd is TweakAdd using x-only tweak semantics (dropping the
// aggregate key's y coordinate before tweaking), for committing arbitrary
// auxiliary data into the aggregate key the way PublicKey.Negate's x-only
// counterpart would for a single key.
func (c *MusigKeyaggCache) XOnlyTweakAdd(tweak [32]byte) (*PublicKey, error) {
	compressed, ok := internal.MusigPubkeyXonlyTweakAddCompressed(&c.cache, &tweak)
	if !ok {
		return nil, ErrTweakFailed
	}
	return &PublicKey{
		key: compressed,
	}, nil
}

// MusigSecnonce is a signer's secret nonce. It must never be copied,
// serialized, or reused: Sign consumes it, and this type refuses to Sign
// with the same value twice — tracked here in Go in addition to the
// library's own best-effort C-level guard, since nonce reuse leaks the
// secret key outright.
type MusigSecnonce struct {
	secnonce [internal.MusigSecnonceLen]byte
	used     bool
}

// MusigPubNonce is a signer's public nonce, sent to whoever aggregates
// nonces for the session.
type MusigPubNonce struct {
	pubnonce [internal.MusigPubnonceLen]byte
}

// MusigGenerateNonce starts a signing session by generating this signer's
// nonce pair. The randomness MuSig2 requires to be unique per call and kept
// secret is drawn here via crypto/rand — never exposed to the caller — so
// there is no way to accidentally reuse it.
//
// priv, msg, and cache are all optional (pass nil to omit); supplying
// whichever are already known only strengthens the nonce against misuse, it
// never weakens it. pub is required: it is the public key this nonce
// commits to signing for.
//
// msg is exactly the 32-byte value that will later be passed to
// MusigProcessNonce — MuSig2 treats it as an opaque 32-byte value, not a
// message it hashes down itself the way SignSchnorr/VerifySchnorr do for an
// arbitrary-length message. If msg represents a longer application message,
// hash it down to 32 bytes yourself (e.g. with SHA-256) before calling
// either this or MusigProcessNonce, and use the exact same 32 bytes for
// both — and, if the aggregate signature needs to verify with
// VerifySchnorr afterward, as the msg passed there too.
func MusigGenerateNonce(priv *PrivateKey, pub *PublicKey, msg *[32]byte, cache *MusigKeyaggCache, extraInput *[32]byte) (*MusigSecnonce, *MusigPubNonce, error) {
	var secrand [32]byte
	if _, err := rand.Read(secrand[:]); err != nil {
		return nil, nil, err
	}

	var privKey *[internal.SeckeyLen]byte
	if priv != nil {
		privKey = &priv.key
	}
	var cachePtr *[internal.MusigKeyaggCacheLen]byte
	if cache != nil {
		cachePtr = &cache.cache
	}

	secnonce, pubnonce, ok := internal.MusigNonceGen(&secrand, privKey, pub.key[:], msg, cachePtr, extraInput)
	if !ok {
		return nil, nil, ErrMusigNonceGenFailed
	}
	return &MusigSecnonce{secnonce: secnonce}, &MusigPubNonce{pubnonce: pubnonce}, nil
}

// MusigGenerateNonceCounter is MusigGenerateNonce for callers without access
// to good randomness: counter replaces the internally-drawn randomness, and
// must never repeat for the same priv — a counter that increments on every
// call is sufficient; unlike true randomness it need not be secret or
// unpredictable, only unique. Unlike MusigGenerateNonce, priv is required
// here (it is used to build the keypair the derivation is bound to). msg is
// as in MusigGenerateNonce.
func MusigGenerateNonceCounter(priv *PrivateKey, counter uint64, msg *[32]byte, cache *MusigKeyaggCache, extraInput *[32]byte) (*MusigSecnonce, *MusigPubNonce, error) {
	var cachePtr *[internal.MusigKeyaggCacheLen]byte
	if cache != nil {
		cachePtr = &cache.cache
	}

	secnonce, pubnonce, ok := internal.MusigNonceGenCounter(&priv.key, counter, msg, cachePtr, extraInput)
	if !ok {
		return nil, nil, ErrMusigNonceGenFailed
	}
	return &MusigSecnonce{secnonce: secnonce}, &MusigPubNonce{pubnonce: pubnonce}, nil
}

// Bytes encodes n into the 66-byte wire form to send to whoever is
// aggregating nonces.
func (n *MusigPubNonce) Bytes() [internal.MusigPubnonceSerializedLen]byte {
	return internal.MusigPubnonceSerialize(&n.pubnonce)
}

// ParseMusigPubNonce decodes a 66-byte pubnonce received from another
// signer.
func ParseMusigPubNonce(b [internal.MusigPubnonceSerializedLen]byte) (*MusigPubNonce, error) {
	pubnonce, ok := internal.MusigPubnonceParse(&b)
	if !ok {
		return nil, ErrInvalidMusigPubNonce
	}
	return &MusigPubNonce{pubnonce: pubnonce}, nil
}

// MusigAggNonce is the combination of every signer's pubnonce for a
// session.
type MusigAggNonce struct {
	aggnonce [internal.MusigAggnonceLen]byte
}

// MusigAggregateNonces combines every signer's pubnonce into one aggregate
// nonce. This can be done by an untrusted party: an incorrectly computed
// aggregate only invalidates the resulting signature, it does not
// compromise anyone's key.
func MusigAggregateNonces(pubnonces []*MusigPubNonce) (*MusigAggNonce, error) {
	packed := make([][internal.MusigPubnonceLen]byte, len(pubnonces))
	for i, n := range pubnonces {
		packed[i] = n.pubnonce
	}

	aggnonce, ok := internal.MusigNonceAgg(packed)
	if !ok {
		return nil, ErrMusigNonceAggFailed
	}
	return &MusigAggNonce{aggnonce: aggnonce}, nil
}

// Bytes encodes agg into the 66-byte wire form to send to the signers.
func (agg *MusigAggNonce) Bytes() [internal.MusigAggnonceSerializedLen]byte {
	return internal.MusigAggnonceSerialize(&agg.aggnonce)
}

// ParseMusigAggNonce decodes a 66-byte aggregate nonce received from
// whoever ran MusigAggregateNonces.
func ParseMusigAggNonce(b [internal.MusigAggnonceSerializedLen]byte) (*MusigAggNonce, error) {
	aggnonce, ok := internal.MusigAggnonceParse(&b)
	if !ok {
		return nil, ErrInvalidMusigAggNonce
	}
	return &MusigAggNonce{aggnonce: aggnonce}, nil
}

// MusigSession is what every remaining step — signing, verifying partial
// signatures, and aggregating them — is keyed off of.
type MusigSession struct {
	session [internal.MusigSessionLen]byte
}

// MusigProcessNonce combines agg with msg and cache into a session. msg is
// the exact 32-byte value being signed for, in the same sense described on
// MusigGenerateNonce — the same 32 bytes must be passed to VerifySchnorr
// later for the aggregate signature to verify, not the longer message it
// may represent.
func MusigProcessNonce(agg *MusigAggNonce, msg [32]byte, cache *MusigKeyaggCache) (*MusigSession, error) {
	session, ok := internal.MusigNonceProcess(&agg.aggnonce, &msg, &cache.cache)
	if !ok {
		return nil, ErrMusigSessionFailed
	}
	return &MusigSession{session: session}, nil
}

// MusigPartialSig is one signer's contribution to a session's final
// signature.
type MusigPartialSig struct {
	sig [internal.MusigPartialSigLen]byte
}

// Sign produces this signer's partial signature for session, consuming s:
// calling Sign on the same *MusigSecnonce again always fails, whether or
// not the first call succeeded. s must have been generated (via
// MusigGenerateNonce or MusigGenerateNonceCounter) for this same priv and
// session.
//
// This does not verify its own output, matching upstream's deviation from
// the specification it implements; call MusigVerifyPartialSig on the result
// if computation errors (not just malice) are a concern.
func (s *MusigSecnonce) Sign(priv *PrivateKey, cache *MusigKeyaggCache, session *MusigSession) (*MusigPartialSig, error) {
	if s.used {
		return nil, ErrMusigSecnonceReused
	}
	s.used = true

	sig, ok := internal.MusigPartialSign(&s.secnonce, &priv.key, &cache.cache, &session.session)
	if !ok {
		return nil, ErrMusigPartialSignFailed
	}
	return &MusigPartialSig{sig: sig}, nil
}

// MusigVerifyPartialSig verifies one signer's partial signature within a
// specific session. Correct operation of a MuSig2 session does not require
// calling this — if any partial signature is wrong, the final aggregate
// signature will simply fail to verify — but this pinpoints which signer's
// contribution was at fault, which the aggregate-only check cannot.
//
// pubnonce and pub must be the exact ones that went into agg (via
// MusigAggregateNonces) and cache (via MusigAggregateKeys) respectively for
// this signer; passing a mismatched pair does not necessarily fail loudly,
// it risks verifying against the wrong signing session entirely.
func MusigVerifyPartialSig(sig *MusigPartialSig, pubnonce *MusigPubNonce, pub *PublicKey, cache *MusigKeyaggCache, session *MusigSession) bool {
	return internal.MusigPartialSigVerify(&sig.sig, &pubnonce.pubnonce, pub.key[:], &cache.cache, &session.session)
}

// Bytes encodes s into the 32-byte wire form to send to whoever is
// aggregating partial signatures.
func (s *MusigPartialSig) Bytes() [internal.MusigPartialSigSerializedLen]byte {
	return internal.MusigPartialSigSerialize(&s.sig)
}

// ParseMusigPartialSig decodes a 32-byte partial signature received from
// another signer.
func ParseMusigPartialSig(b [internal.MusigPartialSigSerializedLen]byte) (*MusigPartialSig, error) {
	sig, ok := internal.MusigPartialSigParse(&b)
	if !ok {
		return nil, ErrInvalidMusigPartialSig
	}
	return &MusigPartialSig{sig: sig}, nil
}

// MusigAggregateSignatures combines sigs into a complete Schnorr
// signature — verifiable the same way any other Schnorr signature is
// (VerifySchnorr), against the aggregate key from MusigAggregateKeys.
// Success here does not mean the result verifies: a single bad partial
// signature (from a computation error, not necessarily malice) still
// combines into a signature that fails verification, which is exactly why
// MusigVerifyPartialSig exists as a way to isolate the culprit ahead of
// time.
func MusigAggregateSignatures(session *MusigSession, sigs []*MusigPartialSig) ([]byte, error) {
	packed := make([][internal.MusigPartialSigLen]byte, len(sigs))
	for i, s := range sigs {
		packed[i] = s.sig
	}

	sig, ok := internal.MusigPartialSigAgg(&session.session, packed)
	if !ok {
		return nil, ErrMusigSigAggFailed
	}
	return sig[:], nil
}
