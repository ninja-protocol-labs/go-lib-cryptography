package internal

/*
#include "shim.h"
*/
import "C"

// MusigPubkeyAgg aggregates pubkeys into a single x-only key, and initializes
// cache — required for every later call in the same MuSig2 session (nonce
// generation, tweaking, signing, verification). Key order changes the
// result; sort the inputs with PubkeySortCompressed first if the aggregate
// must not depend on it. At most MaxCombinePubkeys keys are accepted.
func MusigPubkeyAgg(pubkeys [][PubkeyCompressedLen]byte) ([XonlyPubkeyLen]byte, [MusigKeyaggCacheLen]byte, bool) {
	var aggPk [XonlyPubkeyLen]byte
	var cache [MusigKeyaggCacheLen]byte
	if len(pubkeys) == 0 || len(pubkeys) > MaxCombinePubkeys {
		return aggPk, cache, false
	}
	ok := C.shim_musig_pubkey_agg(context(), (*C.uchar)(&pubkeys[0][0]), C.size_t(len(pubkeys)), (*C.uchar)(&aggPk[0]), (*C.uchar)(&cache[0])) == 1
	return aggPk, cache, ok
}

// MusigPubkeyGetCompressed recovers the full (non-x-only) aggregate key from
// cache. Needed before MusigPubkeyECTweakAddCompressed, which tweaks the full
// point rather than the x-only one.
func MusigPubkeyGetCompressed(cache *[MusigKeyaggCacheLen]byte) ([PubkeyCompressedLen]byte, bool) {
	var out [PubkeyCompressedLen]byte
	length := C.size_t(len(out))
	ok := C.shim_musig_pubkey_get(context(), (*C.uchar)(&cache[0]), (*C.uchar)(&out[0]), &length, 1) == 1
	return out, ok
}

// MusigPubkeyGetUncompressed is MusigPubkeyGetCompressed, uncompressed.
func MusigPubkeyGetUncompressed(cache *[MusigKeyaggCacheLen]byte) ([PubkeyUncompressedLen]byte, bool) {
	var out [PubkeyUncompressedLen]byte
	length := C.size_t(len(out))
	ok := C.shim_musig_pubkey_get(context(), (*C.uchar)(&cache[0]), (*C.uchar)(&out[0]), &length, 0) == 1
	return out, ok
}

// MusigPubkeyECTweakAddCompressed tweaks the aggregate key in cache by adding
// tweak*G to the full point, mutating cache in place so that later signing
// in this session produces a signature valid for the tweaked key. Use this
// over a plain PubkeyTweakAddCompressed whenever the tweaked key will be
// signed for, not just computed.
func MusigPubkeyECTweakAddCompressed(cache *[MusigKeyaggCacheLen]byte, tweak *[TweakLen]byte) ([PubkeyCompressedLen]byte, bool) {
	var out [PubkeyCompressedLen]byte
	length := C.size_t(len(out))
	ok := C.shim_musig_pubkey_ec_tweak_add(context(), (*C.uchar)(&cache[0]), (*C.uchar)(&tweak[0]), (*C.uchar)(&out[0]), &length, 1) == 1
	return out, ok
}

// MusigPubkeyECTweakAddUncompressed is MusigPubkeyECTweakAddCompressed,
// uncompressed.
func MusigPubkeyECTweakAddUncompressed(cache *[MusigKeyaggCacheLen]byte, tweak *[TweakLen]byte) ([PubkeyUncompressedLen]byte, bool) {
	var out [PubkeyUncompressedLen]byte
	length := C.size_t(len(out))
	ok := C.shim_musig_pubkey_ec_tweak_add(context(), (*C.uchar)(&cache[0]), (*C.uchar)(&tweak[0]), (*C.uchar)(&out[0]), &length, 0) == 1
	return out, ok
}

// MusigPubkeyXonlyTweakAddCompressed tweaks the aggregate key in cache the
// way XonlyPubkeyTweakAdd tweaks a standalone x-only key, mutating cache in
// place. Same sign-for-the-tweaked-key requirement as
// MusigPubkeyECTweakAddCompressed.
func MusigPubkeyXonlyTweakAddCompressed(cache *[MusigKeyaggCacheLen]byte, tweak *[TweakLen]byte) ([PubkeyCompressedLen]byte, bool) {
	var out [PubkeyCompressedLen]byte
	length := C.size_t(len(out))
	ok := C.shim_musig_pubkey_xonly_tweak_add(context(), (*C.uchar)(&cache[0]), (*C.uchar)(&tweak[0]), (*C.uchar)(&out[0]), &length, 1) == 1
	return out, ok
}

// MusigPubkeyXonlyTweakAddUncompressed is
// MusigPubkeyXonlyTweakAddCompressed, uncompressed.
func MusigPubkeyXonlyTweakAddUncompressed(cache *[MusigKeyaggCacheLen]byte, tweak *[TweakLen]byte) ([PubkeyUncompressedLen]byte, bool) {
	var out [PubkeyUncompressedLen]byte
	length := C.size_t(len(out))
	ok := C.shim_musig_pubkey_xonly_tweak_add(context(), (*C.uchar)(&cache[0]), (*C.uchar)(&tweak[0]), (*C.uchar)(&out[0]), &length, 0) == 1
	return out, ok
}

// MusigNonceGen starts a signing session by generating this signer's secret
// and public nonce. seckey, msg, keyaggCache, and extraInput are all
// optional (nil to omit); supplying whichever are already known only
// strengthens the nonce against misuse, it never weakens it.
//
// sessionSecrand must be unique to this call and never reused — nonce reuse
// leaks the secret key outright. The library overwrites it in place on
// success, so it comes back zeroed; that is not a bug, it is proof the value
// was consumed and must not be passed to this function again.
//
// The returned secnonce carries the same warning as the type it wraps: never
// copy or reuse it once it has been consumed by MusigPartialSign.
func MusigNonceGen(
	sessionSecrand *[32]byte,
	seckey *[SeckeyLen]byte,
	pubkey []byte,
	msg *[MessageLen]byte,
	keyaggCache *[MusigKeyaggCacheLen]byte,
	extraInput *[32]byte,
) ([MusigSecnonceLen]byte, [MusigPubnonceLen]byte, bool) {
	var secnonce [MusigSecnonceLen]byte
	var pubnonce [MusigPubnonceLen]byte
	if len(pubkey) == 0 {
		return secnonce, pubnonce, false
	}

	var seckeyPtr, msgPtr, keyaggCachePtr, extraInputPtr *C.uchar
	if seckey != nil {
		seckeyPtr = (*C.uchar)(&seckey[0])
	}
	if msg != nil {
		msgPtr = (*C.uchar)(&msg[0])
	}
	if keyaggCache != nil {
		keyaggCachePtr = (*C.uchar)(&keyaggCache[0])
	}
	if extraInput != nil {
		extraInputPtr = (*C.uchar)(&extraInput[0])
	}

	ok := C.shim_musig_nonce_gen(
		context(),
		(*C.uchar)(&sessionSecrand[0]),
		seckeyPtr,
		(*C.uchar)(&pubkey[0]), C.size_t(len(pubkey)),
		msgPtr,
		keyaggCachePtr,
		extraInputPtr,
		(*C.uchar)(&secnonce[0]),
		(*C.uchar)(&pubnonce[0]),
	) == 1
	return secnonce, pubnonce, ok
}

// MusigNonceGenCounter is MusigNonceGen for callers without access to good
// randomness: nonrepeatingCnt replaces sessionSecrand, and must never repeat
// for the same seckey — a counter that increments on every call is
// sufficient; unlike sessionSecrand it need not be secret or unpredictable,
// only unique. msg, keyaggCache, and extraInput remain optional as in
// MusigNonceGen.
func MusigNonceGenCounter(
	seckey *[SeckeyLen]byte,
	nonrepeatingCnt uint64,
	msg *[MessageLen]byte,
	keyaggCache *[MusigKeyaggCacheLen]byte,
	extraInput *[32]byte,
) ([MusigSecnonceLen]byte, [MusigPubnonceLen]byte, bool) {
	var secnonce [MusigSecnonceLen]byte
	var pubnonce [MusigPubnonceLen]byte

	var msgPtr, keyaggCachePtr, extraInputPtr *C.uchar
	if msg != nil {
		msgPtr = (*C.uchar)(&msg[0])
	}
	if keyaggCache != nil {
		keyaggCachePtr = (*C.uchar)(&keyaggCache[0])
	}
	if extraInput != nil {
		extraInputPtr = (*C.uchar)(&extraInput[0])
	}

	ok := C.shim_musig_nonce_gen_counter(
		context(),
		(*C.uchar)(&seckey[0]),
		C.uint64_t(nonrepeatingCnt),
		msgPtr,
		keyaggCachePtr,
		extraInputPtr,
		(*C.uchar)(&secnonce[0]),
		(*C.uchar)(&pubnonce[0]),
	) == 1
	return secnonce, pubnonce, ok
}

// MusigPubnonceParse decodes a 66-byte pubnonce received from another
// signer into the library's internal representation, the form
// MusigNonceAgg requires.
func MusigPubnonceParse(input66 *[MusigPubnonceSerializedLen]byte) ([MusigPubnonceLen]byte, bool) {
	var out [MusigPubnonceLen]byte
	ok := C.shim_musig_pubnonce_parse(context(), (*C.uchar)(&input66[0]), (*C.uchar)(&out[0])) == 1
	return out, ok
}

// MusigPubnonceSerialize encodes a pubnonce — this signer's own, as returned
// by MusigNonceGen — into the 66-byte form to send to other signers. This
// cannot fail.
func MusigPubnonceSerialize(pubnonce *[MusigPubnonceLen]byte) [MusigPubnonceSerializedLen]byte {
	var out [MusigPubnonceSerializedLen]byte
	C.shim_musig_pubnonce_serialize(context(), (*C.uchar)(&pubnonce[0]), (*C.uchar)(&out[0]))
	return out
}

// MusigAggnonceParse decodes a 66-byte aggregate nonce received from
// whoever ran MusigNonceAgg into the internal representation
// MusigNonceProcess requires.
func MusigAggnonceParse(input66 *[MusigAggnonceSerializedLen]byte) ([MusigAggnonceLen]byte, bool) {
	var out [MusigAggnonceLen]byte
	ok := C.shim_musig_aggnonce_parse(context(), (*C.uchar)(&input66[0]), (*C.uchar)(&out[0])) == 1
	return out, ok
}

// MusigAggnonceSerialize encodes an aggregate nonce into the 66-byte form to
// send to the signers. This cannot fail.
func MusigAggnonceSerialize(aggnonce *[MusigAggnonceLen]byte) [MusigAggnonceSerializedLen]byte {
	var out [MusigAggnonceSerializedLen]byte
	C.shim_musig_aggnonce_serialize(context(), (*C.uchar)(&aggnonce[0]), (*C.uchar)(&out[0]))
	return out
}

// MusigNonceAgg aggregates pubnonces (each already parsed into the internal
// form, via MusigPubnonceParse for nonces received from others, or used
// directly from MusigNonceGen for this signer's own) into one aggregate
// nonce. This can be done by an untrusted party: an incorrectly computed
// aggregate only invalidates the resulting signature, it does not
// compromise anyone's key. At most MaxCombinePubkeys nonces are accepted.
func MusigNonceAgg(pubnonces [][MusigPubnonceLen]byte) ([MusigAggnonceLen]byte, bool) {
	var out [MusigAggnonceLen]byte
	if len(pubnonces) == 0 || len(pubnonces) > MaxCombinePubkeys {
		return out, false
	}
	ok := C.shim_musig_nonce_agg(context(), (*C.uchar)(&pubnonces[0][0]), C.size_t(len(pubnonces)), (*C.uchar)(&out[0])) == 1
	return out, ok
}

// MusigNonceProcess combines aggnonce with msg and cache into a session,
// the object every remaining step (signing, verifying, and aggregating
// partial signatures) is keyed off of.
func MusigNonceProcess(aggnonce *[MusigAggnonceLen]byte, msg *[MessageLen]byte, cache *[MusigKeyaggCacheLen]byte) ([MusigSessionLen]byte, bool) {
	var session [MusigSessionLen]byte
	ok := C.shim_musig_nonce_process(context(), (*C.uchar)(&aggnonce[0]), (*C.uchar)(&msg[0]), (*C.uchar)(&cache[0]), (*C.uchar)(&session[0])) == 1
	return session, ok
}

// MusigPartialSigParse decodes a 32-byte partial signature received from
// another signer into the library's internal representation, the form
// MusigPartialSigVerify requires.
func MusigPartialSigParse(input32 *[MusigPartialSigSerializedLen]byte) ([MusigPartialSigLen]byte, bool) {
	var out [MusigPartialSigLen]byte
	ok := C.shim_musig_partial_sig_parse(context(), (*C.uchar)(&input32[0]), (*C.uchar)(&out[0])) == 1
	return out, ok
}

// MusigPartialSigSerialize encodes a partial signature — this signer's own,
// as returned by MusigPartialSign — into the 32-byte form to send to
// whoever is aggregating. This cannot fail.
func MusigPartialSigSerialize(sig *[MusigPartialSigLen]byte) [MusigPartialSigSerializedLen]byte {
	var out [MusigPartialSigSerializedLen]byte
	C.shim_musig_partial_sig_serialize(context(), (*C.uchar)(&sig[0]), (*C.uchar)(&out[0]))
	return out
}

// MusigPartialSign produces this signer's partial signature for session.
//
// secnonce is consumed: the library overwrites it in place as a best-effort
// guard against reuse, and this call fails outright if handed a secnonce
// that is already all zeros — meaning it was already used here before. It
// must have been generated (via MusigNonceGen or MusigNonceGenCounter) for
// this same seckey and session.
//
// This does not verify its own output, matching upstream's deviation from
// the specification it implements; call MusigPartialSigVerify on the result
// if computation errors (not just malice) are a concern.
func MusigPartialSign(secnonce *[MusigSecnonceLen]byte, seckey *[SeckeyLen]byte, cache *[MusigKeyaggCacheLen]byte, session *[MusigSessionLen]byte) ([MusigPartialSigLen]byte, bool) {
	var sig [MusigPartialSigLen]byte
	ok := C.shim_musig_partial_sign(context(), (*C.uchar)(&secnonce[0]), (*C.uchar)(&seckey[0]), (*C.uchar)(&cache[0]), (*C.uchar)(&session[0]), (*C.uchar)(&sig[0])) == 1
	return sig, ok
}

// MusigPartialSigVerify verifies one signer's partial signature within a
// specific session. Correct operation of a MuSig2 session does not require
// calling this — if any partial signature is wrong, the final aggregate
// signature will simply fail to verify — but this pinpoints which signer's
// contribution was at fault, which the aggregate-only check cannot.
//
// pubnonce and pubkey must be the exact ones that went into aggnonce (via
// MusigNonceAgg) and cache (via MusigPubkeyAgg) respectively for this
// signer; passing a mismatched pair does not necessarily fail loudly, it
// risks verifying against the wrong signing session entirely.
func MusigPartialSigVerify(sig *[MusigPartialSigLen]byte, pubnonce *[MusigPubnonceLen]byte, pubkey []byte, cache *[MusigKeyaggCacheLen]byte, session *[MusigSessionLen]byte) bool {
	if len(pubkey) == 0 {
		return false
	}
	return C.shim_musig_partial_sig_verify(
		context(),
		(*C.uchar)(&sig[0]),
		(*C.uchar)(&pubnonce[0]),
		(*C.uchar)(&pubkey[0]), C.size_t(len(pubkey)),
		(*C.uchar)(&cache[0]),
		(*C.uchar)(&session[0]),
	) == 1
}

// MusigPartialSigAgg combines partialSigs into a complete Schnorr signature —
// verifiable the same way any other Schnorr signature is (SchnorrVerify),
// against the aggregate key from MusigPubkeyAgg. Success here does not mean
// the result verifies: a single bad partial signature (from a computation
// error, not necessarily malice) still combines into a signature that fails
// verification, which is exactly why MusigPartialSigVerify exists as a way
// to isolate the culprit ahead of time. At most MaxCombinePubkeys partial
// signatures are accepted.
func MusigPartialSigAgg(session *[MusigSessionLen]byte, partialSigs [][MusigPartialSigLen]byte) ([SignatureCompactLen]byte, bool) {
	var sig [SignatureCompactLen]byte
	if len(partialSigs) == 0 || len(partialSigs) > MaxCombinePubkeys {
		return sig, false
	}
	ok := C.shim_musig_partial_sig_agg(context(), (*C.uchar)(&session[0]), (*C.uchar)(&partialSigs[0][0]), C.size_t(len(partialSigs)), (*C.uchar)(&sig[0])) == 1
	return sig, ok
}
