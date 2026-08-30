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
