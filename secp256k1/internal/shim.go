// Package internal is the cgo boundary for the vendored libsecp256k1.
//
// Everything that touches C lives here; the public secp256k1 package consumes
// this one through plain Go types only. Keeping the boundary in a single
// internal package means the exported API never leaks cgo details, and lets a
// pure-Go backend be swapped in later without touching callers.
package internal

/*
#cgo CFLAGS: -I${SRCDIR}/lib/secp256k1
#cgo CFLAGS: -I${SRCDIR}/lib/secp256k1/src
#cgo CFLAGS: -I${SRCDIR}/lib/secp256k1/include
#cgo CFLAGS: -DENABLE_MODULE_ECDH=1
#cgo CFLAGS: -DENABLE_MODULE_EXTRAKEYS=1
#cgo CFLAGS: -DENABLE_MODULE_SCHNORRSIG=1
#cgo CFLAGS: -DENABLE_MODULE_RECOVERY=1
#cgo CFLAGS: -DENABLE_MODULE_ELLSWIFT=1
#cgo CFLAGS: -DENABLE_MODULE_MUSIG=1
#cgo CFLAGS: -DECMULT_WINDOW_SIZE=15
#cgo CFLAGS: -DECMULT_GEN_PREC_BITS=4

// Without these, escape analysis has to assume every C function stashes the
// pointers it is handed, so each buffer crossing the boundary is forced onto
// the heap. No shim function retains a caller pointer past its return, and none
// calls back into Go, so both promises hold for the whole surface.
#cgo noescape shim_context_create
#cgo nocallback shim_context_create
#cgo noescape shim_seckey_verify
#cgo nocallback shim_seckey_verify
#cgo noescape shim_pubkey_create
#cgo nocallback shim_pubkey_create
#cgo noescape shim_pubkey_parse
#cgo nocallback shim_pubkey_parse
#cgo noescape shim_ecdsa_sign_compact
#cgo nocallback shim_ecdsa_sign_compact
#cgo noescape shim_ecdsa_verify_compact
#cgo nocallback shim_ecdsa_verify_compact
#cgo noescape shim_ecdsa_sign_der
#cgo nocallback shim_ecdsa_sign_der
#cgo noescape shim_ecdsa_verify_der
#cgo nocallback shim_ecdsa_verify_der
#cgo noescape shim_ecdsa_signature_normalize
#cgo nocallback shim_ecdsa_signature_normalize
#cgo noescape shim_ecdsa_signature_der_to_compact
#cgo nocallback shim_ecdsa_signature_der_to_compact
#cgo noescape shim_ecdsa_signature_compact_to_der
#cgo nocallback shim_ecdsa_signature_compact_to_der
#cgo noescape shim_seckey_negate
#cgo nocallback shim_seckey_negate
#cgo noescape shim_pubkey_negate
#cgo nocallback shim_pubkey_negate
#cgo noescape shim_pubkey_combine
#cgo nocallback shim_pubkey_combine
#cgo noescape shim_pubkey_cmp
#cgo nocallback shim_pubkey_cmp
#cgo noescape shim_pubkey_sort
#cgo nocallback shim_pubkey_sort
#cgo noescape shim_seckey_tweak_add
#cgo nocallback shim_seckey_tweak_add
#cgo noescape shim_seckey_tweak_mul
#cgo nocallback shim_seckey_tweak_mul
#cgo noescape shim_pubkey_tweak_add
#cgo nocallback shim_pubkey_tweak_add
#cgo noescape shim_pubkey_tweak_mul
#cgo nocallback shim_pubkey_tweak_mul
#cgo noescape shim_ecdsa_sign_recoverable
#cgo nocallback shim_ecdsa_sign_recoverable
#cgo noescape shim_ecdsa_recover
#cgo nocallback shim_ecdsa_recover
#cgo noescape shim_xonly_pubkey_create
#cgo nocallback shim_xonly_pubkey_create
#cgo noescape shim_xonly_pubkey_verify
#cgo nocallback shim_xonly_pubkey_verify
#cgo noescape shim_xonly_pubkey_from_pubkey
#cgo nocallback shim_xonly_pubkey_from_pubkey
#cgo noescape shim_xonly_pubkey_cmp
#cgo nocallback shim_xonly_pubkey_cmp
#cgo noescape shim_xonly_pubkey_tweak_add
#cgo nocallback shim_xonly_pubkey_tweak_add
#cgo noescape shim_xonly_pubkey_tweak_add_check
#cgo nocallback shim_xonly_pubkey_tweak_add_check
#cgo noescape shim_seckey_xonly_tweak_add
#cgo nocallback shim_seckey_xonly_tweak_add
#cgo noescape shim_schnorr_sign
#cgo nocallback shim_schnorr_sign
#cgo noescape shim_schnorr_verify
#cgo nocallback shim_schnorr_verify
#cgo noescape shim_ecdh
#cgo nocallback shim_ecdh
#cgo noescape shim_ellswift_encode
#cgo nocallback shim_ellswift_encode
#cgo noescape shim_ellswift_decode
#cgo nocallback shim_ellswift_decode
#cgo noescape shim_ellswift_create
#cgo nocallback shim_ellswift_create
#cgo noescape shim_ellswift_xdh
#cgo nocallback shim_ellswift_xdh
#cgo noescape shim_musig_pubkey_agg
#cgo nocallback shim_musig_pubkey_agg
#cgo noescape shim_musig_pubkey_get
#cgo nocallback shim_musig_pubkey_get
#cgo noescape shim_musig_pubkey_ec_tweak_add
#cgo nocallback shim_musig_pubkey_ec_tweak_add
#cgo noescape shim_musig_pubkey_xonly_tweak_add
#cgo nocallback shim_musig_pubkey_xonly_tweak_add
#cgo noescape shim_musig_nonce_gen
#cgo nocallback shim_musig_nonce_gen
#cgo noescape shim_musig_nonce_gen_counter
#cgo nocallback shim_musig_nonce_gen_counter
#cgo noescape shim_musig_pubnonce_parse
#cgo nocallback shim_musig_pubnonce_parse
#cgo noescape shim_musig_pubnonce_serialize
#cgo nocallback shim_musig_pubnonce_serialize
#cgo noescape shim_musig_aggnonce_parse
#cgo nocallback shim_musig_aggnonce_parse
#cgo noescape shim_musig_aggnonce_serialize
#cgo nocallback shim_musig_aggnonce_serialize
#cgo noescape shim_musig_nonce_agg
#cgo nocallback shim_musig_nonce_agg
#cgo noescape shim_musig_nonce_process
#cgo nocallback shim_musig_nonce_process
#cgo noescape shim_musig_partial_sig_parse
#cgo nocallback shim_musig_partial_sig_parse
#cgo noescape shim_musig_partial_sig_serialize
#cgo nocallback shim_musig_partial_sig_serialize
#cgo noescape shim_musig_partial_sign
#cgo nocallback shim_musig_partial_sign
#cgo noescape shim_musig_partial_sig_verify
#cgo nocallback shim_musig_partial_sig_verify
#cgo noescape shim_musig_partial_sig_agg
#cgo nocallback shim_musig_partial_sig_agg

#include "shim.h"
*/
import "C"

// Buffer sizes. Plain Go int literals rather than aliasing C.SHIM_* directly
// — gopls (and so most editors) can't run cgo while indexing, so a cgo-derived
// array length like [C.SHIM_MESSAGE_LEN]byte reads to it as unresolvable,
// which has been observed to make it mis-infer the pointer type of a
// parameter such as msg *[MessageLen]byte entirely (e.g. as *[]byte),
// producing a false type error at the call site despite `go build` being
// clean. The compile-time assertions below are what actually keep these
// from drifting out of sync with the C headers, instead of the alias
// itself.
const (
	SeckeyLen             = 32
	PubkeyCompressedLen   = 33
	PubkeyUncompressedLen = 65
	XonlyPubkeyLen        = 32
	SignatureCompactLen   = 64
	SignatureDERMaxLen    = 72
	MessageLen            = 32
	SharedSecretLen       = 32
	TweakLen              = 32
	HashLen               = 32
	MaxCombinePubkeys     = 64
	EllswiftLen           = 64

	MusigKeyaggCacheLen          = 197
	MusigSecnonceLen             = 132
	MusigPubnonceLen             = 132
	MusigPubnonceSerializedLen   = 66
	MusigAggnonceLen             = 132
	MusigAggnonceSerializedLen   = 66
	MusigSessionLen              = 133
	MusigPartialSigLen           = 36
	MusigPartialSigSerializedLen = 32
)

// Compile-time assertions that the constants above exactly match the C
// headers. An array size expression only compiles if it is non-negative, so
// each pair — the difference taken in both directions — only compiles if the
// two sides are equal; any drift fails the build immediately.
var (
	_ [SeckeyLen - int(C.SHIM_SECKEY_LEN)]byte
	_ [int(C.SHIM_SECKEY_LEN) - SeckeyLen]byte
	_ [PubkeyCompressedLen - int(C.SHIM_PUBKEY_COMPRESSED_LEN)]byte
	_ [int(C.SHIM_PUBKEY_COMPRESSED_LEN) - PubkeyCompressedLen]byte
	_ [PubkeyUncompressedLen - int(C.SHIM_PUBKEY_UNCOMPRESSED_LEN)]byte
	_ [int(C.SHIM_PUBKEY_UNCOMPRESSED_LEN) - PubkeyUncompressedLen]byte
	_ [XonlyPubkeyLen - int(C.SHIM_XONLY_PUBKEY_LEN)]byte
	_ [int(C.SHIM_XONLY_PUBKEY_LEN) - XonlyPubkeyLen]byte
	_ [SignatureCompactLen - int(C.SHIM_SIGNATURE_COMPACT_LEN)]byte
	_ [int(C.SHIM_SIGNATURE_COMPACT_LEN) - SignatureCompactLen]byte
	_ [SignatureDERMaxLen - int(C.SHIM_SIGNATURE_DER_MAX_LEN)]byte
	_ [int(C.SHIM_SIGNATURE_DER_MAX_LEN) - SignatureDERMaxLen]byte
	_ [MessageLen - int(C.SHIM_MESSAGE_LEN)]byte
	_ [int(C.SHIM_MESSAGE_LEN) - MessageLen]byte
	_ [SharedSecretLen - int(C.SHIM_SHARED_SECRET_LEN)]byte
	_ [int(C.SHIM_SHARED_SECRET_LEN) - SharedSecretLen]byte
	_ [TweakLen - int(C.SHIM_TWEAK_LEN)]byte
	_ [int(C.SHIM_TWEAK_LEN) - TweakLen]byte
	_ [HashLen - int(C.SHIM_HASH_LEN)]byte
	_ [int(C.SHIM_HASH_LEN) - HashLen]byte
	_ [MaxCombinePubkeys - int(C.SHIM_MAX_COMBINE_PUBKEYS)]byte
	_ [int(C.SHIM_MAX_COMBINE_PUBKEYS) - MaxCombinePubkeys]byte
	_ [EllswiftLen - int(C.SHIM_ELLSWIFT_LEN)]byte
	_ [int(C.SHIM_ELLSWIFT_LEN) - EllswiftLen]byte
	_ [MusigKeyaggCacheLen - int(C.SHIM_MUSIG_KEYAGG_CACHE_LEN)]byte
	_ [int(C.SHIM_MUSIG_KEYAGG_CACHE_LEN) - MusigKeyaggCacheLen]byte
	_ [MusigSecnonceLen - int(C.SHIM_MUSIG_SECNONCE_LEN)]byte
	_ [int(C.SHIM_MUSIG_SECNONCE_LEN) - MusigSecnonceLen]byte
	_ [MusigPubnonceLen - int(C.SHIM_MUSIG_PUBNONCE_LEN)]byte
	_ [int(C.SHIM_MUSIG_PUBNONCE_LEN) - MusigPubnonceLen]byte
	_ [MusigPubnonceSerializedLen - int(C.SHIM_MUSIG_PUBNONCE_SERIALIZED_LEN)]byte
	_ [int(C.SHIM_MUSIG_PUBNONCE_SERIALIZED_LEN) - MusigPubnonceSerializedLen]byte
	_ [MusigAggnonceLen - int(C.SHIM_MUSIG_AGGNONCE_LEN)]byte
	_ [int(C.SHIM_MUSIG_AGGNONCE_LEN) - MusigAggnonceLen]byte
	_ [MusigAggnonceSerializedLen - int(C.SHIM_MUSIG_AGGNONCE_SERIALIZED_LEN)]byte
	_ [int(C.SHIM_MUSIG_AGGNONCE_SERIALIZED_LEN) - MusigAggnonceSerializedLen]byte
	_ [MusigSessionLen - int(C.SHIM_MUSIG_SESSION_LEN)]byte
	_ [int(C.SHIM_MUSIG_SESSION_LEN) - MusigSessionLen]byte
	_ [MusigPartialSigLen - int(C.SHIM_MUSIG_PARTIAL_SIG_LEN)]byte
	_ [int(C.SHIM_MUSIG_PARTIAL_SIG_LEN) - MusigPartialSigLen]byte
	_ [MusigPartialSigSerializedLen - int(C.SHIM_MUSIG_PARTIAL_SIG_SERIALIZED_LEN)]byte
	_ [int(C.SHIM_MUSIG_PARTIAL_SIG_SERIALIZED_LEN) - MusigPartialSigSerializedLen]byte
)
