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

#include "shim.h"
*/
import "C"

// Buffer sizes, taken from the header so the two cannot drift apart.
const (
	SeckeyLen             = C.SHIM_SECKEY_LEN
	PubkeyCompressedLen   = C.SHIM_PUBKEY_COMPRESSED_LEN
	PubkeyUncompressedLen = C.SHIM_PUBKEY_UNCOMPRESSED_LEN
	XonlyPubkeyLen        = C.SHIM_XONLY_PUBKEY_LEN
	SignatureCompactLen   = C.SHIM_SIGNATURE_COMPACT_LEN
	SignatureDERMaxLen    = C.SHIM_SIGNATURE_DER_MAX_LEN
	MessageLen            = C.SHIM_MESSAGE_LEN
	SharedSecretLen       = C.SHIM_SHARED_SECRET_LEN
	TweakLen              = C.SHIM_TWEAK_LEN
	HashLen               = C.SHIM_HASH_LEN
	MaxCombinePubkeys     = C.SHIM_MAX_COMBINE_PUBKEYS
	EllswiftLen           = C.SHIM_ELLSWIFT_LEN

	MusigKeyaggCacheLen          = C.SHIM_MUSIG_KEYAGG_CACHE_LEN
	MusigSecnonceLen             = C.SHIM_MUSIG_SECNONCE_LEN
	MusigPubnonceLen             = C.SHIM_MUSIG_PUBNONCE_LEN
	MusigPubnonceSerializedLen   = C.SHIM_MUSIG_PUBNONCE_SERIALIZED_LEN
	MusigAggnonceLen             = C.SHIM_MUSIG_AGGNONCE_LEN
	MusigAggnonceSerializedLen   = C.SHIM_MUSIG_AGGNONCE_SERIALIZED_LEN
	MusigSessionLen              = C.SHIM_MUSIG_SESSION_LEN
	MusigPartialSigLen           = C.SHIM_MUSIG_PARTIAL_SIG_LEN
	MusigPartialSigSerializedLen = C.SHIM_MUSIG_PARTIAL_SIG_SERIALIZED_LEN
)
