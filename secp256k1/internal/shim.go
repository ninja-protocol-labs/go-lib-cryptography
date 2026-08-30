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
)
