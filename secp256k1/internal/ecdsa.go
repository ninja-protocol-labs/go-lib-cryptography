package internal

/*
#include "shim.h"
*/
import "C"

// ECDSASignCompact signs msg (a 32-byte digest, not a raw message) with
// seckey, using RFC 6979 deterministic nonce derivation. Signing the same
// msg/seckey pair twice always produces the identical signature.
func ECDSASignCompact(msg *[MessageLen]byte, seckey *[SeckeyLen]byte) ([SignatureCompactLen]byte, bool) {
	var sig [SignatureCompactLen]byte
	ok := C.shim_ecdsa_sign_compact(context(), (*C.uchar)(&msg[0]), (*C.uchar)(&seckey[0]), nil, (*C.uchar)(&sig[0])) == 1
	return sig, ok
}

// ECDSASignCompactHedged is ECDSASignCompact with auxRand folded into the
// nonce derivation as extra entropy, so repeated signatures over the same
// msg/seckey pair are unlinkable — matching what an HSM or any random-nonce
// signer produces — while staying immune to nonce reuse if auxRand turns out
// to be predictable or even attacker-known. auxRand need not be secret.
func ECDSASignCompactHedged(msg *[MessageLen]byte, seckey *[SeckeyLen]byte, auxRand *[32]byte) ([SignatureCompactLen]byte, bool) {
	var sig [SignatureCompactLen]byte
	ok := C.shim_ecdsa_sign_compact(context(), (*C.uchar)(&msg[0]), (*C.uchar)(&seckey[0]), (*C.uchar)(&auxRand[0]), (*C.uchar)(&sig[0])) == 1
	return sig, ok
}

// ECDSAVerifyCompact reports whether sig is a valid signature over msg (a
// 32-byte digest) by the key pubkey (compressed or uncompressed).
//
// A high-S signature is rejected unless normalize is set, in which case it is
// folded into low-S form before verifying — needed only for signatures from
// implementations that do not enforce low-S themselves.
func ECDSAVerifyCompact(msg *[MessageLen]byte, pubkey []byte, sig *[SignatureCompactLen]byte, normalize bool) bool {
	if len(pubkey) == 0 {
		return false
	}

	var norm C.int
	if normalize {
		norm = 1
	}

	return C.shim_ecdsa_verify_compact(
		context(),
		(*C.uchar)(&msg[0]),
		(*C.uchar)(&pubkey[0]), C.size_t(len(pubkey)),
		(*C.uchar)(&sig[0]),
		norm,
	) == 1
}

// ECDSASignDER is ECDSASignCompact, DER-encoded. Unlike the compressed and
// uncompressed pubkey forms, DER has no second fixed-size sibling to split
// against: its length varies with the signature's R and S values, so the
// output is a max-size buffer plus n, the number of leading bytes actually
// written.
func ECDSASignDER(msg *[MessageLen]byte, seckey *[SeckeyLen]byte) ([SignatureDERMaxLen]byte, int, bool) {
	var sig [SignatureDERMaxLen]byte
	length := C.size_t(len(sig))
	ok := C.shim_ecdsa_sign_der(context(), (*C.uchar)(&msg[0]), (*C.uchar)(&seckey[0]), nil, (*C.uchar)(&sig[0]), &length) == 1
	return sig, int(length), ok
}

// ECDSASignDERHedged is ECDSASignDER with the same aux_rand semantics as
// ECDSASignCompactHedged.
func ECDSASignDERHedged(msg *[MessageLen]byte, seckey *[SeckeyLen]byte, auxRand *[32]byte) ([SignatureDERMaxLen]byte, int, bool) {
	var sig [SignatureDERMaxLen]byte
	length := C.size_t(len(sig))
	ok := C.shim_ecdsa_sign_der(context(), (*C.uchar)(&msg[0]), (*C.uchar)(&seckey[0]), (*C.uchar)(&auxRand[0]), (*C.uchar)(&sig[0]), &length) == 1
	return sig, int(length), ok
}

// ECDSAVerifyDER is ECDSAVerifyCompact for a DER-encoded signature.
func ECDSAVerifyDER(msg *[MessageLen]byte, pubkey []byte, sig []byte, normalize bool) bool {
	if len(pubkey) == 0 || len(sig) == 0 {
		return false
	}

	var norm C.int
	if normalize {
		norm = 1
	}

	return C.shim_ecdsa_verify_der(
		context(),
		(*C.uchar)(&msg[0]),
		(*C.uchar)(&pubkey[0]), C.size_t(len(pubkey)),
		(*C.uchar)(&sig[0]), C.size_t(len(sig)),
		norm,
	) == 1
}

// ECDSASignatureNormalize folds sig into low-S form. wasHigh reports whether
// sig needed normalizing, which lets a caller enforcing a low-S policy reject
// the original instead of silently accepting the fixed-up version. ok is
// false only if sig's R or S component is out of range.
func ECDSASignatureNormalize(sig *[SignatureCompactLen]byte) ([SignatureCompactLen]byte, bool, bool) {
	var out [SignatureCompactLen]byte
	var high C.int
	ok := C.shim_ecdsa_signature_normalize(context(), (*C.uchar)(&sig[0]), (*C.uchar)(&out[0]), &high) == 1
	return out, high == 1, ok
}

// ECDSASignatureDERToCompact re-encodes a DER signature as compact, without
// re-signing.
func ECDSASignatureDERToCompact(sig []byte) ([SignatureCompactLen]byte, bool) {
	var out [SignatureCompactLen]byte
	if len(sig) == 0 {
		return out, false
	}
	ok := C.shim_ecdsa_signature_der_to_compact(context(), (*C.uchar)(&sig[0]), C.size_t(len(sig)), (*C.uchar)(&out[0])) == 1
	return out, ok
}

// ECDSASignatureCompactToDER re-encodes a compact signature as DER, without
// re-signing. n reports how many leading bytes of the returned buffer are
// valid, for the same reason as in ECDSASignDER. ok is false only if sig's R
// or S component is out of range.
func ECDSASignatureCompactToDER(sig *[SignatureCompactLen]byte) ([SignatureDERMaxLen]byte, int, bool) {
	var out [SignatureDERMaxLen]byte
	length := C.size_t(len(out))
	ok := C.shim_ecdsa_signature_compact_to_der(context(), (*C.uchar)(&sig[0]), (*C.uchar)(&out[0]), &length) == 1
	return out, int(length), ok
}

// ECDSASignRecoverable is ECDSASignCompact plus a recovery id: the extra
// value that lets ECDSARecover reconstruct the signer's public key from the
// signature and message alone, with no public key supplied.
func ECDSASignRecoverable(msg *[MessageLen]byte, seckey *[SeckeyLen]byte) ([SignatureCompactLen]byte, int, bool) {
	var sig [SignatureCompactLen]byte
	var recID C.int
	ok := C.shim_ecdsa_sign_recoverable(context(), (*C.uchar)(&msg[0]), (*C.uchar)(&seckey[0]), nil, (*C.uchar)(&sig[0]), &recID) == 1
	return sig, int(recID), ok
}

// ECDSASignRecoverableHedged is ECDSASignRecoverable with the same aux_rand
// semantics as ECDSASignCompactHedged.
func ECDSASignRecoverableHedged(msg *[MessageLen]byte, seckey *[SeckeyLen]byte, auxRand *[32]byte) ([SignatureCompactLen]byte, int, bool) {
	var sig [SignatureCompactLen]byte
	var recID C.int
	ok := C.shim_ecdsa_sign_recoverable(context(), (*C.uchar)(&msg[0]), (*C.uchar)(&seckey[0]), (*C.uchar)(&auxRand[0]), (*C.uchar)(&sig[0]), &recID) == 1
	return sig, int(recID), ok
}

// ECDSARecoverCompressed recovers the compressed public key that produced sig
// (with the recovery id from ECDSASignRecoverable) over msg.
//
// recoveryID is checked against its only valid range, [0, 3], before
// crossing into C: libsecp256k1 rejects it there too, but only after
// logging it as a caller misuse, which a plain out-of-range value from
// untrusted input does not deserve.
func ECDSARecoverCompressed(msg *[MessageLen]byte, sig *[SignatureCompactLen]byte, recoveryID int) ([PubkeyCompressedLen]byte, bool) {
	var out [PubkeyCompressedLen]byte
	if recoveryID < 0 || recoveryID > 3 {
		return out, false
	}
	length := C.size_t(len(out))
	ok := C.shim_ecdsa_recover(context(), (*C.uchar)(&msg[0]), (*C.uchar)(&sig[0]), C.int(recoveryID), (*C.uchar)(&out[0]), &length, 1) == 1
	return out, ok
}

// ECDSARecoverUncompressed is ECDSARecoverCompressed, uncompressed.
func ECDSARecoverUncompressed(msg *[MessageLen]byte, sig *[SignatureCompactLen]byte, recoveryID int) ([PubkeyUncompressedLen]byte, bool) {
	var out [PubkeyUncompressedLen]byte
	if recoveryID < 0 || recoveryID > 3 {
		return out, false
	}
	length := C.size_t(len(out))
	ok := C.shim_ecdsa_recover(context(), (*C.uchar)(&msg[0]), (*C.uchar)(&sig[0]), C.int(recoveryID), (*C.uchar)(&out[0]), &length, 0) == 1
	return out, ok
}
