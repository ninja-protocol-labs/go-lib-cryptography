package internal

/*
#include "shim.h"
*/
import "C"

// SeckeyVerify reports whether seckey is a usable secret key, meaning it decodes
// to a scalar in [1, n-1]. Zero and anything at or above the curve order are
// rejected.
//
// The argument is a pointer to a fixed-size array rather than a slice: it makes
// the length a compile-time guarantee instead of a runtime check, and keeps the
// buffer on the caller's stack.
func SeckeyVerify(seckey *[SeckeyLen]byte) bool {
	return C.shim_seckey_verify(context(), (*C.uchar)(&seckey[0])) == 1
}

// PubkeyCreateCompressed derives the 33-byte compressed public key for seckey.
func PubkeyCreateCompressed(seckey *[SeckeyLen]byte) ([PubkeyCompressedLen]byte, bool) {
	var pub [PubkeyCompressedLen]byte
	length := C.size_t(len(pub))
	ok := C.shim_pubkey_create(context(), (*C.uchar)(&seckey[0]), (*C.uchar)(&pub[0]), &length, 1) == 1
	return pub, ok
}

// PubkeyCreateUncompressed derives the 65-byte uncompressed public key for
// seckey.
func PubkeyCreateUncompressed(seckey *[SeckeyLen]byte) ([PubkeyUncompressedLen]byte, bool) {
	var pub [PubkeyUncompressedLen]byte
	length := C.size_t(len(pub))
	ok := C.shim_pubkey_create(context(), (*C.uchar)(&seckey[0]), (*C.uchar)(&pub[0]), &length, 0) == 1
	return pub, ok
}

// PubkeyParseCompressed validates pubkey — either the 33-byte compressed or
// the 65-byte uncompressed encoding — and returns it re-serialized in
// compressed form.
//
// The input is a slice rather than a fixed array because its length is exactly
// what is being validated: unlike seckey or a tweak, there is no single correct
// size to bake into the type.
func PubkeyParseCompressed(pubkey []byte) ([PubkeyCompressedLen]byte, bool) {
	var out [PubkeyCompressedLen]byte
	if len(pubkey) == 0 {
		return out, false
	}
	length := C.size_t(len(out))
	ok := C.shim_pubkey_parse(context(), (*C.uchar)(&pubkey[0]), C.size_t(len(pubkey)), (*C.uchar)(&out[0]), &length, 1) == 1
	return out, ok
}

// PubkeyParseUncompressed validates pubkey — either the 33-byte compressed or
// the 65-byte uncompressed encoding — and returns it re-serialized in
// uncompressed form.
func PubkeyParseUncompressed(pubkey []byte) ([PubkeyUncompressedLen]byte, bool) {
	var out [PubkeyUncompressedLen]byte
	if len(pubkey) == 0 {
		return out, false
	}
	length := C.size_t(len(out))
	ok := C.shim_pubkey_parse(context(), (*C.uchar)(&pubkey[0]), C.size_t(len(pubkey)), (*C.uchar)(&out[0]), &length, 0) == 1
	return out, ok
}
