package internal

/*
#include "shim.h"
*/
import "C"

// ECDH computes the shared secret between seckey and pubkey (compressed or
// uncompressed): SHA-256 of the compressed encoding of seckey*pubkey.
func ECDH(pubkey []byte, seckey *[SeckeyLen]byte) ([SharedSecretLen]byte, bool) {
	var out [SharedSecretLen]byte
	if len(pubkey) == 0 {
		return out, false
	}
	ok := C.shim_ecdh(context(), (*C.uchar)(&pubkey[0]), C.size_t(len(pubkey)), (*C.uchar)(&seckey[0]), (*C.uchar)(&out[0])) == 1
	return out, ok
}
