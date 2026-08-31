package internal

/*
#include "shim.h"
*/
import "C"
import "unsafe"

// Keygen derives a secret key scalar (big-endian) from ikm and info. See
// shim_keygen's doc comment in shim.h for the parameters' meaning.
func Keygen(ikm, info []byte) [32]byte {
	var out [32]byte

	var ikmPtr *C.byte
	if len(ikm) > 0 {
		ikmPtr = (*C.byte)(unsafe.Pointer(&ikm[0]))
	}
	var infoPtr *C.byte
	if len(info) > 0 {
		infoPtr = (*C.byte)(unsafe.Pointer(&info[0]))
	}

	C.shim_keygen(
		(*C.byte)(unsafe.Pointer(&out[0])),
		ikmPtr, C.size_t(len(ikm)),
		infoPtr, C.size_t(len(info)),
	)
	return out
}
