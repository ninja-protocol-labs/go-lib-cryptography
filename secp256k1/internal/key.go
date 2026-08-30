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
