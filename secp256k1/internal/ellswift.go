package internal

/*
#include "shim.h"
*/
import "C"

// EllswiftEncode re-encodes pubkey (compressed or uncompressed) as 64 bytes
// indistinguishable from uniform randomness. rnd selects among the encoding's
// several valid representations for the same point; the output is not stable
// even for identical inputs across library versions, so it must not be
// treated as a canonical serialization.
func EllswiftEncode(pubkey []byte, rnd *[32]byte) ([EllswiftLen]byte, bool) {
	var out [EllswiftLen]byte
	if len(pubkey) == 0 {
		return out, false
	}
	ok := C.shim_ellswift_encode(context(), (*C.uchar)(&pubkey[0]), C.size_t(len(pubkey)), (*C.uchar)(&rnd[0]), (*C.uchar)(&out[0])) == 1
	return out, ok
}

// EllswiftDecodeCompressed decodes an EllswiftEncode-produced encoding back
// to a compressed public key. Every 64-byte input decodes to some valid
// point, so this cannot fail.
func EllswiftDecodeCompressed(ell *[EllswiftLen]byte) [PubkeyCompressedLen]byte {
	var out [PubkeyCompressedLen]byte
	length := C.size_t(len(out))
	C.shim_ellswift_decode(context(), (*C.uchar)(&ell[0]), (*C.uchar)(&out[0]), &length, 1)
	return out
}

// EllswiftDecodeUncompressed is EllswiftDecodeCompressed, uncompressed.
func EllswiftDecodeUncompressed(ell *[EllswiftLen]byte) [PubkeyUncompressedLen]byte {
	var out [PubkeyUncompressedLen]byte
	length := C.size_t(len(out))
	C.shim_ellswift_decode(context(), (*C.uchar)(&ell[0]), (*C.uchar)(&out[0]), &length, 0)
	return out
}

// EllswiftCreate derives the ElligatorSwift encoding of seckey's public key
// directly, without a separate public-key-derivation step. auxRand is
// optional extra entropy for the encoding (not for the key itself); pass nil
// to omit it.
func EllswiftCreate(seckey *[SeckeyLen]byte, auxRand *[32]byte) ([EllswiftLen]byte, bool) {
	var out [EllswiftLen]byte
	var auxPtr *C.uchar
	if auxRand != nil {
		auxPtr = (*C.uchar)(&auxRand[0])
	}
	ok := C.shim_ellswift_create(context(), (*C.uchar)(&seckey[0]), auxPtr, (*C.uchar)(&out[0])) == 1
	return out, ok
}

// EllswiftECDH computes the shared secret between two ElligatorSwift-encoded
// points as SHA-256(ellA || ellB || x), x being the shared point's x
// coordinate. ellA and ellB are fixed roles, not peer/own — isPartyB selects
// which one seckey corresponds to, and that correspondence is the caller's
// responsibility: it is not checked.
func EllswiftECDH(ellA, ellB *[EllswiftLen]byte, seckey *[SeckeyLen]byte, isPartyB bool) ([HashLen]byte, bool) {
	var out [HashLen]byte
	var party C.int
	if isPartyB {
		party = 1
	}
	ok := C.shim_ellswift_xdh(context(), (*C.uchar)(&ellA[0]), (*C.uchar)(&ellB[0]), (*C.uchar)(&seckey[0]), party, (*C.uchar)(&out[0])) == 1
	return out, ok
}
