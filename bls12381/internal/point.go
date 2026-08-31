package internal

/*
#include "shim.h"
*/
import "C"

// G1 points, wire format and arithmetic. See point.go's G2 half below for
// the minimal-signature-size mirror of everything here.

// P1Uncompress parses a 48-byte compressed G1 point. The int is one of the
// Err* codes in shim.go (ErrSuccess on success); it checks the encoding and
// that the point is on the curve, but not subgroup membership — call
// P1AffineInG1 for that.
func P1Uncompress(in *[P1CompressedLen]byte) ([P1AffineLen]byte, int) {
	var out [P1AffineLen]byte
	code := C.shim_p1_uncompress((*C.byte)(&out[0]), (*C.byte)(&in[0]))
	return out, int(code)
}

// P1Deserialize is P1Uncompress for the 96-byte uncompressed encoding.
func P1Deserialize(in *[P1SerializedLen]byte) ([P1AffineLen]byte, int) {
	var out [P1AffineLen]byte
	code := C.shim_p1_deserialize((*C.byte)(&out[0]), (*C.byte)(&in[0]))
	return out, int(code)
}

func P1AffineCompress(p *[P1AffineLen]byte) [P1CompressedLen]byte {
	var out [P1CompressedLen]byte
	C.shim_p1_affine_compress((*C.byte)(&out[0]), (*C.byte)(&p[0]))
	return out
}

func P1AffineSerialize(p *[P1AffineLen]byte) [P1SerializedLen]byte {
	var out [P1SerializedLen]byte
	C.shim_p1_affine_serialize((*C.byte)(&out[0]), (*C.byte)(&p[0]))
	return out
}

func P1AffineOnCurve(p *[P1AffineLen]byte) bool {
	return C.shim_p1_affine_on_curve((*C.byte)(&p[0])) == 1
}

func P1AffineInG1(p *[P1AffineLen]byte) bool {
	return C.shim_p1_affine_in_g1((*C.byte)(&p[0])) == 1
}

func P1AffineIsInf(p *[P1AffineLen]byte) bool {
	return C.shim_p1_affine_is_inf((*C.byte)(&p[0])) == 1
}

func P1AffineIsEqual(a, b *[P1AffineLen]byte) bool {
	return C.shim_p1_affine_is_equal((*C.byte)(&a[0]), (*C.byte)(&b[0])) == 1
}

func P1AffineGenerator() [P1AffineLen]byte {
	var out [P1AffineLen]byte
	C.shim_p1_affine_generator((*C.byte)(&out[0]))
	return out
}

func P1Add(a, b *[P1AffineLen]byte) [P1AffineLen]byte {
	var out [P1AffineLen]byte
	C.shim_p1_add((*C.byte)(&out[0]), (*C.byte)(&a[0]), (*C.byte)(&b[0]))
	return out
}

func P1Double(a *[P1AffineLen]byte) [P1AffineLen]byte {
	var out [P1AffineLen]byte
	C.shim_p1_double((*C.byte)(&out[0]), (*C.byte)(&a[0]))
	return out
}

// P1Mult multiplies p by a big-endian scalar of up to ScalarLen (32) bytes.
// nbits is the scalar's width in bits, not bytes — pass fewer than 256 for a
// shorter scalar (e.g. a small blinding factor) without padding it out
// first. See shim_p1_mult's doc comment in shim.h for why this is
// big-endian despite blst's own underlying primitive being little-endian.
func P1Mult(p *[P1AffineLen]byte, scalar []byte, nbits int) [P1AffineLen]byte {
	var out [P1AffineLen]byte
	var scalarPtr *C.byte
	if len(scalar) > 0 {
		scalarPtr = (*C.byte)(&scalar[0])
	}
	C.shim_p1_mult((*C.byte)(&out[0]), (*C.byte)(&p[0]), scalarPtr, C.size_t(nbits))
	return out
}

func P1Neg(p *[P1AffineLen]byte) [P1AffineLen]byte {
	var out [P1AffineLen]byte
	C.shim_p1_neg((*C.byte)(&out[0]), (*C.byte)(&p[0]))
	return out
}

// G2 points — the mirror of the G1 functions above, at G2's sizes.

func P2Uncompress(in *[P2CompressedLen]byte) ([P2AffineLen]byte, int) {
	var out [P2AffineLen]byte
	code := C.shim_p2_uncompress((*C.byte)(&out[0]), (*C.byte)(&in[0]))
	return out, int(code)
}

func P2Deserialize(in *[P2SerializedLen]byte) ([P2AffineLen]byte, int) {
	var out [P2AffineLen]byte
	code := C.shim_p2_deserialize((*C.byte)(&out[0]), (*C.byte)(&in[0]))
	return out, int(code)
}

func P2AffineCompress(p *[P2AffineLen]byte) [P2CompressedLen]byte {
	var out [P2CompressedLen]byte
	C.shim_p2_affine_compress((*C.byte)(&out[0]), (*C.byte)(&p[0]))
	return out
}

func P2AffineSerialize(p *[P2AffineLen]byte) [P2SerializedLen]byte {
	var out [P2SerializedLen]byte
	C.shim_p2_affine_serialize((*C.byte)(&out[0]), (*C.byte)(&p[0]))
	return out
}

func P2AffineOnCurve(p *[P2AffineLen]byte) bool {
	return C.shim_p2_affine_on_curve((*C.byte)(&p[0])) == 1
}

func P2AffineInG2(p *[P2AffineLen]byte) bool {
	return C.shim_p2_affine_in_g2((*C.byte)(&p[0])) == 1
}

func P2AffineIsInf(p *[P2AffineLen]byte) bool {
	return C.shim_p2_affine_is_inf((*C.byte)(&p[0])) == 1
}

func P2AffineIsEqual(a, b *[P2AffineLen]byte) bool {
	return C.shim_p2_affine_is_equal((*C.byte)(&a[0]), (*C.byte)(&b[0])) == 1
}

func P2AffineGenerator() [P2AffineLen]byte {
	var out [P2AffineLen]byte
	C.shim_p2_affine_generator((*C.byte)(&out[0]))
	return out
}

func P2Add(a, b *[P2AffineLen]byte) [P2AffineLen]byte {
	var out [P2AffineLen]byte
	C.shim_p2_add((*C.byte)(&out[0]), (*C.byte)(&a[0]), (*C.byte)(&b[0]))
	return out
}

func P2Double(a *[P2AffineLen]byte) [P2AffineLen]byte {
	var out [P2AffineLen]byte
	C.shim_p2_double((*C.byte)(&out[0]), (*C.byte)(&a[0]))
	return out
}

// See P1Mult — same big-endian-in, capped-at-32-bytes contract.
func P2Mult(p *[P2AffineLen]byte, scalar []byte, nbits int) [P2AffineLen]byte {
	var out [P2AffineLen]byte
	var scalarPtr *C.byte
	if len(scalar) > 0 {
		scalarPtr = (*C.byte)(&scalar[0])
	}
	C.shim_p2_mult((*C.byte)(&out[0]), (*C.byte)(&p[0]), scalarPtr, C.size_t(nbits))
	return out
}

func P2Neg(p *[P2AffineLen]byte) [P2AffineLen]byte {
	var out [P2AffineLen]byte
	C.shim_p2_neg((*C.byte)(&out[0]), (*C.byte)(&p[0]))
	return out
}
