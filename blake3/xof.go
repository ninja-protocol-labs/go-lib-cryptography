package blake3

import (
	"io"

	"lukechampine.com/blake3"
)

// XOF is BLAKE3's extendable output: absorb input with Write, then read as
// many bytes as you want with Read.
//
// What sets it apart from sha3's SHAKE and blake2b's BLAKE2Xb is that no
// length is declared up front and none is bound into the state: the first
// 32 bytes are Sum256's digest, the first 64 are Sum512's, and the stream
// continues from there. Reading more never changes what came before. The
// stream is 2⁶⁴-1 bytes long, which is not a limit anyone reaches.
//
// # No Seek, for now
//
// BLAKE3's output is genuinely seekable — its tree structure lets an
// implementation jump to byte 2⁴⁰ without producing the ones before it,
// which neither SHAKE nor BLAKE2Xb can do. That is not exposed here
// because the backend's Seek is wrong: in lukechampine.com/blake3 v1.4.1
// it lands correctly only within the first 64 bytes of each 1024-byte
// group, and returns another part of the stream everywhere else.
//
// Wrapping a broken primitive in a workaround is not something this
// package will do, so Seek is simply absent until upstream fixes it.
type XOF struct {
	h *blake3.Hasher
	r *blake3.OutputReader
}

// NewXOF returns an unkeyed BLAKE3 XOF.
func NewXOF() *XOF {
	return &XOF{h: blake3.New(Size256, nil)}
}

// NewKeyedXOF returns a keyed BLAKE3 XOF — the same PRF the SumKeyed
// functions expose, read to whatever length is wanted. Useful as a
// keystream or as the output of a KDF step.
func NewKeyedXOF(key [KeyLen]byte) *XOF {
	return &XOF{h: blake3.New(Size256, key[:])}
}

// Write absorbs more input. Once the stream has been committed — by the
// first Read — it returns ErrWriteAfterRead without absorbing anything,
// since continuing to absorb would produce bytes no other implementation
// agrees with.
func (x *XOF) Write(p []byte) (int, error) {
	if x.r != nil {
		return 0, ErrWriteAfterRead
	}
	return x.h.Write(p)
}

// Read produces the next bytes of the stream. It never returns an error
// and never a short read.
func (x *XOF) Read(p []byte) (int, error) {
	if x.r == nil {
		x.r = x.h.XOF()
	}
	return x.r.Read(p)
}

// Reset returns x to its initial state — nothing absorbed, ready to be
// written to again — keeping the key or context it was constructed with.
func (x *XOF) Reset() {
	x.h.Reset()
	x.r = nil
}

// Ensure XOF satisfies the interfaces its doc claims.
var (
	_ io.Writer = (*XOF)(nil)
	_ io.Reader = (*XOF)(nil)
)
