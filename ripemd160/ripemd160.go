package ripemd160

import (
	"hash"

	"golang.org/x/crypto/ripemd160"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Digest is a RIPEMD-160 digest.
type Digest struct {
	b [Size]byte
}

// Hash returns the RIPEMD-160 digest of data.
func Hash(data []byte) *Digest {
	var b [Size]byte

	h := ripemd160.New()
	h.Write(data)
	h.Sum(b[:0])

	return &Digest{
		b: b,
	}
}

// DigestFromBytes wraps bytes that are already a RIPEMD-160 digest, as one
// read off the wire or out of storage.
func DigestFromBytes(b []byte) (*Digest, error) {
	if len(b) != Size {
		return nil, ErrInvalidDigest
	}

	return &Digest{
		b: [Size]byte(b),
	}, nil
}

// New returns a streaming RIPEMD-160 hash, for data that does not arrive
// in one piece. Its Sum appends to the slice it is given, unlike Hash's
// Digest.
func New() hash.Hash {
	return ripemd160.New()
}

func (d *Digest) Bytes() [Size]byte {
	return d.b
}

func (d *Digest) Equal(o *Digest) bool {
	if o == nil {
		return false
	}
	return d.b == o.b
}

// IsZero catches a `var d Digest`; no constructor returns one.
func (d *Digest) IsZero() bool {
	return d == nil || *d == Digest{}
}

func (d *Digest) String() string {
	return encoding.Hex.Encode(d.b[:])
}
