package sha3

import (
	"crypto/sha3"
	"hash"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Digest224 is a SHA3-224 digest.
type Digest224 struct {
	b [Size224]byte
}

// Hash224 returns the SHA3-224 digest of data.
func Hash224(data []byte) *Digest224 {
	return &Digest224{
		b: sha3.Sum224(data),
	}
}

// Digest224FromBytes wraps bytes that are already a SHA3-224 digest, as
// one read off the wire or out of storage.
func Digest224FromBytes(b []byte) (*Digest224, error) {
	if len(b) != Size224 {
		return nil, ErrInvalidDigest
	}

	return &Digest224{
		b: [Size224]byte(b),
	}, nil
}

// New224 returns a streaming SHA3-224 hash, for data that does not arrive
// in one piece. Its Sum appends to the slice it is given, unlike Hash224's
// Digest224.
func New224() hash.Hash {
	return sha3.New224()
}

func (d *Digest224) Bytes() [Size224]byte {
	return d.b
}

func (d *Digest224) Equal(o *Digest224) bool {
	if o == nil {
		return false
	}
	return d.b == o.b
}

// IsZero catches a `var d Digest224`; no constructor returns one.
func (d *Digest224) IsZero() bool {
	return d == nil || *d == Digest224{}
}

func (d *Digest224) String() string {
	return encoding.Hex.Encode(d.b[:])
}
