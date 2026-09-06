package md5

import (
	"crypto/md5"
	"hash"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Digest is an MD5 digest.
type Digest struct {
	b [Size]byte
}

// Hash returns the MD5 digest of data.
//
// See the package doc before using this for anything an adversary can
// influence.
func Hash(data []byte) *Digest {
	return &Digest{
		b: md5.Sum(data),
	}
}

// DigestFromBytes wraps bytes that are already an MD5 digest, as one read
// off the wire or out of storage.
func DigestFromBytes(b []byte) (*Digest, error) {
	if len(b) != Size {
		return nil, ErrInvalidDigest
	}

	return &Digest{
		b: [Size]byte(b),
	}, nil
}

// New returns a streaming MD5 hash, for data that does not arrive in one
// piece. Its Sum appends to the slice it is given, unlike Hash's Digest.
func New() hash.Hash {
	return md5.New()
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
