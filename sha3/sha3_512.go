package sha3

import (
	"crypto/sha3"
	"hash"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Digest512 is a SHA3-512 digest.
type Digest512 struct {
	b [Size512]byte
}

// Hash512 returns the SHA3-512 digest of data.
func Hash512(data []byte) *Digest512 {
	return &Digest512{
		b: sha3.Sum512(data),
	}
}

// Digest512FromBytes wraps bytes that are already a SHA3-512 digest, as
// one read off the wire or out of storage.
func Digest512FromBytes(b []byte) (*Digest512, error) {
	if len(b) != Size512 {
		return nil, ErrInvalidDigest
	}

	return &Digest512{
		b: [Size512]byte(b),
	}, nil
}

// New512 returns a streaming SHA3-512 hash, for data that does not arrive
// in one piece. Its Sum appends to the slice it is given, unlike Hash512's
// Digest512.
func New512() hash.Hash {
	return sha3.New512()
}

// Bytes returns the digest, as a copy.
func (d *Digest512) Bytes() [Size512]byte {
	return d.b
}

// Equal reports whether o is the same digest. It is nil-safe, and not
// constant-time — a digest is public.
func (d *Digest512) Equal(o *Digest512) bool {
	if o == nil {
		return false
	}
	return d.b == o.b
}

// IsZero catches a `var d Digest512`; no constructor returns one.
func (d *Digest512) IsZero() bool {
	return d == nil || *d == Digest512{}
}

// String returns the digest as lowercase hex.
func (d *Digest512) String() string {
	return encoding.Hex.Encode(d.b[:])
}
