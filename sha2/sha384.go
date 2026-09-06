package sha2

import (
	"crypto/sha512"
	"hash"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Digest384 is a SHA-384 digest.
type Digest384 struct {
	b [Size384]byte
}

// Hash384 returns the SHA-384 digest of data.
//
// SHA-384 is SHA-512 truncated to 48 bytes from a different initial
// state. It withholds a quarter of the state, which is not enough to
// stop a length-extension attack.
func Hash384(data []byte) *Digest384 {
	return &Digest384{
		b: sha512.Sum384(data),
	}
}

// Digest384FromBytes wraps bytes that are already a SHA-384 digest, as
// one read off the wire or out of storage.
func Digest384FromBytes(b []byte) (*Digest384, error) {
	if len(b) != Size384 {
		return nil, ErrInvalidDigest
	}

	return &Digest384{
		b: [Size384]byte(b),
	}, nil
}

// New384 returns a streaming SHA-384 hash, for data that does not
// arrive in one piece. Its Sum appends to the slice it is given, unlike
// Hash384's Digest384.
func New384() hash.Hash {
	return sha512.New384()
}

// Bytes returns the digest, as a copy.
func (d *Digest384) Bytes() [Size384]byte {
	return d.b
}

// Equal reports whether o is the same digest. It is nil-safe, and not
// constant-time — a digest is public.
func (d *Digest384) Equal(o *Digest384) bool {
	if o == nil {
		return false
	}
	return d.b == o.b
}

// IsZero catches a `var d Digest384`; no constructor returns one.
func (d *Digest384) IsZero() bool {
	return d == nil || *d == Digest384{}
}

// String returns the digest as lowercase hex.
func (d *Digest384) String() string {
	return encoding.Hex.Encode(d.b[:])
}
