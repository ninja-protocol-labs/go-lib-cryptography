package sha2

import (
	"crypto/sha256"
	"hash"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Digest224 is a SHA-224 digest.
type Digest224 struct {
	b [Size224]byte
}

// Hash224 returns the SHA-224 digest of data.
//
// SHA-224 is SHA-256 truncated to 28 bytes from a different initial
// state. It is length-extendable in the same way SHA-256 is; the
// truncation does not withhold enough state to prevent it.
func Hash224(data []byte) *Digest224 {
	return &Digest224{
		b: sha256.Sum224(data),
	}
}

// Digest224FromBytes wraps bytes that are already a SHA-224 digest, as
// one read off the wire or out of storage.
func Digest224FromBytes(b []byte) (*Digest224, error) {
	if len(b) != Size224 {
		return nil, ErrInvalidDigest
	}

	return &Digest224{
		b: [Size224]byte(b),
	}, nil
}

// New224 returns a streaming SHA-224 hash, for data that does not
// arrive in one piece. Its Sum appends to the slice it is given, unlike
// Hash224's Digest224.
func New224() hash.Hash {
	return sha256.New224()
}

// Bytes returns the digest, as a copy.
func (d *Digest224) Bytes() [Size224]byte {
	return d.b
}

// Equal reports whether o is the same digest. It is nil-safe, and not
// constant-time — a digest is public.
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

// String returns the digest as lowercase hex.
func (d *Digest224) String() string {
	return encoding.Hex.Encode(d.b[:])
}
