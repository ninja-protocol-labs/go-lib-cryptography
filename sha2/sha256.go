package sha2

import (
	"crypto/sha256"
	"hash"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Digest256 is a SHA-256 digest.
type Digest256 struct {
	b [Size256]byte
}

// Hash256 returns the SHA-256 digest of data.
//
// This is the family's default, and the one with dedicated instructions
// on most current hardware. Note that it is length-extendable: see the
// package doc before using it over anything secret.
func Hash256(data []byte) *Digest256 {
	return &Digest256{
		b: sha256.Sum256(data),
	}
}

// Digest256FromBytes wraps bytes that are already a SHA-256 digest, as
// one read off the wire or out of storage.
func Digest256FromBytes(b []byte) (*Digest256, error) {
	if len(b) != Size256 {
		return nil, ErrInvalidDigest
	}

	return &Digest256{
		b: [Size256]byte(b),
	}, nil
}

// New256 returns a streaming SHA-256 hash, for data that does not
// arrive in one piece. Its Sum appends to the slice it is given, unlike
// Hash256's Digest256.
func New256() hash.Hash {
	return sha256.New()
}

// Bytes returns the digest, as a copy.
func (d *Digest256) Bytes() [Size256]byte {
	return d.b
}

// Equal reports whether o is the same digest. It is nil-safe, and not
// constant-time — a digest is public.
func (d *Digest256) Equal(o *Digest256) bool {
	if o == nil {
		return false
	}
	return d.b == o.b
}

// IsZero catches a `var d Digest256`; no constructor returns one.
func (d *Digest256) IsZero() bool {
	return d == nil || *d == Digest256{}
}

// String returns the digest as lowercase hex.
func (d *Digest256) String() string {
	return encoding.Hex.Encode(d.b[:])
}
