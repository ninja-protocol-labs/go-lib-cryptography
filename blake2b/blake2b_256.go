package blake2b

import (
	"hash"

	"golang.org/x/crypto/blake2b"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Digest256 is a 32-byte BLAKE2b digest.
//
// Every digest length is a distinct function, not a truncation of a longer
// one, which is why each has its own type here — see the package doc.
type Digest256 struct {
	b [Size256]byte
}

// Hash256 returns the unkeyed 32-byte BLAKE2b digest of data.
//
// Not the first 32 bytes of Hash512 — see the package doc.
func Hash256(data []byte) *Digest256 {
	return &Digest256{
		b: blake2b.Sum256(data),
	}
}

// HashKeyed256 returns the 32-byte BLAKE2b digest of data under key —
// a MAC, with no HMAC wrapper needed. key must be at most MaxKeyLen bytes;
// a nil key gives the same result as Hash256.
func HashKeyed256(key, data []byte) (*Digest256, error) {
	var b [Size256]byte

	h, err := New256(key)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	h.Sum(b[:0])

	return &Digest256{
		b: b,
	}, nil
}

// Digest256FromBytes wraps bytes that are already a 32-byte BLAKE2b
// digest, as one read off the wire or out of storage.
func Digest256FromBytes(b []byte) (*Digest256, error) {
	if len(b) != Size256 {
		return nil, ErrInvalidDigest
	}

	return &Digest256{
		b: [Size256]byte(b),
	}, nil
}

// New256 returns a streaming 32-byte BLAKE2b hash, keyed by key. Pass
// nil for the unkeyed hash.
func New256(key []byte) (hash.Hash, error) {
	return newSized(Size256, key)
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
