package blake2b

import (
	"hash"

	"golang.org/x/crypto/blake2b"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Digest384 is a 48-byte BLAKE2b digest.
//
// Every digest length is a distinct function, not a truncation of a longer
// one, which is why each has its own type here — see the package doc.
type Digest384 struct {
	b [Size384]byte
}

// Hash384 returns the unkeyed 48-byte BLAKE2b digest of data.
func Hash384(data []byte) *Digest384 {
	return &Digest384{
		b: blake2b.Sum384(data),
	}
}

// HashKeyed384 returns the 48-byte BLAKE2b digest of data under key —
// a MAC, with no HMAC wrapper needed. key must be at most MaxKeyLen bytes;
// a nil key gives the same result as Hash384.
func HashKeyed384(key, data []byte) (*Digest384, error) {
	var b [Size384]byte

	h, err := New384(key)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	h.Sum(b[:0])

	return &Digest384{
		b: b,
	}, nil
}

// Digest384FromBytes wraps bytes that are already a 48-byte BLAKE2b
// digest, as one read off the wire or out of storage.
func Digest384FromBytes(b []byte) (*Digest384, error) {
	if len(b) != Size384 {
		return nil, ErrInvalidDigest
	}

	return &Digest384{
		b: [Size384]byte(b),
	}, nil
}

// New384 returns a streaming 48-byte BLAKE2b hash, keyed by key. Pass
// nil for the unkeyed hash.
func New384(key []byte) (hash.Hash, error) {
	return newSized(Size384, key)
}

func (d *Digest384) Bytes() [Size384]byte {
	return d.b
}

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

func (d *Digest384) String() string {
	return encoding.Hex.Encode(d.b[:])
}
