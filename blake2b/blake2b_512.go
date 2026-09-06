package blake2b

import (
	"hash"

	"golang.org/x/crypto/blake2b"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Digest512 is a 64-byte BLAKE2b digest.
//
// Every digest length is a distinct function, not a truncation of a longer
// one, which is why each has its own type here — see the package doc.
type Digest512 struct {
	b [Size512]byte
}

// Hash512 returns the unkeyed 64-byte BLAKE2b digest of data. This is
// BLAKE2b's full output and the one to use when nothing forces a shorter
// digest.
func Hash512(data []byte) *Digest512 {
	return &Digest512{
		b: blake2b.Sum512(data),
	}
}

// HashKeyed512 returns the 64-byte BLAKE2b digest of data under key —
// a MAC, with no HMAC wrapper needed. key must be at most MaxKeyLen bytes;
// a nil key gives the same result as Hash512.
//
// This is the MAC to reach for unless something fixes a shorter tag length.
func HashKeyed512(key, data []byte) (*Digest512, error) {
	var b [Size512]byte

	h, err := New512(key)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	h.Sum(b[:0])

	return &Digest512{
		b: b,
	}, nil
}

// Digest512FromBytes wraps bytes that are already a 64-byte BLAKE2b
// digest, as one read off the wire or out of storage.
func Digest512FromBytes(b []byte) (*Digest512, error) {
	if len(b) != Size512 {
		return nil, ErrInvalidDigest
	}

	return &Digest512{
		b: [Size512]byte(b),
	}, nil
}

// New512 returns a streaming 64-byte BLAKE2b hash, keyed by key. Pass
// nil for the unkeyed hash.
func New512(key []byte) (hash.Hash, error) {
	return newSized(Size512, key)
}

func (d *Digest512) Bytes() [Size512]byte {
	return d.b
}

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

func (d *Digest512) String() string {
	return encoding.Hex.Encode(d.b[:])
}
