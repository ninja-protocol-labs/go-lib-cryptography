package sha2

import (
	"crypto/sha512"
	"hash"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Digest512_256 is a SHA-512/256 digest.
type Digest512_256 struct {
	b [Size512_256]byte
}

// Hash512_256 returns the SHA-512/256 digest of data.
//
// The same length as SHA-256, from the 64-bit compression function, and
// not vulnerable to length extension because most of the state is
// withheld. Prefer it over Hash256 where nothing external fixes the
// choice and the hardware has no SHA-256 instructions.
func Hash512_256(data []byte) *Digest512_256 {
	return &Digest512_256{
		b: sha512.Sum512_256(data),
	}
}

// Digest512_256FromBytes wraps bytes that are already a SHA-512/256 digest, as
// one read off the wire or out of storage.
func Digest512_256FromBytes(b []byte) (*Digest512_256, error) {
	if len(b) != Size512_256 {
		return nil, ErrInvalidDigest
	}

	return &Digest512_256{
		b: [Size512_256]byte(b),
	}, nil
}

// New512_256 returns a streaming SHA-512/256 hash, for data that does not
// arrive in one piece. Its Sum appends to the slice it is given, unlike
// Hash512_256's Digest512_256.
func New512_256() hash.Hash {
	return sha512.New512_256()
}

func (d *Digest512_256) Bytes() [Size512_256]byte {
	return d.b
}

func (d *Digest512_256) Equal(o *Digest512_256) bool {
	if o == nil {
		return false
	}
	return d.b == o.b
}

// IsZero catches a `var d Digest512_256`; no constructor returns one.
func (d *Digest512_256) IsZero() bool {
	return d == nil || *d == Digest512_256{}
}

func (d *Digest512_256) String() string {
	return encoding.Hex.Encode(d.b[:])
}
