package sha2

import (
	"crypto/sha512"
	"hash"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Digest512_224 is a SHA-512/224 digest.
type Digest512_224 struct {
	b [Size512_224]byte
}

// Hash512_224 returns the SHA-512/224 digest of data.
//
// SHA-512/224 is the 64-bit compression function truncated to 28 bytes.
// Most of the state is withheld, so unlike SHA-224 it is not vulnerable
// to length extension.
func Hash512_224(data []byte) *Digest512_224 {
	return &Digest512_224{
		b: sha512.Sum512_224(data),
	}
}

// Digest512_224FromBytes wraps bytes that are already a SHA-512/224 digest, as
// one read off the wire or out of storage.
func Digest512_224FromBytes(b []byte) (*Digest512_224, error) {
	if len(b) != Size512_224 {
		return nil, ErrInvalidDigest
	}

	return &Digest512_224{
		b: [Size512_224]byte(b),
	}, nil
}

// New512_224 returns a streaming SHA-512/224 hash, for data that does not
// arrive in one piece. Its Sum appends to the slice it is given, unlike
// Hash512_224's Digest512_224.
func New512_224() hash.Hash {
	return sha512.New512_224()
}

func (d *Digest512_224) Bytes() [Size512_224]byte {
	return d.b
}

func (d *Digest512_224) Equal(o *Digest512_224) bool {
	if o == nil {
		return false
	}
	return d.b == o.b
}

// IsZero catches a `var d Digest512_224`; no constructor returns one.
func (d *Digest512_224) IsZero() bool {
	return d == nil || *d == Digest512_224{}
}

func (d *Digest512_224) String() string {
	return encoding.Hex.Encode(d.b[:])
}
