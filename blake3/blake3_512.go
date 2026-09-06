package blake3

import (
	"hash"

	"lukechampine.com/blake3"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Digest512 is the first 64 bytes of BLAKE3's output.
//
// Every BLAKE3 length is a prefix of the same stream, so a Digest512's
// first 32 bytes are exactly the Digest256 of the same input — unlike
// BLAKE2b, where each length is a different function.
type Digest512 struct {
	b [Size512]byte
}

// Hash512 returns the first 64 bytes of BLAKE3's output over data. Its first
// 32 bytes are exactly Hash256(data).
func Hash512(data []byte) *Digest512 {
	return &Digest512{
		b: blake3.Sum512(data),
	}
}

// HashKeyed512 returns the first 64 bytes of keyed BLAKE3 over data —
// a MAC, with no HMAC wrapper needed.
func HashKeyed512(key [KeyLen]byte, data []byte) *Digest512 {
	var b [Size512]byte

	h := blake3.New(Size512, key[:])
	_, _ = h.Write(data)
	h.Sum(b[:0])

	return &Digest512{
		b: b,
	}
}

// Digest512FromBytes wraps bytes that are already a 64-byte BLAKE3
// digest, as one read off the wire or out of storage.
func Digest512FromBytes(b []byte) (*Digest512, error) {
	if len(b) != Size512 {
		return nil, ErrInvalidDigest
	}

	return &Digest512{
		b: [Size512]byte(b),
	}, nil
}

// New512 returns a streaming BLAKE3 hash producing 64 bytes, for data
// that does not arrive in one piece.
func New512() hash.Hash {
	return blake3.New(Size512, nil)
}

// NewKeyed512 returns a streaming keyed BLAKE3 hash producing 64
// bytes.
func NewKeyed512(key [KeyLen]byte) hash.Hash {
	return blake3.New(Size512, key[:])
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
