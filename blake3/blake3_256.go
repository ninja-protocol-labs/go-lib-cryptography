package blake3

import (
	"hash"

	"lukechampine.com/blake3"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Digest256 is the first 32 bytes of BLAKE3's output.
type Digest256 struct {
	b [Size256]byte
}

// Hash256 returns the first 32 bytes of BLAKE3's output over data.
func Hash256(data []byte) *Digest256 {
	return &Digest256{
		b: blake3.Sum256(data),
	}
}

// HashKeyed256 returns the first 32 bytes of keyed BLAKE3 over data —
// a MAC, with no HMAC wrapper needed.
func HashKeyed256(key [KeyLen]byte, data []byte) *Digest256 {
	var b [Size256]byte

	h := blake3.New(Size256, key[:])
	_, _ = h.Write(data)
	h.Sum(b[:0])

	return &Digest256{
		b: b,
	}
}

// Digest256FromBytes wraps bytes that are already a 32-byte BLAKE3
// digest, as one read off the wire or out of storage.
func Digest256FromBytes(b []byte) (*Digest256, error) {
	if len(b) != Size256 {
		return nil, ErrInvalidDigest
	}

	return &Digest256{
		b: [Size256]byte(b),
	}, nil
}

// New256 returns a streaming BLAKE3 hash producing 32 bytes, for data
// that does not arrive in one piece.
func New256() hash.Hash {
	return blake3.New(Size256, nil)
}

// NewKeyed256 returns a streaming keyed BLAKE3 hash producing 32
// bytes.
func NewKeyed256(key [KeyLen]byte) hash.Hash {
	return blake3.New(Size256, key[:])
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
