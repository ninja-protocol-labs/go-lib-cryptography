package keccak

import (
	"hash"

	"golang.org/x/crypto/sha3"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Digest512 is a Keccak-512 digest — Ethereum's keccak512, not SHA3-512.
type Digest512 struct {
	b [Size512]byte
}

// Hash512 returns the Keccak-512 digest of data.
func Hash512(data []byte) *Digest512 {
	var b [Size512]byte

	h := sha3.NewLegacyKeccak512()
	h.Write(data)
	h.Sum(b[:0])

	return &Digest512{
		b: b,
	}
}

// Digest512FromBytes wraps bytes that are already a Keccak-512 digest, as
// one read off the wire or out of storage.
func Digest512FromBytes(b []byte) (*Digest512, error) {
	if len(b) != Size512 {
		return nil, ErrInvalidDigest
	}

	return &Digest512{
		b: [Size512]byte(b),
	}, nil
}

// New512 returns a streaming Keccak-512 hash, for data that does not
// arrive in one piece. Its Sum appends to the slice it is given, unlike
// Hash512's Digest512.
func New512() hash.Hash {
	return sha3.NewLegacyKeccak512()
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
