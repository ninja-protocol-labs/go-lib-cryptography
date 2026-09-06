package sha3

import (
	"crypto/sha3"
	"hash"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Digest256 is a SHA3-256 digest.
type Digest256 struct {
	b [Size256]byte
}

// Hash256 returns the SHA3-256 digest of data.
//
// This is FIPS 202's SHA-3, not Ethereum's Keccak-256 — see the package
// doc.
func Hash256(data []byte) *Digest256 {
	return &Digest256{
		b: sha3.Sum256(data),
	}
}

// Digest256FromBytes wraps bytes that are already a SHA3-256 digest, as
// one read off the wire or out of storage.
func Digest256FromBytes(b []byte) (*Digest256, error) {
	if len(b) != Size256 {
		return nil, ErrInvalidDigest
	}

	return &Digest256{
		b: [Size256]byte(b),
	}, nil
}

// New256 returns a streaming SHA3-256 hash, for data that does not arrive
// in one piece. Its Sum appends to the slice it is given, unlike Hash256's
// Digest256.
func New256() hash.Hash {
	return sha3.New256()
}

func (d *Digest256) Bytes() [Size256]byte {
	return d.b
}

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

func (d *Digest256) String() string {
	return encoding.Hex.Encode(d.b[:])
}
