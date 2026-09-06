package bn254mimc

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// Digest is one BN254 scalar-field element: the output of every hash in
// this package, and a valid input to the next one.
type Digest struct {
	b [Size]byte
}

// DigestFromBytes wraps 32 big-endian bytes that are already a digest.
//
// Unlike the byte hashes, this validates: a digest is a field element, so
// bytes that do not encode a value below r were never one.
func DigestFromBytes(b []byte) (*Digest, error) {
	if err := validate(b); err != nil {
		return nil, err
	}

	return &Digest{
		b: [Size]byte(b),
	}, nil
}

// Bytes returns the digest, as a copy. It is one canonical field
// element, so it can be fed straight back into Hash or Compress.
func (d *Digest) Bytes() [Size]byte {
	return d.b
}

// Equal reports whether o is the same digest. It is nil-safe, and not
// constant-time — a digest is public.
func (d *Digest) Equal(o *Digest) bool {
	if o == nil {
		return false
	}
	return d.b == o.b
}

// IsZero catches a `var d Digest`; no constructor returns one.
func (d *Digest) IsZero() bool {
	return d == nil || *d == Digest{}
}

// String returns the digest as lowercase hex.
func (d *Digest) String() string {
	return encoding.Hex.Encode(d.b[:])
}

// validate checks that b is one canonical field element.
func validate(b []byte) error {
	if len(b) != ElementLen {
		return ErrNotCanonical
	}
	var e fr.Element
	if err := e.SetBytesCanonical(b); err != nil {
		return ErrNotCanonical
	}
	return nil
}

// validateAll checks a whole batch before any of it is absorbed, so that a
// bad element cannot leave a partially written hash behind.
func validateAll(elems [][]byte) error {
	for i := range elems {
		if err := validate(elems[i]); err != nil {
			return err
		}
	}
	return nil
}
