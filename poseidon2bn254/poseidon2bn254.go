// Package poseidon2bn254 is the public API for Poseidon2 over BN254's
// scalar field.
//
// # This is Poseidon2, not Poseidon
//
// They are different functions. Poseidon2 (Grassi, Khovratovich, Schofnegger,
// 2023) rebuilds Poseidon's linear layer to cut the number of constraints,
// and uses different round constants; it shares no digests with the original.
//
// That matters more here than the SHA-3/Keccak distinction does, because
// "Poseidon" in the wild is not one function either: circomlib, Polygon and
// StarkNet each ship their own parameter choices, and none of them agree
// with each other or with this. A hash produced by a circom circuit will
// not verify here. The package is named poseidon2 so that nobody has to
// discover that at integration time.
//
// # This is not a byte hash
//
// Like mimcbn254 and unlike every other hash in this module, Poseidon2 is
// an arithmetic hash: it is defined over a prime field and its input is a
// sequence of field elements. That is what makes it cheap to prove — its
// round function is field multiplications a circuit can express directly,
// where SHA-256's bit operations are not. Outside a circuit there is no
// reason to prefer it.
//
// Element carries one field element as 32 canonical big-endian bytes.
// Anything not below r is rejected with ErrNotCanonical rather than
// reduced, since reducing would map two distinct inputs to one digest.
//
// Taking elements rather than bytes also closes a hazard gnark-crypto
// documents in the construction underneath: its Merkle-Damgard wrapper
// zero-pads a short final block instead of applying real padding, so for
// arbitrary byte input the digest of x and of x followed by zeros can be
// the same. With input measured in whole field elements there is no partial
// block and no such ambiguity.
//
// # Compress and Sum are different functions
//
// Unlike mimcbn254, where compressing two elements is just hashing two
// elements, Poseidon2 has a genuine 2-to-1 compression function, and the
// arbitrary-length hash is Merkle-Damgard built on top of it starting from
// an all-zero initial state. So:
//
//	Compress(a, b) != Sum(a, b)          // Sum is Compress(Compress(IV, a), b)
//
// Use Compress for the internal nodes of a Merkle tree — that is what it is
// for, and it is one permutation call rather than two. Use Sum for a digest
// over a sequence.
//
// # Which parameters
//
// The permutation is width 2, with 6 full rounds and 50 partial rounds:
// gnark-crypto's defaults for this curve, and what its circuits verify
// against. There is deliberately no way to change them. Choosing parameters
// is how this family ended up mutually incompatible; a library offering the
// choice mostly offers a new way to be incompatible.
//
// # Security
//
// Poseidon2 rests on a far smaller body of cryptanalysis than SHA-2, and
// low-degree arithmetic hashes as a class are under active attack work —
// Gröbner-basis attacks on this shape improve periodically. That is the
// price of being cheap to prove. Do not use it as a general-purpose hash
// outside the circuit that needs it.
package poseidon2bn254

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

const (
	// ElementLen is the byte length of one field element, and so of every
	// input and output of this package.
	ElementLen = fr.Bytes

	// Size is the byte length of a digest: one field element.
	Size = ElementLen

	// BlockSize is the byte length of one absorbed block, again one field
	// element.
	BlockSize = ElementLen

	// Width is the permutation's state width in field elements. It is 2,
	// which is what makes Compress a 2-to-1 function.
	Width = 2

	// FullRounds and PartialRounds are the permutation's round counts for
	// this curve. They are here to be read, not chosen — see the package
	// doc on why the parameters are fixed.
	FullRounds    = 6
	PartialRounds = 50
)

// Element is one BN254 scalar-field element, big-endian, and canonical:
// its value must be below r. Use FromBytes to build one from untrusted
// input, or construct it directly when the value is known to be in range.
type Element [ElementLen]byte

// FromBytes parses 32 big-endian bytes into an Element, checking that they
// encode a value below r.
//
// This is the parsing boundary, so it takes a slice: an array parameter
// would push the length check to the caller as a panicking conversion.
func FromBytes(b []byte) (Element, error) {
	var out Element
	if len(b) != ElementLen {
		return out, ErrNotCanonical
	}
	var e fr.Element
	if err := e.SetBytesCanonical(b); err != nil {
		return out, ErrNotCanonical
	}
	copy(out[:], b)
	return out, nil
}

// Compress is Poseidon2's 2-to-1 compression function — one permutation
// call, which is what a Merkle tree wants at each internal node.
//
// It is not Sum(left, right); see the package doc.
func Compress(left, right Element) (Element, error) {
	out, err := poseidon2.NewDefaultPermutation().Compress(left[:], right[:])
	if err != nil {
		return Element{}, ErrNotCanonical
	}
	return Element(out), nil
}

// Sum returns the Merkle-Damgard digest of elems over Compress, starting
// from an all-zero initial state.
//
// It reports ErrNoInput for an empty call rather than returning that
// initial state, and ErrNotCanonical if any element is out of range.
// Elements are validated before any of them is absorbed, so a rejected
// call leaves nothing half-hashed.
func Sum(elems ...Element) (Element, error) {
	d := New()
	if err := d.Write(elems...); err != nil {
		return Element{}, err
	}
	return d.Sum()
}

// Digest is a streaming Poseidon2 hash, for input that does not arrive at
// once.
//
// It is not a hash.Hash. That interface is defined in terms of bytes, and
// accepting arbitrary bytes here would mean either rejecting most of them
// or inheriting the zero-padding ambiguity described in the package doc.
type Digest struct {
	h       hasher
	written int
}

// hasher is the slice of gnark's StateStorer this package actually uses,
// named so the backend type stays out of the API.
type hasher interface {
	Write(p []byte) (int, error)
	Sum(b []byte) []byte
	Reset()
}

// New returns an empty Digest.
func New() *Digest {
	return &Digest{h: poseidon2.NewMerkleDamgardHasher()}
}

// Write absorbs elems.
//
// Every element is validated before any is absorbed. That is not only
// tidiness: the construction underneath sets its running state to nil when
// a compression fails, which would leave the digest permanently broken.
// Validating first means Write either absorbs everything or changes
// nothing.
func (d *Digest) Write(elems ...Element) error {
	if err := validate(elems); err != nil {
		return err
	}
	for i := range elems {
		if _, err := d.h.Write(elems[i][:]); err != nil {
			return ErrNotCanonical
		}
	}
	d.written += len(elems)
	return nil
}

// Sum returns the digest of everything written so far, and reports
// ErrNoInput if that is nothing.
//
// Unlike mimcbn254's, this Sum is a pure read: it does not advance the
// hash, so writing more afterwards continues from where the last Write
// left off and Sum can be called as often as you like.
func (d *Digest) Sum() (Element, error) {
	if d.written == 0 {
		return Element{}, ErrNoInput
	}
	return Element(d.h.Sum(nil)), nil
}

// Reset returns d to its initial state.
func (d *Digest) Reset() {
	d.h.Reset()
	d.written = 0
}

// validate checks a whole batch before any of it is absorbed.
func validate(elems []Element) error {
	var e fr.Element
	for i := range elems {
		if err := e.SetBytesCanonical(elems[i][:]); err != nil {
			return ErrNotCanonical
		}
	}
	return nil
}
