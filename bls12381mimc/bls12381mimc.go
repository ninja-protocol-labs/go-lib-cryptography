// Package bn254mimc is the public API for MiMC over BLS12-381's scalar field.
//
// # This is not a byte hash
//
// Every other hash in this module takes bytes and returns bytes. MiMC does
// not: it is an arithmetic hash, defined over a prime field, and its input
// is a sequence of field elements. That is the whole reason it exists —
// its round function is a handful of field multiplications, which a
// zero-knowledge circuit can prove for a fraction of what proving SHA-256
// would cost. Outside a circuit it is slower than SHA-256 and has had far
// less cryptanalysis; there is no reason to reach for it unless a proof
// system is involved.
//
// Element carries one field element as 32 canonical big-endian bytes. The
// canonicality is not decoration: 32 bytes has more values than the field
// has elements, and quietly reducing an out-of-range one would map two
// distinct inputs to the same hash. Anything out of range is rejected with
// ErrNotCanonical rather than reduced.
//
// To hash arbitrary bytes, map them into the field first — with a
// hash-to-field construction, not by chopping them into 32-byte pieces and
// hoping each lands in range.
//
// # The curve is part of the function
//
// MiMC over BLS12-381's 𝔽r and MiMC over BN254's 𝔽r are different
// functions over different fields, with different round constants. They
// share no digests and cannot be substituted for one another, which is why
// the curve is in this package's name rather than in a parameter.
//
// # Which parameterisation
//
// MiMC is a family, not a single function. This one is gnark-crypto's: the
// Miyaguchi-Preneel mode over the x⁵ S-box, 110 rounds, with constants
// derived from the seed string "seed". It is what gnark's circuits verify
// against, and it interoperates with those and with nothing else in
// particular — MiMC as used by circomlib and by various rollups is a
// different parameterisation and produces different digests.
//
// There is deliberately no way to change the parameters here. Choosing
// them is how the ecosystem ended up with a dozen mutually incompatible
// MiMCs; a library that offers the choice mostly offers a new way to be
// incompatible.
//
// # Two modes
//
// Sum hashes any number of elements. Compress hashes exactly two, which is
// what a Merkle tree needs at every node — it is Sum of two elements, named
// for the thing it is used for. Digest is the streaming form, for input
// that does not arrive at once.
//
// # Security
//
// MiMC's security rests on a much smaller body of analysis than SHA-2's,
// and low-degree arithmetic hashes as a class have been the subject of
// active attack work — Gröbner-basis attacks on this shape of construction
// improve periodically. It is the price of being cheap to prove. Do not use
// it as a general-purpose hash outside the circuit that needs it.
package bls12381mimc

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
)

const (
	// ElementLen is the byte length of one field element, and so of every
	// input and output of this package.
	ElementLen = fr.Bytes

	// Size is the byte length of a digest. MiMC's output is a single field
	// element, so it is ElementLen.
	Size = ElementLen

	// BlockSize is the byte length of one absorbed block, again one field
	// element.
	BlockSize = ElementLen
)

// Element is one BLS12-381 scalar-field element, big-endian, and canonical:
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

// Sum returns the MiMC digest of elems.
//
// It reports ErrNoInput for an empty call rather than returning the zero
// element, which is what the library underneath does — see ErrNoInput —
// and ErrNotCanonical if any element is out of range. Elements are
// validated before any of them is absorbed, so a rejected call leaves
// nothing half-hashed.
func Sum(elems ...Element) (Element, error) {
	if len(elems) == 0 {
		return Element{}, ErrNoInput
	}
	parsed, err := parse(elems)
	if err != nil {
		return Element{}, err
	}
	sum := mimc.NewFieldHasher().SumElements(parsed)
	return Element(sum.Bytes()), nil
}

// Compress returns the MiMC digest of exactly two elements — the 2-to-1
// step a Merkle tree takes at every internal node.
//
// It is Sum(left, right), named for what it is used for. There is no
// separate compression function in MiMC the way there is in Poseidon2;
// hashing two elements is the operation.
func Compress(left, right Element) (Element, error) {
	return Sum(left, right)
}

// Digest is a streaming MiMC hash, for input that does not arrive at once.
//
// It is not a hash.Hash. That interface is defined in terms of bytes, and
// accepting arbitrary bytes here would mean either rejecting most of them
// or silently reducing them into the field — see the package doc.
type Digest struct {
	h       mimc.FieldHasher
	written int
}

// New returns an empty Digest.
func New() *Digest {
	return &Digest{h: mimc.NewFieldHasher()}
}

// Write absorbs elems.
//
// Every element is validated before any is absorbed, so a call that
// returns ErrNotCanonical has changed nothing and the digest stays usable.
func (d *Digest) Write(elems ...Element) error {
	parsed, err := parse(elems)
	if err != nil {
		return err
	}
	for i := range parsed {
		d.h.WriteElement(parsed[i])
	}
	d.written += len(parsed)
	return nil
}

// Sum returns the digest of everything written so far, and reports
// ErrNoInput if that is nothing.
//
// Writing more afterwards continues the same hash rather than starting a
// new one, so Write(a); Sum(); Write(b); Sum() gives the digest of a and
// then the digest of a ∥ b. Use Reset to start over.
func (d *Digest) Sum() (Element, error) {
	if d.written == 0 {
		return Element{}, ErrNoInput
	}
	sum := d.h.SumElement()
	return Element(sum.Bytes()), nil
}

// Reset returns d to its initial state.
func (d *Digest) Reset() {
	d.h.Reset()
	d.written = 0
}

// parse validates and converts a whole batch before any of it is used, so
// that a bad element cannot leave a partially absorbed hash behind.
func parse(elems []Element) ([]fr.Element, error) {
	out := make([]fr.Element, len(elems))
	for i := range elems {
		if err := out[i].SetBytesCanonical(elems[i][:]); err != nil {
			return nil, ErrNotCanonical
		}
	}
	return out, nil
}
