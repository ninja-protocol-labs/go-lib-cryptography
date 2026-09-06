package bls12377mimc

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
)

// Hash returns the MiMC digest of elems, each one canonical big-endian
// field element.
//
// It reports ErrNoInput for an empty call rather than returning the zero
// element, which is what the library underneath does — see ErrNoInput —
// and ErrNotCanonical if any element is out of range. Elements are
// validated before any of them is absorbed, so a rejected call leaves
// nothing half-hashed.
func Hash(elems ...[]byte) (*Digest, error) {
	if len(elems) == 0 {
		return nil, ErrNoInput
	}
	if err := validateAll(elems); err != nil {
		return nil, err
	}

	h := mimc.NewFieldHasher()
	for i := range elems {
		var e fr.Element
		e.SetBytes(elems[i])
		h.WriteElement(e)
	}
	sum := h.SumElement()

	return &Digest{
		b: sum.Bytes(),
	}, nil
}

// Compress returns the MiMC digest of exactly two elements — the 2-to-1
// step a Merkle tree takes at every internal node.
//
// It is Hash(left, right), named for what it is used for. There is no
// separate compression function in MiMC the way there is in Poseidon2;
// hashing two elements is the operation.
func Compress(left, right []byte) (*Digest, error) {
	return Hash(left, right)
}

// Hasher is a streaming MiMC hash, for input that does not arrive at once.
//
// It is not a hash.Hash. That interface is defined in terms of bytes, and
// accepting arbitrary bytes here would mean either rejecting most of them
// or silently reducing them into the field — see the package doc.
type Hasher struct {
	h       mimc.FieldHasher
	written int
}

// New returns an empty Hasher.
func New() *Hasher {
	return &Hasher{
		h: mimc.NewFieldHasher(),
	}
}

// Write absorbs elems.
//
// Every element is validated before any is absorbed, so a call that
// returns ErrNotCanonical has changed nothing and the hash stays usable.
func (h *Hasher) Write(elems ...[]byte) error {
	if err := validateAll(elems); err != nil {
		return err
	}
	for i := range elems {
		var e fr.Element
		e.SetBytes(elems[i])
		h.h.WriteElement(e)
	}
	h.written += len(elems)
	return nil
}

// Sum returns the digest of everything written so far, and reports
// ErrNoInput if that is nothing.
//
// Writing more afterwards continues the same hash rather than starting a
// new one, so Write(a); Sum(); Write(b); Sum() gives the digest of a and
// then the digest of a ∥ b. Use Reset to start over.
func (h *Hasher) Sum() (*Digest, error) {
	if h.written == 0 {
		return nil, ErrNoInput
	}
	sum := h.h.SumElement()

	return &Digest{
		b: sum.Bytes(),
	}, nil
}

// Reset returns h to its initial state.
func (h *Hasher) Reset() {
	h.h.Reset()
	h.written = 0
}
