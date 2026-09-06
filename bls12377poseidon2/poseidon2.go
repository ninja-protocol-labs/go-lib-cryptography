package bls12377poseidon2

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
	gnarkhash "github.com/consensys/gnark-crypto/hash"
)

// Compress is Poseidon2's 2-to-1 compression function — one permutation
// call, which is what a Merkle tree wants at each internal node.
//
// It is not Hash(left, right); see the package doc.
func Compress(left, right []byte) (*Digest, error) {
	if err := validateAll([][]byte{left, right}); err != nil {
		return nil, err
	}

	out, err := poseidon2.NewDefaultPermutation().Compress(left, right)
	if err != nil {
		return nil, ErrNotCanonical
	}

	return &Digest{
		b: [Size]byte(out),
	}, nil
}

// Hash returns the Merkle-Damgard digest of elems over Compress, starting
// from an all-zero initial state.
//
// It reports ErrNoInput for an empty call rather than returning that
// initial state, and ErrNotCanonical if any element is out of range.
// Elements are validated before any of them is absorbed, so a rejected
// call leaves nothing half-hashed.
func Hash(elems ...[]byte) (*Digest, error) {
	h := New()
	if err := h.Write(elems...); err != nil {
		return nil, err
	}
	return h.Sum()
}

// Hasher is a streaming Poseidon2 hash, for input that does not arrive at
// once.
//
// It is not a hash.Hash. That interface is defined in terms of bytes, and
// accepting arbitrary bytes here would mean either rejecting most of them
// or inheriting the zero-padding ambiguity described in the package doc.
type Hasher struct {
	h       gnarkhash.StateStorer
	written int
}

// New returns an empty Hasher.
func New() *Hasher {
	return &Hasher{
		h: poseidon2.NewMerkleDamgardHasher(),
	}
}

// Write absorbs elems.
//
// Every element is validated before any is absorbed. That is not only
// tidiness: the construction underneath sets its running state to nil when
// a compression fails, which would leave the hash permanently broken.
// Validating first means Write either absorbs everything or changes
// nothing.
func (h *Hasher) Write(elems ...[]byte) error {
	if err := validateAll(elems); err != nil {
		return err
	}
	for i := range elems {
		if _, err := h.h.Write(elems[i]); err != nil {
			return ErrNotCanonical
		}
	}
	h.written += len(elems)
	return nil
}

// Sum returns the digest of everything written so far, and reports
// ErrNoInput if that is nothing.
//
// Unlike bls12377mimc's, this Sum is a pure read: it does not advance the
// hash, so writing more afterwards continues from where the last Write
// left off and Sum can be called as often as you like.
func (h *Hasher) Sum() (*Digest, error) {
	if h.written == 0 {
		return nil, ErrNoInput
	}

	return &Digest{
		b: [Size]byte(h.h.Sum(nil)),
	}, nil
}

// Reset returns h to its initial state.
func (h *Hasher) Reset() {
	h.h.Reset()
	h.written = 0
}
